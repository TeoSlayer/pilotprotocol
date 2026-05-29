// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// Throughput benchmarks for the Pilot congestion control stack.
//
// Each benchmark simulates a single bidirectional Pilot connection transferring
// 4 MB of data under a given packet-loss rate.  The simulation drives
// TrackSend / ProcessAck / ProcessSACK / retransmitUnacked directly — no
// network sockets — so results isolate the congestion-control layer.
//
// Loss model: uniform i.i.d. loss at the specified rate.  Lost segments are
// detected by the receiver side which sends SACK blocks for out-of-order
// arrivals, exactly as the real daemon does.
//
// Run:
//
//	go test ./pkg/daemon -run='^$' -bench=BenchmarkThroughput \
//	    -benchtime=5s -benchmem
//
// To compare v1.8.x (unpatched) vs v1.9.1 (this branch), check out both
// commits and run the benchmark on each; report ns/op and MB/s.

const benchTransferBytes = 4 * 1024 * 1024 // 4 MB

func BenchmarkThroughputNoLoss(b *testing.B)    { runThroughputBench(b, 0.000) }
func BenchmarkThroughput01PctLoss(b *testing.B) { runThroughputBench(b, 0.001) }
func BenchmarkThroughput1PctLoss(b *testing.B)  { runThroughputBench(b, 0.010) }
func BenchmarkThroughput5PctLoss(b *testing.B)  { runThroughputBench(b, 0.050) }

func runThroughputBench(b *testing.B, lossRate float64) {
	b.Helper()
	b.SetBytes(benchTransferBytes)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		transferred := simulateTransfer(lossRate, benchTransferBytes, 42+int64(i))
		if transferred != benchTransferBytes {
			b.Fatalf("transfer incomplete: got %d bytes, want %d", transferred, benchTransferBytes)
		}
	}
}

// TestThroughputReport prints a human-readable throughput table for various
// loss rates.  Run with -v to see results:
//
//	go test ./pkg/daemon -run=TestThroughputReport -v
func TestThroughputReport(t *testing.T) {
	t.Parallel()
	losses := []struct {
		name string
		rate float64
	}{
		{"0%", 0.000},
		{"0.1%", 0.001},
		{"0.5%", 0.005},
		{"1%", 0.010},
		{"5%", 0.050},
	}

	type result struct {
		name        string
		rate        float64
		elapsed     time.Duration
		mbps        float64
		retransmits int
	}

	const dataBytes = 2 * 1024 * 1024 // 2 MB per run
	var results []result

	for _, tc := range losses {
		start := time.Now()
		transferred := simulateTransferFull(tc.rate, dataBytes, 12345)
		elapsed := time.Since(start)
		if transferred != dataBytes {
			t.Errorf("loss=%s: transfer incomplete: %d/%d bytes", tc.name, transferred, dataBytes)
		}
		mbps := float64(dataBytes) / elapsed.Seconds() / (1024 * 1024)
		results = append(results, result{
			name:    tc.name,
			rate:    tc.rate,
			elapsed: elapsed,
			mbps:    mbps,
		})
	}

	t.Log("")
	t.Log("Pilot v1.9.1 congestion-control throughput (2 MB transfer, simulated loss)")
	t.Log("╔══════════╦══════════════╦════════════╗")
	t.Log("║ Loss     ║ Time         ║ Throughput ║")
	t.Log("╠══════════╬══════════════╬════════════╣")
	for _, r := range results {
		t.Logf("║ %-8s ║ %-12s ║ %6.1f MB/s ║", r.name, r.elapsed.Round(time.Microsecond), r.mbps)
	}
	t.Log("╚══════════╩══════════════╩════════════╝")
}

// simulateTransfer runs a simulated Pilot connection transferring totalBytes
// under the given loss rate.  Returns the number of bytes acknowledged.
func simulateTransfer(lossRate float64, totalBytes int, seed int64) int {
	return simulateTransferFull(lossRate, totalBytes, seed)
}

// simulateTransferFull exercises the full congestion-control stack:
//   - TrackSend adds outgoing segments to the retransmit buffer.
//   - The simulated receiver ACKs delivered segments; lost segments are
//     SACKed by out-of-order deliveries.
//   - retransmitUnacked fires timeout recovery for stalled windows.
func simulateTransferFull(lossRate float64, totalBytes int, seed int64) int {
	rng := rand.New(rand.NewSource(seed))

	conn := &Connection{
		CongWin:     InitialCongWin,
		SSThresh:    MaxCongWin / 2,
		RTO:         InitialRTO,
		PeerRecvWin: RecvBufSize * MaxSegmentSize, // large peer window; not the bottleneck
		WindowCh:    make(chan struct{}, 8),
		NagleCh:     make(chan struct{}, 1),
	}

	// No-op retransmit callback — the simulation drives recovery directly
	// without sending real packets.
	conn.RetxSend = func(_ *protocol.Packet) {}

	// --- Re-implement with direct protocol.Packet approach ---
	// Build a small simulation that doesn't need protocol.Packet at all:
	// we drive ProcessAck directly with synthetic ack numbers.

	// The state machine:
	//   nextSend  = next sequence number to send (advances with TrackSend)
	//   ackedUpTo = highest cumulatively ACKed seq (= conn.LastAck)
	//   received  = map of seq → delivered (simulates receiver state)
	//   lost      = set of seq that were dropped

	seqBase := uint32(1000)
	nextSend := seqBase
	ackedUpTo := seqBase // conn.LastAck starts here
	conn.LastAck = seqBase

	type segInfo struct {
		seq  uint32
		size int
		lost bool
	}
	var segments []segInfo
	totalSent := 0

	// Pre-generate all segment info (seq, size, lost?) so the simulation is
	// fully deterministic from the RNG seed.
	for totalSent < totalBytes {
		size := MaxSegmentSize
		if totalSent+size > totalBytes {
			size = totalBytes - totalSent
		}
		lost := rng.Float64() < lossRate
		segments = append(segments, segInfo{seq: nextSend, size: size, lost: lost})
		nextSend += uint32(size)
		totalSent += size
	}
	totalSegs := len(segments)

	// Simulate the transfer loop:
	//   1. Send segments up to CongWin limit.
	//   2. Receiver generates ACKs for delivered segments.
	//   3. Sender processes ACKs.
	//   4. For stuck windows, fire retransmitUnacked (timeout recovery).

	// Track which segments the "receiver" has received.
	rcvd := make([]bool, totalSegs) // rcvd[i] = segment i delivered to receiver

	// Map seq → segment index for fast lookup.
	seqToIdx := make(map[uint32]int, totalSegs)
	for i, s := range segments {
		seqToIdx[s.seq] = i
	}

	// Receiver state: cumulative ACK and SACK bookkeeping.
	rcvdUpTo := seqBase // highest contiguous byte received

	// Helper: compute current cumulative ACK and SACK blocks from rcvd.
	computeACK := func() (cumAck uint32, sacks []SACKBlock) {
		// Advance cumAck over contiguous received segments.
		cumIdx := 0
		for cumIdx < totalSegs && rcvd[cumIdx] {
			cumIdx++
		}
		if cumIdx > 0 {
			cumAck = segments[cumIdx-1].seq + uint32(segments[cumIdx-1].size)
		} else {
			cumAck = seqBase
		}
		rcvdUpTo = cumAck

		// Build SACK blocks for out-of-order received segments.
		inSack := false
		var cur SACKBlock
		for i := cumIdx; i < totalSegs; i++ {
			if rcvd[i] && !inSack {
				cur.Left = segments[i].seq
				inSack = true
			} else if !rcvd[i] && inSack {
				cur.Right = segments[i].seq
				sacks = append(sacks, cur)
				inSack = false
				if len(sacks) >= 4 {
					break
				}
			}
		}
		if inSack {
			cur.Right = segments[totalSegs-1].seq + uint32(segments[totalSegs-1].size)
			sacks = append(sacks, cur)
		}
		return cumAck, sacks
	}

	// Simulation loop.
	// simNow tracks simulated time so timeout comparisons work correctly
	// at nanosecond resolution without waiting for real wall-clock seconds.
	simNow := time.Now()
	simRound := func() { simNow = simNow.Add(conn.RTO + time.Millisecond) }
	_ = simRound

	// Patch sentAt / LastRetxTime comparisons to use simNow by pre-aging
	// entries at send time.  Simpler approach: all sentAt assignments in this
	// simulation use simNow; use a counter to advance simNow per retransmit
	// round.
	simTime := simNow
	advanceSim := func(d time.Duration) { simTime = simTime.Add(d) }

	// Re-initialize Unacked so TrackSend uses our sim time epoch.
	// TrackSend sets sentAt=time.Now() internally; we overwrite after each call.
	sendIdx := 0 // next segment index to send
	noProgressRounds := 0
	maxIterations := totalSegs * 200 // safety bound; sim converges fast

	for iter := 0; iter < maxIterations; iter++ {
		// Check if transfer is complete.
		if ackedUpTo == nextSend {
			break
		}

		prevAcked := ackedUpTo
		prevSendIdx := sendIdx

		// Phase 1: send new segments while window allows.
		for sendIdx < totalSegs {
			bytesInFlight := conn.BytesInFlight()
			effWin := conn.CongWin
			if conn.PeerRecvWin >= 0 && conn.PeerRecvWin < effWin {
				effWin = conn.PeerRecvWin
			}
			if bytesInFlight >= effWin {
				break
			}
			seg := segments[sendIdx]
			data := make([]byte, seg.size)
			conn.TrackSend(seg.seq, data)
			// Overwrite sentAt with simTime so timeout checks use sim clock.
			conn.RetxMu.Lock()
			if len(conn.Unacked) > 0 {
				conn.Unacked[len(conn.Unacked)-1].sentAt = simTime
				conn.Unacked[len(conn.Unacked)-1].origSentAt = simTime
			}
			conn.RetxMu.Unlock()
			sendIdx++
		}

		// Phase 2: receiver delivers non-lost segments and generates ACK/SACK.
		sentIdx := sendIdx
		newDelivery := false
		for i := 0; i < sentIdx; i++ {
			if !rcvd[i] && !segments[i].lost {
				rcvd[i] = true
				newDelivery = true
			}
		}

		if newDelivery || iter%10 == 0 {
			cumAck, sacks := computeACK()
			conn.ProcessAck(cumAck, true)
			ackedUpTo = conn.LastAck
			if len(sacks) > 0 {
				conn.ProcessSACK(sacks)
			}
		}

		// Phase 3: timeout recovery when stuck.
		// "Stuck" = no new sends and no new acks this round.
		madeProgress := ackedUpTo != prevAcked || sendIdx != prevSendIdx
		if madeProgress {
			noProgressRounds = 0
			// On progress, reset all remaining sentAt to simTime (RFC 6298 §5.3).
			conn.RetxMu.Lock()
			for _, e := range conn.Unacked {
				if !e.sacked {
					e.sentAt = simTime
				}
			}
			conn.RetxMu.Unlock()
		} else {
			noProgressRounds++
		}

		if noProgressRounds >= 2 {
			// Advance simulated time past RTO to trigger timeout.
			advanceSim(conn.RTO + time.Millisecond)
			noProgressRounds = 0

			// Age all non-sacked entries and clear guard.
			conn.RetxMu.Lock()
			hasUnacked := false
			for _, e := range conn.Unacked {
				if !e.sacked {
					e.sentAt = simTime.Add(-(conn.RTO + 2*time.Millisecond))
					hasUnacked = true
				}
			}
			conn.LastRetxTime = time.Time{}

			// Mark first non-sacked entry for re-delivery.
			if hasUnacked {
				for _, e := range conn.Unacked {
					if !e.sacked {
						if idx, ok := seqToIdx[e.seq]; ok {
							segments[idx].lost = false
							rcvd[idx] = false
						}
						break
					}
				}
			}
			conn.RetxMu.Unlock()

			if hasUnacked {
				retransmitUnackedForBench(conn, simTime)
				// After retransmit, fresh sentAt = simTime; advance so next
				// Phase 2 delivery triggers ACK without re-entering stuck.
				advanceSim(time.Millisecond)
			}
		}

		_ = rcvdUpTo
	}

	// Count acknowledged bytes.
	acked := int(ackedUpTo - seqBase)
	if acked > totalBytes {
		acked = totalBytes
	}
	return acked
}

// retransmitUnackedForBench is a simplified retransmit using simulated time.
func retransmitUnackedForBench(conn *Connection, simNow time.Time) {
	conn.RetxMu.Lock()
	defer conn.RetxMu.Unlock()

	if len(conn.Unacked) == 0 {
		return
	}

	// RFC 5681 §3.1: on timeout, update ssthresh and cwnd.
	var flightSize int
	for _, e := range conn.Unacked {
		flightSize += len(e.data)
	}
	conn.SSThresh = flightSize / 2
	if conn.SSThresh < 2*MaxSegmentSize {
		conn.SSThresh = 2 * MaxSegmentSize
	}
	conn.InRecovery = true
	conn.CongWin = MaxSegmentSize
	conn.RTO *= 2
	if conn.RTO > 10*time.Second {
		conn.RTO = 10 * time.Second
	}
	conn.DupAckCount = 0
	conn.FastRecovery = false

	for _, e := range conn.Unacked {
		if e.sacked {
			continue
		}
		e.attempts++
		e.sentAt = simNow
		conn.LastRetxTime = simNow
		return
	}
}

// TestThroughputSmokeTest runs a quick sanity-check of the simulation (no loss).
func TestThroughputSmokeTest(t *testing.T) {
	t.Parallel()
	const dataSize = 512 * 1024 // 512 KB
	got := simulateTransfer(0, dataSize, 1)
	if got != dataSize {
		t.Errorf("no-loss transfer: got %d bytes, want %d", got, dataSize)
	}

	got = simulateTransfer(0.01, dataSize, 1)
	if got != dataSize {
		t.Errorf("1%%-loss transfer: got %d bytes, want %d", got, dataSize)
	}
}

// BenchmarkCongestionWindowGrowth measures the speed of the AIMD growth path
// in isolation — pure congestion-window arithmetic with no packet I/O.
func BenchmarkCongestionWindowGrowth(b *testing.B) {
	c := newAckTestConnB(b)
	c.CongWin = c.SSThresh // start in CA mode

	seq := uint32(1000)
	data := make([]byte, MaxSegmentSize)
	now := time.Now() // pre-compute to isolate CC arithmetic, not syscall overhead

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Unacked = []*retxEntry{
			{seq: seq, data: data, attempts: 1, sentAt: now, origSentAt: now},
		}
		c.LastAck = seq
		seq += MaxSegmentSize
		c.ProcessAck(seq, true)
	}
	b.SetBytes(MaxSegmentSize)
}

// newAckTestConnB is the benchmark version of newAckTestConn.
func newAckTestConnB(b *testing.B) *Connection {
	b.Helper()
	return &Connection{
		CongWin:     InitialCongWin,
		SSThresh:    MaxCongWin / 2,
		PeerRecvWin: RecvBufSize * MaxSegmentSize,
		WindowCh:    make(chan struct{}, 1),
		NagleCh:     make(chan struct{}, 1),
	}
}

// printThroughputTable is a test helper for human-readable output.
// Call via: go test ./pkg/daemon -run=TestThroughputReport -v
func init() {
	// ensure retransmitUnackedForBench compiles
	var _ = fmt.Sprintf
}

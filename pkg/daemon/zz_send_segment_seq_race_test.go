// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// TestConcurrentNoDelaySendDuplicateSeq verifies that two goroutines calling
// SendData concurrently on a NoDelay connection never produce duplicate
// sequence numbers in the retransmit buffer.
//
// Bug (pre-v1.9.1): sendSegment reads conn.SendSeq and increments it in two
// SEPARATE conn.Mu critical sections, with d.tunnels.Send() between them:
//
//	conn.Mu.Lock(); seq = conn.SendSeq; conn.Mu.Unlock()   // ← reads here
//	d.tunnels.Send(...)                                      // ← gap: Mu not held
//	conn.Mu.Lock(); conn.SendSeq += len(data); conn.Mu.Unlock() // ← writes here
//
// Two concurrent goroutines can BOTH read conn.SendSeq before either
// increments it, producing packets with the same sequence number.
// The peer discards one as a duplicate. The discarded segment's data is
// permanently lost: ProcessAck removes both retxEntries when the peer ACKs
// the single seq point, while SendSeq has advanced as if 2×MSS was sent.
// Subsequent sends start at SendSeq+2×MSS, arriving out-of-order at the peer
// which is still waiting for SendSeq+MSS — the connection is silently corrupted.
//
// Fix (v1.9.1): pre-increment conn.SendSeq inside the same conn.Mu critical
// section as the read, atomically reserving a unique sequence slot per goroutine:
//
//	conn.Mu.Lock(); seq = conn.SendSeq; conn.SendSeq += len(data); conn.Mu.Unlock()
//
// GREEN assertion: across 500 iterations, no two Unacked entries share a seq.
// Against unpatched code, the race triggers within the first few dozen iterations
// on any dual-core machine.
func TestConcurrentNoDelaySendDuplicateSeq(t *testing.T) {
	prev := runtime.GOMAXPROCS(runtime.NumCPU())
	defer runtime.GOMAXPROCS(prev)

	if runtime.GOMAXPROCS(0) < 2 {
		t.Skip("need ≥2 cores to exercise the goroutine race")
	}

	d := New(Config{})
	peerConn := addPeerOnDaemon(t, d, 0xCC220001)
	t.Cleanup(func() { peerConn.Close() })
	d.setNodeID_testhelper(0x44440000)

	conn := d.ports.NewConnection(51000, protocol.Addr{Network: 0, Node: 0xCC220001}, 80)
	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x44440000}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: 0xCC220001}
	conn.State = StateEstablished
	conn.NoDelay = true // bypass Nagle so both goroutines hit sendSegment directly
	conn.Mu.Unlock()
	conn.RetxMu.Lock()
	conn.PeerRecvWin = 1 << 20 // 1 MiB advertised window — never blocks on flow control
	conn.RetxMu.Unlock()
	// RetxStop must be a non-nil, non-closed channel so sendSegment's select
	// case on RetxStop doesn't immediately trigger ErrConnClosed.
	conn.RetxStop = make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-conn.RetxStop:
		default:
			close(conn.RetxStop)
		}
		d.ports.RemoveConnection(conn.ID)
	})

	data := make([]byte, MaxSegmentSize)
	for i := range data {
		data[i] = byte(i)
	}

	const iterations = 500
	for iter := 0; iter < iterations; iter++ {
		// Reset per-iteration state.
		conn.RetxMu.Lock()
		conn.Unacked = nil
		conn.RetxMu.Unlock()
		conn.Mu.Lock()
		conn.SendSeq = uint32(iter) * 3 * MaxSegmentSize // well-spaced starting points
		conn.Mu.Unlock()

		// Synchronised launch: barrier ensures both goroutines are scheduled
		// before either calls SendData, maximising the concurrent-entry window.
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		for i := 0; i < 2; i++ {
			go func() {
				defer wg.Done()
				<-start
				_ = d.SendData(conn, data)
			}()
		}
		close(start) // release both simultaneously
		wg.Wait()

		// Drain peerConn to prevent socket buffer overflow across iterations.
		_ = peerConn.SetReadDeadline(time.Now().Add(2 * time.Millisecond))
		buf := make([]byte, 65536)
		for {
			if _, _, err := peerConn.ReadFromUDP(buf); err != nil {
				break
			}
		}

		// Check for duplicate sequence numbers in the retransmit buffer.
		conn.RetxMu.Lock()
		seqSeen := make(map[uint32]bool)
		for _, e := range conn.Unacked {
			if seqSeen[e.seq] {
				conn.RetxMu.Unlock()
				// FIXED: pre-incrementing SendSeq inside the Mu critical section
				// ensures each concurrent goroutine reserves a unique seq before
				// releasing the lock — the two sendSegment calls can never share
				// a seq number, preventing silent data loss on concurrent writes.
				t.Errorf("iter %d: duplicate seq %d in Unacked — "+
					"sendSegment TOCTOU on conn.SendSeq causes two goroutines "+
					"to send with identical sequence numbers; "+
					"one segment silently discarded by peer → data loss",
					iter, e.seq)
				return
			}
			seqSeen[e.seq] = true
		}
		conn.RetxMu.Unlock()
	}
	// If we reached here without finding a duplicate, the fix was applied (or
	// the race never triggered — but over 500 iterations with ≥2 cores the
	// latter is astronomically unlikely without the fix).
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// TestConcurrentSendAndCloseConnectionDuplicateSeq verifies that a concurrent
// SendData + CloseConnection pair never produce a FIN and a data segment with
// the same sequence number.
//
// Bug (pre-v1.9.1): CloseConnection reads conn.SendSeq in a first conn.Mu
// critical section and increments it in a second one, with d.tunnels.Send()
// and conn.TrackSend() between them:
//
//	conn.Mu.Lock(); sendSeq = conn.SendSeq; ...conn.Mu.Unlock() // ← read
//	d.tunnels.Send(fin)                                          // ← gap
//	conn.TrackSend(sendSeq, finData)
//	conn.Mu.Lock(); conn.SendSeq++; conn.Mu.Unlock()            // ← write
//
// A concurrent sendSegment (e.g. from SendData) can acquire conn.Mu in the
// gap and also read the same SendSeq, emitting a data segment with the same
// sequence number as the FIN sentinel. The peer discards the duplicate; one of
// the two entries in Unacked is never retransmitted (it was acked alongside
// the other), leading to either a dropped data segment or a dropped FIN —
// silent data loss, or a connection that never closes cleanly.
//
// Fix (v1.9.1): increment conn.SendSeq inside the same conn.Mu critical
// section where it is read in CloseConnection, mirroring the fix already
// applied to sendSegment in iter 23.
//
// GREEN assertion: across 500 iterations, no two Unacked entries share a seq.
// Against unpatched code, the race triggers within the first few iterations
// on any dual-core machine.
func TestConcurrentSendAndCloseConnectionDuplicateSeq(t *testing.T) {
	prev := runtime.GOMAXPROCS(runtime.NumCPU())
	defer runtime.GOMAXPROCS(prev)

	if runtime.GOMAXPROCS(0) < 2 {
		t.Skip("need ≥2 cores to exercise the goroutine race")
	}

	d := New(Config{})
	peerConn := addPeerOnDaemon(t, d, 0xDD330001)
	t.Cleanup(func() { peerConn.Close() })
	d.setNodeID_testhelper(0x55550000)

	const iterations = 500
	for iter := 0; iter < iterations; iter++ {
		// Create a fresh connection for each iteration — CloseConnection is
		// a one-shot operation that transitions state to FinWait.
		conn := d.ports.NewConnection(52000, protocol.Addr{Network: 0, Node: 0xDD330001}, 80)
		conn.Mu.Lock()
		conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x55550000}
		conn.RemoteAddr = protocol.Addr{Network: 0, Node: 0xDD330001}
		conn.State = StateEstablished
		conn.NoDelay = true
		conn.Mu.Unlock()
		conn.RetxMu.Lock()
		conn.PeerRecvWin = 1 << 20
		conn.RetxMu.Unlock()
		conn.RetxStop = make(chan struct{})

		data := make([]byte, MaxSegmentSize)
		for i := range data {
			data[i] = byte(i)
		}

		// Synchronised launch: release both goroutines simultaneously so
		// CloseConnection and sendSegment race for conn.Mu.
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)

		// Goroutine A: sends one MSS segment (goes through sendSegment).
		go func() {
			defer wg.Done()
			<-start
			_ = d.SendData(conn, data)
		}()

		// Goroutine B: closes the connection (sends FIN, TrackSend, SendSeq++).
		go func() {
			defer wg.Done()
			<-start
			d.CloseConnection(conn)
		}()

		close(start) // release both simultaneously
		wg.Wait()

		// Drain peerConn to prevent socket buffer overflow.
		_ = peerConn.SetReadDeadline(time.Now().Add(2 * time.Millisecond))
		buf := make([]byte, 65536)
		for {
			if _, _, err := peerConn.ReadFromUDP(buf); err != nil {
				break
			}
		}

		// Close RetxStop and remove from port table before checking.
		close(conn.RetxStop)
		d.ports.RemoveConnection(conn.ID)

		// Check for duplicate sequence numbers in the retransmit buffer.
		// Each entry is either: the data segment or the FIN sentinel.
		// A duplicate means CloseConnection and sendSegment raced for SendSeq.
		conn.RetxMu.Lock()
		seqSeen := make(map[uint32]bool)
		for _, e := range conn.Unacked {
			if seqSeen[e.seq] {
				conn.RetxMu.Unlock()
				// FIXED: pre-incrementing SendSeq inside the first Mu
				// critical section in CloseConnection prevents it from
				// sharing a seq with a concurrent sendSegment caller.
				t.Errorf("iter %d: duplicate seq %d in Unacked (len=%d) — "+
					"CloseConnection TOCTOU on conn.SendSeq races with "+
					"sendSegment; FIN and data share a sequence number → "+
					"one is silently discarded by the peer",
					iter, e.seq, len(conn.Unacked))
				return
			}
			seqSeen[e.seq] = true
		}
		conn.RetxMu.Unlock()
	}
}

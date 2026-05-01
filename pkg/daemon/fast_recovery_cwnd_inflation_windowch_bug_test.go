// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestFastRecoveryExtraACKInflationSignalsWindowCh verifies that the CongWin
// inflation produced by each additional dup-ACK after the third (RFC 5681
// §3.2 step 5) signals WindowCh when the inflation causes WindowAvailable()
// to transition from false to true.
//
// Bug (current): ProcessAck's additional dup-ACK path increments CongWin but
// returns before reaching the WindowCh signal code:
//
//	} else if c.DupAckCount > 3 && len(c.Unacked) > 0 {
//	    c.CongWin += MaxSegmentSize   // ← can open window
//	    ...
//	}
//	return                            // ← returns before WindowCh signal
//
//	// Signal that window opened up   ← never reached from dup-ACK path
//	if c.WindowCh != nil {
//	    select { case c.WindowCh <- struct{}{}: default: }
//	}
//
// RFC 5681 §3.2 step 5 states that each additional dup-ACK "MUST increment
// cwnd by SMSS" to reflect segments that left the network.  The intent is
// that the sender sends one new segment per additional dup-ACK, keeping the
// pipe full.  If WindowCh is not signaled, a sender blocked in sendSegment
// waits up to ZeroWinProbeInitial (500 ms) for the probe timer before it
// re-evaluates the window — a 500 ms stall per additional dup-ACK in fast
// recovery for connections whose bandwidth-delay product pushes them into
// the congestion-window-full state.
//
// Concrete example (8 segments in flight, MaxSegmentSize = 4096 bytes):
//   initial:    CongWin = 8*MSS = 32768, BytesInFlight = 32768
//   3rd dup-ACK (fast retransmit):
//               SSThresh = 16384, CongWin = 16384+3*4096 = 28672
//               WindowAvailable = (32768 < 28672) = false
//   4th dup-ACK: CongWin = 32768. WindowAvailable = (32768 < 32768) = false
//   5th dup-ACK: CongWin = 36864. WindowAvailable = (32768 < 36864) = true
//               → window opened but WindowCh NOT signaled (bug)
//
// GREEN assertion: after the 5th dup-ACK, WindowCh has a token because the
// window became available.  Against unpatched code WindowCh is empty and a
// blocked sendSegment would stall for 500 ms.
func TestFastRecoveryExtraACKInflationSignalsWindowCh(t *testing.T) {
	pm := NewPortManager()
	conn := pm.NewConnection(7370, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	const numSegs = 8

	// 8 in-flight segments, window exactly full.
	conn.RetxMu.Lock()
	conn.LastAck = 1000
	conn.CongWin = numSegs * MaxSegmentSize  // 32768
	conn.SSThresh = conn.CongWin             // high enough to be in AIMD territory
	for i := 0; i < numSegs; i++ {
		conn.Unacked = append(conn.Unacked, &retxEntry{
			seq:      uint32(1000 + i*MaxSegmentSize),
			data:     make([]byte, MaxSegmentSize),
			attempts: 1,
			sentAt:   time.Now(),
		})
	}
	conn.RetxMu.Unlock()

	// Drain any pre-existing token from initialization.
	select {
	case <-conn.WindowCh:
	default:
	}

	// 3 dup-ACKs — triggers fast retransmit (DupAckCount=3).
	// After this: CongWin = SSThresh + 3*MSS = 16384 + 12288 = 28672.
	// BytesInFlight = 32768 > 28672 → window still closed.
	for i := 0; i < 3; i++ {
		conn.ProcessAck(1000, true)
	}

	// 4th dup-ACK — CongWin = 28672 + 4096 = 32768.
	// BytesInFlight = 32768 >= 32768 → window still closed.
	conn.ProcessAck(1000, true)

	// 5th dup-ACK — CongWin = 32768 + 4096 = 36864.
	// BytesInFlight = 32768 < 36864 → window opens.
	conn.ProcessAck(1000, true)

	conn.RetxMu.Lock()
	avail := conn.WindowAvailable()
	congWin := conn.CongWin
	conn.RetxMu.Unlock()

	if !avail {
		t.Skipf("test setup error: WindowAvailable()=false after 5 dup-ACKs "+
			"(CongWin=%d, BytesInFlight=%d); adjust segment count",
			congWin, numSegs*MaxSegmentSize)
	}

	// WindowCh must contain a token because the window just opened.
	// Without the fix: WindowCh is empty and a blocked sendSegment stalls for
	// up to ZeroWinProbeInitial (500 ms) before the probe timer fires.
	select {
	case <-conn.WindowCh:
		// correct — window opened and WindowCh was signaled
	default:
		t.Errorf("5 dup-ACKs opened the congestion window "+
			"(CongWin=%d > BytesInFlight=%d, WindowAvailable=true) "+
			"but ProcessAck did not signal WindowCh; "+
			"a sender blocked in sendSegment will stall up to ZeroWinProbeInitial=%v "+
			"before re-evaluating the window; "+
			"fix: signal WindowCh in the DupAckCount>3 inflation path when "+
			"WindowAvailable() becomes true",
			congWin, numSegs*MaxSegmentSize, ZeroWinProbeInitial)
	}
}

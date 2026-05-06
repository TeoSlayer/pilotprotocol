// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestFastRetransmitEntryInflatesWindowAndSignalsWindowCh verifies that when
// the 3rd duplicate ACK triggers fast retransmit and the resulting
// SSThresh + 3*SMSS exceeds BytesInFlight, WindowCh is signaled so a sender
// blocked in sendSegment can wake up immediately.
//
// Bug (current): the DupAckCount==3 path computes:
//
//	c.SSThresh = c.CongWin / 2          // (clamped to MaxSegmentSize)
//	c.CongWin  = c.SSThresh + 3*MaxSegmentSize
//
// and then returns without a WindowCh signal.  For small congestion windows
// (CongWin < 6*SMSS), the new CongWin is LARGER than the old one, so a sender
// that was blocked by a full window may now have room — but is not told.
//
// Concrete example (window = 2 segments):
//
//	initial:    CongWin = 2*MSS = 8192, BytesInFlight = 8192 (window full)
//	3rd dup-ACK (fast retransmit):
//	            SSThresh = max(8192/2, MSS) = 4096
//	            CongWin  = 4096 + 3*4096 = 16384
//	            WindowAvailable = (8192 < 16384) = true
//	            → window opened but WindowCh NOT signaled (bug)
//
// This differs from the iter-39 bug (which fixed the DupAckCount>3 path):
// the DupAckCount==3 path on entry to fast recovery also inflates CongWin for
// very small windows without signaling the sender.
//
// GREEN assertion: after the 3rd dup-ACK, WindowCh has a token because the
// window became available.  Against unpatched code WindowCh is empty and a
// blocked sendSegment stalls for up to ZeroWinProbeInitial (500 ms).
func TestFastRetransmitEntryInflatesWindowAndSignalsWindowCh(t *testing.T) {
	pm := NewPortManager()
	conn := pm.NewConnection(7380, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	const numSegs = 2 // small window: 2 in-flight segments fill the window

	// 2 in-flight segments filling a 2-segment congestion window.
	conn.RetxMu.Lock()
	conn.LastAck = 1000
	conn.CongWin = numSegs * MaxSegmentSize // 8192 bytes
	conn.SSThresh = 4 * conn.CongWin        // high: won't constrain
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
	// SSThresh = max(8192/2, 4096) = 4096
	// CongWin  = 4096 + 3*4096 = 16384
	// BytesInFlight = 8192 < CongWin = 16384 → window opens
	for i := 0; i < 3; i++ {
		conn.ProcessAck(1000, true)
	}

	conn.RetxMu.Lock()
	avail := conn.WindowAvailable()
	congWin := conn.CongWin
	conn.RetxMu.Unlock()

	if !avail {
		t.Skipf("test setup error: WindowAvailable()=false after 3 dup-ACKs "+
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
		t.Errorf("3rd dup-ACK fast-retransmit inflated CongWin=%d "+
			"(BytesInFlight=%d, WindowAvailable=true) "+
			"but ProcessAck did not signal WindowCh; "+
			"a sender blocked in sendSegment will stall up to ZeroWinProbeInitial=%v; "+
			"fix: signal WindowCh in the DupAckCount==3 fast-retransmit path "+
			"when the new CongWin makes WindowAvailable() true",
			congWin, numSegs*MaxSegmentSize, ZeroWinProbeInitial)
	}
}

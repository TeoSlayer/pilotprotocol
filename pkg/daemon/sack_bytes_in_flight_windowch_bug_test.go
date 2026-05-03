// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestSACKReducesBytesInFlightAndSignalsWindowCh verifies that after
// ProcessSACK marks a subset of in-flight segments as received, two
// things happen:
//
//  1. BytesInFlight() excludes the SACKed bytes (they are already at the peer).
//  2. ProcessSACK signals WindowCh when the exclusion opens the send window.
//
// Bug (current): BytesInFlight iterates c.Unacked and adds len(e.data) for
// every entry, regardless of e.sacked:
//
//	func (c *Connection) BytesInFlight() int {
//	    total := 0
//	    for _, e := range c.Unacked {
//	        total += len(e.data)  // ← counts SACKed entries too
//	    }
//	    return total
//	}
//
// SACKed segments remain in c.Unacked until a cumulative ACK removes them,
// so between the SACK and the eventual cumulative ACK, BytesInFlight()
// overcounts.  WindowAvailable() (BytesInFlight() < EffectiveWindow())
// therefore stays false even though the peer has already received those bytes
// and the congestion window has real room.  A sender blocked in sendSegment
// waits up to ZeroWinProbeInitial (500 ms) before re-evaluating.
//
// Additionally, ProcessSACK never signals WindowCh, so a sender sleeping on
// that channel is not woken when the SACK frees space.
//
// Concrete example (window = 4 segments):
//
//	initial:   CongWin = 4*MSS = 16384, BytesInFlight = 16384 (window full)
//	SACK covering seg1 and seg2 (2 * MSS = 8192 bytes):
//	  correct: BytesInFlight = 2*MSS = 8192, WindowAvailable = true
//	  bug:     BytesInFlight = 4*MSS = 16384, WindowAvailable = false
//	           → sender stalls up to ZeroWinProbeInitial (500 ms)
//
// GREEN assertion:
//  1. After ProcessSACK, BytesInFlight() == 2*MSS (unsacked bytes only).
//  2. WindowAvailable() is true.
//  3. WindowCh has a token (ProcessSACK signaled it when the window opened).
func TestSACKReducesBytesInFlightAndSignalsWindowCh(t *testing.T) {
	pm := NewPortManager()
	conn := pm.NewConnection(7390, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	const numSegs = 4

	// Fill the window exactly: 4 in-flight segments, CongWin = 4*MSS.
	conn.RetxMu.Lock()
	conn.LastAck = 1000
	conn.CongWin = numSegs * MaxSegmentSize // 16384
	conn.SSThresh = 4 * conn.CongWin        // high — won't constrain
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

	// Verify the window is full before the SACK.
	conn.RetxMu.Lock()
	if conn.WindowAvailable() {
		t.Fatal("test setup error: window should be full before SACK")
	}
	conn.RetxMu.Unlock()

	// SACK covers seg1 and seg2 — the middle two segments are already at the peer.
	// After this, only seg0 and seg3 are truly in flight (2 * MSS = 8192 bytes).
	seg1Start := uint32(1000 + MaxSegmentSize)
	seg2End := uint32(1000 + 3*MaxSegmentSize)
	conn.ProcessSACK([]SACKBlock{{Left: seg1Start, Right: seg2End}})

	conn.RetxMu.Lock()
	bif := conn.BytesInFlight()
	avail := conn.WindowAvailable()
	congWin := conn.CongWin
	conn.RetxMu.Unlock()

	// 1. BytesInFlight should exclude the 2 SACKed segments.
	wantBIF := 2 * MaxSegmentSize
	if bif != wantBIF {
		t.Errorf("BytesInFlight()=%d after SACK, want %d (2 unsacked segments); "+
			"SACKed segments must not count as in-flight — "+
			"fix: skip e.sacked entries in BytesInFlight()",
			bif, wantBIF)
	}

	// 2. WindowAvailable should be true: 2*MSS in flight < 4*MSS CongWin.
	if !avail {
		t.Errorf("WindowAvailable()=false after SACK (BytesInFlight=%d, CongWin=%d); "+
			"SACK freed 2*MSS from the window — "+
			"fix: BytesInFlight() must exclude sacked entries so EffectiveWindow check is correct",
			bif, congWin)
	}

	// 3. WindowCh must have a token: the SACK opened the window, so a sender
	// blocked in sendSegment should wake immediately instead of waiting
	// up to ZeroWinProbeInitial (500 ms) for the probe timer.
	select {
	case <-conn.WindowCh:
		// correct — SACK opened the window and ProcessSACK signaled it
	default:
		t.Errorf("ProcessSACK SACKed 2 segments (BytesInFlight now %d, CongWin=%d, "+
			"WindowAvailable=%v) but did not signal WindowCh; "+
			"a sender blocked in sendSegment will stall up to ZeroWinProbeInitial=%v; "+
			"fix: signal WindowCh in ProcessSACK when WindowAvailable() becomes true",
			bif, congWin, avail, ZeroWinProbeInitial)
	}
}

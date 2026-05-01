// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestFastRecoveryExitDeflatesCongWin verifies that when the first new ACK
// arrives after a 3-dup-ACK fast-retransmit episode, the congestion window is
// deflated back to SSThresh before AIMD growth (RFC 5681 §3.2 step 6).
//
// Bug (pre-v1.9.1): ProcessAck resets DupAckCount to 0 on a new ACK but does
// not deflate CongWin. Fast recovery inflates CongWin to SSThresh+k*MSS (one
// MSS per dup ACK received after the 3rd). On exit the window stays inflated:
//
//	// step 4: fast retransmit
//	c.CongWin = c.SSThresh + 3*MaxSegmentSize
//	// step 5: each additional dup ACK
//	c.CongWin += MaxSegmentSize
//	// step 6 (MISSING): new ACK should set c.CongWin = c.SSThresh
//
// Consequence: after a fast-retransmit episode the sender re-enters AIMD
// growth from the inflated recovery window instead of the halved ssthresh, as
// if no congestion signal had been received. On a 40 KB initial window with
// four dup ACKs the post-recovery window starts at ~52 KB instead of ~20 KB —
// 2.5× too large — triggering the very burst of data that caused the loss event
// in the first place.  Under sustained 0.5% loss this makes the stream
// throughput-unstable: cwnd never converges to a steady state.
//
// Fix (v1.9.1): capture oldDupAckCount before clearing it, and when
// oldDupAckCount >= 3 set c.CongWin = c.SSThresh at the top of the new-ACK
// branch, before the AIMD growth step.
//
// GREEN assertion: after 4 dup ACKs (CongWin inflated to SSThresh+4*MSS) a
// new ACK that acks 1 MSS of data leaves CongWin at SSThresh + a single AIMD
// increment, not at SSThresh + 4*MSS + AIMD.  Against unpatched code CongWin
// grows from the inflated starting point.
func TestFastRecoveryExitDeflatesCongWin(t *testing.T) {
	pm := NewPortManager()
	conn := pm.NewConnection(6350, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	const ssthresh = 20000

	// Simulate state after 3-dup-ACK fast retransmit + 1 additional dup ACK.
	// RFC 5681 §3.2:
	//   step 4: CongWin = SSThresh + 3*MSS  (fast retransmit entry)
	//   step 5: CongWin += MSS               (4th dup ACK)
	// → CongWin = SSThresh + 4*MSS
	inflatedCongWin := ssthresh + 4*MaxSegmentSize

	conn.RetxMu.Lock()
	conn.LastAck = 1000
	conn.DupAckCount = 4 // 3 dup ACKs fired retransmit, 1 additional
	conn.SSThresh = ssthresh
	conn.CongWin = inflatedCongWin
	// Fast retransmit DID fire at DupAckCount==3, so InRecovery must be true.
	// iter-59 gates the deflation on wasInRecovery; without this field the
	// test setup misrepresents the state and the deflation would not fire.
	conn.InRecovery = true
	conn.RecoveryPoint = 1000 + MaxSegmentSize // new ACK will reach this and clear it
	// Put one unacked entry so ProcessAck has something to remove when ack > LastAck
	conn.Unacked = []*retxEntry{
		{seq: 1000, data: make([]byte, MaxSegmentSize), attempts: 2, sentAt: time.Now()},
	}
	conn.RetxMu.Unlock()

	// New ACK acks exactly one segment (1 MSS = 4096 bytes)
	conn.ProcessAck(1000+MaxSegmentSize, true)

	conn.RetxMu.Lock()
	congWin := conn.CongWin
	dupAckCount := conn.DupAckCount
	conn.RetxMu.Unlock()

	// FIXED (RFC 5681 §3.2 step 6): on fast recovery exit set cwnd = ssthresh,
	// then grow via AIMD. Since CongWin (ssthresh=20000) >= SSThresh, the CA
	// increment is at most MaxSegmentSize*MaxSegmentSize/ssthresh ≈ 838 bytes.
	// Upper bound: ssthresh + MaxSegmentSize (one full MSS of slow-start growth
	// is impossible here since CongWin == SSThresh exactly, but be generous).
	maxAllowed := ssthresh + MaxSegmentSize

	if dupAckCount != 0 {
		t.Errorf("fast recovery exit: DupAckCount=%d, want 0", dupAckCount)
	}
	// FAILS against unpatched code: CongWin = inflatedCongWin + AIMD increment
	//                                       = SSThresh+4*MSS + ~838 = 36838
	if congWin > maxAllowed {
		t.Errorf("fast recovery exit: CongWin=%d, want <= %d (SSThresh=%d + MSS=%d); "+
			"ProcessAck does not reset CongWin to SSThresh when exiting fast recovery "+
			"(RFC 5681 §3.2 step 6); window stays inflated at SSThresh+%d*MSS=%d then "+
			"grows via AIMD from there instead of from SSThresh=%d, making the sender "+
			"re-enter the congestion that caused the loss event; "+
			"fix: set c.CongWin = c.SSThresh before the AIMD step when oldDupAckCount >= 3",
			congWin, maxAllowed, ssthresh, MaxSegmentSize,
			4, inflatedCongWin, ssthresh)
	}
}

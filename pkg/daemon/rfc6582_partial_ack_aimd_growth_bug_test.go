// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"
)

// TestPartialACKInFastRecoveryDoesNotApplyAIMDGrowth verifies that a partial
// ACK during fast recovery does NOT trigger AIMD cwnd growth — only RFC 6582
// §3 step 6b deflation applies.
//
// RFC 6582 §3 step 6b:
//
//	"Deflate the congestion window by the amount of new data acknowledged
//	by the Cumulative Acknowledgment field.  If the partial ACK acknowledges
//	at least one SMSS of new data, then add back SMSS bytes to the congestion
//	window.  As partial ACKs come in, this process repeats until either all
//	the data outstanding when fast retransmit was entered is acknowledged or
//	until the slow start threshold is reached."
//
// The cwnd adjustment for a partial ACK is:
//
//	cwnd = cwnd − bytesAcked + (bytesAcked ≥ SMSS ? SMSS : 0)
//
// For a 1-SMSS partial ACK (bytesAcked == SMSS):
//
//	cwnd_net = −SMSS + SMSS = 0  (cwnd unchanged)
//
// Bug: after the RFC 6582 deflation block, the code falls through to the
// RFC 3465 AIMD growth section which is NOT gated on "not in fast recovery":
//
//	if bytesAcked > 0 {
//	    // CA mode: cwnd += SMSS² / cwnd   ← fires even during fast recovery
//	}
//
// For a 1-SMSS partial ACK with cwnd = SSThresh + 3*SMSS = 8*SMSS:
//
//	Deflation:   cwnd − SMSS + SMSS = 8*SMSS           (net 0)
//	AIMD (bug):  cwnd += SMSS²/(8*SMSS) = SMSS/8 = 512  (spurious growth)
//	Result:      cwnd = 8*SMSS + 512                    (inflated)
//
// The RFC specifies only the deflation formula during fast recovery; there is
// no provision for AIMD reward for partial ACKs.  The extra growth violates
// "as partial ACKs come in, this process repeats until … the slow start
// threshold is reached" — if AIMD keeps inflating cwnd, it can never reach
// ssthresh via deflation.
//
// Fix: skip the AIMD growth section when processing a fast-recovery partial
// ACK.  Set a boolean skipAIMD in the partial-ACK branch and gate the
// RFC 3465 section on !skipAIMD:
//
//	skipAIMD = true  // in the partial-ACK (c.InRecovery && wasInRecovery) branch
//	…
//	if !skipAIMD && bytesAcked > 0 { /* AIMD */ }
//
// GREEN assertion: after a 1-SMSS partial ACK with cwnd = SSThresh + 3*SMSS,
// cwnd == SSThresh + 3*SMSS (no net change), NOT > SSThresh + 3*SMSS (which
// would indicate spurious AIMD growth).
func TestPartialACKInFastRecoveryDoesNotApplyAIMDGrowth(t *testing.T) {
	c := newAckTestConn(t)

	const (
		seqA = uint32(1000)
		seqB = seqA + MaxSegmentSize // 5096
		seqC = seqB + MaxSegmentSize // 9192
		seqD = seqC + MaxSegmentSize // 13288 — RecoveryPoint (beyond seqC)
	)

	cs := &capturedSender{}
	c.RetxSend = cs.send

	// Fast recovery state after 3 dup ACKs triggered fast retransmit:
	//   SSThresh = 5*MSS (halved from 10*MSS when FlightSize=10*MSS)
	//   CongWin  = SSThresh + 3*MSS = 8*MSS (fast-recovery inflation)
	//   InRecovery = true, FastRecovery = true
	//   RecoveryPoint = seqD (beyond current unacked data)
	//   Unacked = [seqB, seqC] (2 segments, seqA already removed)
	c.InRecovery = true
	c.FastRecovery = true
	c.RecoveryPoint = seqD
	c.SSThresh = 5 * MaxSegmentSize
	c.CongWin = c.SSThresh + 3*MaxSegmentSize // = 8*MSS = 32768

	now := time.Now()
	c.LastAck = seqB // seqA already acknowledged
	c.Unacked = []*retxEntry{
		// seqB: first unacked; will be retransmitted by step 6a on partial ACK
		{seq: seqB, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: now, origSentAt: now},
		// seqC: second unacked; still below RecoveryPoint=seqD
		{seq: seqC, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: now, origSentAt: now},
	}

	cwndBefore := c.CongWin // = 8*MSS

	// Partial ACK: ack=seqC acknowledges seqB (1 SMSS).
	// RFC 6582 §3 6b for bytesAcked=SMSS: cwnd_net = −SMSS + SMSS = 0.
	// cwnd must NOT grow beyond cwndBefore.
	c.ProcessAck(seqC, true)

	// Verify partial ACK was recognised (seqB removed, seqC remains)
	if len(c.Unacked) != 1 {
		t.Fatalf("expected 1 remaining entry after partial ACK, got %d", len(c.Unacked))
	}
	if !c.InRecovery {
		t.Fatal("InRecovery must remain true — ack=seqC < RecoveryPoint=seqD")
	}

	// Verify fast retransmit fired (RFC 6582 §3 step 6a).
	if len(cs.all()) == 0 {
		t.Fatal("step 6a: fastRetransmit did not fire for partial ACK")
	}

	// RFC 6582 §3 step 6b: for a 1-SMSS partial ACK the net cwnd change is
	// zero.  AIMD growth is not part of the step-6b formula and must not apply.
	// With bug: CongWin = cwndBefore + SMSS/8 = cwndBefore + 512 (> cwndBefore).
	if c.CongWin > cwndBefore {
		t.Errorf("RFC 6582 §3 step 6b: cwnd grew from %d to %d during partial ACK "+
			"(delta=%d); AIMD growth must be skipped during fast-recovery partial ACKs; "+
			"bug: code falls through to RFC 3465 AIMD section after deflation block — "+
			"CA increment SMSS²/cwnd=%d is added spuriously; "+
			"fix: set skipAIMD=true in the partial-ACK branch and gate AIMD on !skipAIMD",
			cwndBefore, c.CongWin, c.CongWin-cwndBefore,
			MaxSegmentSize*MaxSegmentSize/cwndBefore)
	}
}

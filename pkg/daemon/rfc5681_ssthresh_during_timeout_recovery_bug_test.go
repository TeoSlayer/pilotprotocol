// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"
)

// TestFastRetransmitDuringTimeoutRecoveryRecomputesSSThresh verifies that
// fast retransmit triggered DURING timeout recovery recomputes ssthresh per
// RFC 5681 §3.2 step 2, rather than leaving the stale timeout-era ssthresh
// in place.
//
// RFC 5681 §3.2 step 2:
//
//	"When the third duplicate ACK is received, a TCP MUST set ssthresh to
//	no more than the value given in equation (4).  When multiple congestion
//	events occur in a window of data, ssthresh MUST be set to no more than
//	the value given in equation (4) for each event."
//
// Equation (4): ssthresh = max(FlightSize/2, 2*SMSS)
//
// Timeline that produces the bug:
//
//	1. Timeout fires for seqA/seqB: ssthresh = max(FlightSize_at_timeout/2, 2*MSS)
//	   e.g. FlightSize was large → ssthresh = 10*MSS.  InRecovery=true, FastRecovery=false.
//	   CongWin reset to 1*MSS.  DupAckCount=0.
//	2. Retransmitted seqA/seqB arrive at peer; peer sends cumulative ACK=seqC.
//	   ProcessAck(seqC) advances LastAck=seqC, clears DupAckCount=0.
//	   InRecovery stays true (RecoveryPoint=seqE > seqC).
//	3. seqC is lost.  Peer sends 3 dup ACKs (ack=seqC).
//	   This is a NEW congestion event — a different segment from the one that
//	   triggered the timeout.
//
// At DupAckCount==3 (step 3), current code:
//
//	if !c.InRecovery {        // FALSE — InRecovery=true from the earlier timeout
//	    ssthresh = max(FlightSize/2, 2*MSS)   // SKIPPED — bug
//	    …
//	}
//	c.FastRecovery = true
//	c.CongWin = c.SSThresh + 3*MSS   // uses stale ssthresh=10*MSS → CongWin=13*MSS
//
// With FlightSize=2*MSS at the time of the 3rd dup ACK, the correct new ssthresh
// is max(2*MSS/2, 2*MSS) = 2*MSS.  CongWin should be 2*MSS+3*MSS = 5*MSS.
// The bug leaves ssthresh=10*MSS and sets CongWin=13*MSS — 2.6× too large.
//
// Fix: change the guard from `if !c.InRecovery` to
// `if !c.InRecovery || !c.FastRecovery`:
//
//   - !c.InRecovery:           fresh entry (no prior recovery) → recompute ✓
//   - !c.FastRecovery && c.InRecovery: fast retransmit during timeout recovery
//     → new loss event → recompute ssthresh per RFC 5681 §3.2 ✓
//   - c.FastRecovery && c.InRecovery: dup ACKs during ongoing fast recovery
//     → same episode → skip recompute ✓ (one-reduction-per-episode rule)
//
// GREEN assertion: after 3 dup ACKs during timeout recovery (InRecovery=true,
// FastRecovery=false) with FlightSize=2*MSS, ssthresh ≤ 2*MaxSegmentSize —
// demonstrably lower than the stale 10*MSS that the bug would leave behind.
func TestFastRetransmitDuringTimeoutRecoveryRecomputesSSThresh(t *testing.T) {
	c := newAckTestConn(t)

	const (
		seqA = uint32(1000)
		seqB = seqA + MaxSegmentSize // 5096
		seqC = seqB + MaxSegmentSize // 9192
		seqD = seqC + MaxSegmentSize // 13288
		seqE = seqD + MaxSegmentSize // 17384 — RecoveryPoint (beyond seqD)
	)

	cs := &capturedSender{}
	c.RetxSend = cs.send

	// Simulate state AFTER:
	//   1. Timeout fired for seqA/seqB: InRecovery=true, FastRecovery=false
	//      ssthresh was set to 10*MSS (FlightSize was large at that point)
	//      CongWin reset to 1*MSS
	//   2. seqA+seqB retransmits were ACKed: LastAck advanced to seqC
	//      DupAckCount reset to 0 by that new ACK
	//      InRecovery still true (RecoveryPoint=seqE > seqC)
	//
	// Now seqC is also lost — this is a NEW congestion event.
	// FlightSize at this point = 2*MSS (seqC + seqD in flight).
	// Expected new ssthresh per RFC 5681 §3.2 eq.4: max(2*MSS/2, 2*MSS) = 2*MSS.
	c.InRecovery = true
	c.FastRecovery = false // timeout cleared it; no fast retransmit entered yet
	c.RecoveryPoint = seqE
	c.DupAckCount = 0
	c.SSThresh = 10 * MaxSegmentSize // stale value from earlier timeout (large FlightSize)
	c.CongWin = MaxSegmentSize       // timeout reset CongWin to 1*MSS
	c.LastAck = seqC                 // seqA+seqB acknowledged; seqC is now first unacked

	now := time.Now()
	c.Unacked = []*retxEntry{
		// seqC: first unacked, will be retransmitted by fast retransmit at DupAckCount=3
		{seq: seqC, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: now, origSentAt: now},
		// seqD: second unacked (contributes to FlightSize = 2*MSS)
		{seq: seqD, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: now, origSentAt: now},
	}

	// Three dup ACKs (ack=seqC, pure ACK) — triggers fast retransmit on the third.
	c.ProcessAck(seqC, true)
	c.ProcessAck(seqC, true)
	c.ProcessAck(seqC, true)

	// Verify fast retransmit actually fired (seqC was retransmitted).
	pkts := cs.all()
	if len(pkts) == 0 {
		t.Fatal("fastRetransmit did not fire on 3rd dup ACK during timeout recovery")
	}

	// RFC 5681 §3.2 step 2: ssthresh MUST be recomputed for the new loss event.
	// FlightSize = 2*MSS → ssthresh = max(2*MSS/2, 2*MSS) = 2*MSS.
	// With the bug: ssthresh is still 10*MSS (the stale timeout-era value).
	if c.SSThresh > 2*MaxSegmentSize {
		t.Errorf("RFC 5681 §3.2 step 2: ssthresh not recomputed for new fast-retransmit "+
			"loss event during timeout recovery; got SSThresh=%d, want ≤%d (2*MSS); "+
			"bug: guard 'if !c.InRecovery' prevents ssthresh update when InRecovery=true "+
			"from a prior timeout, even though the 3 dup ACKs are for a different "+
			"segment — a new congestion event per RFC 5681 §3.2: "+
			"'When multiple congestion events occur in a window of data, ssthresh "+
			"MUST be set to no more than the value given in equation (4) for each event'; "+
			"fix: change guard to '!c.InRecovery || !c.FastRecovery' so that fast "+
			"retransmit during timeout recovery (FastRecovery=false) triggers ssthresh recompute",
			c.SSThresh, 2*MaxSegmentSize)
	}
}

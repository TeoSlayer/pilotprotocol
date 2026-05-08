// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"
)

// TestSecondPartialAckInFastRecoveryRetransmitsFirstUnacked verifies that
// EVERY partial ACK during fast recovery triggers a retransmit of the first
// unacknowledged segment per RFC 6582 §3 step 6a, not only the first partial
// ACK following the 3-dup-ACK fast retransmit trigger.
//
// RFC 6582 §3 step 6 (partial ACK during fast recovery):
//
//	"(a) Retransmit the first unacknowledged segment.
//	 (b) Deflate the congestion window by the amount of new data
//	     acknowledged by the cumulative acknowledgment field …
//	 As partial ACKs come in, this process repeats …"
//
// "As partial ACKs come in, this process repeats" — the behaviour is
// unconditional within fast recovery, not limited to the first partial ACK.
//
// Current code guards step 6 with:
//
//	if oldDupAckCount >= 3 && wasInRecovery { … step 6 … }
//
// When the first partial ACK fires (oldDupAckCount=3 → condition true),
// ProcessAck resets DupAckCount=0.  If only 0–2 more dup ACKs arrive before
// the second partial ACK, oldDupAckCount < 3 and the condition is false —
// step 6 never runs for the second partial ACK:
//
//	  - fastRetransmit not called  → first still-unacked segment not retransmitted
//	  - cwnd not deflated          → AIMD growth fires instead, inflating cwnd
//
// Concrete scenario (after entering fast recovery):
//
//	State after first partial ACK:
//	  InRecovery=true, DupAckCount=0 (reset by ProcessAck)
//	  Unacked = [seqB (unacked), seqC (unacked)]
//	  RecoveryPoint = seqD (> seqC)
//
//	1 dup ACK arrives → DupAckCount = 1
//	Second partial ACK (ack = seqC, covers seqB):
//	  oldDupAckCount = 1 < 3  →  step 6 block skipped
//	  bug:  fastRetransmit NOT called  →  seqC not retransmitted
//	  fix:  step 6 runs unconditionally during fast recovery
//
// Fix: add FastRecovery bool to Connection. Set it when fast retransmit fires
// (DupAckCount==3 branch). Clear it on full recovery exit (ack≥RecoveryPoint)
// and on RTO timeout (retransmitUnacked). Change the guard to:
//
//	if (oldDupAckCount >= 3 || wasFastRecovery) && wasInRecovery { … step 6 … }
//
// where wasFastRecovery is captured before the recovery-exit check.
//
// GREEN assertion: after a second partial ACK with only 1 dup ACK in between
// (DupAckCount=1 when the ACK arrives), RetxSend is called — fastRetransmit
// fired for the first remaining unacknowledged segment.
func TestSecondPartialAckInFastRecoveryRetransmitsFirstUnacked(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)

	const (
		seqA = uint32(1000)
		seqB = seqA + MaxSegmentSize // 5096
		seqC = seqB + MaxSegmentSize // 9192
		seqD = seqC + MaxSegmentSize // 13288 — RecoveryPoint (beyond second partial ACK)
	)

	cs := &capturedSender{}
	c.RetxSend = cs.send

	// Simulate state AFTER the first partial ACK has already fired step 6:
	//   - Fast retransmit entered at DupAckCount=3 → FastRecovery=true was set
	//   - First partial ACK (ack=seqB) removed seqA, reset DupAckCount=0, called fastRetransmit
	//   - 1 dup ACK arrived → DupAckCount=1
	//
	// Critically: FastRecovery=true because we entered via fast retransmit.
	// The bug: without wasFastRecovery in the step 6 guard, the second partial
	// ACK has oldDupAckCount=1 < 3 and step 6 is skipped.
	c.InRecovery = true
	c.FastRecovery = true // set by fast retransmit entry (ProcessAck DupAckCount==3 path)
	c.RecoveryPoint = seqD
	c.DupAckCount = 1     // only 1 dup ACK between partial ACKs (< 3 threshold)
	c.SSThresh = 5 * MaxSegmentSize
	c.CongWin = c.SSThresh + 3*MaxSegmentSize // 32768 — fast recovery inflated

	now := time.Now()
	c.Unacked = []*retxEntry{
		// seqB: first remaining, must be retransmitted by step 6a
		{seq: seqB, data: make([]byte, MaxSegmentSize), attempts: 2, sentAt: now, origSentAt: now},
		// seqC: covered by the second partial ACK (ack=seqC removes seqB)
		{seq: seqC, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: now, origSentAt: now},
	}

	// Second partial ACK: covers seqB (ack=seqC), does NOT reach RecoveryPoint=seqD.
	// RFC 6582 §3 step 6a: must retransmit seqC (first remaining after seqB is acked).
	c.ProcessAck(seqC, true)

	if len(c.Unacked) != 1 {
		t.Fatalf("expected 1 remaining entry after second partial ACK, got %d", len(c.Unacked))
	}
	if !c.InRecovery {
		t.Fatal("InRecovery must stay true — ack=seqC has not reached RecoveryPoint=seqD")
	}

	pkts := cs.all()
	if len(pkts) == 0 {
		t.Errorf("RFC 6582 §3 step 6a: second partial ACK in fast recovery did not "+
			"call fastRetransmit; bug: step 6 is gated on oldDupAckCount >= 3, but "+
			"DupAckCount was reset to 0 by the first partial ACK and only reached 1 "+
			"before the second partial ACK; fix: track fast-recovery entry with "+
			"FastRecovery bool field, use '(oldDupAckCount >= 3 || wasFastRecovery) && "+
			"wasInRecovery' so that every partial ACK during fast recovery fires step 6")
	}
}

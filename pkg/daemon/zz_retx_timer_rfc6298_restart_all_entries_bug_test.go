// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"
)

// TestNewACKRestartsRetxTimerForAllRemainingEntries verifies that when a
// cumulative ACK advances SND.UNA, the retransmission timer is restarted for
// ALL remaining non-sacked unacked segments, not only the oldest one.
//
// RFC 6298 §5.3:
//
//	"When an ACK is received that acknowledges new data, restart the
//	retransmission timer so that it will expire after RTO seconds (for
//	the current value of RTO)."
//
// Standard TCP uses a SINGLE retransmission timer that covers all outstanding
// data.  After a timer restart, NO outstanding segment should time out before
// `now + RTO`.  In the per-entry model, the timer is approximated by each
// entry's sentAt; a restart must update sentAt for EVERY non-sacked remaining
// entry so that none of them have an effective deadline shorter than
// `now + RTO`.
//
// The current fix (iter-70) resets sentAt only for the FIRST non-sacked
// remaining entry (the oldest), then breaks.  Subsequent entries retain their
// original sentAt values.  If those entries were sent near the RTO boundary,
// retransmitUnacked will fire them as "timed out" within the next tick
// (100 ms), even though the path just demonstrated it is active by delivering
// the cumulative ACK.
//
// Concrete scenario:
//
//	RTO        = InitialRTO = 1s
//	Entry A    seq=seqA  sentAt = now - 950ms  (acked by this ACK)
//	Entry B    seq=seqB  sentAt = now - 950ms  (oldest remaining)
//	Entry C    seq=seqC  sentAt = now - 950ms  (second remaining)
//	Cumulative ACK = seqB  (covers A only)
//
//	After the ACK:
//	  RFC 6298 §5.3 (correct): B.sentAt = now, C.sentAt = now
//	                           → B and C time out at now + RTO (1s from now)
//	  bug: B.sentAt = now,  C.sentAt still = now-950ms
//	       → C times out at now-950ms + 1s = now+50ms
//	       → retransmitUnacked fires C 50ms after the ACK (spurious retransmit)
//
// Fix: remove the `break` from the RFC 6298 §5.3 timer-restart loop in
// ProcessAck so that ALL non-sacked remaining entries have their sentAt
// reset:
//
//	ackNow := time.Now()
//	for _, e := range c.Unacked {
//	    if !e.sacked {
//	        e.sentAt = ackNow  // was: e.sentAt = ackNow; break
//	    }
//	}
//
// GREEN assertion: after ProcessAck(seqB), ALL remaining non-sacked entries
// have sentAt within 100 ms of now (not the stale 950 ms-old value), so none
// of them will time out during the next retransmitUnacked tick.
func TestNewACKRestartsRetxTimerForAllRemainingEntries(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)

	const (
		seqA = uint32(1000)
		seqB = seqA + MaxSegmentSize // 5096
		seqC = seqB + MaxSegmentSize // 9192
	)

	stale := time.Now().Add(-950 * time.Millisecond) // close to RTO boundary

	c.LastAck = seqA
	c.CongWin = InitialCongWin
	c.SSThresh = MaxCongWin / 2
	c.Unacked = []*retxEntry{
		// A: acked by this cumulative ACK
		{seq: seqA, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: stale, origSentAt: stale},
		// B: oldest remaining — already checked by TestNewACKRestartsRetxTimerForOldestRemaining
		{seq: seqB, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: stale, origSentAt: stale},
		// C: second remaining — must ALSO be restarted per RFC 6298 §5.3
		{seq: seqC, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: stale, origSentAt: stale},
	}

	// Cumulative ACK covers A only.
	c.ProcessAck(seqB, true)

	if len(c.Unacked) != 2 {
		t.Fatalf("expected 2 remaining entries, got %d", len(c.Unacked))
	}

	// B: oldest remaining — sentAt must be reset (already covered by iter-70 test).
	b := c.Unacked[0]
	if b.seq != seqB {
		t.Fatalf("Unacked[0].seq = %d, want seqB=%d", b.seq, seqB)
	}

	// C: second remaining — sentAt must ALSO be reset per RFC 6298 §5.3.
	// With the bug, C.sentAt is still 'stale' (950ms ago), meaning
	// retransmitUnacked would fire C on the very next tick (now-950ms+1s=now+50ms).
	cc := c.Unacked[1]
	if cc.seq != seqC {
		t.Fatalf("Unacked[1].seq = %d, want seqC=%d", cc.seq, seqC)
	}

	elapsedC := time.Since(cc.sentAt)
	if elapsedC > 100*time.Millisecond {
		t.Errorf("second remaining entry (seqC) sentAt NOT reset after new ACK "+
			"(RFC 6298 §5.3 must restart timer for ALL remaining entries): "+
			"time.Since(seqC.sentAt)=%v, want ≤100ms; "+
			"bug: only oldest entry gets restart; seqC.sentAt=%v (stale), "+
			"so retransmitUnacked would fire seqC in ≈50ms despite active path; "+
			"fix: remove break from timer-restart loop in ProcessAck",
			elapsedC, stale.Format("15:04:05.000"))
	}
}

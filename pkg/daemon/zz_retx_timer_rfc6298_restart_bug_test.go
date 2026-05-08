// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"
)

// TestNewACKRestartsRetxTimerForOldestRemaining verifies that when a cumulative
// ACK advances SND.UNA, the retransmit timer for the new oldest unacked segment
// is restarted from the ACK arrival time (RFC 6298 §5.3).
//
// RFC 6298 §5.3:
//
//	"When an ACK is received that acknowledges new data, restart the
//	retransmission timer so that it will expire after RTO seconds (for
//	the current value of RTO)."
//
// In a per-entry model the single RFC 6298 timer maps to the oldest
// (lowest-seq) non-sacked entry in Unacked. When a new cumulative ACK
// removes that entry, the timer "moves" to the new oldest, and it should
// start counting from the ACK arrival time — not from when that entry was
// originally sent.
//
// The current code does NOT update sentAt after removing acked entries. If
// the new oldest entry was sent long ago (older than conn.RTO), retransmit-
// Unacked would fire immediately on the next tick (100ms) even though the
// path just proved it is active by delivering the previous segment's ACK.
//
// Concrete scenario:
//
//	RTO        = InitialRTO = 1s
//	Entry A    seq=seqA  sentAt = now - 2s  (timed out, would retransmit)
//	Entry B    seq=seqB  sentAt = now - 2s  (timed out, would retransmit)
//	Cumulative ACK = seqB  (covers A, not B)
//
//	After the ACK:
//	  RFC 6298 §5.3: B.sentAt = now   → B times out at now + RTO (1s from now)
//	  bug: B.sentAt still now-2s      → retransmitUnacked fires B on the next
//	                                    tick (now-2s + 1s = now-1s < now), a
//	                                    spurious retransmit while the path is
//	                                    demonstrably working.
//
// Fix: in ProcessAck, after "c.Unacked = remaining", reset sentAt on the
// first (oldest) non-sacked remaining entry:
//
//	now := time.Now()
//	for _, e := range c.Unacked {
//	    if !e.sacked {
//	        e.sentAt = now
//	        break
//	    }
//	}
//
// GREEN assertion: after the new ACK, the oldest remaining entry's sentAt
// is close to now (< 100ms ago), not the stale pre-ACK timestamp (2s ago).
func TestNewACKRestartsRetxTimerForOldestRemaining(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)

	const (
		seqA = uint32(1000)
		seqB = seqA + MaxSegmentSize // 5096
	)

	stale := time.Now().Add(-2 * InitialRTO) // 2*RTO in the past

	c.LastAck = seqA
	c.CongWin = InitialCongWin
	c.SSThresh = MaxCongWin / 2
	c.Unacked = []*retxEntry{
		// A: will be removed by this ACK
		{seq: seqA, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: stale},
		// B: oldest remaining after the ACK — sentAt should be reset per RFC 6298 §5.3
		{seq: seqB, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: stale},
	}

	// Cumulative ACK covers A only.
	c.ProcessAck(seqB, true)

	if len(c.Unacked) != 1 {
		t.Fatalf("expected 1 remaining entry, got %d", len(c.Unacked))
	}

	b := c.Unacked[0]
	if b.seq != seqB {
		t.Fatalf("remaining entry seq = %d, want %d", b.seq, seqB)
	}

	// RFC 6298 §5.3: B's sentAt must be reset to ~now after the new ACK.
	// With the bug, sentAt is still 'stale' (2*RTO ago), so
	// time.Since(b.sentAt) ≈ 2s >> 100ms.
	elapsed := time.Since(b.sentAt)
	if elapsed > 100*time.Millisecond {
		t.Errorf("oldest remaining entry sentAt not reset after new ACK "+
			"(RFC 6298 §5.3 timer restart): time.Since(sentAt)=%v, want ≤100ms; "+
			"bug: sentAt is still %v before ACK; stale sentAt means "+
			"retransmitUnacked fires immediately on the next tick even though the "+
			"path just proved active — fix: update sentAt=time.Now() for the "+
			"first non-sacked remaining entry after c.Unacked=remaining in ProcessAck",
			elapsed, stale.Format("15:04:05.000"))
	}
}

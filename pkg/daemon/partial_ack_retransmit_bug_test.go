// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"
)

// TestPartialAckDuringRecoveryRetransmitsFirstUnacked verifies that when a
// cumulative ACK arrives during fast recovery but only partially covers the
// recovery window (a "partial ACK"), the first unacknowledged segment is
// immediately retransmitted per RFC 6582 §3 step 6a.
//
// RFC 6582 §3 step 6:
//
//	"Upon receiving a cumulative ACK for N (N > 2) new bytes:
//	  a. Retransmit the first unacknowledged segment."
//
// The current code handles steps 6b–6c (cwnd deflation and CA growth) but
// never calls fastRetransmit in the partial-ACK branch, leaving recovery
// dependent on the 100ms RTO ticker to fill the gap rather than immediately
// retransmitting the next lost segment.
//
// Concrete scenario:
//
//	SSThresh      = 5*MSS = 20480
//	CongWin       = SSThresh + 3*MSS = 32768  (fast-recovery inflation)
//	InRecovery    = true
//	DupAckCount   = 3
//	RecoveryPoint = seqC + MSS = seqA + 3*MSS = 13288
//	Unacked       = [seqA, seqB, seqC]  (seqA=1000, seqB=5096, seqC=9192)
//	LastAck       = seqA = 1000
//
//	Partial ACK = seqB (acks seqA only, seqB+seqC still outstanding)
//
//	After ProcessAck(seqB, true):
//	  RFC 6582 §3 step 6a: fastRetransmit must fire → RetxSend called with seqB
//	  bug: fastRetransmit is never called → RetxSend is NOT called
//
// Fix: in ProcessAck, in the partial-ACK branch (InRecovery still true after
// the new ACK), call fastRetransmit(recvAck) after the cwnd deflation:
//
//	} else {
//	    // Partial ACK deflation …
//	    c.CongWin -= bytesAcked
//	    …
//	    // RFC 6582 §3 step 6a
//	    c.fastRetransmit(recvAck)
//	}
//
// GREEN assertion: after ProcessAck(seqB, true), RetxSend is called exactly
// once with a packet whose Seq == seqB (the first remaining unacknowledged
// segment).
func TestPartialAckDuringRecoveryRetransmitsFirstUnacked(t *testing.T) {
	c := newAckTestConn(t)

	const (
		seqA = uint32(1000)
		seqB = seqA + MaxSegmentSize // 5096
		seqC = seqB + MaxSegmentSize // 9192
	)
	recoveryPoint := seqC + MaxSegmentSize // 13288

	cs := &capturedSender{}
	c.RetxSend = cs.send

	c.LastAck = seqA
	c.DupAckCount = 3
	c.InRecovery = true
	c.FastRecovery = true // fast retransmit entered recovery (new episode, not timeout)
	c.RecoveryPoint = recoveryPoint
	c.SSThresh = 5 * MaxSegmentSize
	c.CongWin = c.SSThresh + 3*MaxSegmentSize // 32768

	now := time.Now()
	c.Unacked = []*retxEntry{
		// seqA: acked by the partial ACK (seqB)
		{seq: seqA, data: make([]byte, MaxSegmentSize), attempts: 2, sentAt: now},
		// seqB: first remaining — must be immediately retransmitted per RFC 6582 §3-6a
		{seq: seqB, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: now},
		// seqC: also outstanding
		{seq: seqC, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: now},
	}

	// Partial ACK covers seqA only (ack = seqB = seqA + MSS).
	c.ProcessAck(seqB, true)

	if len(c.Unacked) != 2 {
		t.Fatalf("expected 2 remaining entries after partial ACK, got %d", len(c.Unacked))
	}
	if !c.InRecovery {
		t.Fatal("InRecovery should remain true after partial ACK (did not reach RecoveryPoint)")
	}

	// RFC 6582 §3 step 6a: RetxSend must have been called once with a packet for seqB.
	pkts := cs.all()
	if len(pkts) == 0 {
		t.Errorf("RFC 6582 §3 step 6a: partial ACK during fast recovery must "+
			"immediately retransmit the first unacknowledged segment (seqB=%d); "+
			"no RetxSend call observed — fix: call fastRetransmit(recvAck) in the "+
			"partial-ACK branch of ProcessAck after cwnd deflation",
			seqB)
		return
	}
	if pkts[0].Seq != seqB {
		t.Errorf("partial-ACK retransmit sent seq=%d, want seqB=%d (first unacked)",
			pkts[0].Seq, seqB)
	}
}

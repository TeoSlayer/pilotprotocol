// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"
)

// TestPartialAckInFastRecoveryDoesNotDeflateToSSThresh verifies that a partial
// ACK during fast recovery performs "partial window deflation" per RFC 6582 §3
// step 6a, rather than unconditionally collapsing cwnd to ssthresh.
//
// RFC 6582 §3 distinguishes two cases for the first new ACK in fast recovery:
//
//	Case 2 (full ACK — covers RecoveryPoint):
//	  Set cwnd = ssthresh.
//
//	Case 1 (partial ACK — below RecoveryPoint):
//	  Deflate cwnd by bytesAcked, then add back one SMSS if bytesAcked >= SMSS.
//	  ("This partial window deflation attempts to ensure that, when fast
//	  recovery eventually ends, approximately ssthresh amount of data will
//	  be outstanding in the network.")
//
// The current code uses a single unconditional rule for both cases:
//
//	c.CongWin = c.SSThresh   // always collapses to ssthresh
//
// When the partial ACK covers exactly 1 SMSS, RFC 6582 says the deflation is
// neutral (−SMSS + SMSS = 0), so cwnd stays at the fast-recovery inflated
// value (ssthresh + 3*SMSS). The current code drops it all the way to
// ssthresh instead.
//
// Concrete scenario:
//
//	SSThresh         =  5*MSS = 20480
//	CongWin          =  8*MSS = 32768  (= ssthresh + 3*MSS; fast-recovery inflation)
//	DupAckCount      =  3              (recovery just entered)
//	InRecovery       =  true
//	RecoveryPoint    =  seqC           (first two Unacked seqs + 2*MSS)
//	Unacked          = [seqA: MSS, seqB: MSS]
//	Partial ACK ack  =  seqB           (acks seqA, 1*MSS, but < RecoveryPoint=seqC)
//
//	  RFC 6582 §3 step 6a:
//	    cwnd -= bytesAcked(=MSS)  → 32768 - 4096 = 28672
//	    bytesAcked >= SMSS → cwnd += MSS     → 28672 + 4096 = 32768 (no net change)
//	    then CA increment = MSS*MSS/32768 = 512
//	    wantCongWin = 32768 + 512 = 33280
//
//	  bug: cwnd = SSThresh = 20480
//	       then CA increment = MSS*MSS/20480 = 819
//	       bugCongWin = 20480 + 819 = 21299
//
// Fix: in the deflation guard inside ProcessAck, distinguish partial ACK
// (InRecovery still true after the recovery-exit check) from full ACK exit:
//
//	if oldDupAckCount >= 3 && wasInRecovery {
//	    if !c.InRecovery {
//	        // Full ACK exit: deflate to ssthresh (RFC 6582 §3 case 2)
//	        c.CongWin = c.SSThresh
//	    } else {
//	        // Partial ACK: partial-window deflation (RFC 6582 §3 step 6a)
//	        c.CongWin -= bytesAcked
//	        if bytesAcked >= MaxSegmentSize {
//	            c.CongWin += MaxSegmentSize
//	        }
//	        if c.CongWin < c.SSThresh {
//	            c.CongWin = c.SSThresh
//	        }
//	    }
//	}
//
// GREEN assertion: after a 1-SMSS partial ACK in fast recovery, CongWin equals
// the fast-recovery inflated value (32768) plus a small CA increment (512) =
// 33280, NOT the over-deflated ssthresh + CA(ssthresh) = 21299.
func TestPartialAckInFastRecoveryDoesNotDeflateToSSThresh(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)

	const (
		ssthresh            = 5 * MaxSegmentSize          // 20480
		fastRecoveryCongWin = ssthresh + 3*MaxSegmentSize // 32768 — entered fast recovery
		seqA                = uint32(1000)
		seqB                = seqA + MaxSegmentSize // 5096
		seqC                = seqB + MaxSegmentSize // 9192 — RecoveryPoint (beyond partial ACK)
	)

	c.LastAck = seqA
	c.SSThresh = ssthresh
	c.CongWin = fastRecoveryCongWin
	c.DupAckCount = 3   // just triggered fast retransmit
	c.InRecovery = true // in fast recovery
	c.RecoveryPoint = seqC
	c.Unacked = []*retxEntry{
		// seqA: already retransmitted (attempts=2), will be acked by partial ACK
		{seq: seqA, data: make([]byte, MaxSegmentSize), attempts: 2, sentAt: time.Now()},
		// seqB: still outstanding beyond the partial ACK
		{seq: seqB, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: time.Now()},
	}

	// Partial ACK: acks seqA (1*MSS), does not reach RecoveryPoint (seqC)
	c.ProcessAck(seqB, true)

	// RFC 6582 §3 step 6a partial-window deflation:
	//   cwnd -= bytesAcked(MSS) → 32768 - 4096 = 28672
	//   bytesAcked >= SMSS → cwnd += SMSS → 28672 + 4096 = 32768 (net neutral)
	//   CA increment = MSS*MSS/32768 = 512
	//   wantCongWin = 32768 + 512 = 33280
	// Bug: cwnd collapsed to ssthresh (20480), then CA on ssthresh → 21299
	const (
		wantCongWin = fastRecoveryCongWin +
			MaxSegmentSize*MaxSegmentSize/fastRecoveryCongWin // 33280
		bugCongWin = ssthresh +
			MaxSegmentSize*MaxSegmentSize/ssthresh // 21299
	)
	if c.CongWin != wantCongWin {
		t.Errorf("partial ACK in fast recovery: CongWin=%d, want %d "+
			"(RFC 6582 §3 step 6a partial-window deflation: neutral for 1 SMSS + "+
			"CA increment=%d); bug collapses to ssthresh+CA=%d, "+
			"fix: distinguish partial ACK (InRecovery still true) from full ACK exit "+
			"in the deflation guard of ProcessAck",
			c.CongWin, wantCongWin,
			MaxSegmentSize*MaxSegmentSize/fastRecoveryCongWin,
			bugCongWin)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// These tests pin the transport-throughput fixes from the 2026-08 overlay
// benchmark investigation (fleet round-trip goodput was ~0.2 MB/s best case
// with multi-minute stalls):
//
//  1. Timeout-based recovery must retransmit ACK-clocked — historically only
//     fast recovery got partial-ACK retransmits (RFC 6582 §3 step 6a), so a
//     window collapse after an RTO drained multi-segment losses at ONE
//     segment per backed-off RTO (~1.3 KB/s observed live).
//  2. retransmitLost may resend a burst of known-lost (below-SACK-frontier)
//     segments per ACK event, bounded by cwnd and maxRetxBurst.
//  3. The receiver's out-of-order buffer must cover a full congestion window,
//     otherwise one loss with >MaxOOOBuf segments in flight silently drops
//     every later in-window segment (loss amplification).

// throughputFixConn builds a Connection in timeout-style recovery with a
// run of consecutive un-SACKed entries (the "hole") followed by SACKed
// entries (the frontier proof), capturing retransmitted seqs.
func throughputFixConn(t *testing.T, holeSegs, sackedSegs int) (*Connection, *[]uint32) {
	t.Helper()
	c := newAckTestConn(t)
	var sent []uint32
	c.RetxSend = func(p *protocol.Packet) { sent = append(sent, p.Seq) }

	seq := uint32(1000)
	for i := 0; i < holeSegs; i++ {
		c.Unacked = append(c.Unacked, &retxEntry{
			seq: seq, data: make([]byte, MaxSegmentSize),
			attempts: 1, sentAt: time.Now(), origSentAt: time.Now(),
		})
		seq += MaxSegmentSize
	}
	for i := 0; i < sackedSegs; i++ {
		c.Unacked = append(c.Unacked, &retxEntry{
			seq: seq, data: make([]byte, MaxSegmentSize),
			attempts: 1, sentAt: time.Now(), origSentAt: time.Now(), sacked: true,
		})
		seq += MaxSegmentSize
	}
	c.LastAck = 1000
	c.RecoveryPoint = seq // everything sent so far is inside the loss window
	return c, &sent
}

// TestTimeoutRecoveryPartialAckRetransmitsAckClocked: a partial ACK during
// timeout recovery (InRecovery=true, FastRecovery=false) must retransmit
// lost segments instead of leaving them to the backed-off RTO timer.
func TestTimeoutRecoveryPartialAckRetransmitsAckClocked(t *testing.T) {
	t.Parallel()
	c, sent := throughputFixConn(t, 8, 4)
	c.InRecovery = true
	c.FastRecovery = false // timeout-entered recovery
	c.CongWin = 4 * MaxSegmentSize
	c.SSThresh = InitialSSThresh

	// Partial ACK: first hole segment arrives (e.g. via an RTO retransmit),
	// cumulative ACK advances one segment but stays below RecoveryPoint.
	c.ProcessAck(1000+MaxSegmentSize, true)

	if len(*sent) == 0 {
		t.Fatalf("partial ACK in timeout recovery retransmitted nothing — " +
			"recovery is left to the backed-off RTO timer at one segment per " +
			"up-to-10s RTO (the throughput-collapse crawl)")
	}
	// The new hole head must be among the retransmissions.
	if (*sent)[0] != 1000+uint32(MaxSegmentSize) {
		t.Errorf("first retransmit seq = %d, want hole head %d",
			(*sent)[0], 1000+MaxSegmentSize)
	}
	// Bounded by cwnd (4 segments): the ACK freed one segment of budget and
	// cwnd grew via slow start, but the burst must stay in the same order of
	// magnitude — never the whole 7-segment hole beyond the window.
	if len(*sent) > c.CongWin/MaxSegmentSize+1 {
		t.Errorf("retransmitted %d segments, want <= cwnd budget %d",
			len(*sent), c.CongWin/MaxSegmentSize+1)
	}
}

// TestRetransmitLostRespectsSackFrontier: only the hole head plus un-SACKed
// segments BELOW the highest SACKed sequence are eligible; segments above
// the frontier may still be in flight and belong to the RTO timer.
func TestRetransmitLostRespectsSackFrontier(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)
	var sent []uint32
	c.RetxSend = func(p *protocol.Packet) { sent = append(sent, p.Seq) }

	const mss = MaxSegmentSize
	mk := func(seq uint32, sacked bool) *retxEntry {
		return &retxEntry{seq: seq, data: make([]byte, mss),
			attempts: 1, sentAt: time.Now(), origSentAt: time.Now(), sacked: sacked}
	}
	// hole(1000), hole(1000+mss), SACKed(1000+2m) — frontier = 1000+3m —
	// then un-SACKed above the frontier (still plausibly in flight).
	c.Unacked = []*retxEntry{
		mk(1000, false),
		mk(1000+1*mss, false),
		mk(1000+2*mss, true),
		mk(1000+3*mss, false),
		mk(1000+4*mss, false),
	}

	c.RetxMu.Lock()
	n := c.retransmitLost(0, 100)
	c.RetxMu.Unlock()

	if n != 2 || len(sent) != 2 {
		t.Fatalf("retransmitLost sent %d (%v), want exactly the 2 below-frontier holes", n, sent)
	}
	if sent[0] != 1000 || sent[1] != 1000+1*mss {
		t.Errorf("retransmitted %v, want [1000 %d]", sent, 1000+1*mss)
	}
}

// TestRetransmitLostNoFrontierSendsHeadOnly: with no SACK information there
// is no loss evidence beyond the cumulative-ACK gap head — exactly one
// segment goes out (the historical fastRetransmit contract).
func TestRetransmitLostNoFrontierSendsHeadOnly(t *testing.T) {
	t.Parallel()
	c, sent := throughputFixConn(t, 6, 0) // all un-SACKed, no frontier

	c.RetxMu.Lock()
	n := c.retransmitLost(0, 100)
	c.RetxMu.Unlock()

	if n != 1 || len(*sent) != 1 || (*sent)[0] != 1000 {
		t.Fatalf("retransmitLost with no SACK frontier sent %d (%v), want just head seq 1000", n, *sent)
	}
}

// TestRetransmitLostBurstCap: one ACK event may never dump more than
// maxRetxBurst segments onto an already-lossy path, regardless of cwnd.
func TestRetransmitLostBurstCap(t *testing.T) {
	t.Parallel()
	c, sent := throughputFixConn(t, 100, 4) // 100-segment hole below the frontier

	c.RetxMu.Lock()
	n := c.retransmitLost(0, 1000)
	c.RetxMu.Unlock()

	if n != maxRetxBurst || len(*sent) != maxRetxBurst {
		t.Fatalf("retransmitLost sent %d segments, want burst cap %d", n, maxRetxBurst)
	}
}

// TestTimeoutRecoveryHoleDrainsInBoundedRounds reproduces the observed
// worst case — a ~180-segment contiguous hole (a full pre-collapse window
// lost at once) with the tail SACKed — and drives ACK-clocked recovery to
// completion. Each round models one RTT: the retransmissions from the
// previous partial ACK arrive, the receiver's cumulative ACK advances over
// them, and the next partial ACK triggers the next burst.
//
// Before the fix, round one retransmits nothing (timeout recovery had no
// partial-ACK retransmit path), the loop makes no progress, and the hole
// drains at one segment per backed-off RTO — 180 segments × up to 10 s.
// After the fix the budget grows with slow start and is capped by
// maxRetxBurst, so the hole must drain within ~hole/maxRetxBurst + log
// rounds ≈ 10 RTTs.
func TestTimeoutRecoveryHoleDrainsInBoundedRounds(t *testing.T) {
	t.Parallel()
	const holeSegs = 180
	c, sent := throughputFixConn(t, holeSegs, 8)
	c.InRecovery = true
	c.FastRecovery = false
	c.CongWin = MaxSegmentSize // post-RTO collapse (RFC 5681 §3.1 LW)
	c.SSThresh = InitialSSThresh

	// The RTO timer delivers the head segment; the first partial ACK follows.
	ack := uint32(1000) + MaxSegmentSize
	rounds := 0
	for {
		rounds++
		*sent = (*sent)[:0]
		c.ProcessAck(ack, true)
		if !c.InRecovery {
			break
		}
		if len(*sent) == 0 {
			t.Fatalf("round %d: partial ACK at seq %d retransmitted nothing — "+
				"recovery stalled with %d unacked entries (pre-fix crawl)",
				rounds, ack, len(c.Unacked))
		}
		// All retransmitted segments are consecutive from the hole head, so
		// the next cumulative ACK advances over every one of them. When the
		// hole is fully covered, the receiver holds the SACKed tail too and
		// the cumulative ACK jumps straight past it (to RecoveryPoint).
		ack += uint32(len(*sent)) * MaxSegmentSize
		if seqAfterOrEqual(ack, 1000+uint32(holeSegs)*MaxSegmentSize) {
			ack = c.RecoveryPoint
		}
		if rounds > 40 {
			t.Fatalf("hole not drained after %d rounds (ack=%d, unacked=%d)",
				rounds, ack, len(c.Unacked))
		}
	}
	// Slow-start budget growth with one ACK per RTT drains 180 segments in
	// ~15 rounds (1+3+5+... capped at maxRetxBurst). Real transfers see
	// multiple ACKs per RTT, so this is the conservative upper bound.
	if rounds > 20 {
		t.Errorf("180-segment hole took %d ACK rounds (RTTs) to drain, want <= 20", rounds)
	}
}

// TestOOOBufferCoversFullCongestionWindow pins the structural relation that
// caused the loss amplification: the receiver must be able to buffer at
// least a full congestion window of out-of-order segments, or one lost
// segment with a full window in flight silently drops everything behind it.
func TestOOOBufferCoversFullCongestionWindow(t *testing.T) {
	t.Parallel()
	if MaxOOOBuf*MaxSegmentSize < MaxCongWin {
		t.Fatalf("MaxOOOBuf (%d segs = %d bytes) < MaxCongWin (%d bytes): "+
			"a single loss with a full window in flight overflows the OOO "+
			"buffer and every later in-window segment is silently dropped",
			MaxOOOBuf, MaxOOOBuf*MaxSegmentSize, MaxCongWin)
	}
}

// TestInitialSSThreshBoundsSlowStartBurst pins the slow-start exit point:
// slow start doubling must hand over to congestion avoidance well before
// the burst reaches the whole-path collapse regime observed at ~550 KB.
func TestInitialSSThreshBoundsSlowStartBurst(t *testing.T) {
	t.Parallel()
	if InitialSSThresh > MaxCongWin/4 {
		t.Fatalf("InitialSSThresh (%d) > MaxCongWin/4 (%d): slow start may "+
			"double straight into a path-collapsing burst before congestion "+
			"avoidance takes over", InitialSSThresh, MaxCongWin/4)
	}
}

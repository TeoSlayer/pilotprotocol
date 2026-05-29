// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// TestSameEpisodeDupAcksDoNotSetFastRecoveryFlag verifies that same-episode
// duplicate ACKs (InRecovery=true from timeout, sendSeq==RecoveryPoint) do
// NOT set the FastRecovery flag, and therefore the RFC 6582 §3 step-6
// deflation path does NOT fire for the subsequent partial ACK.
//
// Bug chain — two consequences of unconditionally setting FastRecovery=true
// in the DupAckCount==3 path:
//
//  1. wasFastRecovery=true on the next new ACK triggers step-6 deflation.
//  2. The step-6b SSThresh floor sets cwnd=ssthresh when the post-timeout
//     cwnd (1 SMSS) is below ssthresh, inflating the window 5× before AIMD.
//
// Concrete scenario (SSThresh=5*MSS, post-timeout CongWin=1*MSS):
//
//	Three same-episode dup ACKs:
//	  iter-76 fix:  CongWin = MaxSegmentSize (not re-inflated)  ✓
//	  BUG:          FastRecovery = true (should stay false)
//
//	Partial ACK arrives (acks seqA only, seqB already sacked, seqC still in
//	flight; ACK < RecoveryPoint):
//	  wasFastRecovery = true  → step-6 guard fires
//	  InRecovery still true   → partial-ACK path (step-6b):
//	    cwnd -= bytesAcked(MSS) = 0
//	    cwnd += MSS            = MaxSegmentSize  (neutral deflation)
//	    floor: cwnd < ssthresh → cwnd = ssthresh = 5*MSS = 20480!
//	  AIMD: cwnd += ~819
//	  bug result: cwnd ≈ 21299 (5× too large)
//
//	Expected (timeout recovery, no fast recovery):
//	  Step-6 must NOT fire (wasFastRecovery=false).
//	  Slow start: cwnd += min(bytesAcked=MSS, 2*MSS) = MSS
//	  fix result: cwnd = 2*MaxSegmentSize = 8192
//
// Fix (two parts):
//
//  1. In the DupAckCount==3 branch, move 'c.FastRecovery = true' inside
//     the '!prevInRecovery || seqAfter(sendSeq, c.RecoveryPoint)' guard
//     (same-episode dup ACKs must not set FastRecovery).
//
//  2. Narrow the step-6 guard from
//     (oldDupAckCount >= 3 || wasFastRecovery) && wasInRecovery
//     to
//     wasFastRecovery && wasInRecovery
//     so that step 6 only fires when FastRecovery was explicitly set
//     (i.e. recovery was entered via fast retransmit for a new episode).
//     This prevents leftover DupAckCount >= 3 from triggering spurious
//     deflation during timeout recovery.
//
// GREEN assertion: after same-episode 3 dup ACKs followed by one partial ACK,
// CongWin is at most 3*MaxSegmentSize (slow start growth), not ~5*MSS
// (step-6 SSThresh floor + AIMD).
func TestSameEpisodeDupAcksDoNotSetFastRecoveryFlag(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	conn := pm.NewConnection(7630, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	conn.RetxSend = func(_ *protocol.Packet) {}
	conn.RetxStop = make(chan struct{})

	const (
		seqA                 = uint32(1000)
		seqB                 = seqA + MaxSegmentSize // 5096 — SACKED by receiver
		seqC                 = seqB + MaxSegmentSize // 9192 — still outstanding
		seqD                 = seqC + MaxSegmentSize // 13288 — RecoveryPoint
		ssthreshAfterTimeout = 5 * MaxSegmentSize    // 20480
	)

	conn.Mu.Lock()
	conn.State = StateEstablished
	// sendSeq == RecoveryPoint: no new data beyond the timeout window.
	conn.SendSeq = seqD
	conn.RecvAck = 0
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	conn.LastAck = seqA
	conn.CongWin = MaxSegmentSize // RFC 5681 §3.1: post-timeout cwnd = 1 SMSS
	conn.SSThresh = ssthreshAfterTimeout
	conn.DupAckCount = 0
	conn.InRecovery = true    // set by the retransmission timeout
	conn.FastRecovery = false // cleared by retransmitUnacked
	conn.RecoveryPoint = seqD // = SendSeq (no new data)
	conn.RTO = InitialRTO
	now := time.Now()
	conn.Unacked = []*retxEntry{
		// seqA: first unacked — timeout retransmitted it once; fastRetransmit will fire for this
		{seq: seqA, data: make([]byte, MaxSegmentSize), attempts: 2, sentAt: now.Add(-100 * time.Millisecond)},
		// seqB: receiver already has it — SACKed
		{seq: seqB, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: now, sacked: true},
		// seqC: outstanding, not yet at receiver
		{seq: seqC, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: now},
	}
	conn.RetxMu.Unlock()

	// Three dup ACKs for seqA — same loss episode (sendSeq==RecoveryPoint).
	conn.ProcessAck(seqA, true) // DupAckCount = 1
	conn.ProcessAck(seqA, true) // DupAckCount = 2
	conn.ProcessAck(seqA, true) // DupAckCount = 3 → fastRetransmit fires; BUG: FastRecovery=true

	// Sanity: iter-76 fix still holds — CongWin not re-inflated to SSThresh+3*MSS.
	conn.RetxMu.Lock()
	if conn.CongWin > MaxSegmentSize {
		t.Fatalf("after 3 same-episode dup ACKs: CongWin=%d, expected iter-76 fix to keep "+
			"CongWin<=%d; prerequisite failed", conn.CongWin, MaxSegmentSize)
	}
	conn.RetxMu.Unlock()

	// Partial ACK: covers seqA (1000-5096) and seqB (5096-9192, sacked), but not seqC.
	// ACK = seqC (9192) < RecoveryPoint (seqD = 13288) → partial ACK.
	// bytesAcked = len(seqA) = MSS (seqB is sacked, not counted).
	conn.ProcessAck(seqC, true)

	conn.RetxMu.Lock()
	congWin := conn.CongWin
	conn.RetxMu.Unlock()

	// Expected (no step-6, slow start from 1 MSS):
	//   cwnd += min(bytesAcked=MSS, 2*MSS) = MSS → cwnd = 2*MaxSegmentSize = 8192
	//
	// Bug (step-6 SSThresh floor):
	//   step-6b: cwnd = max(1MSS - MSS + MSS, ssthresh) = ssthresh = 20480
	//   AIMD: cwnd += ~819 → cwnd ≈ 21299
	//
	// Allow small extra growth (CongWin may grow slightly due to AIMD after
	// slow-start CongWin exceeds SSThresh, but must stay well below SSThresh).
	maxAllowed := 3 * MaxSegmentSize // generous: 2*MSS correct + 1*MSS tolerance
	if congWin > maxAllowed {
		t.Errorf("partial ACK after same-episode dup ACKs (timeout recovery): "+
			"CongWin=%d, want <=%d (slow-start growth from 1 MSS); "+
			"RFC 6582 §3: same episode (sendSeq=%d == RecoveryPoint=%d) — FastRecovery "+
			"must not be set on the 3rd dup ACK, and step-6 must not fire on the "+
			"subsequent partial ACK; bug: FastRecovery=true set unconditionally in "+
			"DupAckCount==3 path, causing wasFastRecovery=true on next new ACK, "+
			"triggering step-6b SSThresh floor that jumps cwnd from 1 MSS to "+
			"SSThresh=%d; fix: (1) move 'c.FastRecovery=true' inside same-episode "+
			"guard in DupAckCount==3 path, (2) change step-6 guard to "+
			"'wasFastRecovery && wasInRecovery'",
			congWin, maxAllowed,
			seqD, seqD,
			ssthreshAfterTimeout)
	}
}

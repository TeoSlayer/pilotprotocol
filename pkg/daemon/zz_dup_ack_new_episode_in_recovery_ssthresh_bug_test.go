// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// TestNewEpisodeDupAcksInRecoveryHalveSSThresh verifies that when three dup ACKs
// trigger fast retransmit for data BEYOND the current recovery point (a new loss
// episode while timeout recovery is still active), SSThresh is halved per
// RFC 5681 §3.2 step 2, and CongWin is set to the new (halved) SSThresh + 3*SMSS.
//
// Background — RFC 5681 §3.2 step 2:
//
//	"When the third duplicate ACK is received, a TCP MUST:
//	  (2) Set ssthresh to max(FlightSize/2, 2*SMSS)."
//
// RFC 6582 §3 allows re-entering fast recovery only when "the highest sequence
// number transmitted" is above "recover" (our RecoveryPoint).  This is a NEW
// loss episode (distinct from the prior timeout recovery).  Each new loss event
// MUST trigger a fresh multiplicative decrease of SSThresh.
//
// Bug: the SSThresh halving in ProcessAck's DupAckCount==3 branch is gated on
// !c.InRecovery.  When InRecovery is already true (timeout) and new data was
// sent beyond the old RecoveryPoint (sendSeq > RecoveryPoint), this guard skips
// the halving and the old (pre-timeout) SSThresh is used to inflate CongWin:
//
//	prevInRecovery := c.InRecovery  // true
//	if !c.InRecovery {              // false → ssthresh block skipped
//	    c.SSThresh = flightSize / 2 // ← never runs
//	    ...
//	}
//	// seqAfter(sendSeq, RecoveryPoint) = true → new episode
//	if !prevInRecovery || seqAfter(sendSeq, c.RecoveryPoint) {
//	    c.CongWin = c.SSThresh + 3*MSS  // old SSThresh → too large
//	}
//
// Concrete scenario (SSThresh=5*MSS from timeout, CongWin=1*MSS, 2 segments in flight):
//
//	FlightSize = 2*MSS = 8192
//	Expected SSThresh = max(8192/2, 2*4096) = max(4096, 8192) = 8192 = 2*MSS
//	Expected CongWin  = 2*MSS + 3*MSS = 5*MSS = 20480
//
//	Bug:
//	  SSThresh = 5*MSS = 20480  (not halved)
//	  CongWin  = 5*MSS + 3*MSS = 8*MSS = 32768  (2.5× too large)
//
// Fix: replace the !c.InRecovery ssthresh guard with the same RFC 6582 §3
// new-episode condition used for CongWin inflation.  Capture the check upfront:
//
//	newEpisode := !c.InRecovery || seqAfter(sendSeq, c.RecoveryPoint)
//	if newEpisode {
//	    c.SSThresh = max(FlightSize/2, 2*SMSS)  // always halve for new episode
//	    c.InRecovery = true
//	    c.RecoveryPoint = sendSeq               // update to current sendSeq
//	}
//	if newEpisode {
//	    c.FastRecovery = true
//	    c.CongWin = c.SSThresh + 3*MSS
//	}
//
// GREEN assertions:
//  1. SSThresh ≤ 2*MaxSegmentSize (halved from FlightSize=2*MSS)
//  2. CongWin ≤ 5*MaxSegmentSize  (new SSThresh + 3*MSS, not old SSThresh + 3*MSS)
func TestNewEpisodeDupAcksInRecoveryHalveSSThresh(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	conn := pm.NewConnection(7640, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	conn.RetxSend = func(_ *protocol.Packet) {}
	conn.RetxStop = make(chan struct{})

	const (
		seqA                 = uint32(1000)
		seqB                 = seqA + MaxSegmentSize   // 5096 — timeout-retransmitted, in Unacked
		seqD                 = seqA + 2*MaxSegmentSize // 9192 — RecoveryPoint from timeout
		seqE                 = seqA + 3*MaxSegmentSize // 13288 — new data, in Unacked
		ssthreshAfterTimeout = 5 * MaxSegmentSize      // 20480 — halved from 10*MSS by timeout
	)
	sendSeq := seqA + 4*MaxSegmentSize // 17384 — beyond RecoveryPoint=seqD

	conn.Mu.Lock()
	conn.State = StateEstablished
	// SendSeq > RecoveryPoint: new data was sent after the timeout.
	conn.SendSeq = sendSeq
	conn.RecvAck = 0
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	conn.LastAck = seqA
	conn.CongWin = MaxSegmentSize        // RFC 5681 §3.1: post-timeout cwnd = 1 SMSS
	conn.SSThresh = ssthreshAfterTimeout // 5*MSS, set by the retransmission timeout
	conn.DupAckCount = 0
	conn.InRecovery = true    // timeout set InRecovery=true
	conn.FastRecovery = false // cleared by timeout
	conn.RecoveryPoint = seqD // timeout's recovery window ends at seqD
	conn.RTO = InitialRTO
	now := time.Now()
	conn.Unacked = []*retxEntry{
		// seqB: first unacked — timeout retransmitted it once (attempts=2)
		{seq: seqB, data: make([]byte, MaxSegmentSize), attempts: 2, sentAt: now.Add(-50 * time.Millisecond)},
		// seqE: new data beyond RecoveryPoint, not yet received
		{seq: seqE, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: now},
	}
	conn.RetxMu.Unlock()

	// Three dup ACKs for seqA — same cumulative ACK, indicating a new loss
	// event for data BEYOND RecoveryPoint (sendSeq=17384 > RecoveryPoint=9192).
	conn.ProcessAck(seqA, true) // DupAckCount = 1
	conn.ProcessAck(seqA, true) // DupAckCount = 2
	conn.ProcessAck(seqA, true) // DupAckCount = 3 → fastRetransmit fires for seqB

	conn.RetxMu.Lock()
	ssthresh := conn.SSThresh
	congWin := conn.CongWin
	conn.RetxMu.Unlock()

	// FlightSize = len(seqB) + len(seqE) = 2*MaxSegmentSize = 8192
	// Expected SSThresh (fix): max(8192/2, 2*4096) = max(4096, 8192) = 8192 = 2*MSS
	// Expected CongWin  (fix): 8192 + 3*4096 = 20480 = 5*MSS
	//
	// Bug SSThresh: 5*MaxSegmentSize = 20480 (not halved — ssthresh block skipped
	//   because !c.InRecovery is false even though this is a new loss episode)
	// Bug CongWin:  20480 + 3*4096 = 32768 = 8*MSS (uses old, too-large SSThresh)

	maxSSThresh := 3 * MaxSegmentSize // generous: expected 2*MSS, allow up to 3*MSS
	if ssthresh > maxSSThresh {
		t.Errorf("new-episode dup ACKs while in timeout recovery: SSThresh=%d, want <=%d; "+
			"RFC 5681 §3.2 step 2 requires SSThresh=max(FlightSize/2=%d, 2*SMSS=%d) for "+
			"each new loss episode; bug: SSThresh halving is gated on !InRecovery, so it "+
			"is skipped when InRecovery=true from a prior timeout, even though sendSeq=%d "+
			"> RecoveryPoint=%d indicates a NEW loss event; fix: use "+
			"'newEpisode := !c.InRecovery || seqAfter(sendSeq, c.RecoveryPoint)' and gate "+
			"the ssthresh block on newEpisode instead of !c.InRecovery",
			ssthresh, maxSSThresh,
			MaxSegmentSize, 2*MaxSegmentSize,
			sendSeq, seqD)
	}

	maxCongWin := 6 * MaxSegmentSize // generous: expected 5*MSS (2*MSS+3*MSS)
	if congWin > maxCongWin {
		t.Errorf("new-episode dup ACKs while in timeout recovery: CongWin=%d, want <=%d; "+
			"RFC 5681 §3.2 step 4 requires CongWin=SSThresh+3*SMSS with the NEW "+
			"(halved) SSThresh; bug: old SSThresh=%d used → CongWin=%d+3*%d=%d; "+
			"fix: halve SSThresh before inflating CongWin for new episodes",
			congWin, maxCongWin,
			ssthreshAfterTimeout, ssthreshAfterTimeout, MaxSegmentSize,
			ssthreshAfterTimeout+3*MaxSegmentSize)
	}
}

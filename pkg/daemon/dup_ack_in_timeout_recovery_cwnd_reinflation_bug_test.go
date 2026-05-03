// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestDupAckInTimeoutRecoveryDoesNotReinflateConn verifies that when exactly
// three duplicate ACKs arrive during timeout-based loss recovery
// (InRecovery=true, CongWin=MaxSegmentSize, FastRecovery=false), the
// congestion window is NOT re-inflated to SSThresh+3*MSS.
//
// Background — RFC 6582 §3 "recover" guard:
//
//	"If a TCP sender uses Fast Retransmit, then after three duplicate ACKs
//	are received … and if the highest sequence number transmitted is
//	greater than 'recover', then:
//	   (2) Set ssthresh …
//	   (3) Set cwnd to ssthresh plus 3*SMSS."
//
// The "recover" variable is set to the highest sequence number transmitted
// when the previous loss event was detected.  After a retransmission
// timeout RFC 6582 says "recover is initialized to the highest sequence
// number transmitted."  Our RecoveryPoint field plays this role.
//
// When SendSeq == RecoveryPoint (no new data was sent after the timeout),
// the condition "highest seq > recover" is FALSE.  Fast recovery MUST NOT
// be re-entered, and in particular cwnd MUST NOT be re-inflated from the
// timeout's 1-MSS slow-start value to SSThresh+3*MSS.
//
// Bug (current code): ProcessAck's DupAckCount==3 branch unconditionally
// executes:
//
//	c.FastRecovery = true
//	c.CongWin = c.SSThresh + 3*MaxSegmentSize  // ← no guard for same episode
//
// even when InRecovery is already true and sendSeq == RecoveryPoint. The
// window jumps from MaxSegmentSize (4096) to SSThresh+3*MSS (e.g. 32768),
// an 8× increase that completely undoes the timeout's RFC 5681 §3.1
// slow-start reset.
//
// Concrete numbers (SSThresh=5*MSS):
//
//	After timeout: CongWin = MaxSegmentSize = 4096
//	After 3 dup ACKs (sendSeq == RecoveryPoint):
//	  bug:  CongWin = 5*4096 + 3*4096 = 32768  (8× too large)
//	  fix:  CongWin = 4096                      (unchanged — same episode)
//
// Fix: capture prevInRecovery := c.InRecovery before the ssthresh block.
// Gate the CongWin inflation with:
//
//	if !prevInRecovery || seqAfter(sendSeq, c.RecoveryPoint) {
//	    c.CongWin = c.SSThresh + 3*MaxSegmentSize
//	    …
//	}
//
// GREEN assertion: after 3 dup ACKs with sendSeq == RecoveryPoint, CongWin
// remains at MaxSegmentSize (the value set by the timeout), not SSThresh+3*MSS.
func TestDupAckInTimeoutRecoveryDoesNotReinflateConn(t *testing.T) {
	pm := NewPortManager()
	conn := pm.NewConnection(7610, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	conn.RetxSend = func(_ *protocol.Packet) {}
	conn.RetxStop = make(chan struct{})

	const (
		seqA                = uint32(1000)
		ssthreshAfterTimeout = 5 * MaxSegmentSize // 20480 — timeout halved from 10*MSS
	)

	conn.Mu.Lock()
	conn.State = StateEstablished
	// SendSeq == RecoveryPoint: no new data beyond the timeout window.
	conn.SendSeq = seqA + MaxSegmentSize
	conn.RecvAck = 0
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	conn.LastAck = seqA
	conn.CongWin = MaxSegmentSize        // RFC 5681 §3.1: post-timeout cwnd = 1 SMSS
	conn.SSThresh = ssthreshAfterTimeout
	conn.DupAckCount = 0
	conn.InRecovery = true               // set by the retransmission timeout
	conn.FastRecovery = false            // cleared by retransmitUnacked
	conn.RecoveryPoint = seqA + MaxSegmentSize // = SendSeq (no new data)
	conn.RTO = InitialRTO
	conn.Unacked = []*retxEntry{{
		seq:      seqA,
		data:     make([]byte, MaxSegmentSize),
		attempts: 2, // already retransmitted once by the timeout
		sentAt:   time.Now().Add(-100 * time.Millisecond),
	}}
	conn.RetxMu.Unlock()

	// Three dup ACKs for seqA — same loss episode, no new data beyond RecoveryPoint.
	conn.ProcessAck(seqA, true) // DupAckCount = 1
	conn.ProcessAck(seqA, true) // DupAckCount = 2
	conn.ProcessAck(seqA, true) // DupAckCount = 3 → DupAckCount==3 branch fires

	conn.RetxMu.Lock()
	congWin := conn.CongWin
	conn.RetxMu.Unlock()

	// RFC 6582 §3: sendSeq (seqA+MSS) == RecoveryPoint (seqA+MSS) → same episode.
	// CongWin must remain at the timeout value (MaxSegmentSize), not be
	// re-inflated to SSThresh+3*MSS.
	//
	// Bug: CongWin = SSThresh+3*MSS = 5*4096+3*4096 = 32768 (8× too large).
	// Fix: guard "c.CongWin = c.SSThresh + 3*MSS" behind the same-episode check.
	if congWin > MaxSegmentSize {
		t.Errorf("3 dup ACKs during timeout recovery (sendSeq==RecoveryPoint): "+
			"CongWin=%d, want <=%d (MaxSegmentSize); "+
			"ProcessAck re-inflated cwnd from the timeout's 1-MSS slow-start value "+
			"to SSThresh+3*MSS=%d, undoing RFC 5681 §3.1 slow-start reset; "+
			"RFC 6582 §3 requires sendSeq > recover to enter fast recovery "+
			"(sendSeq=%d == RecoveryPoint=%d here, so fast recovery MUST be skipped); "+
			"fix: capture prevInRecovery := c.InRecovery before the ssthresh block "+
			"and gate 'c.CongWin = c.SSThresh + 3*MSS' on "+
			"'!prevInRecovery || seqAfter(sendSeq, c.RecoveryPoint)'",
			congWin, MaxSegmentSize,
			ssthreshAfterTimeout+3*MaxSegmentSize,
			seqA+MaxSegmentSize, seqA+MaxSegmentSize)
	}
}

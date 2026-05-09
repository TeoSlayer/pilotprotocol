// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestDupAckFastRetransmitInRecoveryDoesNotRehalveSSThresh verifies that when
// 3 dup ACKs arrive while InRecovery is already true (set by a prior timeout),
// ProcessAck's fast-retransmit path does NOT halve SSThresh a second time.
//
// Bug: ProcessAck's DupAckCount==3 path unconditionally halves SSThresh:
//
//	c.SSThresh = c.CongWin / 2   // ← NOT guarded by !c.InRecovery
//	c.CongWin  = c.SSThresh + 3*MaxSegmentSize
//	if !c.InRecovery {
//	    c.InRecovery = true
//	    c.RecoveryPoint = sendSeq
//	}
//
// When InRecovery is already true (a timeout for segment A already fired,
// halved SSThresh once, and set CongWin=InitialCongWin), the subsequent 3
// dup ACKs for the same gap halve SSThresh again from the timeout's CongWin:
//
//	After timeout:              SSThresh=10*MSS, CongWin=10*MSS (InitialCongWin)
//	3 dup ACKs fire fast retx:  SSThresh=5*MSS   (WRONG — second halving)
//	Fix (guarded by !InRecovery): SSThresh=10*MSS (unchanged — same episode)
//
// Both the timeout and the 3 dup ACKs belong to the same loss episode (segment
// A is still missing). RFC 5681 §3.2 intends one multiplicative decrease per
// episode; halving twice over-penalises the connection.
//
// GREEN assertion: SSThresh after 3 dup ACKs equals SSThresh set by the
// prior timeout (no second halving).
func TestDupAckFastRetransmitInRecoveryDoesNotRehalveSSThresh(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	conn := pm.NewConnection(7520, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	var retxSent int
	conn.RetxSend = func(_ *protocol.Packet) { retxSent++ }
	conn.RetxStop = make(chan struct{})

	const seqA = uint32(1000)

	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.SendSeq = seqA + MaxSegmentSize
	conn.RecvAck = 0
	conn.Mu.Unlock()

	// Simulate state after a timeout already fired for segment A:
	// SSThresh halved once, CongWin = InitialCongWin, InRecovery = true.
	conn.RetxMu.Lock()
	conn.LastAck = seqA
	conn.CongWin = InitialCongWin       // timeout set this (10*MSS)
	conn.SSThresh = 10 * MaxSegmentSize // timeout halved from 20*MSS → 10*MSS
	conn.DupAckCount = 0                // timeout reset this (iter-51)
	conn.InRecovery = true              // timeout set this
	conn.RecoveryPoint = seqA + MaxSegmentSize
	conn.RTO = InitialRTO
	conn.Unacked = []*retxEntry{{
		seq:      seqA,
		data:     make([]byte, MaxSegmentSize),
		attempts: 2, // already retransmitted once by the timeout
		sentAt:   time.Now().Add(-100 * time.Millisecond),
		sacked:   false,
	}}
	conn.RetxMu.Unlock()

	// Record SSThresh after the simulated timeout.
	ssthreshAfterTimeout := 10 * MaxSegmentSize

	// Process 3 dup ACKs — same loss event as the timeout (peer has B, C, D but not A).
	// Fast retransmit fires on 3rd dup ACK.
	conn.ProcessAck(seqA, true) // DupAckCount = 1
	conn.ProcessAck(seqA, true) // DupAckCount = 2
	conn.ProcessAck(seqA, true) // DupAckCount = 3 → fast retransmit fires

	if retxSent == 0 {
		t.Fatal("test setup error: fast retransmit did not fire; " +
			"check that BytesInFlight > 0 and RetxSend is wired")
	}

	conn.RetxMu.Lock()
	ssthreshAfterDupAck := conn.SSThresh
	conn.RetxMu.Unlock()

	// SSThresh must be unchanged: the timeout already halved it for this loss
	// episode; the 3 dup ACKs are the same loss event and must not halve again.
	//
	// Fix: guard the SSThresh halving in ProcessAck's DupAckCount==3 path with
	// !c.InRecovery, the same way retransmitUnacked guards its halving.
	if ssthreshAfterDupAck != ssthreshAfterTimeout {
		t.Errorf("fast retransmit during recovery: SSThresh=%d after 3 dup ACKs, "+
			"want %d (timeout value); same loss episode must not halve SSThresh "+
			"twice; bug: ProcessAck fast-retransmit path does not guard "+
			"'c.SSThresh = c.CongWin / 2' with !c.InRecovery",
			ssthreshAfterDupAck, ssthreshAfterTimeout)
	}
}

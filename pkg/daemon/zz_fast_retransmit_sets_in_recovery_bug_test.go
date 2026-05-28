// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// TestFastRetransmitSetsInRecoveryPreventsDoubleSSThreshHalving verifies that
// when fast retransmit fires (DupAckCount == 3) and a subsequent timeout fires
// for the same loss episode, SSThresh is NOT halved a second time.
//
// Bug: ProcessAck's fast-retransmit path halves SSThresh (SSThresh = CongWin/2)
// and sets CongWin = SSThresh+3*MSS, but does not set InRecovery = true.
// retransmitUnacked guards SSThresh halving with `!conn.InRecovery`:
//
//	if !conn.InRecovery {
//	    conn.SSThresh = conn.CongWin / 2   // ← fires again for the same episode!
//	    conn.CongWin  = InitialCongWin
//	    conn.InRecovery = true
//	}
//
// When InRecovery is false (fast retransmit never set it), a subsequent timeout
// reduces SSThresh a SECOND time using the current (inflated fast-recovery)
// CongWin:
//
//	After fast retransmit:  SSThresh=10*MSS, CongWin=13*MSS, InRecovery=false
//	Timeout fires:          SSThresh = 13*MSS/2 = 6*MSS   (WRONG — second halving)
//	Fix (InRecovery set):   SSThresh unchanged  = 10*MSS   (correct — one halving)
//
// RFC 5681 §3.2 intends one multiplicative decrease per loss episode. Both fast
// retransmit and a subsequent timeout for the same un-ACKed segment belong to
// the same episode: halving twice over-penalises the connection.
//
// GREEN assertion: SSThresh after the timeout equals SSThresh after fast retransmit.
func TestFastRetransmitSetsInRecoveryPreventsDoubleSSThreshHalving(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	conn := d.ports.NewConnection(7500, protocol.Addr{}, 80)
	t.Cleanup(func() { d.ports.RemoveConnection(conn.ID) })

	var retxSent int
	conn.RetxSend = func(_ *protocol.Packet) { retxSent++ }
	conn.RetxStop = make(chan struct{})

	const seqA = uint32(1000)

	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.SendSeq = seqA + MaxSegmentSize
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	conn.LastAck = seqA
	conn.CongWin = 20 * MaxSegmentSize
	conn.SSThresh = 30 * MaxSegmentSize
	conn.DupAckCount = 0
	conn.InRecovery = false
	conn.RTO = InitialRTO
	conn.Unacked = []*retxEntry{{
		seq:      seqA,
		data:     make([]byte, MaxSegmentSize),
		attempts: 1,
		sentAt:   time.Now().Add(-500 * time.Millisecond), // in-flight, not yet past RTO
		sacked:   false,
	}}
	conn.RetxMu.Unlock()

	// Process 3 dup ACKs → triggers fast retransmit, halves SSThresh once.
	conn.ProcessAck(seqA, true) // DupAckCount = 1
	conn.ProcessAck(seqA, true) // DupAckCount = 2
	conn.ProcessAck(seqA, true) // DupAckCount = 3 → fast retransmit fires

	if retxSent == 0 {
		t.Fatal("test setup error: fast retransmit did not fire; " +
			"check that BytesInFlight > 0 and RetxSend is wired")
	}
	retxSent = 0

	// Record SSThresh after fast retransmit (one halving: 20*MSS/2 = 10*MSS).
	conn.RetxMu.Lock()
	ssthreshAfterFR := conn.SSThresh
	// fastRetransmit reset sentAt to now; push past RTO so retransmitUnacked fires.
	conn.Unacked[0].sentAt = time.Now().Add(-2 * InitialRTO)
	conn.RetxMu.Unlock()

	// Trigger timeout retransmit — must NOT re-halve SSThresh.
	d.retransmitUnacked(conn)

	if retxSent == 0 {
		t.Fatal("test setup error: retransmitUnacked did not fire after fast retransmit; " +
			"check that sentAt is older than RTO and RetxSend is wired")
	}

	conn.RetxMu.Lock()
	ssthreshAfterTimeout := conn.SSThresh
	conn.RetxMu.Unlock()

	// SSThresh must be unchanged: fast retransmit already halved it once for this
	// loss episode; the subsequent timeout is for the same un-ACKed segment and
	// must not halve it again.
	//
	// Fix requires two changes:
	//   1. ProcessAck: set InRecovery=true (and RecoveryPoint) when fast retransmit fires.
	//   2. retransmitUnacked: move CongWin=InitialCongWin outside the !InRecovery block
	//      so timeouts always enter slow-start, but only halve SSThresh for new episodes.
	if ssthreshAfterTimeout != ssthreshAfterFR {
		t.Errorf("timeout during fast recovery: SSThresh=%d after timeout, want %d "+
			"(value after fast retransmit); the same loss episode must not halve "+
			"SSThresh twice; bug: ProcessAck fast-retransmit path does not set "+
			"InRecovery=true, so retransmitUnacked treats the timeout as a new "+
			"loss event and halves SSThresh again",
			ssthreshAfterTimeout, ssthreshAfterFR)
	}
}

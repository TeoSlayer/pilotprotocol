// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestRetransmitUnackedResetsDupAckCount verifies that retransmitUnacked resets
// DupAckCount to 0 when it performs a timeout retransmit.
//
// Bug: retransmitUnacked does not reset DupAckCount. When a connection is in
// fast recovery (DupAckCount ≥ 3) and a retransmit timeout fires for the same
// segment, DupAckCount remains at its fast-recovery value. The next new ACK
// then sees oldDupAckCount ≥ 3 and executes the fast-recovery-exit deflation:
//
//	if oldDupAckCount >= 3 {
//	    c.CongWin = c.SSThresh   // ← overrides timeout's CongWin = InitialCongWin
//	}
//
// The timeout's `CongWin = InitialCongWin` is the correct post-timeout window
// (RFC 5681 §3.1: "set cwnd to 1 SMSS [or IW10 here]"). The subsequent
// fast-recovery-exit deflation sets CongWin = SSThresh instead, which may be
// LESS than InitialCongWin — pushing the connection into a state where it
// has lower throughput than the timeout's slow-start reset intended.
//
// Concrete example (MSS = 4096):
//
//	Initial state:  CongWin=15*MSS, DupAckCount=5 (fast recovery)
//	Timeout fires:  SSThresh=7*MSS, CongWin=InitialCongWin=10*MSS
//	DupAckCount not reset → DupAckCount still=5
//
//	Next ACK (ack > LastAck):
//	  oldDupAckCount = 5 >= 3
//	  bug:  CongWin = SSThresh = 7*MSS   (< InitialCongWin — WRONG)
//	  fix:  CongWin = InitialCongWin (timeout's value retained)
//
// GREEN assertion: DupAckCount == 0 after retransmitUnacked fires.
func TestRetransmitUnackedResetsDupAckCount(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	conn := d.ports.NewConnection(7490, protocol.Addr{}, 80)
	t.Cleanup(func() { d.ports.RemoveConnection(conn.ID) })

	// Wire up RetxSend so retransmitUnacked can send without panicking.
	var retxSent int
	conn.RetxSend = func(_ *protocol.Packet) { retxSent++ }
	conn.RetxStop = make(chan struct{})

	// Simulate a connection in fast recovery: DupAckCount=5, CongWin inflated.
	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.SendSeq = 1000 + MaxSegmentSize
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	conn.LastAck = 1000
	conn.CongWin = 15 * MaxSegmentSize
	conn.SSThresh = 16 * MaxSegmentSize
	conn.DupAckCount = 5 // in fast recovery
	conn.RTO = InitialRTO
	conn.Unacked = []*retxEntry{
		{
			seq:      1000,
			data:     make([]byte, MaxSegmentSize),
			attempts: 1,
			sentAt:   time.Now().Add(-2 * InitialRTO), // well past RTO
			sacked:   false,
		},
	}
	conn.RetxMu.Unlock()

	// Trigger timeout-based retransmit.
	d.retransmitUnacked(conn)

	// retransmitUnacked must have fired (sanity check).
	if retxSent == 0 {
		t.Fatal("test setup error: retransmitUnacked did not send a packet; " +
			"check that sentAt is older than RTO and RetxSend is wired")
	}

	// DupAckCount MUST be 0 after a timeout retransmit: a timeout supersedes
	// fast-recovery state.  Leaving it at 5 causes the next new ACK to
	// execute the fast-recovery-exit path (CongWin=SSThresh) instead of
	// staying at InitialCongWin.
	conn.RetxMu.Lock()
	dupAckCount := conn.DupAckCount
	conn.RetxMu.Unlock()

	if dupAckCount != 0 {
		t.Errorf("retransmitUnacked: DupAckCount=%d, want 0; "+
			"timeout retransmit must reset DupAckCount so the next new ACK "+
			"does not trigger spurious fast-recovery-exit (CongWin=SSThresh); "+
			"fix: add 'conn.DupAckCount = 0' to the retransmit path in retransmitUnacked",
			dupAckCount)
	}
}

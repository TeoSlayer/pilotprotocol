// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestFastRecoveryInflationRequiresInRecovery verifies that the DupAckCount > 3
// CongWin inflation path does NOT fire when InRecovery is false.
//
// Background: iter-57 made fastRetransmit return bool and gated the fast-
// recovery state mutations (SSThresh halving, InRecovery=true, CongWin
// inflation) on that bool.  This correctly prevents phantom recovery state
// when fastRetransmit is a no-op (MaxRetxAttempts guard).
//
// Consequence: after iter-57, it is now possible for DupAckCount to reach > 3
// while InRecovery is still false — specifically when the DupAckCount==3
// trigger fired a no-op fastRetransmit (attempts == MaxRetxAttempts) and the
// entry was not sacked by subsequent DupACKs.
//
// The DupAckCount > 3 branch:
//
//	} else if c.DupAckCount > 3 && len(c.Unacked) > 0 {
//	    c.CongWin += MaxSegmentSize   // ← no InRecovery guard
//
// The inline comment says "Inflate window for each additional dup ACK (only
// in recovery)" — but the code has no !InRecovery guard.  Before iter-57 this
// was harmless because DupAckCount > 3 implied InRecovery == true (iter-55/56
// guaranteed the == 3 branch always entered recovery).  After iter-57 that
// guarantee is gone.
//
// The inflation happens even though we are not in recovery, producing a window
// that is larger than intended — up to 4×MSS inflated before the first dup
// ACK beyond the 3rd.  If the peer later sends a new ACK, ProcessAck deflates
// CongWin to SSThresh (the oldDupAckCount >= 3 path).  But SSThresh was NOT
// halved (iter-57 gated that too), so SSThresh equals the pre-loss CongWin.
// The deflation sets CongWin = SSThresh = pre-loss CongWin — still incorrect
// for this no-op scenario.
//
// GREEN assertion: after 4 dup ACKs with the entry at MaxRetxAttempts, CongWin
// is UNCHANGED from its initial value (no inflation at DupAckCount==3 or ==4).
func TestFastRecoveryInflationRequiresInRecovery(t *testing.T) {
	pm := NewPortManager()
	conn := pm.NewConnection(7560, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	conn.RetxSend = func(_ *protocol.Packet) {}
	conn.RetxStop = make(chan struct{})

	const seqA = uint32(1000)

	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.SendSeq = seqA + MaxSegmentSize
	conn.RecvAck = 0
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	conn.LastAck = seqA
	conn.CongWin = InitialCongWin
	conn.SSThresh = 20 * MaxSegmentSize
	conn.InRecovery = false
	conn.DupAckCount = 0
	conn.RTO = InitialRTO
	conn.Unacked = []*retxEntry{{
		seq:      seqA,
		data:     make([]byte, MaxSegmentSize),
		attempts: MaxRetxAttempts, // no-op fast retransmit — recovery not entered
		sentAt:   time.Now().Add(-100 * time.Millisecond),
		sacked:   false,
	}}
	conn.RetxMu.Unlock()

	// 3 dup ACKs: DupAckCount==3 path fires no-op fastRetransmit,
	// iter-57 ensures InRecovery stays false and CongWin stays at InitialCongWin.
	conn.ProcessAck(seqA, true)
	conn.ProcessAck(seqA, true)
	conn.ProcessAck(seqA, true) // DupAckCount = 3 → no-op fast retransmit

	// 4th dup ACK: DupAckCount = 4, DupAckCount > 3 branch fires.
	// Bug: CongWin += MaxSegmentSize even though InRecovery == false.
	conn.ProcessAck(seqA, true)

	conn.RetxMu.Lock()
	congWin := conn.CongWin
	inRecovery := conn.InRecovery
	conn.RetxMu.Unlock()

	// Invariant: no inflation should happen outside of recovery.
	// The comment in the DupAckCount > 3 branch says "only in recovery";
	// the code must enforce it with an explicit InRecovery guard.
	if inRecovery {
		t.Errorf("InRecovery=true after no-op fastRetransmit; iter-57 should keep it false")
	}
	if congWin != InitialCongWin {
		t.Errorf("CongWin=%d after 4 dup ACKs with no-op fastRetransmit, want InitialCongWin=%d; "+
			"DupAckCount > 3 inflated CongWin even though InRecovery is false; "+
			"fix: add '&& c.InRecovery' to the 'DupAckCount > 3' branch condition",
			congWin, InitialCongWin)
	}
}

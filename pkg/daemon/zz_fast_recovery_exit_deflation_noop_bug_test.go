// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestFastRecoveryExitDeflationRequiresActualRecovery verifies that the
// "fast-recovery exit" CongWin deflation (c.CongWin = c.SSThresh) only fires
// when the connection was actually in fast recovery — i.e. when InRecovery was
// true at DupAckCount == 3.
//
// Background: the deflation guard in ProcessAck's new-ACK branch is:
//
//	if oldDupAckCount >= 3 {
//	    c.CongWin = c.SSThresh
//	}
//
// This was correct before iter-57: DupAckCount >= 3 implied InRecovery == true
// because fastRetransmit always entered recovery. After iter-57, fastRetransmit
// can return false (MaxRetxAttempts guard), leaving InRecovery == false while
// DupAckCount still reaches 3 and above. Now oldDupAckCount >= 3 does NOT
// imply recovery was entered.
//
// Consequence: when recovery was NOT entered (InRecovery == false) but
// DupAckCount reached 3+, a subsequent new ACK fires the deflation:
//
//	c.CongWin = c.SSThresh   (SSThresh = 20*MSS, CongWin = InitialCongWin = 10*MSS)
//
// This is an *increase*, not a deflation — CongWin jumps from 10*MSS to 20*MSS.
// The connection then continues from an over-estimated window, potentially
// causing the very congestion that recovery was meant to address.
//
// Fix: capture wasInRecovery := c.InRecovery before the recovery-exit check,
// then use:
//
//	if oldDupAckCount >= 3 && wasInRecovery {
//	    c.CongWin = c.SSThresh
//	}
//
// GREEN assertion: after 4 dup ACKs with no-op fast retransmit followed by a
// new ACK, CongWin grows via slow start from InitialCongWin (one bytesAcked
// increment), not deflated-then-AIMD from SSThresh.
func TestFastRecoveryExitDeflationRequiresActualRecovery(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	conn := pm.NewConnection(7570, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	conn.RetxSend = func(_ *protocol.Packet) {}
	conn.RetxStop = make(chan struct{})

	const seqA = uint32(1000)
	const initialSSThresh = 20 * MaxSegmentSize // larger than InitialCongWin

	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.SendSeq = seqA + MaxSegmentSize
	conn.RecvAck = 0
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	conn.LastAck = seqA
	conn.CongWin = InitialCongWin   // 10*MSS
	conn.SSThresh = initialSSThresh // 20*MSS  (intentionally > InitialCongWin)
	conn.InRecovery = false
	conn.DupAckCount = 0
	conn.RTO = InitialRTO
	conn.Unacked = []*retxEntry{{
		seq:      seqA,
		data:     make([]byte, MaxSegmentSize),
		attempts: MaxRetxAttempts, // fastRetransmit no-op → InRecovery stays false
		sentAt:   time.Now().Add(-100 * time.Millisecond),
		sacked:   false,
	}}
	conn.RetxMu.Unlock()

	// 3 dup ACKs: no-op fast retransmit (iter-56/57 guards), InRecovery stays false.
	// 4th dup ACK: DupAckCount > 3 && InRecovery guard (iter-58) prevents inflation.
	conn.ProcessAck(seqA, true) // DupAckCount = 1
	conn.ProcessAck(seqA, true) // DupAckCount = 2
	conn.ProcessAck(seqA, true) // DupAckCount = 3 → no-op fastRetransmit
	conn.ProcessAck(seqA, true) // DupAckCount = 4

	// New ACK that covers the entry (peer finally acked the one segment in flight).
	// This triggers the new-ACK branch with oldDupAckCount = 4 >= 3.
	// Bug: deflation fires (c.CongWin = c.SSThresh = 20*MSS) even though recovery
	//      was never entered (InRecovery was false throughout).
	newAck := seqA + MaxSegmentSize // covers the only entry
	conn.ProcessAck(newAck, true)

	conn.RetxMu.Lock()
	congWin := conn.CongWin
	inRecovery := conn.InRecovery
	conn.RetxMu.Unlock()

	if inRecovery {
		t.Errorf("InRecovery=true after no-op fastRetransmit scenario; should stay false")
	}

	// With the bug: deflation sets CongWin = SSThresh = 20*MSS = 81920, then
	// AIMD grows slightly (CongWin >= SSThresh → congestion avoidance).
	//
	// With the fix: no deflation fires (recovery was never entered); CongWin
	// starts at InitialCongWin = 10*MSS and grows via slow start by bytesAcked
	// (= MaxSegmentSize = 4096), reaching InitialCongWin + MaxSegmentSize = 45056.
	//
	// Maximum allowed: InitialCongWin + MaxSegmentSize (one slow-start step).
	maxAllowed := InitialCongWin + MaxSegmentSize
	if congWin > maxAllowed {
		t.Errorf("CongWin=%d after new ACK following no-op fastRetransmit, "+
			"want <= %d (InitialCongWin=%d + MaxSegmentSize=%d, slow start); "+
			"deflation 'c.CongWin = c.SSThresh' fired incorrectly: recovery was never "+
			"entered (InRecovery was false when DupAckCount reached 3) but "+
			"oldDupAckCount >= 3 triggered the deflation, inflating CongWin from "+
			"InitialCongWin=%d to SSThresh=%d; "+
			"fix: gate deflation with 'wasInRecovery' captured before clearing InRecovery",
			congWin, maxAllowed, InitialCongWin, MaxSegmentSize,
			InitialCongWin, initialSSThresh)
	}
}

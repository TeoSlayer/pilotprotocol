// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestAdditionalDupAckInTimeoutRecoveryDoesNotInflateConn verifies that when
// MORE than three duplicate ACKs arrive during timeout-based loss recovery
// with sendSeq == RecoveryPoint, the per-dup-ACK window inflation step
// (RFC 5681 §3.2 step 5: cwnd += SMSS per additional dup ACK) does NOT fire.
//
// Context — same recovery episode (RFC 6582 §3 "recover" guard):
//
// iter-76 fixed the initial CongWin re-inflation for the 3rd dup ACK:
// ProcessAck's DupAckCount==3 branch no longer sets cwnd=ssthresh+3*MSS when
// sendSeq <= recover.  But the DupAckCount>3 branch:
//
//	} else if c.DupAckCount > 3 && c.InRecovery && len(c.Unacked) > 0 {
//	    c.CongWin += MaxSegmentSize   // ← RFC 5681 §3.2 step 5 inflation
//
// is NOT gated by the RFC 6582 §3 recover condition.  For every additional
// dup ACK beyond the 3rd (DupAckCount = 4, 5, 6, …), the window grows by
// 1 SMSS even though per RFC 6582 fast recovery MUST NOT be entered.
//
// Concrete scenario (SSThresh=5*MSS, post-timeout CongWin=MaxSegmentSize):
//
//	Dup ACK 3:  DupAckCount==3 branch — CongWin stays at MaxSegmentSize
//	            (iter-76 fix: sendSeq == RecoveryPoint → no re-inflation)
//	Dup ACK 4:  DupAckCount>3 branch — CongWin += MSS = 2*MaxSegmentSize
//	            BUG: RFC 6582 §3: same episode, should NOT inflate
//	Dup ACK 5:  CongWin = 3*MaxSegmentSize  (2× over post-timeout value)
//	…
//
// Fix: guard the DupAckCount>3 inflation with the RFC 6582 §3 recover check:
//
//	} else if c.DupAckCount > 3 && c.InRecovery && len(c.Unacked) > 0 {
//	    // RFC 6582 §3: same-episode dup ACKs (sendSeq <= recover) must not
//	    // inflate the window (fast recovery was not entered for this window).
//	    if !seqAfter(sendSeq, c.RecoveryPoint) {
//	        break  // or return
//	    }
//	    c.CongWin += MaxSegmentSize
//	    …
//
// GREEN assertion: after 4 dup ACKs with sendSeq==RecoveryPoint, CongWin
// is still MaxSegmentSize (not 2*MaxSegmentSize).
func TestAdditionalDupAckInTimeoutRecoveryDoesNotInflateConn(t *testing.T) {
	pm := NewPortManager()
	conn := pm.NewConnection(7620, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	conn.RetxSend = func(_ *protocol.Packet) {}
	conn.RetxStop = make(chan struct{})

	const (
		seqA                = uint32(1000)
		ssthreshAfterTimeout = 5 * MaxSegmentSize
	)

	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.SendSeq = seqA + MaxSegmentSize // == RecoveryPoint: no new data
	conn.RecvAck = 0
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	conn.LastAck = seqA
	conn.CongWin = MaxSegmentSize        // post-timeout: 1 SMSS
	conn.SSThresh = ssthreshAfterTimeout
	conn.DupAckCount = 0
	conn.InRecovery = true
	conn.FastRecovery = false
	conn.RecoveryPoint = seqA + MaxSegmentSize // = SendSeq
	conn.RTO = InitialRTO
	conn.Unacked = []*retxEntry{{
		seq:      seqA,
		data:     make([]byte, MaxSegmentSize),
		attempts: 2, // timeout already retransmitted once
		sentAt:   time.Now().Add(-100 * time.Millisecond),
	}}
	conn.RetxMu.Unlock()

	// Four dup ACKs — same loss episode.
	conn.ProcessAck(seqA, true) // DupAckCount = 1
	conn.ProcessAck(seqA, true) // DupAckCount = 2
	conn.ProcessAck(seqA, true) // DupAckCount = 3 → DupAckCount==3 branch (iter-76: no inflation)
	conn.ProcessAck(seqA, true) // DupAckCount = 4 → DupAckCount>3 branch (BUG: inflates)

	conn.RetxMu.Lock()
	congWin := conn.CongWin
	conn.RetxMu.Unlock()

	// RFC 6582 §3: sendSeq == RecoveryPoint → same episode, must NOT inflate.
	// Bug: CongWin = MaxSegmentSize + MaxSegmentSize = 8192 after dup ACK 4.
	// Fix: guard DupAckCount>3 inflation with seqAfter(sendSeq, c.RecoveryPoint).
	if congWin > MaxSegmentSize {
		t.Errorf("4th dup ACK during timeout recovery (sendSeq==RecoveryPoint): "+
			"CongWin=%d, want <=%d (MaxSegmentSize); "+
			"DupAckCount>3 branch inflated cwnd by %d bytes despite RFC 6582 §3 "+
			"recover guard (sendSeq=%d == RecoveryPoint=%d → same episode, no "+
			"fast recovery); fix: add 'if !seqAfter(sendSeq, c.RecoveryPoint) { break }' "+
			"at the top of the DupAckCount>3 branch",
			congWin, MaxSegmentSize,
			congWin-MaxSegmentSize,
			seqA+MaxSegmentSize, seqA+MaxSegmentSize)
	}
}

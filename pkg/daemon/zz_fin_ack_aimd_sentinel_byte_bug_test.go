// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestFINAckDoesNotDriveAIMD verifies that when a FIN-ACK arrives and the
// only entry removed from Unacked is the FIN sentinel, CongWin is not modified
// — the FIN's internal 1-byte sentinel must not count as "newly acknowledged
// data bytes" for AIMD growth.
//
// Background: CloseConnection tracks the FIN in conn.Unacked as:
//
//	&retxEntry{data: []byte{0}, seq: sendSeq, isFIN: true, ...}
//
// The 1-byte sentinel (data=[0]) exists so that retxEntry has non-zero length
// for internal retransmit bookkeeping.  The actual FIN packet carries no
// payload.  The FIN consumes one sequence-number slot so the cumulative ACK
// for a FIN-only close advances by 1 byte from the sender's perspective.
//
// The bytesAcked loop in ProcessAck:
//
//	for _, e := range c.Unacked {
//	    if seqAfterOrEqual(ack, e.seq+uint32(len(e.data))) && !e.sacked {
//	        bytesAcked += len(e.data)   // ← adds 1 for the FIN sentinel
//	    }
//	}
//
// For the FIN entry: len(e.data) = 1, e.sacked = false.  When the FIN-ACK
// arrives at ack = seq+1, the condition is true and bytesAcked += 1.
//
// The AIMD block then runs with bytesAcked = 1.  In congestion avoidance:
//
//	increment = MaxSegmentSize * 1 / CongWin  // = 0 for any CongWin > MSS
//	if increment < 1 { increment = 1 }        // minimum fires
//	CongWin += 1                              // spurious 1-byte growth
//
// The "< 1 → 1" minimum is designed to prevent stalls when a sub-MSS DATA
// ACK produces a fractional AIMD increment.  It must NOT fire for the FIN
// sentinel byte because FIN is a control segment — its 1-byte internal
// representation is an implementation artifact, not user data.  Counting it
// inflates CongWin by 1 byte per connection close.
//
// Concrete scenario (congestion avoidance):
//
//	CongWin = 20*MSS = 81920, SSThresh = 10*MSS = 40960  (CongWin > SSThresh → CA)
//	Unacked = [FIN: seq=1000, data=[]byte{0}, isFIN=true, sacked=false]
//	LastAck = 1000
//
//	FIN-ACK at 1001 (covers the FIN sentinel):
//	  bug:  bytesAcked = 1 (sentinel counted); CA minimum fires;
//	        CongWin = 81920 + 1 = 81921 — spurious growth
//	  fix:  bytesAcked = 0 (isFIN excluded); AIMD skipped;
//	        CongWin = 81920 (unchanged)
//
// Fix: add `&& !e.isFIN` to the bytesAcked loop condition so that the FIN
// sentinel's 1-byte data does not participate in AIMD accounting.
//
// GREEN assertion: after a FIN-ACK that removes only the FIN sentinel entry,
// CongWin equals its pre-call value.
func TestFINAckDoesNotDriveAIMD(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	conn := pm.NewConnection(7601, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	const finSeq = uint32(1000)

	const initialCongWin = 20 * MaxSegmentSize // 81920 — well above SSThresh
	const ssthresh = 10 * MaxSegmentSize       // 40960 — CongWin > SSThresh → CA

	conn.RetxMu.Lock()
	conn.LastAck = finSeq
	conn.CongWin = initialCongWin
	conn.SSThresh = ssthresh
	conn.InRecovery = false
	conn.DupAckCount = 0
	conn.Unacked = []*retxEntry{
		{
			seq:      finSeq,
			data:     []byte{0}, // 1-byte FIN sentinel (len=1, seq-space advance=1)
			attempts: 1,
			sentAt:   time.Now(),
			sacked:   false,
			isFIN:    true, // marks this as the FIN entry, not user data
		},
	}
	conn.RetxMu.Unlock()

	// FIN-ACK: ack = finSeq+1 (one past the FIN's single-byte sentinel).
	// This is a pure ACK (pureACK=true) for the FIN.
	conn.ProcessAck(finSeq+1, true)

	conn.RetxMu.Lock()
	congWin := conn.CongWin
	conn.RetxMu.Unlock()

	// CongWin must be unchanged: FIN is a control segment; its 1-byte
	// sentinel must not participate in AIMD accounting.  The "< 1 → 1"
	// CA minimum must not fire for a 1-byte isFIN sentinel.
	if congWin != initialCongWin {
		t.Errorf("FIN-ACK: CongWin=%d, want %d (unchanged); "+
			"the FIN entry has isFIN=true and data=[]byte{0} (1-byte sentinel); "+
			"bytesAcked counted len(e.data)=1 for the FIN sentinel, "+
			"causing the congestion-avoidance 'increment < 1 → 1' minimum to fire "+
			"and adding 1 spurious byte to CongWin (4096*1/%d=0 rounds up to 1); "+
			"fix: add '&& !e.isFIN' to the bytesAcked loop in ProcessAck so the "+
			"FIN sentinel byte does not drive AIMD growth",
			congWin, initialCongWin, initialCongWin)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// TestProcessSACKAllSackedSignalsNagleCh verifies that when ProcessSACK marks
// every entry in c.Unacked as sacked (BytesInFlight drops to 0), NagleCh is
// signaled so a nagleFlush goroutine blocked on NagleCh wakes immediately.
//
// Bug (current): ProcessSACK signals WindowCh when BytesInFlight()==0 (added
// in iter-41) but does NOT signal NagleCh.  The nagleFlush function checks:
//
//	hasUnacked := len(conn.Unacked) > 0
//
// With all entries sacked, len(Unacked) > 0 so nagleFlush enters the wait:
//
//	select {
//	case <-conn.NagleCh:   // would unblock here — but NagleCh has no token
//	case <-nagleTimer.C:   // fires after NagleTimeout = 40 ms
//	...
//	}
//
// Since NagleCh has no token, the sender waits the full NagleTimeout (40 ms)
// before sending a sub-MSS segment, even though the peer already holds every
// in-flight byte.  ProcessAck only signals NagleCh when len(c.Unacked)==0,
// i.e., after the cumulative ACK arrives and drains the list — but between
// the SACK (all-sacked) and the cumulative ACK, any nagleFlush caller stalls.
//
// Concrete example:
//
//	Unacked = [seg0-sacked, seg1-sacked, seg2-sacked]
//	BytesInFlight() = 0 (all sacked)
//	NagleBuf has 100 bytes (sub-MSS)
//
//	nagleFlush sees len(Unacked)=3 → hasUnacked=true → enters wait
//	  bug:  NagleCh has no token → waits 40 ms
//	  fix:  ProcessSACK signals NagleCh when BytesInFlight()==0
//	        → nagleFlush immediately gets token → sends without stall
//
// GREEN assertion: after ProcessSACK marks all Unacked entries as sacked,
// NagleCh has a token.
func TestProcessSACKAllSackedSignalsNagleCh(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	conn := pm.NewConnection(7430, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	const numSegs = 3

	conn.RetxMu.Lock()
	conn.LastAck = 2000
	conn.CongWin = 8 * MaxSegmentSize
	conn.SSThresh = 16 * MaxSegmentSize
	// 3 in-flight entries, none yet sacked.
	for i := 0; i < numSegs; i++ {
		conn.Unacked = append(conn.Unacked, &retxEntry{
			seq:      uint32(2000 + i*MaxSegmentSize),
			data:     make([]byte, MaxSegmentSize),
			attempts: 1,
			sentAt:   time.Now(),
			sacked:   false, // not yet sacked
		})
	}
	conn.RetxMu.Unlock()

	// Drain any pre-existing NagleCh token.
	select {
	case <-conn.NagleCh:
	default:
	}

	// Verify BytesInFlight > 0 before SACK (all entries in flight).
	conn.RetxMu.Lock()
	bifBefore := conn.BytesInFlight()
	conn.RetxMu.Unlock()
	if bifBefore == 0 {
		t.Fatal("test setup error: BytesInFlight() should be > 0 before SACK")
	}

	// SACK covering all 3 segments — peer has them all.
	blocks := []SACKBlock{
		{
			Left:  2000,
			Right: uint32(2000 + numSegs*MaxSegmentSize),
		},
	}
	conn.ProcessSACK(blocks)

	// Verify BytesInFlight dropped to 0.
	conn.RetxMu.Lock()
	bifAfter := conn.BytesInFlight()
	unackedLen := len(conn.Unacked)
	conn.RetxMu.Unlock()

	if bifAfter != 0 {
		t.Fatalf("BytesInFlight()=%d after all-sacked SACK, want 0", bifAfter)
	}
	if unackedLen != numSegs {
		t.Fatalf("len(Unacked)=%d, want %d (entries stay until cumulative ACK)", unackedLen, numSegs)
	}

	// NagleCh MUST have a token: BytesInFlight dropped to 0, so any nagleFlush
	// goroutine waiting for "all data ACKed" should wake immediately instead of
	// stalling for NagleTimeout (40 ms).
	select {
	case <-conn.NagleCh:
		// correct — ProcessSACK signaled NagleCh when BytesInFlight dropped to 0
	default:
		t.Errorf("ProcessSACK with all-sacked result: NagleCh has no token; "+
			"BytesInFlight()=0 but len(Unacked)=%d; "+
			"a nagleFlush goroutine blocked on NagleCh will stall for NagleTimeout=%v "+
			"even though the peer already has all outstanding bytes; "+
			"fix: signal NagleCh in ProcessSACK when BytesInFlight()==0, "+
			"alongside the existing WindowCh signal",
			unackedLen, NagleTimeout)
	}
}

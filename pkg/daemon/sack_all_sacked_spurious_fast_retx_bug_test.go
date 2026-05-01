// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestAllSACKedUnackedDoesNotTriggerSpuriousFastRetransmit verifies that
// when every entry in c.Unacked is SACKed (the peer has all outstanding
// segments but the cumulative ACK has not yet advanced), duplicate ACKs
// do NOT trigger fast retransmit and do NOT reduce SSThresh/CongWin.
//
// Bug (current): ProcessAck's dup-ACK guard is:
//
//	if len(c.Unacked) == 0 {
//	    return // skip dup-ACK counting
//	}
//
// After the iter-41 BytesInFlight fix, SACKed segments remain in
// c.Unacked until a cumulative ACK removes them.  If all in-flight
// entries are SACKed, len(c.Unacked) > 0 but BytesInFlight() == 0.
// The guard does NOT fire; DupAckCount increments to 3 and fast retransmit
// fires:
//
//	c.fastRetransmit(recvAck)  // does nothing — all sacked
//	c.SSThresh = c.CongWin / 2 // ← spurious halving
//	c.CongWin  = c.SSThresh + 3*MaxSegmentSize
//
// The next new ACK triggers fast-recovery exit deflation:
//
//	if oldDupAckCount >= 3 { c.CongWin = c.SSThresh }  // 2*MSS
//
// So two spurious events halve throughput (SSThresh: 8*MSS → 4*MSS →
// CongWin deflated to 4*MSS) even though no packet was actually lost.
//
// Concrete example (window = 8 segments):
//
//	initial:   CongWin = 8*MSS = 32768, SSThresh = 16*MSS = 65536
//	Unacked = [seg0-sacked, seg1-sacked, seg2-sacked]  (all at peer)
//	BytesInFlight() = 0 (iter-41 fix excludes sacked)
//
//	3 dup-ACKs:
//	  bug:  DupAckCount reaches 3 → SSThresh = 16384, CongWin = 28672
//	  fix:  BytesInFlight()==0 guard fires → DupAckCount stays 0,
//	        SSThresh unchanged = 65536, CongWin unchanged = 32768
//
// GREEN assertion: after 3 dup-ACKs with all-sacked Unacked,
// SSThresh and CongWin are unchanged.
func TestAllSACKedUnackedDoesNotTriggerSpuriousFastRetransmit(t *testing.T) {
	pm := NewPortManager()
	conn := pm.NewConnection(7420, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	const numSegs = 3
	initialCongWin := 8 * MaxSegmentSize
	initialSSThresh := 16 * MaxSegmentSize // high — won't constrain

	conn.RetxMu.Lock()
	conn.LastAck = 1000
	conn.CongWin = initialCongWin
	conn.SSThresh = initialSSThresh
	// All 3 entries are sacked — peer has them all.
	for i := 0; i < numSegs; i++ {
		conn.Unacked = append(conn.Unacked, &retxEntry{
			seq:      uint32(1000 + i*MaxSegmentSize),
			data:     make([]byte, MaxSegmentSize),
			attempts: 1,
			sentAt:   time.Now(),
			sacked:   true, // already received by peer
		})
	}
	conn.RetxMu.Unlock()

	// Verify: len(Unacked) > 0 but BytesInFlight() == 0.
	conn.RetxMu.Lock()
	bif := conn.BytesInFlight()
	unackedLen := len(conn.Unacked)
	conn.RetxMu.Unlock()

	if unackedLen == 0 {
		t.Fatal("test setup error: Unacked should be non-empty")
	}
	if bif != 0 {
		t.Fatalf("test setup error: BytesInFlight()=%d, want 0 (all entries sacked)", bif)
	}

	// 3 dup-ACKs — would trigger fast retransmit in unpatched code.
	for i := 0; i < 3; i++ {
		conn.ProcessAck(1000, true) // ack == LastAck → dup-ACK path
	}

	conn.RetxMu.Lock()
	ssthresh := conn.SSThresh
	congWin := conn.CongWin
	dupAckCount := conn.DupAckCount
	conn.RetxMu.Unlock()

	// SSThresh must NOT be halved — no real loss occurred.
	if ssthresh != initialSSThresh {
		t.Errorf("3 dup-ACKs with all-sacked Unacked: SSThresh=%d, want %d (unchanged); "+
			"BytesInFlight()==0 means no packet is actually in flight; "+
			"spurious fast retransmit incorrectly halved SSThresh; "+
			"fix: change dup-ACK guard from 'len(c.Unacked)==0' to 'c.BytesInFlight()==0'",
			ssthresh, initialSSThresh)
	}

	// CongWin must NOT be inflated by fast-retransmit CongWin = SSThresh + 3*MSS.
	if congWin != initialCongWin {
		t.Errorf("3 dup-ACKs with all-sacked Unacked: CongWin=%d, want %d (unchanged); "+
			"spurious fast-retransmit path changed CongWin; "+
			"fix: change dup-ACK guard from 'len(c.Unacked)==0' to 'c.BytesInFlight()==0'",
			congWin, initialCongWin)
	}

	// DupAckCount should be 0 — the guard should have returned early every time.
	if dupAckCount != 0 {
		t.Errorf("3 dup-ACKs with all-sacked Unacked: DupAckCount=%d, want 0; "+
			"with BytesInFlight()==0 there is nothing to trigger fast retransmit on; "+
			"fix: change dup-ACK guard from 'len(c.Unacked)==0' to 'c.BytesInFlight()==0'",
			dupAckCount)
	}
}

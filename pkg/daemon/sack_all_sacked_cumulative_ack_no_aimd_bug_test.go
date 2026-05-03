// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestSACKAllSackedCumulativeAckDoesNotGrowCongWin verifies that when a
// cumulative ACK covers segments that were ALL previously SACKed, CongWin
// is not modified — there are no newly-acknowledged bytes to reward with
// AIMD growth.
//
// Background: iter-60 fixed bytesAcked overcounting by replacing the raw
// sequence-space delta with a loop over Unacked that sums len(e.data) for
// non-sacked entries fully covered by the ACK.  When every covered entry is
// sacked, the loop produces bytesAcked = 0.
//
// The congestion-avoidance branch then runs:
//
//	increment := MaxSegmentSize * bytesAcked / c.CongWin  // = 0
//	if increment < 1 {
//	    increment = 1   // ← fires because 0 < 1
//	}
//	c.CongWin += increment  // +1 byte — wrong
//
// The "< 1 → 1" minimum was designed to prevent stalls when a sub-MSS ACK
// produces a fractional AIMD increment.  It must NOT fire when bytesAcked = 0:
// zero newly-acknowledged bytes means no new data was delivered, so no AIMD
// reward is warranted.
//
// Concrete scenario (congestion avoidance, two segments both sacked):
//
//	CongWin = 20*MSS, SSThresh = 10*MSS  (CongWin >= SSThresh → CA)
//	Unacked = [A: seq=1000, 4096 bytes, sacked=true]
//	          [B: seq=5096, 4096 bytes, sacked=true]
//	LastAck = 1000
//
//	Cumulative ACK at 9192 (covers both A and B — all sacked):
//	  iter-60 fix: bytesAcked = 0
//	  bug:  increment = 0 < 1 → 1;  CongWin = 20*MSS + 1 = 81921
//	  fix:  bytesAcked = 0 → skip AIMD; CongWin = 20*MSS = 81920 (unchanged)
//
// Fix: guard the AIMD growth block with "if bytesAcked > 0" so that the
// "< 1 → 1" minimum cannot fire when the cumulative ACK delivers no new
// unacknowledged bytes.
//
// GREEN assertion: after a cumulative ACK that covers only sacked segments,
// CongWin equals its pre-call value (no AIMD growth at all).
func TestSACKAllSackedCumulativeAckDoesNotGrowCongWin(t *testing.T) {
	pm := NewPortManager()
	conn := pm.NewConnection(7590, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	const (
		seqA = uint32(1000)
		seqB = seqA + MaxSegmentSize
	)

	const initialCongWin = 20 * MaxSegmentSize // 81920
	const ssthresh = 10 * MaxSegmentSize       // 40960 — CongWin >= SSThresh → CA

	conn.RetxMu.Lock()
	conn.LastAck = seqA
	conn.CongWin = initialCongWin
	conn.SSThresh = ssthresh
	conn.InRecovery = false
	conn.DupAckCount = 0
	conn.Unacked = []*retxEntry{
		{
			seq:      seqA,
			data:     make([]byte, MaxSegmentSize),
			attempts: 1,
			sentAt:   time.Now(),
			sacked:   true, // already at peer via SACK
		},
		{
			seq:      seqB,
			data:     make([]byte, MaxSegmentSize),
			attempts: 1,
			sentAt:   time.Now(),
			sacked:   true, // already at peer via SACK
		},
	}
	conn.RetxMu.Unlock()

	// Sanity: BytesInFlight() == 0 (both entries sacked).
	conn.RetxMu.Lock()
	bif := conn.BytesInFlight()
	conn.RetxMu.Unlock()
	if bif != 0 {
		t.Fatalf("test setup error: BytesInFlight()=%d, want 0 (both entries sacked)", bif)
	}

	// Cumulative ACK covers both sacked entries — iter-60 fix yields bytesAcked=0.
	conn.ProcessAck(seqB+MaxSegmentSize, true)

	conn.RetxMu.Lock()
	congWin := conn.CongWin
	conn.RetxMu.Unlock()

	// CongWin must be exactly unchanged: no bytes were newly delivered, so no
	// AIMD growth is due.  The "increment < 1 → 1" guard must not fire when
	// bytesAcked = 0.
	if congWin != initialCongWin {
		t.Errorf("cumulative ACK covering only sacked segments: "+
			"CongWin=%d, want %d (unchanged); "+
			"bytesAcked=0 (all segments already sacked via iter-60 fix) "+
			"but the congestion-avoidance 'increment < 1 → 1' minimum fired, "+
			"adding 1 spurious byte to CongWin; "+
			"fix: guard the AIMD block with 'if bytesAcked > 0' so the "+
			"minimum cannot fire when no new data was delivered",
			congWin, initialCongWin)
	}
}

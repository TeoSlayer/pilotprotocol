// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestProcessSACKWraparound verifies that ProcessSACK correctly marks
// unacked segments as sacked when the sequence number space has wrapped
// around uint32 max (2^32 = 4 GiB transferred on one connection).
//
// Bug (pre-v1.9.1): ProcessSACK compares e.seq and segEnd to SACK block
// boundaries using raw uint32 arithmetic:
//
//	if e.seq >= b.Left && segEnd <= b.Right {
//
// When the sequence number space wraps around 0xFFFFFFFF, a SACK block
// like [0xFFFFF000, 0x00001000] has b.Right < b.Left in raw uint32 space.
// Two sub-cases fail:
//
//	(A) Segment straddles the wrap: seq=0xFFFFF000, segEnd=0xFFFFF010.
//	    segEnd <= b.Right → 0xFFFFF010 <= 0x00001000 → FALSE (wrong).
//	    The segment IS within the block in circular space (b.Right = 0x00001000
//	    is 0x10010 bytes past segEnd in serial arithmetic), so it should be
//	    sacked — but isn't.
//
//	(B) Segment has fully wrapped: seq=0x00000010, segEnd=0x00000020.
//	    e.seq >= b.Left → 0x00000010 >= 0xFFFFF000 → FALSE (wrong).
//	    The segment IS within the block (seq comes after Left in circular
//	    space), so it should be sacked — but isn't.
//
// Result: the sender retransmits data the peer already received and
// acknowledged via SACK. Under sustained load at the wrap point, every
// non-trivial segment in the affected window is spuriously retransmitted,
// doubling bandwidth use and inflating Unacked until ACK processing catches up.
//
// Fix (v1.9.1): replace raw comparisons with seqAfterOrEqual / seqAfter
// throughout ProcessSACK, consistent with the circular arithmetic already
// used in ProcessAck, seqAfter, and seqAfterOrEqual.
//
// GREEN assertion: after ProcessSACK, both segments are marked sacked.
// Against unpatched code, neither segment is sacked.
func TestProcessSACKWraparound(t *testing.T) {
	pm := NewPortManager()
	conn := pm.NewConnection(6100, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	// Segment A: seq just below the uint32 wraparound, segEnd also below.
	// segEnd = 0xFFFFF010 — raw check segEnd <= 0x00001000 is false.
	dataA := make([]byte, 0x10)
	// Segment B: seq just above the uint32 wraparound (fully wrapped).
	// seq = 0x00000010 — raw check seq >= 0xFFFFF000 is false.
	dataB := make([]byte, 0x10)

	conn.RetxMu.Lock()
	conn.Unacked = []*retxEntry{
		{seq: 0xFFFFF000, data: dataA}, // segEnd = 0xFFFFF010
		{seq: 0x00000010, data: dataB}, // segEnd = 0x00000020
	}
	conn.RetxMu.Unlock()

	// SACK block that wraps around: covers 0xFFFFF000..0xFFFFFFFF and
	// 0x00000000..0x00001000 in circular sequence space.
	blocks := []SACKBlock{
		{Left: 0xFFFFF000, Right: 0x00001000},
	}

	conn.ProcessSACK(blocks)

	conn.RetxMu.Lock()
	sackedA := conn.Unacked[0].sacked
	sackedB := conn.Unacked[1].sacked
	conn.RetxMu.Unlock()

	// FIXED: use seqAfterOrEqual for both sides of the containment check.
	if !sackedA {
		t.Errorf("segment A (seq=0xFFFFF000, segEnd=0xFFFFF010) not sacked " +
			"by block [0xFFFFF000, 0x00001000] — ProcessSACK raw 'segEnd <= Right' " +
			"comparison fails at uint32 wraparound (0xFFFFF010 <= 0x00001000 = false); " +
			"fix: use seqAfterOrEqual(b.Right, segEnd)")
	}
	if !sackedB {
		t.Errorf("segment B (seq=0x00000010, segEnd=0x00000020) not sacked " +
			"by block [0xFFFFF000, 0x00001000] — ProcessSACK raw 'e.seq >= Left' " +
			"comparison fails at uint32 wraparound (0x00000010 >= 0xFFFFF000 = false); " +
			"fix: use seqAfterOrEqual(e.seq, b.Left)")
	}
}

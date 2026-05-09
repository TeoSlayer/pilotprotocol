// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestSACKBlocksWraparound verifies that SACKBlocks correctly builds separate
// SACK blocks for out-of-order segments on both sides of the uint32 sequence
// number wraparound, not incorrectly merging them into one.
//
// Bug (pre-v1.9.1): SACKBlocks uses raw uint32 comparisons to decide whether
// a sorted OOO segment is contiguous with the current accumulated block:
//
//	if seg.seq <= cur.Right {   // contiguous/overlapping
//	    if segEnd > cur.Right { // extends the block
//	        cur.Right = segEnd
//	    }
//	} else {                    // gap — emit and start new block
//	    ...
//	}
//
// After a sequence number wraparound (>4 GiB sent on one connection), seg.seq
// values just past 0x00000000 are numerically smaller than cur.Right values
// near 0xFFFFFFFF.  The sort step uses seqAfter (circular arithmetic), so the
// wrapped segment comes AFTER the pre-wraparound segment in sorted order.
// Then the merge check:
//
//	seg.seq = 0x00000100
//	cur.Right = 0xFFFFF010
//	seg.seq <= cur.Right → 0x100 <= 0xFFFFF010 → TRUE  (raw uint32, wrong)
//
// treats a segment that is 0xFF10 bytes past cur.Right in circular space as
// overlapping, swallowing it into the previous block.  The resulting SACK
// omits the second block entirely.  The sender does not suppress retransmission
// of the second segment — a spurious retransmit per ACK until the cumulative
// ACK catches up.
//
// Fix (v1.9.1): replace the raw comparisons with circular-arithmetic helpers:
//
//	seqAfterOrEqual(cur.Right, seg.seq)  for the adjacency check
//	seqAfter(segEnd, cur.Right)          for the extension check
//
// GREEN assertion: SACKBlocks returns two distinct blocks for two non-contiguous
// OOO segments straddling the wraparound.  Against unpatched code it returns one.
func TestSACKBlocksWraparound(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	conn := pm.NewConnection(6200, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	// Two non-contiguous OOO segments near the uint32 wraparound:
	//   seg1: [0xFFFFF000, 0xFFFFF010)  — just before the wrap
	//   seg2: [0x00000100, 0x00000110)  — just after the wrap
	//
	// Gap between them in circular space:
	//   0xFFFFFFFF - 0xFFFFF010 + 1 + 0x100 = 0xFF1 bytes — clearly a gap.
	//
	// The sort (seqAfter) correctly orders seg1 before seg2 because 0x00000100
	// is "after" 0xFFFFF000 in circular space.  The raw merge check then fires:
	//   0x00000100 <= 0xFFFFF010 → TRUE → seg2 wrongly absorbed into seg1's block.

	conn.RecvMu.Lock()
	conn.OOOBuf = []*recvSegment{
		{seq: 0xFFFFF000, data: make([]byte, 16)}, // segEnd = 0xFFFFF010
		{seq: 0x00000100, data: make([]byte, 16)}, // segEnd = 0x00000110
	}
	conn.RecvMu.Unlock()

	conn.RecvMu.Lock()
	blocks := conn.SACKBlocks()
	conn.RecvMu.Unlock()

	// FIXED: circular merge check produces two separate blocks.
	if len(blocks) != 2 {
		t.Errorf("SACKBlocks returned %d block(s), want 2 — "+
			"raw 'seg.seq <= cur.Right' comparison at uint32 wraparound "+
			"(0x00000100 <= 0xFFFFF010 = true, raw) incorrectly merges two "+
			"non-contiguous OOO segments into one SACK block, causing the sender "+
			"to spuriously retransmit the second segment on every ACK; "+
			"fix: use seqAfterOrEqual(cur.Right, seg.seq) for the adjacency check",
			len(blocks))
		return
	}

	// Verify the two blocks cover the right ranges (in circular sort order).
	if blocks[0].Left != 0xFFFFF000 || blocks[0].Right != 0xFFFFF010 {
		t.Errorf("block[0] = {0x%X, 0x%X}, want {0xFFFFF000, 0xFFFFF010}",
			blocks[0].Left, blocks[0].Right)
	}
	if blocks[1].Left != 0x00000100 || blocks[1].Right != 0x00000110 {
		t.Errorf("block[1] = {0x%X, 0x%X}, want {0x00000100, 0x00000110}",
			blocks[1].Left, blocks[1].Right)
	}
}

// TestSACKBlocksWraparoundContiguous verifies the happy path: two OOO segments
// that ARE contiguous across the wraparound ARE correctly merged into one block.
//
// seg1: [0xFFFFF000, 0x00000000)  (wraps to 0; segEnd = 0x00000000 after add)
// Wait — use seg1 that ends exactly where seg2 begins:
//
//	seg1: [0xFFFFFF00, 0xFFFFFFFF+1) = [0xFFFFFF00, 0x00000000)
//	seg2: [0x00000000, 0x00000010)
//
// They are contiguous: seg1's right edge == seg2's left edge.
func TestSACKBlocksWraparoundContiguous(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	conn := pm.NewConnection(6201, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	conn.RecvMu.Lock()
	conn.OOOBuf = []*recvSegment{
		{seq: 0xFFFFFF00, data: make([]byte, 256)}, // segEnd = 0x00000000 (wraps)
		{seq: 0x00000000, data: make([]byte, 16)},  // segEnd = 0x00000010
	}
	conn.RecvMu.Unlock()

	conn.RecvMu.Lock()
	blocks := conn.SACKBlocks()
	conn.RecvMu.Unlock()

	// Contiguous across the wrap — should be one merged block.
	if len(blocks) != 1 {
		t.Errorf("SACKBlocks returned %d block(s) for contiguous wraparound "+
			"segments, want 1 merged block", len(blocks))
		return
	}
	if blocks[0].Left != 0xFFFFFF00 || blocks[0].Right != 0x00000010 {
		t.Errorf("merged block = {0x%X, 0x%X}, want {0xFFFFFF00, 0x00000010}",
			blocks[0].Left, blocks[0].Right)
	}
}

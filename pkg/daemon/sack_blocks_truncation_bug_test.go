// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestSACKBlocksTruncationKeepsHighestSeq verifies that when OOOBuf holds
// more than 4 non-contiguous blocks, SACKBlocks() retains the 4 highest-seq
// blocks rather than the 4 lowest-seq blocks.
//
// Bug (current): SACKBlocks() sorts OOO segments ascending by seq and then
// truncates:
//
//	if len(blocks) > 4 {
//	    blocks = blocks[:4]   // ← keeps lowest 4
//	}
//
// With 5 gaps [A, B, C, D, E] (ascending seq), blocks[:4] = [A, B, C, D].
// Block E (the highest-seq gap) is silently dropped and never reported to
// the sender.  The sender therefore retransmits E's range on every RTT
// until the lowest gaps get filled and SACK "scrolls" up to cover E —
// wasting bandwidth and inflating retransmit stats even though the receiver
// already has those bytes.
//
// RFC 2018 §4: "The first SACK block MUST specify the contiguous block of
// data most recently received."  In our seq-sorted OOO buffer, the highest-
// seq block is the best proxy for "most recently received" and should be
// preferred over the lowest-seq block when truncation is necessary.
//
// Concrete example (5 gaps):
//
//	OOO segments: seq 100, 300, 500, 700, 900 (each 100 bytes)
//	Blocks (sorted asc): [100,200), [300,400), [500,600), [700,800), [900,1000)
//
//	bug:  blocks[:4]           → [100,200), [300,400), [500,600), [700,800)
//	                              → [900,1000) never reported, sender retransmits
//	fix:  blocks[len-4:]       → [300,400), [500,600), [700,800), [900,1000)
//	                              → [900,1000) reported, sender does not retransmit
//
// GREEN assertion: with 5 OOO segments (5 blocks), the highest-seq block
// [900,1000) appears in the SACKBlocks() return value.
func TestSACKBlocksTruncationKeepsHighestSeq(t *testing.T) {
	pm := NewPortManager()
	conn := pm.NewConnection(7450, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	// Five OOO segments with gaps between them (5 distinct blocks).
	// Each is 100 bytes with a 100-byte gap: seqs 100, 300, 500, 700, 900.
	oooSeqs := []uint32{100, 300, 500, 700, 900}
	conn.RecvMu.Lock()
	for _, seq := range oooSeqs {
		conn.OOOBuf = append(conn.OOOBuf, &recvSegment{
			seq:  seq,
			data: make([]byte, 100),
		})
	}

	blocks := conn.SACKBlocks()
	conn.RecvMu.Unlock()

	// Must have exactly 4 blocks (limit).
	if len(blocks) != 4 {
		t.Fatalf("SACKBlocks() with 5 OOO blocks returned %d blocks, want 4", len(blocks))
	}

	// The highest-seq block [900, 1000) must be present.
	const wantLeft, wantRight = uint32(900), uint32(1000)
	found := false
	for _, b := range blocks {
		if b.Left == wantLeft && b.Right == wantRight {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("SACKBlocks() with 5 OOO blocks did not include highest-seq block [%d,%d); "+
			"got blocks: %v; "+
			"blocks[:4] keeps the 4 lowest blocks, dropping block E=[900,1000); "+
			"sender will unnecessarily retransmit E's range on each RTT; "+
			"fix: change blocks[:4] to blocks[len(blocks)-4:] to keep highest-seq blocks",
			wantLeft, wantRight, blocks)
	}
}

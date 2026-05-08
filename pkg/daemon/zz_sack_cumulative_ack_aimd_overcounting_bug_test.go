// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestSACKCumulativeAckDoesNotInflateBytesAcked verifies that when a
// cumulative ACK covers segments that were already SACKed, those previously
// SACKed bytes are NOT counted as "newly acknowledged" for AIMD growth.
//
// Background: BytesInFlight() correctly excludes SACKed entries — they are
// already at the peer and must not consume congestion-window space.  However,
// ProcessAck computes:
//
//	bytesAcked := int(ack - c.LastAck)
//
// This is the raw advancement of the cumulative ACK pointer, which includes
// bytes that were previously SACKed.  Those bytes were already excluded from
// BytesInFlight, so they never "used up" window.  Counting them again as
// newly acknowledged over-credits AIMD growth.
//
// Concrete example (slow start, two segments):
//
//	LastAck = 1000
//	Unacked = [A: seq=1000, 4096 bytes, not sacked]
//	          [B: seq=5096, 4096 bytes, sacked]
//
//	BytesInFlight() = 4096  (only A — B excluded as sacked)
//
//	Cumulative ACK at 9192 (covers both A and B):
//	  bug:  bytesAcked = 9192 - 1000 = 8192 = 2*MSS
//	        CongWin += 8192  (grows by 2 MSS in slow start)
//	  fix:  bytesAcked = 4096  (only non-sacked segment A)
//	        CongWin += 4096  (grows by 1 MSS — one new segment acknowledged)
//
// Consequence: with the bug, a connection that receives SACK reports followed
// by a cumulative ACK grows its congestion window ~2× faster than intended
// per RFC 3465 §2 ("newly acknowledged bytes").  Under sustained traffic with
// SACK enabled this produces a persistently over-inflated window, re-entering
// the congestion that triggered the loss event.
//
// Fix: replace "bytesAcked := int(ack - c.LastAck)" with a loop over Unacked
// that sums len(e.data) only for non-sacked entries fully covered by the ACK:
//
//	bytesAcked := 0
//	for _, e := range c.Unacked {
//	    if seqAfterOrEqual(ack, e.seq+uint32(len(e.data))) && !e.sacked {
//	        bytesAcked += len(e.data)
//	    }
//	}
//
// GREEN assertion: after a cumulative ACK covering one non-sacked segment (A)
// and one sacked segment (B), CongWin grows by exactly 1*MSS (only A), not
// by 2*MSS (A+B).
func TestSACKCumulativeAckDoesNotInflateBytesAcked(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	conn := pm.NewConnection(7580, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	const (
		seqA = uint32(1000)
		seqB = seqA + MaxSegmentSize // 5096
	)

	conn.RetxMu.Lock()
	conn.LastAck = seqA
	// In slow start: CongWin < SSThresh so every new ACK grows CongWin by bytesAcked.
	conn.CongWin = InitialCongWin                // 10*MSS = 40960
	conn.SSThresh = 40 * MaxSegmentSize          // 163840 — well above CongWin
	conn.InRecovery = false
	conn.DupAckCount = 0
	conn.Unacked = []*retxEntry{
		{
			seq:      seqA,
			data:     make([]byte, MaxSegmentSize),
			attempts: 1,
			sentAt:   time.Now(),
			sacked:   false, // in flight — counts toward BytesInFlight
		},
		{
			seq:      seqB,
			data:     make([]byte, MaxSegmentSize),
			attempts: 1,
			sentAt:   time.Now(),
			sacked:   true, // already at peer via SACK — NOT in BytesInFlight
		},
	}
	conn.RetxMu.Unlock()

	// Sanity: BytesInFlight should be 1*MSS (only non-sacked segment A).
	conn.RetxMu.Lock()
	bif := conn.BytesInFlight()
	conn.RetxMu.Unlock()
	if bif != MaxSegmentSize {
		t.Fatalf("test setup error: BytesInFlight()=%d, want %d (1 non-sacked segment)",
			bif, MaxSegmentSize)
	}

	// Cumulative ACK at seqB+MaxSegmentSize covers both A and B.
	// Only segment A was "newly acknowledged" — B was already SACKed.
	newAck := seqB + MaxSegmentSize
	conn.ProcessAck(newAck, true)

	conn.RetxMu.Lock()
	congWin := conn.CongWin
	conn.RetxMu.Unlock()

	// FIXED (RFC 3465 §2): bytesAcked should count only non-sacked bytes —
	// segment A (4096 bytes).  Slow start: CongWin += 4096 → InitialCongWin + MSS.
	//
	// With the bug: bytesAcked = ack - LastAck = 8192 = 2*MSS; slow start
	// CongWin grows by 8192 → InitialCongWin + 2*MSS = 49152, which is 4096
	// bytes more than the one segment that was actually newly delivered.
	wantMax := InitialCongWin + MaxSegmentSize // 45056 — grow by exactly 1 MSS
	if congWin > wantMax {
		t.Errorf("cumulative ACK covering 1 non-sacked + 1 sacked segment: "+
			"CongWin=%d, want <= %d (InitialCongWin=%d + 1*MSS=%d); "+
			"bytesAcked = ack - LastAck = %d counted the SACKed segment B "+
			"(%d bytes) as newly acknowledged — B was already in the peer's "+
			"receive buffer, excluded from BytesInFlight, and must not drive "+
			"AIMD growth (RFC 3465 §2: 'newly acknowledged bytes only'); "+
			"fix: replace 'bytesAcked := int(ack - c.LastAck)' with a loop "+
			"over Unacked that sums len(e.data) for non-sacked entries fully "+
			"covered by the ACK",
			congWin, wantMax, InitialCongWin, MaxSegmentSize,
			int(newAck-seqA), MaxSegmentSize)
	}
}

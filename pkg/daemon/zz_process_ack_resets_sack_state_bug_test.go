// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestProcessAckPartialDoesNotResetSACKedState verifies that when a partial
// cumulative ACK removes some (but not all) entries from Unacked, remaining
// entries that were previously marked sacked keep their sacked=true state.
//
// Bug (current): ProcessAck's remaining-entry loop unconditionally resets
// e.sacked = false for every non-ACKed entry:
//
//	} else {
//	    e.sacked = false   // ← discards valid SACK state
//	    remaining = append(remaining, e)
//	}
//
// This means a piggybacked ACK (data segment from peer) that advances the
// cumulative ACK without carrying SACK blocks discards any SACK state
// established by prior ProcessSACK calls. BytesInFlight inflates to include
// all remaining entries — even those the peer has already confirmed receiving
// — potentially stalling the sender until the next SACK-carrying pure ACK
// arrives.
//
// RFC 2018 §5: "The data receiver MUST retain the SACK information for
// entries above the cumulative acknowledgment point."
//
// Concrete example:
//
//	Unacked = [A (seq=1000, unsacked), B (seq=5000, sacked), C (seq=9000, sacked)]
//	BytesInFlight() = len(A) = MSS   (B and C excluded because sacked)
//
//	Partial ACK for A (ack=5000, pureACK=false — piggybacked data ACK):
//	  bug:  B.sacked=false, C.sacked=false
//	        BytesInFlight() = 2*MSS  (B+C both counted — overstated by 2×)
//	  fix:  B.sacked=true, C.sacked=true  (RFC 2018 §5)
//	        BytesInFlight() = 0     (B and C confirmed by peer; correct)
//
// GREEN assertion: after a partial ACK covering only A, B and C retain
// sacked=true and BytesInFlight()==0.
func TestProcessAckPartialDoesNotResetSACKedState(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	conn := pm.NewConnection(7470, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	// Three entries: A is in-flight (unsacked), B and C are at the peer (sacked).
	const (
		seqA = uint32(1000)
		seqB = uint32(1000 + MaxSegmentSize)  // = 5096
		seqC = uint32(1000 + 2*MaxSegmentSize) // = 9192
	)

	conn.RetxMu.Lock()
	conn.LastAck = seqA
	conn.CongWin = 8 * MaxSegmentSize
	conn.SSThresh = 16 * MaxSegmentSize
	conn.Unacked = []*retxEntry{
		{seq: seqA, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: time.Now(), sacked: false},
		{seq: seqB, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: time.Now(), sacked: true},
		{seq: seqC, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: time.Now(), sacked: true},
	}
	conn.RetxMu.Unlock()

	// Verify setup: BytesInFlight should be exactly 1*MSS (only A in flight).
	conn.RetxMu.Lock()
	bifBefore := conn.BytesInFlight()
	conn.RetxMu.Unlock()
	if bifBefore != MaxSegmentSize {
		t.Fatalf("test setup error: BytesInFlight()=%d, want %d (only A unsacked)",
			bifBefore, MaxSegmentSize)
	}

	// Partial cumulative ACK covers only A (pureACK=false — simulates a
	// piggybacked data ACK that contains no SACK blocks).
	// ack = seqB means "I have received everything up to seqB".
	conn.ProcessAck(seqB, false)

	conn.RetxMu.Lock()
	var bSacked, cSacked bool
	for _, e := range conn.Unacked {
		if e.seq == seqB {
			bSacked = e.sacked
		}
		if e.seq == seqC {
			cSacked = e.sacked
		}
	}
	bifAfter := conn.BytesInFlight()
	unackedLen := len(conn.Unacked)
	conn.RetxMu.Unlock()

	// A should be removed (cumulative ACK covered it).
	if unackedLen != 2 {
		t.Fatalf("ProcessAck partial: len(Unacked)=%d, want 2 (A removed, B and C remain)",
			unackedLen)
	}

	// B must retain sacked=true — the peer confirmed receiving it via SACK;
	// a partial ACK that doesn't cover B must not discard that information.
	if !bSacked {
		t.Errorf("ProcessAck partial ACK for A: B.sacked=false, want true; "+
			"RFC 2018 §5 requires retaining SACK state above cumulative ACK; "+
			"fix: remove 'e.sacked = false' from the remaining-entries loop in ProcessAck",
		)
	}

	// C must retain sacked=true for the same reason.
	if !cSacked {
		t.Errorf("ProcessAck partial ACK for A: C.sacked=false, want true; "+
			"RFC 2018 §5 requires retaining SACK state above cumulative ACK",
		)
	}

	// BytesInFlight must be 0: both remaining entries are sacked (peer has them).
	if bifAfter != 0 {
		t.Errorf("ProcessAck partial ACK for A: BytesInFlight()=%d, want 0; "+
			"B and C are sacked (peer has them) but counted as in-flight after "+
			"ProcessAck reset e.sacked=false; "+
			"fix: remove 'e.sacked = false' from the remaining-entries loop in ProcessAck",
			bifAfter)
	}
}

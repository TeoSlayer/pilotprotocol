// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestProcessAckPartialRemovesLastUnsackedSignalsNagleCh verifies that when
// a partial cumulative ACK removes the last non-sacked entry from Unacked
// (BytesInFlight drops to 0 while sacked entries remain), NagleCh is
// signaled so a waiting nagleFlush wakes immediately instead of stalling.
//
// Background: after iter-49's fix, sacked entries are retained in Unacked
// when a cumulative ACK advances past them.  ProcessAck's NagleCh signal
// condition is:
//
//	if len(c.Unacked) == 0 && c.NagleCh != nil {
//
// When only sacked entries remain (len > 0, BytesInFlight == 0), this
// condition is false and NagleCh is NOT signaled.  A nagleFlush goroutine
// that entered the wait-for-NagleCh path (because hasUnacked was true when
// it checked — BytesInFlight was > 0 at that point) will block for the full
// NagleTimeout (40 ms) before sending.
//
// Concrete example:
//
//	Unacked = [A (unsacked), B (sacked), C (sacked)]
//	BytesInFlight = MSS  (only A is in-flight)
//
//	nagleFlush checks hasUnacked = (BytesInFlight() > 0) = true → enters wait
//
//	Partial ACK covers A (ack = seqA + MSS):
//	  iter-49 retains B.sacked=true, C.sacked=true
//	  Unacked = [B (sacked), C (sacked)]
//	  BytesInFlight() = 0  → Nagle should flush immediately
//
//	  bug:  len(Unacked) = 2 ≠ 0 → NagleCh NOT signaled → 40 ms stall
//	  fix:  c.BytesInFlight() == 0 → NagleCh signaled → immediate wake
//
// GREEN assertion: after a partial ACK removes the last unsacked entry while
// sacked entries remain, NagleCh has a token.
func TestProcessAckPartialRemovesLastUnsackedSignalsNagleCh(t *testing.T) {
	pm := NewPortManager()
	conn := pm.NewConnection(7480, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	const (
		seqA = uint32(2000)
		seqB = uint32(2000 + MaxSegmentSize)
		seqC = uint32(2000 + 2*MaxSegmentSize)
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

	// Verify setup: BytesInFlight = MSS (only A in flight).
	conn.RetxMu.Lock()
	bifBefore := conn.BytesInFlight()
	conn.RetxMu.Unlock()
	if bifBefore != MaxSegmentSize {
		t.Fatalf("test setup error: BytesInFlight()=%d, want %d", bifBefore, MaxSegmentSize)
	}

	// Drain any pre-existing NagleCh token.
	select {
	case <-conn.NagleCh:
	default:
	}

	// Partial ACK for A only (pureACK=false — piggybacked data ACK, no SACK blocks).
	// iter-49 preserves B.sacked=true, C.sacked=true.
	// BytesInFlight drops to 0: Nagle should flush immediately.
	conn.ProcessAck(seqB, false) // ack = seqB removes A, leaves B and C

	conn.RetxMu.Lock()
	bifAfter := conn.BytesInFlight()
	unackedLen := len(conn.Unacked)
	conn.RetxMu.Unlock()

	if unackedLen != 2 {
		t.Fatalf("ProcessAck partial: len(Unacked)=%d, want 2", unackedLen)
	}
	if bifAfter != 0 {
		t.Fatalf("ProcessAck partial (after iter-49 fix): BytesInFlight()=%d, want 0 "+
			"(B and C sacked, iter-49 retains sacked state)", bifAfter)
	}

	// NagleCh MUST have a token: BytesInFlight dropped to 0.
	// A nagleFlush goroutine that entered the wait because hasUnacked was true
	// (at the time it evaluated BytesInFlight()=MSS) must wake immediately.
	select {
	case <-conn.NagleCh:
		// correct — ProcessAck signaled NagleCh when last unsacked entry was removed
	default:
		t.Errorf("ProcessAck removed last unsacked entry (BytesInFlight=0, "+
			"but len(Unacked)=%d with sacked entries): NagleCh has no token; "+
			"a nagleFlush goroutine waiting on NagleCh will stall for NagleTimeout=%v; "+
			"fix: change NagleCh signal condition from 'len(c.Unacked)==0' to "+
			"'c.BytesInFlight()==0' in ProcessAck",
			unackedLen, NagleTimeout)
	}
}

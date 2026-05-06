// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"
)

// TestSSGrowthCapsIncrementAt2SMSS verifies that slow-start AIMD growth is
// capped at 2*SMSS per ACK when the ACK acknowledges more than two full
// segments (RFC 3465 §2.1).
//
// RFC 3465 §2.1:
//
//	"A TCP sender SHOULD NOT increase cwnd by more than 2*SMSS bytes per
//	ACK during slow start."
//
//	In ABC terms: cwnd += min(bytes_acked, 2*SMSS)
//
// The current implementation uses cwnd += bytes_acked unconditionally, which
// over-rewards a delayed ACK that covers three or more segments. For a single
// large delayed ACK (e.g. covering 3 segments), the window grows by 3*SMSS in
// one step instead of the RFC-mandated 2*SMSS.
//
// Concrete scenario:
//
//	CongWin  =  3*MSS = 12288  (in SS: CongWin < SSThresh = 40*MSS)
//	SSThresh = 40*MSS          (large, won't be crossed)
//	Unacked  = [A: MSS, B: MSS, C: MSS]  — all not sacked
//	ACK covers all three: bytes_acked = 3*MSS = 12288
//
//	  bug: CongWin += 12288  → 24576  (3*MSS per ACK — exceeds RFC limit)
//	  fix: CongWin += 8192   → 20480  (min(12288, 2*MSS) = 8192)
//
// Fix: in the slow-start branch of ProcessAck, replace
//
//	c.CongWin += bytesAcked
//
// with
//
//	inc := bytesAcked
//	if inc > 2*MaxSegmentSize {
//	    inc = 2 * MaxSegmentSize
//	}
//	c.CongWin += inc
//
// GREEN assertion: after ACKing 3 full segments in slow start, CongWin
// increases by exactly 2*SMSS (= 8192), not 3*SMSS (= 12288).
func TestSSGrowthCapsIncrementAt2SMSS(t *testing.T) {
	c := newAckTestConn(t)

	const (
		initialCongWin = 3 * MaxSegmentSize  // 12288 — well into SS (< SSThresh)
		ssthresh       = 40 * MaxSegmentSize // 163840 — large, won't be crossed
		seqA           = uint32(1000)
		seqB           = seqA + MaxSegmentSize // 5096
		seqC           = seqB + MaxSegmentSize // 9192
	)

	c.LastAck = seqA
	c.CongWin = initialCongWin
	c.SSThresh = ssthresh
	// Three full-sized unacked segments — delayed ACK covers all three.
	c.Unacked = []*retxEntry{
		{seq: seqA, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: time.Now()},
		{seq: seqB, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: time.Now()},
		{seq: seqC, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: time.Now()},
	}

	// ACK covers all three segments: bytes_acked = 3*MSS = 12288.
	c.ProcessAck(seqC+MaxSegmentSize, true)

	// RFC 3465 §2.1: when bytes_acked > 2*SMSS, increment = 2*SMSS.
	// 2*SMSS = 8192.
	// Bug: cwnd += 12288 (3*MSS) uses raw bytes_acked exceeding RFC limit.
	const (
		wantIncrement = 2 * MaxSegmentSize             // 8192
		bugIncrement  = 3 * MaxSegmentSize             // 12288
		wantCongWin   = initialCongWin + wantIncrement // 20480
	)
	if c.CongWin != wantCongWin {
		t.Errorf("SS growth with bytes_acked=3*SMSS: CongWin=%d, want %d "+
			"(RFC 3465 §2.1 max increment=2*SMSS=%d); "+
			"bug: CongWin+=bytes_acked=%d exceeds RFC per-ACK limit; "+
			"fix: cap inc=min(bytes_acked, 2*MaxSegmentSize) in SS branch of ProcessAck",
			c.CongWin, wantCongWin, wantIncrement, bugIncrement)
	}
}

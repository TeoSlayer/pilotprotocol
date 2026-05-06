// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"
)

// TestCAGrowthCapsIncrementAtSMSS verifies that the congestion-avoidance AIMD
// increment is capped at SMSS*SMSS/cwnd when the ACK acknowledges more than
// one full segment (RFC 3465 §2.2).
//
// RFC 3465 §2.2 distinguishes two cases:
//
//	When bytes_acked <= SMSS:  cwnd += SMSS * bytes_acked / cwnd
//	When bytes_acked >  SMSS:  cwnd += SMSS * SMSS       / cwnd
//
// The current implementation uses SMSS*bytes_acked/cwnd unconditionally, which
// over-rewards a delayed ACK that covers multiple segments and makes the window
// grow faster than one full segment per RTT when bytes_acked > SMSS.
//
// Concrete scenario:
//
//	CongWin  = 10*MSS = 40960  (in CA: CongWin > SSThresh)
//	SSThresh =  5*MSS = 20480
//	Unacked  = [A: MSS bytes, B: MSS bytes]  — both not sacked
//	ACK covers both A and B: bytes_acked = 2*MSS = 8192
//
//	  bug: increment = MSS*8192/40960 = 819  (uses bytes_acked directly)
//	  fix: increment = MSS*4096/40960 = 409  (caps at SMSS per RFC 3465 §2.2)
//
// Fix: in the CA branch of ProcessAck, replace
//
//	increment := MaxSegmentSize * bytesAcked / c.CongWin
//
// with
//
//	eff := bytesAcked
//	if eff > MaxSegmentSize {
//	    eff = MaxSegmentSize
//	}
//	increment := MaxSegmentSize * eff / c.CongWin
//
// GREEN assertion: after ACKing 2 full segments in CA, CongWin increases by
// exactly SMSS*SMSS/cwnd (= 409), not SMSS*2*SMSS/cwnd (= 819).
func TestCAGrowthCapsIncrementAtSMSS(t *testing.T) {
	c := newAckTestConn(t)

	const (
		initialCongWin = 10 * MaxSegmentSize // 40960 — in CA (> SSThresh)
		ssthresh       = 5 * MaxSegmentSize  // 20480
		seqA           = uint32(1000)
		seqB           = seqA + MaxSegmentSize // 5096
	)

	c.LastAck = seqA
	c.CongWin = initialCongWin
	c.SSThresh = ssthresh
	// Two full-sized unacked segments — delayed ACK will cover both.
	c.Unacked = []*retxEntry{
		{seq: seqA, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: time.Now()},
		{seq: seqB, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: time.Now()},
	}

	// ACK covers both segments: bytes_acked = 2*MSS = 8192.
	c.ProcessAck(seqB+MaxSegmentSize, true)

	// RFC 3465 §2.2: when bytes_acked > SMSS, increment = SMSS*SMSS/cwnd.
	// SMSS*SMSS/cwnd = 4096*4096/40960 = 409.
	// Bug: SMSS*bytes_acked/cwnd = 4096*8192/40960 = 819.
	const (
		wantIncrement = MaxSegmentSize * MaxSegmentSize / initialCongWin       // 409
		bugIncrement  = MaxSegmentSize * (2 * MaxSegmentSize) / initialCongWin // 819
		wantCongWin   = initialCongWin + wantIncrement                         // 41369
	)
	if c.CongWin != wantCongWin {
		t.Errorf("CA growth with bytes_acked=2*SMSS: CongWin=%d, want %d "+
			"(RFC 3465 §2.2 increment=SMSS*SMSS/cwnd=%d); "+
			"bug: increment=SMSS*bytes_acked/cwnd=%d uses raw bytes_acked instead of "+
			"min(bytes_acked, SMSS); fix: cap eff=min(bytes_acked, MaxSegmentSize) "+
			"before computing increment in the CA branch of ProcessAck",
			c.CongWin, wantCongWin, wantIncrement, bugIncrement)
	}
}

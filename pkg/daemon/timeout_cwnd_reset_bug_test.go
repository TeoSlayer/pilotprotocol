// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestTimeoutResetsCongWinTo1SMSS verifies that when the retransmission timer
// fires, cwnd is set to 1 SMSS (the loss window, LW) per RFC 5681 §3.1,
// not to the 10-SMSS RFC 6928 initial cwnd.
//
// RFC 5681 §3.1 (timeout retransmit):
//
//	"Furthermore, upon a timeout (as defined in [RFC6298] section 5) the
//	retransmitting host MUST set cwnd to no more than the loss window, LW,
//	which equals 1 full-sized segment (regardless of the value of IW)."
//
// RFC 6928 §3 raised the INITIAL cwnd (IW) to up to 10 SMSS for connection
// startup, but it explicitly does NOT change the post-timeout behavior.
// RFC 5681's LW = 1 SMSS remains the standard after loss detection via the
// retransmission timer.
//
// The current code sets:
//
//	conn.CongWin = InitialCongWin   // 10*SMSS = 40960 — wrong after timeout
//
// When SSThresh < InitialCongWin (the common case: SSThresh is halved from
// the in-flight bytes, often 2–5 SMSS), the connection re-enters congestion
// avoidance (CongWin >= SSThresh) immediately instead of restarting from
// slow start as required.
//
// Concrete scenario:
//
//	CongWin   = 20*SMSS = 81920  (large established session)
//	SSThresh  = 10*SMSS = 40960  (initial)
//	Unacked   = [A: 1*MSS, timed out]
//	FlightSize = 1*MSS = 4096
//
//	Timeout fires →
//	  RFC 5681 §3.1: CongWin = 1*SMSS = 4096 (LW); SSThresh = max(4096/2, 2*MSS) = 8192
//	  bug: CongWin = InitialCongWin = 40960 (10*SMSS)
//
// After the RFC-correct reset, CongWin (4096) < SSThresh (8192) → slow start.
// With the bug, CongWin (40960) > SSThresh (8192) → CA starts immediately,
// skipping slow start and re-injecting 10x as much data as permitted.
//
// Fix: in retransmitUnacked, replace
//
//	conn.CongWin = InitialCongWin
//
// with
//
//	conn.CongWin = MaxSegmentSize   // RFC 5681 §3.1 LW = 1 SMSS
//
// GREEN assertion: after RTO retransmit CongWin == MaxSegmentSize (1 SMSS),
// not InitialCongWin (10 SMSS).
func TestTimeoutResetsCongWinTo1SMSS(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	conn := d.ports.NewConnection(7606, protocol.Addr{}, 80)
	t.Cleanup(func() {
		conn.Mu.Lock()
		conn.State = StateClosed
		conn.Mu.Unlock()
		d.ports.RemoveConnection(conn.ID)
	})

	var retxSent int
	conn.RetxSend = func(*protocol.Packet) { retxSent++ }
	conn.RetxStop = make(chan struct{})

	const (
		seqA            = uint32(1000)
		initialCongWin  = 20 * MaxSegmentSize // 81920 — large established window
		initialSSThresh = 10 * MaxSegmentSize // 40960 — initial ssthresh
	)

	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.SendSeq = seqA + MaxSegmentSize
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	conn.LastAck = seqA
	conn.CongWin = initialCongWin
	conn.SSThresh = initialSSThresh
	conn.InRecovery = false
	conn.DupAckCount = 0
	conn.RTO = InitialRTO
	conn.Unacked = []*retxEntry{{
		seq:      seqA,
		data:     make([]byte, MaxSegmentSize), // 1*MSS
		attempts: 1,
		sentAt:   time.Now().Add(-2 * InitialRTO), // timed out
		sacked:   false,
	}}
	conn.RetxMu.Unlock()

	d.retransmitUnacked(conn)

	if retxSent == 0 {
		t.Fatal("test setup error: retransmitUnacked did not fire; check sentAt and RTO")
	}

	conn.RetxMu.Lock()
	cwnd := conn.CongWin
	conn.RetxMu.Unlock()

	// RFC 5681 §3.1: cwnd = LW = 1*SMSS = MaxSegmentSize after timeout.
	// Bug: cwnd = InitialCongWin = 10*SMSS = 40960.
	if cwnd != MaxSegmentSize {
		t.Errorf("post-timeout CongWin=%d, want %d (RFC 5681 §3.1 LW=1*SMSS); "+
			"bug sets InitialCongWin=%d (10*SMSS) which skips slow start when "+
			"SSThresh < InitialCongWin; fix: conn.CongWin = MaxSegmentSize",
			cwnd, MaxSegmentSize, InitialCongWin)
	}
}

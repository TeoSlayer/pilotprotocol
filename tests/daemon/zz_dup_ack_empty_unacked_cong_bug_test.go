// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon_test

import (
	"testing"

	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
)

// TestDupACKWithEmptyUnackedShrinksCongWin verifies that three duplicate ACKs
// arriving when the connection has no unacknowledged data do NOT reduce the
// congestion window.
//
// Bug (pre-v1.9.1): ProcessAck's 3-dup-ACK handler unconditionally reduces
// SSThresh and inflates CongWin regardless of whether there is any data in
// flight:
//
//	if c.DupAckCount == 3 {
//	    c.fastRetransmit(recvAck)   // noop when Unacked is empty
//	    c.SSThresh = c.CongWin / 2  // ← always executes
//	    c.CongWin = c.SSThresh + 3*MaxSegmentSize
//	}
//
// The keepalive mechanism in idleSweepLoop sends pure ACKs with the same
// cumulative ACK value (nothing new to acknowledge) to idle connections.
// Each such ACK is processed by the PEER's ProcessAck, which sees
// ack == LastAck and increments DupAckCount.  After three keepalive probes
// (≥3 minutes at the 60-second interval), DupAckCount reaches 3, triggering
// the handler that halves SSThresh and sets CongWin = SSThresh + 3*MSS.
//
// Consequence: after any three-minute idle period a connection resumes data
// transfer with a severely deflated congestion window.  On a connection that
// previously reached 200 KB CongWin, three keepalive cycles reduce it to
// 4096+3*4096 = ~16 KB — a 12× regression.  Combined with the iter-30 fix
// (fast-recovery exit deflates CongWin = SSThresh), the first new ACK after
// the idle period deflates it further: CongWin = SSThresh ≈ MaxSegmentSize,
// forcing slow-start from a 1-segment window for the first RTT.
//
// RFC 5681 §3.2 implies fast retransmit/fast recovery actions apply only when
// FlightSize > 0 ("bytes currently in flight"); no in-flight data means there
// is nothing to recover from.  Modifying SSThresh/CongWin when Unacked is
// empty is not justified by the RFC.
//
// Fix (v1.9.1): guard the SSThresh/CongWin modification with len(c.Unacked) > 0:
//
//	if c.DupAckCount == 3 {
//	    if len(c.Unacked) > 0 {
//	        c.fastRetransmit(recvAck)
//	        c.SSThresh = c.CongWin / 2
//	        ...
//	        c.CongWin = c.SSThresh + 3*MaxSegmentSize
//	    }
//	}
//
// GREEN assertion: after three dup-ACKs on a connection with no unacked data,
// CongWin and SSThresh are unchanged.  Against unpatched code CongWin shrinks.
func TestDupACKWithEmptyUnackedShrinksCongWin(t *testing.T) {
	t.Parallel()
	pm := daemon.NewPortManager()
	conn := pm.NewConnection(7250, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	const initialCongWin = 200_000 // large window from a previous bulk transfer
	const initialSSThresh = 100_000

	conn.RetxMu.Lock()
	conn.LastAck = 5000
	conn.CongWin = initialCongWin
	conn.SSThresh = initialSSThresh
	conn.Unacked = nil // empty — no data in flight
	conn.RetxMu.Unlock()

	// Send 3 dup-ACKs (same Ack=LastAck, pureACK=true).
	// This mimics 3 keepalive probes from the remote end arriving here.
	for i := 0; i < 3; i++ {
		conn.ProcessAck(5000, true) // ack == LastAck → dup-ACK
	}

	conn.RetxMu.Lock()
	congWin := conn.CongWin
	ssthresh := conn.SSThresh
	dupAckCount := conn.DupAckCount
	conn.RetxMu.Unlock()

	// FIXED: no data in flight → no reason to reduce congestion window.
	// FAILS against unpatched code: after 3rd dup-ACK, SSThresh = CongWin/2
	// = 100_000 and CongWin = SSThresh + 3*MSS = 100_000 + 12_288 = 112_288
	// (deflated from 200_000), regardless of Unacked being empty.
	if congWin != initialCongWin {
		t.Errorf("3 dup-ACKs with empty Unacked: CongWin=%d, want %d (unchanged); "+
			"ProcessAck unconditionally halves SSThresh and inflates CongWin on "+
			"3rd dup-ACK even when Unacked is empty — keepalive probes or other "+
			"spurious dup-ACKs trigger window reduction with no loss event to "+
			"justify it, causing the connection to resume data transfer from a "+
			"deflated window after any 3-keepalive idle period; "+
			"fix: guard SSThresh/CongWin modification with len(c.Unacked) > 0",
			congWin, initialCongWin)
	}
	if ssthresh != initialSSThresh {
		t.Errorf("3 dup-ACKs with empty Unacked: SSThresh=%d, want %d (unchanged); "+
			"spurious fast-recovery entry with no data in flight",
			ssthresh, initialSSThresh)
	}
	_ = dupAckCount // DupAckCount behaviour with empty Unacked not under test
}

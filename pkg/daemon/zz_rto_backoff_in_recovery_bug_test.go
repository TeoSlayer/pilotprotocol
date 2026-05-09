// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestRetransmitUnackedDoublesRTOOnEachTimeout verifies that the
// retransmission timeout triggers exponential RTO backoff on EVERY timeout
// firing, not only the first timeout of a loss event.
//
// Bug (current): retransmitUnacked gates RTO doubling behind isNewLossEvent:
//
//	isNewLossEvent := !conn.InRecovery
//	if isNewLossEvent {
//	    conn.SSThresh = conn.CongWin / 2
//	    conn.CongWin  = InitialCongWin
//	    conn.InRecovery = true
//	    conn.RecoveryPoint = sendSeq
//	    conn.RTO = conn.RTO * 2   // ← only doubled here
//	    ...
//	}
//	// During recovery, retransmit without further RTO doubling ← BUG comment
//
// When InRecovery is already true (e.g., retransmission itself was lost),
// isNewLossEvent = false and the RTO doubling block is skipped.  All
// subsequent timeouts fire at the same interval, with no exponential
// back-off.
//
// RFC 6298 §5.5–5.6:
//
//	"When the retransmission timer expires … back off the timer: the new
//	value of RTO is minimum of (2 * RTO) and the allowed maximum."
//
// There is no exception for "already in recovery."  Every timer expiry must
// double RTO.
//
// Concrete example:
//
//	Initial RTO = 1 s.  First timeout (isNewLossEvent = true) → RTO = 2 s.
//	Retransmit lost; InRecovery stays true.
//	Second timeout (isNewLossEvent = false):
//	  want  RTO = 4 s (doubled per RFC 6298 §5.6)
//	  got   RTO = 2 s (unchanged — doubling block skipped)
//	  → connection retries every 2 s instead of backing off to 4 s, 8 s, …
//
// GREEN assertion: after retransmitUnacked fires a second time while
// InRecovery=true, conn.RTO > the pre-call value.
func TestRetransmitUnackedDoublesRTOOnEachTimeout(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	conn := d.ports.NewConnection(7400, protocol.Addr{}, 80)
	t.Cleanup(func() { d.ports.RemoveConnection(conn.ID) })

	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 2}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: 1}
	conn.Mu.Unlock()

	const startRTO = 2 * time.Second // as if already doubled once by first timeout

	conn.RetxMu.Lock()
	conn.RTO = startRTO
	conn.InRecovery = true         // simulate: already in recovery from first timeout
	conn.RecoveryPoint = 9999      // high — won't exit recovery during this test
	conn.CongWin = InitialCongWin  // already reduced by first timeout
	conn.SSThresh = MaxSegmentSize // already reduced
	conn.LastAck = 1000
	conn.Unacked = []*retxEntry{
		// attempts=2: retransmitted once already — Karn's algorithm applies,
		// but the timeout/RTO path does not depend on attempts.
		{seq: 1000, data: make([]byte, 100), attempts: 2,
			sentAt: time.Now().Add(-3 * startRTO)}, // well past RTO
	}
	conn.RetxMu.Unlock()

	// Wire a no-op RetxSend so the retransmit path can complete.
	conn.RetxMu.Lock()
	conn.RetxSend = func(*protocol.Packet) {}
	conn.RetxMu.Unlock()

	// Second timeout fires — InRecovery=true, should still double RTO.
	d.retransmitUnacked(conn)

	conn.RetxMu.Lock()
	rto := conn.RTO
	conn.RetxMu.Unlock()

	// RFC 6298 §5.6 requires RTO to at least double (before jitter).
	// With jitter the post-call RTO can be up to startRTO*2 * 1.25 = 5 s.
	// The minimum correct value is startRTO*2 = 4 s.
	// The buggy value is startRTO = 2 s (unchanged).
	if rto <= startRTO {
		t.Errorf("retransmitUnacked with InRecovery=true: RTO=%v, want > %v; "+
			"RFC 6298 §5.5–5.6 requires doubling RTO on every timeout expiry, "+
			"not only the first timeout of a loss event; "+
			"fix: move RTO doubling outside the isNewLossEvent block in retransmitUnacked",
			rto, startRTO)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestFastRecoveryExitDeflatesWhenNoRecoveryEntered verifies that the fast-recovery
// exit deflation (CongWin = SSThresh on oldDupAckCount >= 3) is NOT applied when
// no fast recovery was actually entered because Unacked was empty during the dup-ACK
// run.
//
// Background:
// v1.9.1 iter-34 fixed the spurious SSThresh/CongWin reduction that occurred when
// 3 dup-ACKs arrived on a connection with no data in flight:
//
//	if c.DupAckCount == 3 && len(c.Unacked) > 0 { ... }
//
// However the fix left DupAckCount incrementing unconditionally. When a subsequent
// NEW ACK arrives (e.g. the first data exchange after a 3-minute idle period),
// ProcessAck saves oldDupAckCount=3 and applies the fast-recovery exit deflation:
//
//	if oldDupAckCount >= 3 {
//	    c.CongWin = c.SSThresh   // ← fires even though no recovery was entered
//	}
//
// Because SSThresh was never modified (iter-34 guarded it), this sets
// CongWin = originalSSThresh — deflating, e.g., 200 KB → 100 KB — on the first
// new ACK after any 3-keepalive idle period.
//
// RFC 5681 §3.2 ties dup-ACK counting to loss detection on in-flight data.
// With no data in flight, incrementing DupAckCount serves no purpose and
// cascades into the spurious recovery-exit deflation.
//
// Fix (v1.9.1): skip DupAckCount increment (and return early) when
// len(c.Unacked) == 0 — counting duplicate ACKs is only meaningful when
// there is data in flight to detect loss on.
//
// GREEN assertion: after 3 dup-ACKs with empty Unacked followed by a new ACK
// that delivers 1000 bytes of data, CongWin is >= initialCongWin (no deflation).
// Against unpatched code CongWin is deflated to SSThresh (~100 KB) on the
// fast-recovery exit path.
func TestFastRecoveryExitDeflatesWhenNoRecoveryEntered(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	conn := pm.NewConnection(7350, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	const initialCongWin = 200_000
	const initialSSThresh = 100_000
	const segLen = 1000

	conn.RetxMu.Lock()
	conn.LastAck = 5000
	conn.CongWin = initialCongWin
	conn.SSThresh = initialSSThresh
	conn.Unacked = nil // empty — no data in flight
	conn.RetxMu.Unlock()

	// 3 dup-ACKs with empty Unacked — iter-34 guards SSThresh/CongWin, but
	// DupAckCount still reaches 3 in unpatched code.
	for i := 0; i < 3; i++ {
		conn.ProcessAck(5000, true)
	}

	// Inject one in-flight segment so the upcoming ACK is a genuine new ACK.
	conn.RetxMu.Lock()
	conn.Unacked = []*retxEntry{{
		seq:      5000,
		data:     make([]byte, segLen),
		attempts: 1,
		sacked:   false,
		sentAt:   time.Now().Add(-10 * time.Millisecond),
	}}
	conn.RetxMu.Unlock()

	// New ACK covering the injected segment — this is the first new ACK after
	// the idle dup-ACK run.
	conn.ProcessAck(5000+segLen, true)

	conn.RetxMu.Lock()
	congWin := conn.CongWin
	conn.RetxMu.Unlock()

	// FIXED: no fast recovery was entered (iter-34 guarded it), so the
	// fast-recovery exit deflation (CongWin = SSThresh) must not fire.
	// FAILS against unpatched code: oldDupAckCount=3 triggers CongWin=SSThresh
	// = 100_000 (down from 200_000), followed by AIMD growth (+~40) = ~100_040.
	if congWin < initialCongWin {
		t.Errorf("new ACK after 3 dup-ACKs on empty Unacked: CongWin=%d, want >= %d; "+
			"oldDupAckCount=3 fires the fast-recovery exit deflation "+
			"(CongWin=SSThresh=%d) even though fast recovery was never entered — "+
			"iter-34 guarded the SSThresh/CongWin modification in the dup-ACK handler "+
			"but DupAckCount still reached 3 (unguarded increment), so the first new "+
			"ACK after the idle period halves the congestion window with no loss event; "+
			"fix: skip DupAckCount increment when len(c.Unacked)==0 so no false "+
			"recovery-exit deflation fires",
			congWin, initialCongWin, initialSSThresh)
	}
}

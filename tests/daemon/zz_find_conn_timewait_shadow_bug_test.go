// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon_test

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/pilot-protocol/common/protocol"
)

// TestFindConnectionPrefersActiveOverTimeWait verifies that when two connections
// share the same 4-tuple (one TIME_WAIT, one Established), FindConnection always
// returns the active (Established) connection, not the stale one.
//
// Bug (pre-v1.9.1): FindConnection iterates pm.connections (a map[uint32]*Connection)
// without filtering by state. Go map iteration is randomised on each range call.
// When a new connection is created on a TIME_WAIT 4-tuple (e.g. after the iter-20
// SYN-dedup fix allowed port reuse), both connections coexist in the map.
// FindConnection returned whichever appeared first in the random iteration order —
// often the stale TIME_WAIT entry. Data packets routed to that entry were silently
// dropped (handler guards `established := conn.State == StateEstablished`), so the
// new connection never received data even though the application called Accept.
// Keepalive and RST handling on the wrong connection also caused spurious resets.
//
// Fix (v1.9.1): FindConnection now does a state-aware scan: if a non-terminal
// connection (not TIME_WAIT, not CLOSED) matches the 4-tuple it is returned
// immediately. A TIME_WAIT/CLOSED entry is kept as a fallback so that the FIN /
// SYN retransmit-dedup paths can still observe stale entries when no active
// connection exists for that 4-tuple.
//
// GREEN assertion: across 500 independent FindConnection calls with one TIME_WAIT
// and one Established connection sharing the same 4-tuple, the Established
// connection is returned every time. Without the fix the test reliably fails
// within the first few iterations (p(always-wrong) < 10^-150 under the fix).
func TestFindConnectionPrefersActiveOverTimeWait(t *testing.T) {
	t.Parallel()
	pm := daemon.NewPortManager()
	peer := protocol.Addr{Network: 0, Node: 0xDEAD0001}

	// Pre-populate a stale TIME_WAIT connection on the 4-tuple.
	stale := pm.NewConnection(9090, peer, 49300)
	stale.Mu.Lock()
	stale.State = daemon.StateTimeWait
	stale.Mu.Unlock()

	// Create the new ESTABLISHED connection on the same 4-tuple
	// (as iter-20's SYN-dedup fix would do after a port-reuse SYN).
	active := pm.NewConnection(9090, peer, 49300)
	active.Mu.Lock()
	active.State = daemon.StateEstablished
	active.Mu.Unlock()

	// Run 500 iterations — each range over the map uses a fresh random seed,
	// so without the fix roughly half return the stale connection.
	for i := 0; i < 500; i++ {
		found := pm.FindConnection(9090, peer, 49300)
		if found == nil {
			t.Fatalf("iteration %d: FindConnection returned nil; expected active connection", i)
		}
		if found.ID == stale.ID {
			// FIXED: a state-aware scan should never return a TIME_WAIT
			// connection when an active one exists on the same 4-tuple.
			t.Errorf("iteration %d: FindConnection returned stale TIME_WAIT connection (ID=%d), "+
				"expected Established connection (ID=%d) — fix not applied",
				i, stale.ID, active.ID)
			return
		}
	}
}

// TestFindConnectionReturnsTimeWaitWhenNoActiveExists verifies that the fallback
// path works: when the only connection matching a 4-tuple is in TIME_WAIT,
// FindConnection still returns it (so FIN-dedup and SYN-dedup handlers work).
func TestFindConnectionReturnsTimeWaitWhenNoActiveExists(t *testing.T) {
	t.Parallel()
	pm := daemon.NewPortManager()
	peer := protocol.Addr{Network: 0, Node: 0xDEAD0002}

	tw := pm.NewConnection(9091, peer, 49400)
	tw.Mu.Lock()
	tw.State = daemon.StateTimeWait
	tw.Mu.Unlock()

	found := pm.FindConnection(9091, peer, 49400)
	if found == nil {
		t.Error("FindConnection returned nil for sole TIME_WAIT connection; fallback path broken")
	}
}

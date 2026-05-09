// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"net"
	"testing"
)

// TestIPCDialCancelsLeakOnCompletedDials verifies that dialCancels stays
// bounded to currently-in-flight dials after completed dials are removed.
//
// Bug (pre-v1.9.1): ipcConn.dialCancels was a []context.CancelFunc that
// grew by one per handleDial call. addDialCancel appended before the dial;
// the defer in handleDial fired dialCancel() (making future calls a no-op)
// but never removed the entry. After N dials, dialCancels held N dead cancel
// funcs. At 1000 dials/s over 8h: 28.8M entries, ~2.3 GB wasted memory per
// IPC connection released only on socket close.
//
// Fix (v1.9.1): dialCancels is now map[uint64]context.CancelFunc; addDialCancel
// returns an opaque ID; removeDialCancel(id) deletes the entry in O(1).
// handleDial's defer calls both dialCancel() and removeDialCancel(id), so
// completed dials don't leave dead entries in the map.
//
// GREEN assertion: after N add+cancel+remove cycles, dialCancelCount must be 0.
// Against unpatched code (slice with no remove), dialCancelCount returns N.
func TestIPCDialCancelsLeakOnCompletedDials(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })

	ic := newIPCConn(serverConn)
	t.Cleanup(func() { ic.Close() })

	const N = 1000

	// Simulate N completed dial lifecycles using the new API: each dial
	// registers a cancel (addDialCancel returns ID), fires it, and removes
	// it (removeDialCancel). This mirrors what the fixed handleDial defer does.
	for i := 0; i < N; i++ {
		_, cancel := context.WithCancel(context.Background())
		id := ic.addDialCancel(cancel)
		cancel()                // simulate defer dialCancel()
		ic.removeDialCancel(id) // v1.9.1 fix: remove after dial completes
	}

	got := ic.dialCancelCount()

	// FIXED: map is empty — no dead cancel funcs retained.
	if got != 0 {
		t.Errorf("dialCancelCount=%d after %d completed dials; expected 0 — dead entries not pruned (fix not applied)",
			got, N)
	}
}

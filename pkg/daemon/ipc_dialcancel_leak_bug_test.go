// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"net"
	"testing"
)

// TestIPCDialCancelsLeakOnCompletedDials reproduces the
// "dialCancels slice grows unboundedly after completed dials" memory leak.
//
// Symptom: ipcConn.dialCancels is a []context.CancelFunc that grows by one
// entry on every handleDial call — addDialCancel appends before the dial,
// and the entry is never removed after the dial completes. The defer in
// handleDial fires dialCancel() (making the context cancel a no-op), but
// the slice entry remains. Close() only empties the slice at IPC connection
// teardown.
//
// For a long-lived IPC connection making many sequential dials (a gateway
// proxying HTTP requests, a service continuously dialing backends), the
// slice grows proportionally to the number of historical dials:
//
//	N dials × ~80 bytes per context.cancelCtx ≈ N × 80 B
//
// At 1000 dials/s over 8 hours: 28.8 M entries, ~2.3 GB of wasted memory.
// Memory is only reclaimed when the IPC connection closes.
//
// What v1.9.1's fix should change: after each dial completes (or errors),
// the cancel func must be removed from dialCancels. addDialCancel should
// return an opaque ID; removeDialCancel(id) deletes the entry by key
// (O(1) with a map, not O(n) with a slice scan).
//
// This test pins the CURRENT (buggy) behavior: N addDialCancel calls
// followed by N cancel calls leave the slice at length N. After GREEN the
// assertion flips: dialCancels is empty after N remove calls.
func TestIPCDialCancelsLeakOnCompletedDials(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })

	ic := newIPCConn(serverConn)
	t.Cleanup(func() { ic.Close() })

	const N = 1000

	// Simulate N completed dial lifecycles: each dial registers a cancel,
	// then fires it (defer dialCancel() in handleDial) but never removes it.
	for i := 0; i < N; i++ {
		_, cancel := context.WithCancel(context.Background())
		ic.addDialCancel(cancel)
		cancel() // simulate defer dialCancel() firing on handleDial return
		// BUG: the entry stays in dialCancels — cancel is not removed
	}

	got := ic.dialCancelCount()

	// CURRENT (buggy) behavior: dialCancels retains all N dead cancel funcs.
	if got != N {
		if got == 0 {
			t.Fatalf("BUG NOT REPRODUCED: dialCancelCount=0 after %d dials (fix may be in place); GREEN flips this", N)
		}
		t.Fatalf("unexpected dialCancelCount %d (expected %d from stale slice)", got, N)
	}
	t.Logf("dialCancels has %d dead entries after %d completed dials — memory leak", got, N)
}

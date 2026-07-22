// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"os"
	"testing"
)

// requireRealNetwork skips a test when it is running on a GitHub-hosted
// runner without an explicit opt-in.
//
// Several integration tests in this package spin up real multi-daemon
// UDP/NAT/WSS/HTTP networking. GitHub's hosted ubuntu-latest runners cannot
// sustain that traffic reliably — the tests fail with real-networking
// timeouts ("context deadline exceeded", "received 0 of 3 datagrams",
// "dial timeout") even though the code is correct. They PASS on a real
// machine (local dev or a self-hosted runner).
//
// This is a VISIBLE skip, not a hidden exclusion:
//   - Local dev (GITHUB_ACTIONS unset)         -> runs.
//   - Self-hosted runner / opt-in              -> runs (PILOT_REAL_NETWORK=1).
//   - GitHub hosted runner, no opt-in          -> SKIP (shows up in output).
func requireRealNetwork(t *testing.T) {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") == "true" && os.Getenv("PILOT_REAL_NETWORK") != "1" {
		t.Skip("requires real multi-daemon UDP/NAT/WSS/HTTP networking — not available on GitHub hosted runners; run locally or on a self-hosted runner, or set PILOT_REAL_NETWORK=1")
	}
}

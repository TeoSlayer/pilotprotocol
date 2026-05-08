// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"testing"
)

// TestSelfDialReturnsErrSelfDial — §4.3 Self-dial guard regression.
//
// Spec (architecture-notes/05-VERIFICATION.md §4.3):
//
//	err := daemon.DialConnection(self.Addr(), 8080)
//	require.Equal(t, ErrSelfDial, err)
//	require.Less(t, elapsed, 100*time.Millisecond)
//
// The daemon does not export an `ErrSelfDial` sentinel today. Self-dial
// is currently unguarded at the public API surface — `DialConnection`
// will run the full SYN+retry path against a tunnel back to the local
// node ID before failing on its own retry budget (multi-second elapsed
// time, generic timeout error). Implementing the spec verbatim requires
// either:
//
//   - introducing an `ErrSelfDial` sentinel in pkg/daemon and a guard at
//     the top of DialConnectionContext, or
//   - exposing a test-only accessor for the self-dial fast-fail decision.
//
// The task scope (and the codebase honesty rule) explicitly forbid
// adding a public test-only accessor to enable a regression. Skipping
// until the production guard lands.
func TestSelfDialReturnsErrSelfDial(t *testing.T) {
	t.Parallel()
	t.Skip("requires daemon-internal access: pkg/daemon does not export ErrSelfDial nor implement a self-dial fast-fail guard at DialConnection (would need a production change to add the sentinel + guard before this regression can pin behavior)")
}

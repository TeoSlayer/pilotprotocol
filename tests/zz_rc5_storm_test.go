// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"testing"
)

// TestDecryptFailGraceUnderStorm — §4.1 rc5 storm avoidance regression.
//
// Spec (architecture-notes/05-VERIFICATION.md §4.1):
//
//	Set up two TunnelManagers with shared crypto. Trigger peer-rekey
//	scenario: install fresh pc, then 30 stale-key frames. Within 3s
//	grace: pc must remain. After 3s: 5+ stale-key frames must drop pc.
//	The cold-restart equivalent: 30/30 + 50/50 = 100%.
//
// This test exercises the `peerCrypto.decryptFailCount` /
// `decryptFailDropThreshold` / `decryptFailDropGrace` interaction inside
// the TunnelManager — all of which are unexported (lowercase) symbols
// inside pkg/daemon:
//
//   - `peerCrypto` (struct, unexported)
//   - `peerCrypto.decryptFailCount` (field, unexported)
//   - `peerCrypto.createdAt` (field, unexported)
//   - `decryptFailDropThreshold` / `decryptFailDropGrace` (constants, unexported)
//   - `TunnelManager.crypto` (map field, unexported)
//
// The white-box tests that pin these invariants live in
// pkg/daemon/tunnel_*_test.go (same package as the implementation), and
// they are intentional: this is heavily white-boxed crypto state.
//
// Writing the same regression from the external `tests/` package would
// require exporting at least `peerCrypto`, the threshold/grace
// constants, and an Install/Drain hook on TunnelManager. The scope
// rule for this task (and the project's honesty rule) explicitly
// forbid exporting public test-only accessors to enable a test.
//
// Skipping: this regression already lives in pkg/daemon at the level
// where the state is observable.
func TestDecryptFailGraceUnderStorm(t *testing.T) {
	t.Parallel()
	t.Skip("requires daemon-internal access: peerCrypto, decryptFailCount, decryptFailDropGrace, TunnelManager.crypto are all package-private; the rc5 storm regression is already covered by white-box tests in pkg/daemon (see tunnel_desync_salvage_test.go, tunnel_dup_keyexchange_test.go, tunnel_crypto_cap_test.go)")
}

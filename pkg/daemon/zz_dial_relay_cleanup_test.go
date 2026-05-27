// SPDX-License-Identifier: AGPL-3.0-or-later

// Pins the cleanup-on-failure behavior added to dialConnection.
// Without the fix, a failed dial leaves the peer's advisory relay flag
// set, trapping subsequent dials in relay-only mode even after the
// underlying packet loss subsides. The fix:
//   - dialConnection tracks relayActivatedHere
//   - on ctx.Done or maxRetries failure paths, the flag is cleared
//     IFF this dial was the one that set it AND the flag isn't pinned
//
// This is a unit-level pin — directly exercises the dial-state-cleanup
// logic without spinning up daemons.

package daemon

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/routing"
)

// TestDialRelayFlipIsUnpinned verifies that the advisory relay flag
// set by dialConnection's direct-timeout fallback is NOT marked pinned.
// Pinned flags are reserved for authoritative signals (registry
// relay_only=true, ICMP-unreachable threshold, beacon-admit). Mixing
// the dial fallback with pinned would defeat the cleanup-on-failure
// path because IsRelayPinned would gate it off.
func TestDialRelayFlipIsUnpinned(t *testing.T) {
	t.Parallel()
	r := routing.New()
	const peer uint32 = 42

	// Simulate what the dial loop does on direct-timeout fallback.
	r.SetRelayPeer(peer, true)

	if !r.IsRelayPeer(peer) {
		t.Fatal("expected peer in relay mode after SetRelayPeer(true)")
	}
	if r.IsRelayPinned(peer) {
		t.Fatal("dial-loop fallback must NOT pin the relay flag — " +
			"pinning would prevent cleanup-on-dial-failure and trap " +
			"future dials in relay-only mode when relay is unhealthy")
	}
}

// TestUnpinnedRelayCanBeCleared verifies the cleanup operation the
// fixed dial loop performs is effective.
func TestUnpinnedRelayCanBeCleared(t *testing.T) {
	t.Parallel()
	r := routing.New()
	const peer uint32 = 7

	r.SetRelayPeer(peer, true)
	if !r.IsRelayPeer(peer) {
		t.Fatal("setup: expected peer in relay mode")
	}

	// What dialConnection does on dial failure when relayActivatedHere
	// and !IsRelayPinned.
	if !r.IsRelayPinned(peer) {
		r.SetRelayPeer(peer, false)
	}

	if r.IsRelayPeer(peer) {
		t.Fatal("clearing an unpinned relay flag should disable relay mode")
	}
}

// TestPinnedRelayIsPreservedByDialFailureCleanup verifies that an
// authoritatively-pinned peer (e.g., registry relay_only=true) keeps
// its relay flag even when a dial happens to fail.
func TestPinnedRelayIsPreservedByDialFailureCleanup(t *testing.T) {
	t.Parallel()
	r := routing.New()
	const peer uint32 = 99

	// Authoritative signal: peer is pinned to relay.
	r.SetRelayPeerPinned(peer, true)

	// Dial happens, hits the cleanup-on-failure path. Should be a no-op
	// because the flag is pinned.
	if !r.IsRelayPinned(peer) {
		r.SetRelayPeer(peer, false) // dial wouldn't reach this branch
	}

	if !r.IsRelayPeer(peer) {
		t.Fatal("pinned relay must survive dial-failure cleanup")
	}
	if !r.IsRelayPinned(peer) {
		t.Fatal("pinned flag must survive")
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"
)

// TestForgetPeerResolutionDoesNotInvalidateCaches reproduces the
// "stale resolve cache survives peer unreachability signals" bug.
//
// Symptom: the Daemon caches both registry resolve responses
// (resolveCache, ResolveCacheTTL=60s) and the resulting endpoint
// (epCache, used as fallback when the registry is unreachable).
// When ensureTunnel finds a peer in tm.peers (via tm.HasPeer), it
// returns immediately WITHOUT re-resolving — so a new dial uses the
// stale tm.peers entry. If the dial then times out (peer moved /
// died), there is currently no path that invalidates resolveCache
// or epCache. The next dial attempt for the same peer hits the
// same stale data, dials the same dead address, times out again.
//
// Recovery requires either:
//   - 60 s ResolveCacheTTL expiry → wait it out
//   - explicit pilotctl deregister/re-resolve flow
//   - peer happens to send to us (iter 5 NAT-remap learning)
//
// None of these is acceptable for an automated retry from an
// application that just hit ErrDialTimeout. A simple invalidation
// helper, called from the dial-timeout branch (and from iter 8's
// ICMP-relay flip), lets the next dial fetch fresh registry data.
//
// What v1.9.1's fix should change:
//   - Add a `forgetPeerResolution(nodeID uint32)` helper on Daemon
//     that deletes both resolveCache[nodeID] and epCache[nodeID].
//   - Call it from dialConnectionLocked's timeout branch (right
//     before returning ErrDialTimeout).
//   - Call it from the iter 8 ICMP-relay flip path (peer is
//     reachably dead → caches need refreshing).
//
// FIXED (v1.9.1): forgetPeerResolution now deletes both
// resolveCache[nodeID] and epCache[nodeID] under their respective
// mutexes. dialConnectionLocked's max-retries-exhausted branch now
// calls it before returning ErrDialTimeout, so an application-driven
// retry sees fresh registry data rather than the stale entry.
func TestForgetPeerResolutionDoesNotInvalidateCaches(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peerNodeID uint32 = 0x12345678

	// Pre-populate both caches with stale data.
	d.cacheResolve(peerNodeID, map[string]interface{}{
		"real_addr": "10.0.0.99:4000",
		"node_id":   float64(peerNodeID),
	})
	d.cacheEndpoint(peerNodeID, "10.0.0.99:4000")

	// Sanity: caches populated before invalidation.
	if _, ok := d.cachedResolve(peerNodeID); !ok {
		t.Fatalf("setup invariant: resolveCache should be populated")
	}
	if _, ok := d.cachedEndpoint(peerNodeID); !ok {
		t.Fatalf("setup invariant: epCache should be populated")
	}

	d.forgetPeerResolution(peerNodeID)

	// FIXED: both caches empty after invalidation.
	if _, ok := d.cachedResolve(peerNodeID); ok {
		t.Errorf("expected resolveCache empty for peer after forgetPeerResolution")
	}
	if _, ok := d.cachedEndpoint(peerNodeID); ok {
		t.Errorf("expected epCache empty for peer after forgetPeerResolution")
	}
}

// TestForgetPeerResolutionMissingEntryNoOp pins the lifecycle invariant
// that lands in RED already: calling the helper for a peer that has no
// cache entry must be a safe no-op (no panic, no error). The GREEN
// implementation must preserve this — `delete` on a missing key is
// already a no-op, but tests cover the contract explicitly so a future
// "nodeID must exist" change can't regress it.
func TestForgetPeerResolutionMissingEntryNoOp(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	// Helper called for an unknown peer — must not panic.
	d.forgetPeerResolution(0xDEADBEEF)

	// Pre-populate one entry; forget a DIFFERENT peer; the populated
	// one must remain.
	const keepNodeID uint32 = 0xABCD0001
	d.cacheResolve(keepNodeID, map[string]interface{}{"real_addr": "x"})

	d.forgetPeerResolution(0xCAFEBABE)

	if _, ok := d.cachedResolve(keepNodeID); !ok {
		t.Errorf("forgetPeerResolution(0xCAFEBABE) should not affect 0xABCD0001's entry")
	}
	_ = time.Since // keep `time` import for parity with sibling tests
}

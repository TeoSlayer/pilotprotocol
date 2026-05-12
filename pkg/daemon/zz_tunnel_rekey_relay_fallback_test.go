// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

// Regression tests for the rekey-relay-fallback path added to recover
// from a local daemon's external NAT mapping changing on restart.
//
// Failure mode (2026-05-11, observed on Mac after rc6 binary swap):
// the daemon restarts, its UDP socket on :4000 rebinds, the NAT
// reassigns a fresh external port, but ~400 peers have the old
// external endpoint cached. Outbound packets from us create fresh
// NAT mappings, but peer replies still land at the old port and are
// black-holed. The rekey loop fires 6 direct retransmits at 4s
// intervals (=24s budget) and gives up — the routing layer's
// blackhole heuristic (BlackholeMissesRequired=3 silent observations,
// each ≥8s) can't accumulate fast enough to flip the peer to relay
// before the rekey budget is exhausted.
//
// The fix: PreRetransmitHook fires once per peer per pending rekey
// retransmit. tunnel.go installs maybeForceRelayOnRekey, which flips
// the peer to relay once attempts reach RekeyRelayFallbackAfter
// (=2). The remaining attempts go via the relay path, which is
// independent of the broken direct NAT mapping.

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/keyexchange"
)

// TestRekeyRelayFallbackFlipsAtThreshold pins the cross-layer policy:
// once the upcoming attempt count reaches RekeyRelayFallbackAfter,
// the peer is moved to relay mode. Earlier attempts do not flip.
func TestRekeyRelayFallbackFlipsAtThreshold(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })

	const peerNodeID uint32 = 0xDEADBEEF

	// First attempt: must NOT flip — the cached endpoint deserves the
	// benefit of the doubt on a single send.
	tm.maybeForceRelayOnRekey(peerNodeID, 1)
	if tm.routing.IsRelayPeer(peerNodeID) {
		t.Fatalf("peer flipped to relay at attempt 1 (expected to wait for RekeyRelayFallbackAfter=%d)",
			keyexchange.RekeyRelayFallbackAfter)
	}

	// At the threshold: flip.
	tm.maybeForceRelayOnRekey(peerNodeID, keyexchange.RekeyRelayFallbackAfter)
	if !tm.routing.IsRelayPeer(peerNodeID) {
		t.Fatalf("peer did NOT flip to relay at attempt %d (RekeyRelayFallbackAfter)",
			keyexchange.RekeyRelayFallbackAfter)
	}

	// Subsequent calls past the threshold remain idempotent — no
	// thrashing, no panic, no event spam.
	tm.maybeForceRelayOnRekey(peerNodeID, keyexchange.RekeyRelayFallbackAfter+5)
	if !tm.routing.IsRelayPeer(peerNodeID) {
		t.Fatalf("peer dropped out of relay after second call past threshold")
	}
}

// TestRekeyRelayFallbackEndToEndFlipsViaTick proves the hook actually
// fires from the retransmit loop and flips a peer mid-cycle. This is
// the daemon-level smoking gun for the 2026-05-11 NAT-remap wedge:
// the rekey loop's own machinery — not just direct calls to the
// hook — engages the relay fallback when the cached endpoint goes
// silent.
//
// Sequence:
//  1. Inject a pendingRekey entry with attempts=RekeyRelayFallbackAfter-1
//     and LastSentAt stale enough to be eligible for retransmit.
//  2. Run rekeyRetransmitTick; the hook fires with attempt=RekeyRelayFallbackAfter
//     (the count we are ABOUT to perform) and flips the peer to relay.
//  3. Assert: peer is on relay, pendingRekey entry survived (attempts
//     bumped by the send path, but the entry is still pending — the
//     send-and-retx machinery has unbroken contract semantics).
func TestRekeyRelayFallbackEndToEndFlipsViaTick(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })

	const peerNodeID uint32 = 0xCAFEBABE

	// Pre-condition: peer is on direct path (not flipped yet).
	if tm.routing.IsRelayPeer(peerNodeID) {
		t.Fatalf("setup invariant: peer should not start on relay")
	}

	// Inject a pending rekey at attempts=N-1 with a stale LastSentAt,
	// so the next tick will retransmit at attempt N=RekeyRelayFallbackAfter.
	// LastSentAt must be older than RekeyRetransmitInterval for the
	// tick to pick it up.
	staleEnough := time.Now().Add(-2 * keyexchange.RekeyRetransmitInterval)
	tm.kx.InjectPendingRekeyForTest(peerNodeID, &pendingRekeyState{
		FirstSentAt: staleEnough,
		LastSentAt:  staleEnough,
		Attempts:    keyexchange.RekeyRelayFallbackAfter - 1,
	})

	tm.rekeyRetransmitTick()

	// Post-condition: the hook ran and flipped the peer to relay.
	if !tm.routing.IsRelayPeer(peerNodeID) {
		st := tm.kx.PendingRekeyForTest(peerNodeID)
		attempts := -1
		if st != nil {
			attempts = st.Attempts
		}
		t.Fatalf("NAT-remap regression: rekey tick did not flip peer to relay "+
			"(attempts=%d, RekeyRelayFallbackAfter=%d)",
			attempts, keyexchange.RekeyRelayFallbackAfter)
	}
}

// TestRekeyRelayFallbackBelowThresholdDoesNotFlip is the symmetric
// guard: the FIRST retransmit (attempts=1 going to attempt=1, i.e.
// the very first send was the initial, this is retx 1) must NOT
// trigger the relay flip — single packet loss on a healthy direct
// path is normal and shouldn't be conflated with a stale NAT mapping.
func TestRekeyRelayFallbackBelowThresholdDoesNotFlip(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })

	const peerNodeID uint32 = 0xFEEDFACE

	// Inject a fresh pending rekey (attempts=0) with a stale LastSentAt
	// so the next tick performs attempt=1.
	staleEnough := time.Now().Add(-2 * keyexchange.RekeyRetransmitInterval)
	tm.kx.InjectPendingRekeyForTest(peerNodeID, &pendingRekeyState{
		FirstSentAt: staleEnough,
		LastSentAt:  staleEnough,
		Attempts:    0,
	})

	tm.rekeyRetransmitTick()

	if tm.routing.IsRelayPeer(peerNodeID) {
		t.Fatalf("peer flipped to relay on the first retx (attempts=1 < RekeyRelayFallbackAfter=%d) — "+
			"too aggressive; would prematurely abandon working direct paths after one packet loss",
			keyexchange.RekeyRelayFallbackAfter)
	}
}

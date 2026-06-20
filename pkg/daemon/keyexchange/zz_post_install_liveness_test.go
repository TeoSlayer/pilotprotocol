// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange_test

// Regression for the stale-gate-never-clears bug observed on
// 2026-05-26: tunnel.onKeyInstalled performed peer-endpoint bookkeeping
// and salvage replay but did NOT call RecordInboundDecrypt, so the
// stale-recovery gate in HandleAuthFrame (InboundDecryptStale) stayed
// permanently armed for any peer whose AEAD data was still being
// blocked by the replay window during the rekey settle-in window.
// Combined with the 1s reply cooldown that fix landed earlier the
// daemon was no longer storming, but recovery still could not exit
// the stale-recovery branch until a successful AEAD decrypt — which
// in turn was blocked on the replay window the rekey was meant to
// reset.
//
// Tunnel's onKeyInstalled hook now invokes recordInboundDecrypt on
// every install. This test exercises the equivalent path at the
// keyexchange layer: register a postInstall hook that mirrors what
// tunnel.go does (call RecordInboundDecrypt), then verify that a
// fresh PILA install makes InboundDecryptStale return false.

import (
	"net"
	"testing"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

func TestPostInstallRecordsInboundLiveness(t *testing.T) {
	t.Parallel()

	a := newPeer(t, 500)
	b := newPeer(t, 501)
	crossWireVerifyFuncs(a, b)
	a.mgr.SetSender(func(uint32, *net.UDPAddr, []byte) error { return nil })

	// Mirror tunnel.onKeyInstalled: every install records inbound liveness.
	a.mgr.SetPostInstallHook(func(ev keyexchange.PostInstallEvent) {
		a.mgr.RecordInboundDecrypt(ev.PeerNodeID)
	})

	// Pre-install: stale gate is armed (no prior decrypt).
	if !a.mgr.InboundDecryptStale(b.id) {
		t.Fatalf("pre-install: InboundDecryptStale = false, want true")
	}

	bFrame := b.mgr.BuildAuthFrame()
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}
	if !a.mgr.HandleAuthFrame(bFrame[4:], from, false) {
		t.Fatalf("PILA install rejected")
	}

	// Post-install: a valid PILA install IS proof of inbound liveness
	// (Ed25519 signature verified). The stale gate must have cleared.
	if a.mgr.InboundDecryptStale(b.id) {
		t.Fatalf("post-install: InboundDecryptStale = true, want false — " +
			"asymmetric-recovery branch would keep re-firing until " +
			"a real AEAD decrypt clears the gate")
	}
	if !a.mgr.LastInboundDecryptHas(b.id) {
		t.Fatalf("post-install: LastInboundDecryptHas = false, want true")
	}
}

// TestPostInstallHookFiresOnInstallNotDuplicate guards the boundary:
// the duplicate-coalescing path at handle.go's `if duplicate { … }`
// does NOT invoke the postInstall hook, so RecordInboundDecrypt is
// only called on real installs — not every PILA receipt. That keeps
// the stale-gate semantically aligned with "successful install"
// rather than "received a frame," preserving the rate-limit fix
// against the symmetric ping-pong storm.
func TestPostInstallHookFiresOnInstallNotDuplicate(t *testing.T) {
	t.Parallel()

	a := newPeer(t, 510)
	b := newPeer(t, 511)
	crossWireVerifyFuncs(a, b)
	a.mgr.SetSender(func(uint32, *net.UDPAddr, []byte) error { return nil })

	var installs int
	a.mgr.SetPostInstallHook(func(ev keyexchange.PostInstallEvent) {
		installs++
	})

	bFrame := b.mgr.BuildAuthFrame()
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}

	// First arrival: install fires hook.
	if !a.mgr.HandleAuthFrame(bFrame[4:], from, false) {
		t.Fatalf("first PILA rejected")
	}
	if installs != 1 {
		t.Fatalf("first install: hook fired %d times, want 1", installs)
	}

	// Same-key arrival inside DuplicateHandshakeDebounce → coalesced.
	if !a.mgr.HandleAuthFrame(bFrame[4:], from, true /*fromRelay*/) {
		t.Fatalf("duplicate PILA rejected")
	}
	if installs != 1 {
		t.Fatalf("duplicate (coalesced): hook fired %d times, want 1 "+
			"(duplicate gate must suppress hook so daemon does not "+
			"re-record liveness on every retransmit)", installs)
	}
}

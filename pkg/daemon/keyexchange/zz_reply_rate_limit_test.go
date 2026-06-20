// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange_test

// Regression for the symmetric key-exchange ping-pong observed against
// nasa-apod and several other specialists on 2026-05-26: a fresh daemon
// restart leaves both sides without recent inbound decrypts, every
// incoming PILA hits HandleAuthFrame's "InboundDecryptStale" branch,
// each side replies with a PILA, and the loop runs at the relay's send
// cadence (~80–150 ms) — 466 "encrypted tunnel established" events for
// a single peer in 90 seconds, choking the data plane.
//
// MarkReplyKeyExchangeSent caps the asymmetric-recovery reply at one
// per KeyExchangeReplyMinInterval per peer. The existing tests in
// zz_asymmetric_recovery_test.go pin that the FIRST reply still goes
// out (the bug it was added for) and that an active session does NOT
// reply (lastInboundDecrypt fresh). The cases below cover the burst
// behaviour the rate-limit was added for.

import (
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

// TestReplyRateLimitBurstSuppressed feeds A a burst of duplicate PILAs
// past the DuplicateHandshakeDebounce window. With stale inbound decrypt
// (no AEAD traffic yet), A would previously reply on every PILA. The
// fix caps the reply count at exactly one per KeyExchangeReplyMinInterval.
func TestReplyRateLimitBurstSuppressed(t *testing.T) {
	t.Parallel()

	a := newPeer(t, 300)
	b := newPeer(t, 301)
	crossWireVerifyFuncs(a, b)

	aSender := &frameRecorder{}
	a.mgr.SetSender(aSender.record)
	b.mgr.SetSender(func(uint32, *net.UDPAddr, []byte) error { return nil })

	bFrame := b.mgr.BuildAuthFrame()
	if bFrame == nil {
		t.Fatalf("BuildAuthFrame returned nil")
	}
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}

	// Initial PILA: A installs B's crypto and replies. Count the reply.
	if !a.mgr.HandleAuthFrame(bFrame[4:], from, false) {
		t.Fatalf("initial PILA rejected")
	}
	initial := aSender.authFrameCount()
	if initial == 0 {
		t.Fatalf("initial PILA produced no reply — install path broken")
	}

	// Wait past DuplicateHandshakeDebounce so subsequent same-key
	// PILAs are NOT coalesced and reach the asymmetric-recovery branch.
	time.Sleep(keyexchange.DuplicateHandshakeDebounce + 50*time.Millisecond)

	// Burst: 10 duplicate PILAs over ~500 ms, well inside the
	// 1 s reply cooldown. Without the gate this produced 10 replies
	// (the symmetric ping-pong). With the gate the cooldown caps the
	// burst at exactly 1 reply (one stale-recovery PILA admitted, the
	// remaining 9 suppressed) — enough to keep the deadlock-recovery
	// path working while breaking the runaway loop.
	for i := 0; i < 10; i++ {
		if !a.mgr.HandleAuthFrame(bFrame[4:], from, false) {
			t.Fatalf("burst PILA #%d rejected", i)
		}
		time.Sleep(50 * time.Millisecond)
	}

	burst := aSender.authFrameCount() - initial
	if burst > 1 {
		t.Fatalf("burst of 10 duplicate PILAs produced %d replies — "+
			"want ≤ 1 (cooldown should suppress 9+), KeyExchangeReplyMinInterval=%v",
			burst, keyexchange.KeyExchangeReplyMinInterval)
	}
}

// TestReplyRateLimitAllowsAfterCooldown pins the upper boundary: once
// KeyExchangeReplyMinInterval elapses, the next stale-recovery PILA
// IS allowed to reply. This guarantees a genuinely lost reply still
// eventually recovers — the rate-limit slows the loop, doesn't kill
// the recovery path.
func TestReplyRateLimitAllowsAfterCooldown(t *testing.T) {
	t.Parallel()

	a := newPeer(t, 310)
	b := newPeer(t, 311)
	crossWireVerifyFuncs(a, b)

	aSender := &frameRecorder{}
	a.mgr.SetSender(aSender.record)
	b.mgr.SetSender(func(uint32, *net.UDPAddr, []byte) error { return nil })

	bFrame := b.mgr.BuildAuthFrame()
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}

	// Initial PILA (install path) fires the cooldown.
	if !a.mgr.HandleAuthFrame(bFrame[4:], from, false) {
		t.Fatalf("initial PILA rejected")
	}
	initial := aSender.authFrameCount()

	// Sleep through the duplicate debounce AND the reply cooldown so
	// the next stale-recovery PILA can fire again.
	time.Sleep(keyexchange.KeyExchangeReplyMinInterval + 100*time.Millisecond)

	if !a.mgr.HandleAuthFrame(bFrame[4:], from, false) {
		t.Fatalf("post-cooldown PILA rejected")
	}
	delta := aSender.authFrameCount() - initial
	if delta != 1 {
		t.Fatalf("post-cooldown reply count = %d, want exactly 1 (recovery "+
			"path must remain functional)", delta)
	}
}

// TestMarkReplyKeyExchangeSentAtomicGate exercises the API directly:
// first call returns true and records, subsequent calls within the
// interval return false, a call past the interval returns true again.
func TestMarkReplyKeyExchangeSentAtomicGate(t *testing.T) {
	t.Parallel()

	m := keyexchange.New(nil)
	const peer = uint32(42)

	if !m.MarkReplyKeyExchangeSent(peer) {
		t.Fatal("first call: want true (no prior reply)")
	}
	if m.MarkReplyKeyExchangeSent(peer) {
		t.Fatal("second call inside cooldown: want false")
	}
	if m.MarkReplyKeyExchangeSent(peer) {
		t.Fatal("third call inside cooldown: want false")
	}

	time.Sleep(keyexchange.KeyExchangeReplyMinInterval + 50*time.Millisecond)

	if !m.MarkReplyKeyExchangeSent(peer) {
		t.Fatal("call past cooldown: want true (gate lifted)")
	}
}

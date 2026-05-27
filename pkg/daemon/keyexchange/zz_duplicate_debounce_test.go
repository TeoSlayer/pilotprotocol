// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange_test

// Regression tests for the duplicate-PILA storm coalescing
// (DuplicateHandshakeDebounce). The user-visible symptom on
// 2026-05-19 was "encrypted tunnel established" firing 4-5× within
// milliseconds for the same peer, because the direct + relay copies
// of a single PILA both landed and each fired the full side-effect
// path (log, bus event, postInstall hook). The fix coalesces same-
// pubkey frames within a short debounce window without breaking the
// asymmetric-recovery reply path
// (see zz_asymmetric_recovery_test.go).

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/keyexchange"
)

// TestDuplicatePILACoalescedSuppressesLogAndHook verifies that a
// same-pubkey PILA arriving inside DuplicateHandshakeDebounce of the
// first install fires postInstall ONCE, not twice. The log + bus
// event suppression is verified indirectly via the hook count, which
// covers the same `duplicate` gate in handle.go.
func TestDuplicatePILACoalescedSuppressesLogAndHook(t *testing.T) {
	t.Parallel()

	a := newPeer(t, 100)
	b := newPeer(t, 200)
	crossWireVerifyFuncs(a, b)
	a.mgr.SetSender(func(uint32, *net.UDPAddr, []byte) error { return nil })

	var hookCount atomic.Int32
	a.mgr.SetPostInstallHook(func(keyexchange.PostInstallEvent) {
		hookCount.Add(1)
	})

	bFrame := b.mgr.BuildAuthFrame()
	if bFrame == nil {
		t.Fatalf("BuildAuthFrame returned nil")
	}
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}

	// First arrival: full side-effect path (hook count = 1).
	if !a.mgr.HandleAuthFrame(bFrame[4:], from, false) {
		t.Fatalf("first PILA rejected")
	}
	if got := hookCount.Load(); got != 1 {
		t.Fatalf("after first PILA: hook count = %d, want 1", got)
	}

	// Duplicate (same X25519 pubkey) arriving immediately — relay
	// copy of the same frame. Must be coalesced: no second hook fire.
	if !a.mgr.HandleAuthFrame(bFrame[4:], from, true /*fromRelay*/) {
		t.Fatalf("duplicate PILA (relay copy) rejected")
	}
	if got := hookCount.Load(); got != 1 {
		t.Fatalf("after duplicate PILA: hook count = %d, want 1 (coalesced)", got)
	}

	// Third arrival, still inside the debounce — also coalesced.
	if !a.mgr.HandleAuthFrame(bFrame[4:], from, false) {
		t.Fatalf("second duplicate PILA rejected")
	}
	if got := hookCount.Load(); got != 1 {
		t.Fatalf("after second duplicate: hook count = %d, want 1", got)
	}
}

// TestDuplicatePILAOutsideDebounceFiresHookAgain pins the upper
// boundary: once the debounce window expires, a same-pubkey frame is
// no longer treated as a duplicate (peer's retransmit cadence is in
// seconds; we want the keep-alive observation, the postInstall hook
// for endpoint-refresh, etc. to fire again). 250ms is short enough
// to keep this fast.
func TestDuplicatePILAOutsideDebounceFiresHookAgain(t *testing.T) {
	t.Parallel()

	a := newPeer(t, 101)
	b := newPeer(t, 201)
	crossWireVerifyFuncs(a, b)
	a.mgr.SetSender(func(uint32, *net.UDPAddr, []byte) error { return nil })

	var hookCount atomic.Int32
	a.mgr.SetPostInstallHook(func(keyexchange.PostInstallEvent) {
		hookCount.Add(1)
	})

	bFrame := b.mgr.BuildAuthFrame()
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}

	if !a.mgr.HandleAuthFrame(bFrame[4:], from, false) {
		t.Fatalf("first PILA rejected")
	}

	// Sleep past the debounce window. 350ms gives 100ms slack.
	time.Sleep(keyexchange.DuplicateHandshakeDebounce + 100*time.Millisecond)

	if !a.mgr.HandleAuthFrame(bFrame[4:], from, false) {
		t.Fatalf("post-debounce PILA rejected")
	}
	if got := hookCount.Load(); got != 2 {
		t.Fatalf("post-debounce: hook count = %d, want 2 (no longer coalesced)", got)
	}
}

// TestDuplicatePILAStillRepliesForAsymmetricRecovery is the cross-
// check with the rc3 asymmetric-recovery bug: even when the duplicate
// gate suppresses log/hook/bus, the SendKeyExchangeToNode-on-stale
// path MUST still fire. A retains crypto for B; B dropped crypto for
// A; B's retransmitted PILA arrives inside the debounce window. A
// must still emit its PILA so B can re-derive.
func TestDuplicatePILAStillRepliesForAsymmetricRecovery(t *testing.T) {
	t.Parallel()

	a := newPeer(t, 102)
	b := newPeer(t, 202)
	crossWireVerifyFuncs(a, b)
	aSender := &frameRecorder{}
	a.mgr.SetSender(aSender.record)
	b.mgr.SetSender(func(uint32, *net.UDPAddr, []byte) error { return nil })

	bFrame := b.mgr.BuildAuthFrame()
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}

	// First arrival — A installs B's crypto and emits its reply.
	if !a.mgr.HandleAuthFrame(bFrame[4:], from, false) {
		t.Fatalf("first PILA rejected")
	}

	// Reset the recorder — we only want to count what A emits on the
	// duplicate.
	aSender.mu.Lock()
	aSender.frames = nil
	aSender.mu.Unlock()

	// B drops crypto for A (DecryptFailDropGrace effect).
	b.mgr.Store().Drop(a.id)

	// B retransmits its PILA. A still has crypto for B with CreatedAt
	// inside the debounce window — A sees this as a duplicate and
	// MUST also emit its PILA because InboundDecryptStale(B) is true
	// (no encrypted data ever flowed from B to A in this test).
	bFrame2 := b.mgr.BuildAuthFrame()
	if !a.mgr.HandleAuthFrame(bFrame2[4:], from, false) {
		t.Fatalf("duplicate PILA rejected")
	}
	if got := aSender.authFrameCount(); got == 0 {
		t.Fatalf("duplicate coalesce ate the asymmetric-recovery reply — got %d, want >= 1", got)
	}
}

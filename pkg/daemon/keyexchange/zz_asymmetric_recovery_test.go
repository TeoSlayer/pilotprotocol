// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange_test

// Regression tests for the asymmetric-crypto-recovery bug observed in
// v1.10.0-rc3 against the live list-agents agent on 2026-05-11:
//
// When a peer drops its envelope.Crypto entry for us (e.g. via the
// DecryptFailDropGrace path after a relay-buffered stale-frame burst)
// but keeps the same X25519 ephemeral, every subsequent PILA it
// retransmits arrives at us with keyChanged=false. handle.go's else
// branch then clears pendingRekey and does nothing — we never send our
// PILA back, so the peer can never derive the shared secret again. The
// tunnel is dead half-symmetrically forever.
//
// The constant KeyExchangeReplyStaleThreshold (6s) + the doc comment on
// it describe the intended fix: in the duplicate-PILA branch, reply with
// our PILA when we have no recent inbound decrypt from the peer.

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// frameRecorder captures frames sent via Manager.SetSender so tests can
// assert what was sent (or not sent).
type frameRecorder struct {
	mu     sync.Mutex
	frames [][]byte
}

func (r *frameRecorder) record(_ uint32, _ *net.UDPAddr, frame []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]byte, len(frame))
	copy(cp, frame)
	r.frames = append(r.frames, cp)
	return nil
}

func (r *frameRecorder) authFrameCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, f := range r.frames {
		if len(f) >= 4 && bytes.Equal(f[0:4], protocol.TunnelMagicAuthEx[:]) {
			n++
		}
	}
	return n
}

// TestAsymmetricRecoveryRepliesOnDuplicatePILAWhenStale reproduces the
// rc3 bug: B drops crypto for A while A retains it; B's retransmitted
// PILA must elicit a PILA reply from A so B can re-derive the shared
// secret. A has never recorded an inbound decrypt from B (we skip data
// exchange), so InboundDecryptStale(B) is trivially true.
//
// Pre-fix: this test fails — A handles the duplicate but emits no PILA.
// Post-fix: A emits exactly one PILA via the staleness-gated reply path.
func TestAsymmetricRecoveryRepliesOnDuplicatePILAWhenStale(t *testing.T) {
	t.Parallel()

	a := newPeer(t, 100)
	b := newPeer(t, 200)
	crossWireVerifyFuncs(a, b)

	aSender := &frameRecorder{}
	a.mgr.SetSender(aSender.record)
	b.mgr.SetSender(func(uint32, *net.UDPAddr, []byte) error { return nil })

	// Step 1: B sends its PILA to A (one-way bootstrap). A installs B's
	// crypto and would reply with its own PILA, captured by aSender.
	bFrame := b.mgr.BuildAuthFrame()
	if bFrame == nil {
		t.Fatalf("B.BuildAuthFrame returned nil")
	}
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}
	if !a.mgr.HandleAuthFrame(bFrame[4:], from, false) {
		t.Fatalf("initial PILA from B rejected by A")
	}
	if !a.mgr.Store().Has(b.id) {
		t.Fatalf("A has no Crypto for B after initial PILA")
	}

	// Reset the recorder: we only care about what A sends in response to
	// the *retransmitted* duplicate PILA, not the initial install reply.
	aSender.mu.Lock()
	aSender.frames = nil
	aSender.mu.Unlock()

	// Step 2: simulate B dropping its envelope.Crypto for A (the
	// DecryptFailDropGrace effect after a stale-frame burst). B's
	// X25519 ephemeral is unchanged — same daemon process.
	b.mgr.Store().Drop(a.id)

	// Step 3: B's retransmit loop ships another PILA to A. Same X25519,
	// same signature challenge body. A sees this as a "duplicate" PILA.
	bFrame2 := b.mgr.BuildAuthFrame()
	if !a.mgr.HandleAuthFrame(bFrame2[4:], from, false) {
		t.Fatalf("retransmitted PILA from B rejected by A")
	}

	// A's lastInboundDecrypt[B] is empty (no encrypted data exchanged
	// yet), so InboundDecryptStale(B) is true. The fix should make A
	// reply with its PILA so B can install fresh crypto.
	if got := aSender.authFrameCount(); got == 0 {
		t.Fatalf("BUG-1: A did not reply with PILA on duplicate from B "+
			"with stale inbound decrypt — got %d auth frames", got)
	}
}

// TestAsymmetricRecoveryRateLimitsRepliesWhenHealthy guards the
// rate-limit half of the fix: if A has a recent successful decrypt
// from B (representing a healthy active session), a duplicate PILA
// from B should NOT trigger a PILA reply — otherwise any rc2-style
// rapid-retransmit peer would force us into an unbounded reply loop.
//
// We seed A's lastInboundDecrypt[B] with a fresh timestamp, then feed
// a duplicate PILA. A must remain silent.
func TestAsymmetricRecoveryRateLimitsRepliesWhenHealthy(t *testing.T) {
	t.Parallel()

	a := newPeer(t, 100)
	b := newPeer(t, 200)
	crossWireVerifyFuncs(a, b)

	aSender := &frameRecorder{}
	a.mgr.SetSender(aSender.record)
	b.mgr.SetSender(func(uint32, *net.UDPAddr, []byte) error { return nil })

	// Bootstrap mutual crypto via initial PILA.
	bFrame := b.mgr.BuildAuthFrame()
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}
	if !a.mgr.HandleAuthFrame(bFrame[4:], from, false) {
		t.Fatalf("initial PILA from B rejected by A")
	}

	// Simulate active session: A has had a recent successful decrypt
	// from B (within the staleness threshold).
	a.mgr.SetLastInboundDecryptForTest(b.id, time.Now())

	// Clear recorder so we only see post-bootstrap activity.
	aSender.mu.Lock()
	aSender.frames = nil
	aSender.mu.Unlock()

	// Duplicate PILA arrives.
	bFrame2 := b.mgr.BuildAuthFrame()
	if !a.mgr.HandleAuthFrame(bFrame2[4:], from, false) {
		t.Fatalf("duplicate PILA rejected")
	}

	// A must NOT reply (rate-limited by staleness threshold).
	if got := aSender.authFrameCount(); got != 0 {
		t.Fatalf("rate limit broken: A replied %d times on duplicate "+
			"with fresh inbound decrypt — must be 0", got)
	}
}

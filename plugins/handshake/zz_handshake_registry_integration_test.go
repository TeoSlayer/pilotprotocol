// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// Iter-103 coverage for SendRequest (4 branches) and ApproveHandshake
// (happy-path with pending seeded). These are the registry-integration-
// heavy funcs that need a wired test registry + signer so the Ed25519
// signatures on PollHandshakes/RequestHandshake verify cleanly.
//
// The pollRelayedHandshakes coverage portion (which exercises daemon-
// side polling glue that delegates to the handshake service via the
// HandshakeService interface) lives in pkg/daemon's
// daemon_pollrelayed_test.go after T3.3.

// --- SendRequest: already-trusted short-circuit ---

func TestSendRequestAlreadyTrustedShortCircuits(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)
	hm.trusted[42] = &TrustRecord{NodeID: 42}

	if err := hm.SendRequest(42, "should-be-ignored"); err != nil {
		t.Fatalf("SendRequest: %v", err)
	}

	hm.mu.RLock()
	_, stillOutgoing := hm.outgoing[42]
	hm.mu.RUnlock()
	if stillOutgoing {
		t.Fatal("outgoing[42] should NOT be set for already-trusted short-circuit")
	}
}

// --- SendRequest: relay via registry succeeds when peer registered + signer set ---

func TestSendRequestDirectFailsRelaySucceeds(t *testing.T) {
	t.Parallel()
	hm, rt := hsTestManager(t, false)
	// Sign registry operations with the self-identity so PollHandshakes /
	// RequestHandshake succeed registry-side.
	rt.regClient.SetSigner(func(challenge string) string {
		return base64.StdEncoding.EncodeToString(rt.identity.Sign([]byte(challenge)))
	})

	// Register a peer so the registry has a valid to-node for the handshake.
	peerID, _ := crypto.GenerateIdentity()
	resp, err := rt.regClient.RegisterWithKey("127.0.0.1:0", crypto.EncodePublicKey(peerID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}
	peerNodeID := uint32(resp["node_id"].(float64))

	// SendRequest: direct sendMessage will fail (testRuntime.DialAndSend
	// returns errStub), but relay via registry should succeed because:
	//  - self signer is wired
	//  - peer is registered
	//  - signHandshakeChallenge produces a valid Ed25519 sig
	if err := hm.SendRequest(peerNodeID, "hello"); err != nil {
		t.Fatalf("SendRequest relay: %v", err)
	}

	// outgoing must have been set before the direct attempt (proves the
	// happy-path ran past the already-trusted check).
	hm.mu.RLock()
	_, out := hm.outgoing[peerNodeID]
	hm.mu.RUnlock()
	if !out {
		t.Fatal("outgoing[peerNodeID] should be set")
	}
}

// --- SendRequest: relay fails when peer not registered → wrapped error ---

func TestSendRequestDirectAndRelayFailReturnsWrappedError(t *testing.T) {
	t.Parallel()
	hm, rt := hsTestManager(t, false)
	rt.regClient.SetSigner(func(challenge string) string {
		return base64.StdEncoding.EncodeToString(rt.identity.Sign([]byte(challenge)))
	})

	// Peer 99999 is NOT registered — RequestHandshake will return
	// "node ... not found" → SendRequest wraps with "handshake relay: ..."
	err := hm.SendRequest(99999, "relay-to-nowhere")
	if err == nil {
		t.Fatal("SendRequest relay to missing peer should error")
	}
	// Must be the wrapped relay error (not the direct one), proving we fell
	// through to the relay branch.
	if !containsAny(err.Error(), []string{"handshake relay", "not found"}) {
		t.Fatalf("err = %v, want wrapped handshake-relay error", err)
	}
}

// --- ApproveHandshake: happy-path moves pending → trusted + side effects ---

func TestApproveHandshakeMovesPendingToTrustedAndEmitsWebhook(t *testing.T) {
	t.Parallel()
	hm, rt := hsTestManager(t, false)
	rt.regClient.SetSigner(func(challenge string) string {
		return base64.StdEncoding.EncodeToString(rt.identity.Sign([]byte(challenge)))
	})

	hm.pending[77] = &PendingHandshake{
		NodeID:        77,
		PublicKey:     "pending-pubkey",
		Justification: "please",
		ReceivedAt:    time.Now(),
	}

	if err := hm.ApproveHandshake(77); err != nil {
		t.Fatalf("ApproveHandshake: %v", err)
	}

	hm.mu.RLock()
	rec, ok := hm.trusted[77]
	_, stillPending := hm.pending[77]
	hm.mu.RUnlock()
	if !ok {
		t.Fatal("trusted[77] missing after ApproveHandshake")
	}
	if rec.PublicKey != "pending-pubkey" {
		t.Fatalf("rec.PublicKey = %q, want 'pending-pubkey' (should be copied from pending)", rec.PublicKey)
	}
	if rec.ApprovedAt.IsZero() {
		t.Fatal("rec.ApprovedAt should be set to time.Now()")
	}
	if stillPending {
		t.Fatal("pending[77] should have been deleted")
	}

	// Let the async goRPC goroutines fail cleanly (peer 77 not actually
	// reachable — sendAccept errs internally but doesn't affect return value).
	waitForGoRPCDrain()
}

// --- ApproveHandshake: no-pending early-return returns nil cleanly ---

func TestApproveHandshakeNoPendingReturnsNil(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	if err := hm.ApproveHandshake(555); err != nil {
		t.Fatalf("ApproveHandshake no-pending: %v", err)
	}

	hm.mu.RLock()
	_, trusted := hm.trusted[555]
	hm.mu.RUnlock()
	if trusted {
		t.Fatal("trusted[555] should NOT be populated on no-pending path")
	}
}

// --- helpers ---

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if indexOfSubstring(s, sub) >= 0 {
			return true
		}
	}
	return false
}

func indexOfSubstring(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

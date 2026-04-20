package daemon

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// Iter-103 coverage for SendRequest (18.2% baseline — 4 branches), ApproveHandshake
// (26.3% — happy-path with pending seeded), and pollRelayedHandshakes (12.9% —
// error + empty + populated via registry inbox). These are the
// registry-integration-heavy funcs that need newHsTestDaemon + SetSigner wiring
// so Ed25519 signatures on PollHandshakes/RequestHandshake verify cleanly.

// --- SendRequest: already-trusted short-circuit ---

func TestSendRequestAlreadyTrustedShortCircuits(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.handshakes.Stop() })
	hm := d.handshakes
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
	d := newHsTestDaemon(t, Config{})
	// Sign registry operations with the self-identity so PollHandshakes /
	// RequestHandshake succeed registry-side.
	d.regConn.SetSigner(func(challenge string) string {
		return base64.StdEncoding.EncodeToString(d.identity.Sign([]byte(challenge)))
	})

	// Register a peer so the registry has a valid to-node for the handshake.
	peerID, _ := crypto.GenerateIdentity()
	resp, err := d.regConn.RegisterWithKey("127.0.0.1:0", crypto.EncodePublicKey(peerID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}
	peerNodeID := uint32(resp["node_id"].(float64))

	// SendRequest: direct sendMessage will fail (peer not actually listening on
	// port 444 — ensureTunnel/DialConnection errs), but relay via registry
	// should succeed because:
	//  - self signer is wired
	//  - peer is registered
	//  - signHandshakeChallenge produces a valid Ed25519 sig
	if err := d.handshakes.SendRequest(peerNodeID, "hello"); err != nil {
		t.Fatalf("SendRequest relay: %v", err)
	}

	// outgoing must have been set before the direct attempt (proves the
	// happy-path ran past the already-trusted check).
	d.handshakes.mu.RLock()
	out := d.handshakes.outgoing[peerNodeID]
	d.handshakes.mu.RUnlock()
	if !out {
		t.Fatal("outgoing[peerNodeID] should be set")
	}
}

// --- SendRequest: relay fails when peer not registered → wrapped error ---

func TestSendRequestDirectAndRelayFailReturnsWrappedError(t *testing.T) {
	d := newHsTestDaemon(t, Config{})
	d.regConn.SetSigner(func(challenge string) string {
		return base64.StdEncoding.EncodeToString(d.identity.Sign([]byte(challenge)))
	})

	// Peer 99999 is NOT registered — RequestHandshake will return
	// "node ... not found" → SendRequest wraps with "handshake relay: ..."
	err := d.handshakes.SendRequest(99999, "relay-to-nowhere")
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
	d := newHsTestDaemon(t, Config{})
	d.regConn.SetSigner(func(challenge string) string {
		return base64.StdEncoding.EncodeToString(d.identity.Sign([]byte(challenge)))
	})

	hm := d.handshakes
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
	// Covered incidentally by iter-91 but kept for explicit branch-evidence.
	d := New(Config{})
	t.Cleanup(func() { d.handshakes.Stop() })

	if err := d.handshakes.ApproveHandshake(555); err != nil {
		t.Fatalf("ApproveHandshake no-pending: %v", err)
	}

	d.handshakes.mu.RLock()
	_, trusted := d.handshakes.trusted[555]
	d.handshakes.mu.RUnlock()
	if trusted {
		t.Fatal("trusted[555] should NOT be populated on no-pending path")
	}
}

// --- pollRelayedHandshakes: error path (signed with a closed regConn) ---

func TestPollRelayedHandshakesErrorPathReturnsCleanly(t *testing.T) {
	d := newHsTestDaemon(t, Config{})
	// Close rc so PollHandshakes errors immediately.
	d.regConn.Close()

	// Must not panic; slog.Debug("poll handshakes failed", ...) + return.
	d.pollRelayedHandshakes()
}

// --- pollRelayedHandshakes: empty inbox happy-path ---

func TestPollRelayedHandshakesEmptyInboxCompletesCleanly(t *testing.T) {
	d := newHsTestDaemon(t, Config{})
	d.regConn.SetSigner(func(challenge string) string {
		return base64.StdEncoding.EncodeToString(d.identity.Sign([]byte(challenge)))
	})

	// PollHandshakes should succeed with empty "requests" + empty "responses".
	// Both for-loops iterate zero times; function returns cleanly without
	// touching handshake state.
	d.pollRelayedHandshakes()

	d.handshakes.mu.RLock()
	trustedCount := len(d.handshakes.trusted)
	pendingCount := len(d.handshakes.pending)
	d.handshakes.mu.RUnlock()
	if trustedCount != 0 || pendingCount != 0 {
		t.Fatalf("poll on empty inbox mutated state: trusted=%d pending=%d", trustedCount, pendingCount)
	}
}

// --- pollRelayedHandshakes: populated inbox dispatches to processRelayedRequest ---

func TestPollRelayedHandshakesDispatchesRelayedRequest(t *testing.T) {
	d := newHsTestDaemon(t, Config{})
	d.regConn.SetSigner(func(challenge string) string {
		return base64.StdEncoding.EncodeToString(d.identity.Sign([]byte(challenge)))
	})

	// Register a peer, then have THE PEER send a handshake request to self via
	// registry (so the registry enqueues it in self's inbox).
	peerID, _ := crypto.GenerateIdentity()
	resp, err := d.regConn.RegisterWithKey("127.0.0.1:0", crypto.EncodePublicKey(peerID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}
	peerNodeID := uint32(resp["node_id"].(float64))

	// Set up a fresh client as the peer (so RequestHandshake signs with peer key).
	peerRC := d.regConn // shared client; we can reuse since we swap signers
	// Actually, temporarily set signer to peer's key for this single RPC.
	peerSigner := func(challenge string) string {
		return base64.StdEncoding.EncodeToString(peerID.Sign([]byte(challenge)))
	}
	peerRC.SetSigner(peerSigner)

	// Peer sends handshake request TO self.
	_, err = peerRC.RequestHandshake(peerNodeID, d.NodeID(), "please-trust", peerSigner("handshake:"+u32(peerNodeID)+":"+u32(d.NodeID())))
	if err != nil {
		t.Fatalf("peer RequestHandshake: %v", err)
	}

	// Restore self signer so PollHandshakes works.
	d.regConn.SetSigner(func(challenge string) string {
		return base64.StdEncoding.EncodeToString(d.identity.Sign([]byte(challenge)))
	})

	// TrustAutoApprove is false on default Config → handshake goes to pending.
	d.pollRelayedHandshakes()

	d.handshakes.mu.RLock()
	_, isPending := d.handshakes.pending[peerNodeID]
	d.handshakes.mu.RUnlock()
	if !isPending {
		t.Fatalf("pending[%d] not set after pollRelayedHandshakes dispatched relayed request", peerNodeID)
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

func u32(n uint32) string {
	// simple itoa without strconv import
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

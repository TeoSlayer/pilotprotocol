// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/trustedagents"
)

// These tests cover the trusted-agents auto-accept branch in
// handleRequest. The branch must fire ONLY when both:
//   1. The peer's node_id appears in the trusted-agents list, AND
//   2. processMessage upstream confirmed the (node_id, public_key)
//      binding via a registry lookup (registryBound == true).
//
// Failure modes we explicitly defend against:
//   - missing pubkey on the wire (registryBound stays false)
//   - registry unreachable / no record (registryBound stays false)
//   - peer is not in the list (no auto-accept regardless of binding)
//   - empty list (no auto-accept under any condition)

const trustedNodeID uint32 = 14161
const untrustedNodeID uint32 = 99999

// --- 1. Happy path: trusted + registryBound -> auto-accepted ---

func TestHandleRequestTrustedAgentBoundAutoAccepts(t *testing.T) {
	defer trustedagents.SetForTest([]trustedagents.Agent{
		{Name: "list-agents", NodeID: trustedNodeID},
	})()

	d := newHsTestDaemon(t, Config{})
	hm := d.handshakes
	defer waitForGoRPCDrain()

	msg := &HandshakeMsg{
		Type:      HandshakeRequest,
		NodeID:    trustedNodeID,
		PublicKey: "list-agents-pubkey",
		Timestamp: time.Now().Unix(),
	}
	hm.handleRequest(nil, msg, true) // registryBound = true

	hm.mu.RLock()
	rec, trusted := hm.trusted[trustedNodeID]
	_, pending := hm.pending[trustedNodeID]
	hm.mu.RUnlock()

	if !trusted {
		t.Fatal("trusted-agents auto-accept failed: peer not in trust map")
	}
	if pending {
		t.Fatal("trusted peer must not be queued in pending")
	}
	if rec.PublicKey != "list-agents-pubkey" {
		t.Fatalf("PublicKey not stored: got %q", rec.PublicKey)
	}
	if rec.Mutual {
		t.Fatal("trusted-agents path is not mutual")
	}
}

// --- 2. Defense: trusted but binding NOT confirmed -> fall through ---

// This is the critical failure-mode test. Without this defense, an
// attacker could claim node 14161 with their own pubkey, sign a
// handshake with their own privkey, pass signature verification
// (because verification is against the *claimed* pubkey when the
// registry can't confirm the binding), and slip into auto-accept.
func TestHandleRequestTrustedAgentNotBoundFallsThrough(t *testing.T) {
	defer trustedagents.SetForTest([]trustedagents.Agent{
		{Name: "list-agents", NodeID: trustedNodeID},
	})()

	d := New(Config{}) // TrustAutoApprove off
	t.Cleanup(func() { d.handshakes.Stop() })
	hm := d.handshakes

	msg := &HandshakeMsg{
		Type:      HandshakeRequest,
		NodeID:    trustedNodeID,
		PublicKey: "ATTACKER-PUBKEY",
		Timestamp: time.Now().Unix(),
	}
	hm.handleRequest(nil, msg, false) // registryBound = false

	hm.mu.RLock()
	_, trusted := hm.trusted[trustedNodeID]
	_, pending := hm.pending[trustedNodeID]
	hm.mu.RUnlock()

	if trusted {
		t.Fatal("SECURITY: peer auto-accepted without registry binding confirmation")
	}
	if !pending {
		t.Fatal("peer should be queued for manual approval when binding not confirmed")
	}
}

// --- 3. Untrusted node + registryBound -> fall through ---

func TestHandleRequestUntrustedAgentBoundFallsThrough(t *testing.T) {
	defer trustedagents.SetForTest([]trustedagents.Agent{
		{Name: "list-agents", NodeID: trustedNodeID},
	})()

	d := newHsTestDaemon(t, Config{})
	hm := d.handshakes
	defer waitForGoRPCDrain()

	msg := &HandshakeMsg{
		Type:      HandshakeRequest,
		NodeID:    untrustedNodeID, // not on the list
		PublicKey: "some-pubkey",
		Timestamp: time.Now().Unix(),
	}
	hm.handleRequest(nil, msg, true)

	hm.mu.RLock()
	_, trusted := hm.trusted[untrustedNodeID]
	_, pending := hm.pending[untrustedNodeID]
	hm.mu.RUnlock()

	if trusted {
		t.Fatal("non-listed node was auto-accepted")
	}
	if !pending {
		t.Fatal("non-listed node should be queued for manual approval")
	}
}

// --- 4. Empty trusted list -> never auto-accept ---

func TestHandleRequestEmptyListNeverAutoAccepts(t *testing.T) {
	defer trustedagents.SetForTest([]trustedagents.Agent{})()

	d := newHsTestDaemon(t, Config{})
	hm := d.handshakes
	defer waitForGoRPCDrain()

	msg := &HandshakeMsg{
		Type:      HandshakeRequest,
		NodeID:    trustedNodeID,
		PublicKey: "some-pubkey",
		Timestamp: time.Now().Unix(),
	}
	hm.handleRequest(nil, msg, true)

	hm.mu.RLock()
	_, trusted := hm.trusted[trustedNodeID]
	_, pending := hm.pending[trustedNodeID]
	hm.mu.RUnlock()

	if trusted {
		t.Fatal("empty list must not auto-accept anyone")
	}
	if !pending {
		t.Fatal("peer should be queued for manual approval when list is empty")
	}
}

// --- 5. Already-trusted peer hits the earlier branch, no rewrite ---

func TestHandleRequestTrustedAgentAlreadyTrustedNoRewrite(t *testing.T) {
	defer trustedagents.SetForTest([]trustedagents.Agent{
		{Name: "list-agents", NodeID: trustedNodeID},
	})()

	d := newHsTestDaemon(t, Config{})
	hm := d.handshakes
	defer waitForGoRPCDrain()

	originalKey := "original-pubkey"
	originalAt := time.Now().Add(-1 * time.Hour)
	hm.trusted[trustedNodeID] = &TrustRecord{
		NodeID:     trustedNodeID,
		PublicKey:  originalKey,
		ApprovedAt: originalAt,
	}

	msg := &HandshakeMsg{
		Type:      HandshakeRequest,
		NodeID:    trustedNodeID,
		PublicKey: "new-pubkey-must-be-ignored",
		Timestamp: time.Now().Unix(),
	}
	hm.handleRequest(nil, msg, true)

	hm.mu.RLock()
	rec := hm.trusted[trustedNodeID]
	hm.mu.RUnlock()

	if rec.PublicKey != originalKey {
		t.Fatalf("PublicKey overwritten: got %q, want %q", rec.PublicKey, originalKey)
	}
	if !rec.ApprovedAt.Equal(originalAt) {
		t.Fatalf("ApprovedAt overwritten: got %v, want %v", rec.ApprovedAt, originalAt)
	}
}

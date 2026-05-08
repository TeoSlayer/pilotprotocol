// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// End-to-end integration tests for the trusted-agents auto-accept path.
// Unlike the focused handleRequest tests, these exercise the full
// processMessage → handleRequest chain with two real identities
// registered against a shared test registry. A real signed handshake
// from B is constructed and fed to A, then A's trust state is
// inspected.
//
// What this proves end-to-end:
//   - The M3 registry-binding check actually fires and sets
//     registryBound=true when the claimed pubkey matches the pubkey the
//     registry has on file for that node_id.
//   - The registryBound flag flows correctly from processMessage to
//     handleRequest.
//   - The trusted-agents check in handleRequest matches by node_id and
//     records a real TrustRecord.

func TestE2EAutoAcceptViaTrustedAgentsList(t *testing.T) {
	reg, rc := startTestRegistry(t)
	t.Cleanup(func() { rc.Close() })
	t.Cleanup(func() { reg.Close() })

	// --- Daemon A: the receiver ---
	aIdentity, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	aResp, err := rc.RegisterWithKey("127.0.0.1:0", crypto.EncodePublicKey(aIdentity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register A: %v", err)
	}
	aNodeID := uint32(aResp["node_id"].(float64))

	rtA := newTestRuntime()
	rtA.identity = aIdentity
	rtA.nodeID = aNodeID
	rtA.regClient = rc
	rtA.trustChecker = testTrustChecker{}
	hmA := NewManager(rtA)
	t.Cleanup(hmA.Stop)
	defer waitForGoRPCDrain()

	// --- Identity B: the trusted service agent ---
	bIdentity, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bResp, err := rc.RegisterWithKey("127.0.0.1:0", crypto.EncodePublicKey(bIdentity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register B: %v", err)
	}
	bNodeID := uint32(bResp["node_id"].(float64))

	// Mark B as a trusted service agent on A's daemon.
	setTestTrustedAgents(t, []testAgent{
		{Hostname: "test-service-agent", NodeID: bNodeID},
	})

	// --- B sends a real signed HandshakeRequest to A ---
	challenge := fmt.Sprintf("handshake:%d:%d", bNodeID, aNodeID)
	sig := bIdentity.Sign([]byte(challenge))
	msg := &HandshakeMsg{
		Type:      HandshakeRequest,
		NodeID:    bNodeID,
		PublicKey: crypto.EncodePublicKey(bIdentity.PublicKey),
		Signature: base64.StdEncoding.EncodeToString(sig),
		Timestamp: time.Now().Unix(),
	}

	// processMessage exercises: timestamp check, replay check, signature
	// verify against registry-bound pubkey (sets registryBound=true),
	// then dispatches to handleRequest with that flag.
	hmA.processMessage(nil, msg)

	// --- Verify B is now in A's trust map (auto-accepted) ---
	hmA.mu.RLock()
	rec, trusted := hmA.trusted[bNodeID]
	_, pending := hmA.pending[bNodeID]
	hmA.mu.RUnlock()

	if !trusted {
		t.Fatalf("E2E auto-accept failed: trusted-agent B (node %d) not in A's trust map", bNodeID)
	}
	if pending {
		t.Fatal("E2E auto-accept failed: B should not be queued for manual approval")
	}
	if rec.PublicKey != crypto.EncodePublicKey(bIdentity.PublicKey) {
		t.Fatalf("stored pubkey wrong: got %q, want %q",
			rec.PublicKey, crypto.EncodePublicKey(bIdentity.PublicKey))
	}
}

func TestE2ENonTrustedAgentGoesToPending(t *testing.T) {
	reg, rc := startTestRegistry(t)
	t.Cleanup(func() { rc.Close() })
	t.Cleanup(func() { reg.Close() })

	// Empty list — nothing is trusted.
	setTestTrustedAgents(t, []testAgent{})

	aIdentity, _ := crypto.GenerateIdentity()
	aResp, _ := rc.RegisterWithKey("127.0.0.1:0", crypto.EncodePublicKey(aIdentity.PublicKey), "", nil)
	aNodeID := uint32(aResp["node_id"].(float64))

	rtA := newTestRuntime()
	rtA.identity = aIdentity
	rtA.nodeID = aNodeID
	rtA.regClient = rc
	rtA.trustChecker = testTrustChecker{}
	hmA := NewManager(rtA)
	t.Cleanup(hmA.Stop)

	bIdentity, _ := crypto.GenerateIdentity()
	bResp, _ := rc.RegisterWithKey("127.0.0.1:0", crypto.EncodePublicKey(bIdentity.PublicKey), "", nil)
	bNodeID := uint32(bResp["node_id"].(float64))

	challenge := fmt.Sprintf("handshake:%d:%d", bNodeID, aNodeID)
	sig := bIdentity.Sign([]byte(challenge))
	msg := &HandshakeMsg{
		Type:      HandshakeRequest,
		NodeID:    bNodeID,
		PublicKey: crypto.EncodePublicKey(bIdentity.PublicKey),
		Signature: base64.StdEncoding.EncodeToString(sig),
		Timestamp: time.Now().Unix(),
	}
	hmA.processMessage(nil, msg)

	hmA.mu.RLock()
	_, trusted := hmA.trusted[bNodeID]
	_, pending := hmA.pending[bNodeID]
	hmA.mu.RUnlock()

	if trusted {
		t.Fatal("non-listed peer was auto-accepted (gate broken)")
	}
	if !pending {
		t.Fatal("non-listed peer should be queued for manual approval")
	}
}

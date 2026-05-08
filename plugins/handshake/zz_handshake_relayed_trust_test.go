// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"testing"
	"time"
)

// Iter-100 coverage for handshake.go relay-path functions:
// processRelayedRequest (0%) all 5 branches + processRelayedApproval (0%)
// both branches. These are called when the registry relays a handshake that
// couldn't traverse direct P2P (typically because peer is private).
//
// All branches use hm.daemon.regConn guards (`if hm.daemon.regConn != nil`),
// so tests with nil regConn exercise the non-relay paths safely. For the
// happy-path trust-establishment behavior we only assert the synchronous
// state-mutation (trusted[x] set, outgoing[x] cleared, saveTrust not panic).

// --- processRelayedRequest: already-trusted short-circuit ---

func TestProcessRelayedRequestAlreadyTrustedShortCircuits(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	existingAt := time.Now().Add(-30 * time.Minute)
	hm.trusted[42] = &TrustRecord{NodeID: 42, ApprovedAt: existingAt, PublicKey: "keep-this"}

	hm.processRelayedRequest(42, "please trust")

	hm.mu.RLock()
	rec := hm.trusted[42]
	hm.mu.RUnlock()
	// already-trusted branch must NOT rewrite the record (no new ApprovedAt/PublicKey).
	if !rec.ApprovedAt.Equal(existingAt) {
		t.Fatalf("ApprovedAt changed: got %v, want %v", rec.ApprovedAt, existingAt)
	}
	if rec.PublicKey != "keep-this" {
		t.Fatalf("PublicKey changed: got %q, want 'keep-this'", rec.PublicKey)
	}
}

// --- processRelayedRequest: mutual auto-approve ---

func TestProcessRelayedRequestMutualAutoApproves(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)
	hm.outgoing[99] = time.Now()

	hm.processRelayedRequest(99, "")

	hm.mu.RLock()
	rec, ok := hm.trusted[99]
	_, stillOutgoing := hm.outgoing[99]
	hm.mu.RUnlock()
	if !ok {
		t.Fatal("trusted[99] missing after mutual relayed auto-approve")
	}
	if !rec.Mutual {
		t.Fatal("rec.Mutual should be true (mutual relay)")
	}
	if stillOutgoing {
		t.Fatal("outgoing[99] should have been cleared")
	}
	// PublicKey is NOT populated by the relay path (comes from backfillPeerKey goRPC).
	if rec.PublicKey != "" {
		t.Fatalf("PublicKey should be empty on relay mutual path (got %q)", rec.PublicKey)
	}
}

// --- processRelayedRequest: TrustAutoApprove ---

func TestProcessRelayedRequestAutoApproveMarksNonMutual(t *testing.T) {
	t.Parallel()
	rt := newTestRuntime()
	rt.trustAutoApprove = true
	hm := NewManager(rt)
	t.Cleanup(hm.Stop)

	hm.processRelayedRequest(55, "from-relay")

	hm.mu.RLock()
	rec, ok := hm.trusted[55]
	_, isPending := hm.pending[55]
	hm.mu.RUnlock()
	if !ok {
		t.Fatal("trusted[55] missing")
	}
	if rec.Mutual {
		t.Fatal("rec.Mutual should be false (auto_approve, not mutual)")
	}
	if isPending {
		t.Fatal("pending[55] should NOT be set when auto-approved")
	}
}

// --- processRelayedRequest: pending-store ---

func TestProcessRelayedRequestStoresInPendingWhenNotAutoApprovable(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	hm.processRelayedRequest(100, "please-approve")

	hm.mu.RLock()
	p, ok := hm.pending[100]
	_, trusted := hm.trusted[100]
	hm.mu.RUnlock()
	if trusted {
		t.Fatal("trusted[100] should NOT be set")
	}
	if !ok {
		t.Fatal("pending[100] missing")
	}
	if p.Justification != "please-approve" {
		t.Fatalf("Justification = %q, want 'please-approve'", p.Justification)
	}
}

// --- processRelayedRequest: trusted-agent auto-approve ---
//
// Regression test for the relayed-path trustedagents gap: a NATed client
// receiving a relayed handshake from a service-agent must auto-approve it
// (mirroring the direct-path trustedagents check) so the reply can be
// delivered without manual approval.

func TestProcessRelayedRequestTrustedAgentAutoApproves(t *testing.T) {
	// NOT parallel — setTestTrustedAgents mutates a package-level map.
	setTestTrustedAgents(t, []testAgent{{NodeID: 77, Hostname: "crtsh.example"}})

	rt := newTestRuntime()
	rt.trustChecker = testTrustChecker{}
	hm := NewManager(rt)
	t.Cleanup(hm.Stop)

	hm.processRelayedRequest(77, "service-agent reply handshake")

	hm.mu.RLock()
	rec, trusted := hm.trusted[77]
	_, pending := hm.pending[77]
	hm.mu.RUnlock()

	if !trusted {
		t.Fatal("trusted[77] missing — relayed trustedagent handshake was not auto-approved")
	}
	if pending {
		t.Fatal("pending[77] should NOT be set for a trusted agent")
	}
	if rec.NodeID != 77 {
		t.Fatalf("NodeID = %d, want 77", rec.NodeID)
	}
	if rec.ApprovedAt.IsZero() {
		t.Fatal("ApprovedAt not set")
	}

	// Events must have fired.
	rt.publishedMu.Lock()
	events := append([]publishedEvent(nil), rt.published...)
	rt.publishedMu.Unlock()
	var gotAutoApproved, gotTrustChanged bool
	for _, ev := range events {
		if ev.Topic == "handshake.auto_approved" {
			gotAutoApproved = true
		}
		if ev.Topic == "trust.changed" {
			gotTrustChanged = true
		}
	}
	if !gotAutoApproved {
		t.Error("handshake.auto_approved event not published")
	}
	if !gotTrustChanged {
		t.Error("trust.changed event not published")
	}
}

// --- processRelayedApproval: already-trusted short-circuit ---

func TestProcessRelayedApprovalAlreadyTrustedShortCircuits(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	existingAt := time.Now().Add(-1 * time.Hour)
	hm.trusted[7] = &TrustRecord{NodeID: 7, ApprovedAt: existingAt, Mutual: false}
	hm.outgoing[7] = time.Now() // simulate a stale outgoing entry

	hm.processRelayedApproval(7)

	hm.mu.RLock()
	rec := hm.trusted[7]
	// outgoing should NOT be cleared — early return fires before the delete.
	_, stillOutgoing := hm.outgoing[7]
	hm.mu.RUnlock()
	if !rec.ApprovedAt.Equal(existingAt) {
		t.Fatal("ApprovedAt mutated despite already-trusted short-circuit")
	}
	if rec.Mutual {
		t.Fatal("rec.Mutual should still be false (short-circuit skipped the overwrite)")
	}
	if !stillOutgoing {
		t.Fatal("outgoing[7] should still be set (delete only runs on trust-establishment path)")
	}
}

// --- processRelayedApproval: establishes trust, clears outgoing ---

func TestProcessRelayedApprovalEstablishesTrustAndClearsOutgoing(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	hm.outgoing[200] = time.Now()

	hm.processRelayedApproval(200)

	hm.mu.RLock()
	rec, ok := hm.trusted[200]
	_, stillOutgoing := hm.outgoing[200]
	hm.mu.RUnlock()
	if !ok {
		t.Fatal("trusted[200] missing — relayed approval didn't establish trust")
	}
	if !rec.Mutual {
		t.Fatal("rec.Mutual should be true on relayed approval")
	}
	if stillOutgoing {
		t.Fatal("outgoing[200] should have been cleared")
	}
}

// --- processRelayedApproval: no outgoing entry still establishes trust ---

func TestProcessRelayedApprovalNoOutgoingStillEstablishes(t *testing.T) {
	t.Parallel()
	// The outgoing map is not a precondition — if somehow the registry relays an
	// approval for a peer we didn't track as outgoing, the code still promotes
	// them to trusted (delete of missing key is a safe no-op in Go).
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	hm.processRelayedApproval(300)

	hm.mu.RLock()
	rec, ok := hm.trusted[300]
	hm.mu.RUnlock()
	if !ok {
		t.Fatal("trusted[300] missing — relayed approval without outgoing should still establish")
	}
	if !rec.Mutual {
		t.Fatal("rec.Mutual should be true")
	}
}

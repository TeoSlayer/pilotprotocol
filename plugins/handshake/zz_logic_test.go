// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// newTestHM is provided by test_helpers_test.go. Returns a fresh
// Manager wired to a testRuntime; identityPath="" disables persistence.

// --- Stop ---

func TestHandshakeStopIdempotentWithNilReapStop(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	// reapStop is nil because Start() was never called.
	hm.Stop() // should not panic
	hm.Stop() // sync.Once guarantees idempotence
}

// --- saveTrust / loadTrust ---

func TestSaveTrustEmptyStorePathIsNoop(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	if hm.storePath != "" {
		t.Fatalf("storePath should be empty, got %q", hm.storePath)
	}
	hm.trusted[1] = &TrustRecord{NodeID: 1, ApprovedAt: time.Now()}
	hm.saveTrust() // no-op, should not panic
}

func TestSaveLoadTrustRoundTripPreservesEntries(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "identity.json")
	hm := newTestHM(t, idPath)
	if hm.storePath == "" {
		t.Fatal("storePath should be derived from IdentityPath")
	}

	approved := time.Now().Truncate(time.Second).UTC()
	received := approved.Add(-10 * time.Minute)
	hm.trusted[42] = &TrustRecord{NodeID: 42, PublicKey: "pk42", ApprovedAt: approved, Mutual: true, Network: 7}
	hm.pending[99] = &PendingHandshake{NodeID: 99, PublicKey: "pk99", Justification: "hi", ReceivedAt: received}

	hm.saveTrust()

	// Load into a fresh manager via NewHandshakeManager which calls loadTrust.
	hm2 := newTestHM(t, idPath)
	tr, ok := hm2.trusted[42]
	if !ok {
		t.Fatal("trusted[42] missing after load")
	}
	if tr.PublicKey != "pk42" || !tr.Mutual || tr.Network != 7 {
		t.Fatalf("trusted entry mismatch: %+v", tr)
	}
	if !tr.ApprovedAt.Equal(approved) {
		t.Fatalf("ApprovedAt = %v, want %v", tr.ApprovedAt, approved)
	}

	pd, ok := hm2.pending[99]
	if !ok {
		t.Fatal("pending[99] missing after load")
	}
	if pd.PublicKey != "pk99" || pd.Justification != "hi" {
		t.Fatalf("pending entry mismatch: %+v", pd)
	}
}

func TestLoadTrustMissingFileIsNoop(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "identity.json")
	// Don't create trust.json — loadTrust should silently return.
	hm := newTestHM(t, idPath)
	if len(hm.trusted) != 0 || len(hm.pending) != 0 {
		t.Fatal("expected empty state when trust.json missing")
	}
}

func TestLoadTrustInvalidJSONIsNoop(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "identity.json")
	trustPath := filepath.Join(dir, "trust.json")
	if err := os.WriteFile(trustPath, []byte("not-json"), 0600); err != nil {
		t.Fatalf("write trust.json: %v", err)
	}
	hm := newTestHM(t, idPath)
	if len(hm.trusted) != 0 || len(hm.pending) != 0 {
		t.Fatal("expected empty state for malformed trust.json")
	}
}

// --- reapReplay ---

func TestReapReplayRemovesStaleEntriesKeepsFresh(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	stale := [32]byte{1}
	fresh := [32]byte{2}
	hm.replayMu.Lock()
	hm.replaySet[stale] = time.Now().Add(-24 * time.Hour)
	hm.replaySet[fresh] = time.Now()
	hm.replayMu.Unlock()

	hm.reapReplay()

	hm.replayMu.Lock()
	defer hm.replayMu.Unlock()
	if _, ok := hm.replaySet[stale]; ok {
		t.Fatal("stale replay entry should be reaped")
	}
	if _, ok := hm.replaySet[fresh]; !ok {
		t.Fatal("fresh replay entry should be preserved")
	}
}

// --- handleRejectMsg / processRelayedRejection ---

func TestHandleRejectMsgDeletesOutgoing(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	hm.mu.Lock()
	hm.outgoing[42] = time.Now()
	hm.mu.Unlock()

	hm.handleRejectMsg(&HandshakeMsg{NodeID: 42, Reason: "no thanks"})

	hm.mu.RLock()
	defer hm.mu.RUnlock()
	if _, ok := hm.outgoing[42]; ok {
		t.Fatal("outgoing[42] should be deleted after reject")
	}
}

func TestProcessRelayedRejectionDeletesOutgoing(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	hm.mu.Lock()
	hm.outgoing[77] = time.Now()
	hm.mu.Unlock()

	hm.processRelayedRejection(77)

	hm.mu.RLock()
	defer hm.mu.RUnlock()
	if _, ok := hm.outgoing[77]; ok {
		t.Fatal("outgoing[77] should be deleted after relayed rejection")
	}
}

// --- handleRevokeMsg (nil regConn path) ---

func TestHandleRevokeMsgDeletesTrustedAndPending(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	hm.mu.Lock()
	hm.trusted[5] = &TrustRecord{NodeID: 5}
	hm.pending[5] = &PendingHandshake{NodeID: 5}
	hm.outgoing[5] = time.Now()
	hm.mu.Unlock()

	hm.handleRevokeMsg(&HandshakeMsg{NodeID: 5})

	hm.mu.RLock()
	defer hm.mu.RUnlock()
	if _, ok := hm.trusted[5]; ok {
		t.Fatal("trusted[5] should be deleted")
	}
	if _, ok := hm.pending[5]; ok {
		t.Fatal("pending[5] should be deleted")
	}
	if _, ok := hm.outgoing[5]; ok {
		t.Fatal("outgoing[5] should be deleted")
	}
}

// --- PendingRequests ---

func TestPendingRequestsReturnsAllEntries(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	hm.mu.Lock()
	hm.pending[1] = &PendingHandshake{NodeID: 1, Justification: "a"}
	hm.pending[2] = &PendingHandshake{NodeID: 2, Justification: "b"}
	hm.mu.Unlock()

	list := hm.PendingRequests()
	if len(list) != 2 {
		t.Fatalf("got %d, want 2 pending", len(list))
	}
	found := map[uint32]string{}
	for _, p := range list {
		found[p.NodeID] = p.Justification
	}
	if found[1] != "a" || found[2] != "b" {
		t.Fatalf("unexpected result: %+v", found)
	}
}

func TestPendingRequestsEmptyReturnsNilSlice(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	list := hm.PendingRequests()
	if list != nil {
		t.Fatalf("empty pending should return nil, got %v", list)
	}
}

// --- signHandshakeChallenge ---

func TestSignHandshakeChallengeNilIdentityReturnsEmpty(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	if hm.rt.HasIdentity() {
		t.Fatal("identity should be nil on bare runtime")
	}
	if sig := hm.signHandshakeChallenge("challenge"); sig != "" {
		t.Fatalf("expected empty sig for nil identity, got %q", sig)
	}
}

func TestSignHandshakeChallengeValidIdentityReturnsVerifiableSignature(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	rt := hm.rt.(*testRuntime)
	rt.identity = id

	challenge := "handshake:1:2"
	sigStr := hm.signHandshakeChallenge(challenge)
	if sigStr == "" {
		t.Fatal("signHandshakeChallenge returned empty for valid identity")
	}
	sig, err := base64.StdEncoding.DecodeString(sigStr)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !crypto.Verify(id.PublicKey, []byte(challenge), sig) {
		t.Fatal("signature should verify against own public key")
	}
}

// --- sameNetwork / sharedNetwork (nil regConn fast-path) ---

func TestSameNetworkNilRegConnReturnsFalse(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	if hm.sameNetwork(99) {
		t.Fatal("sameNetwork with nil regConn should return false")
	}
}

func TestSharedNetworkNilRegConnReturnsZero(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	if got := hm.sharedNetwork(99); got != 0 {
		t.Fatalf("sharedNetwork with nil regConn = %d, want 0", got)
	}
}

// --- ApproveHandshake / RejectHandshake early returns ---

func TestApproveHandshakeMissingPendingReturnsNilNoError(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	// No pending entry for nodeID=123 — should return nil immediately
	// without reaching sendAccept/goRPC.
	if err := hm.ApproveHandshake(123); err != nil {
		t.Fatalf("missing pending should return nil, got %v", err)
	}
	// No trusted entry should have been created.
	if _, ok := hm.trusted[123]; ok {
		t.Fatal("trusted should not be populated for missing pending")
	}
}

// --- RevokeTrust: untrusted returns error ---

func TestRevokeTrustUntrustedReturnsError(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	err := hm.RevokeTrust(555)
	if err == nil {
		t.Fatal("expected error for untrusted node")
	}
}

// --- sendAcceptLocked wraps goRPC — verify it increments wg ---

func TestGoRPCTracksGoroutineInWaitGroup(t *testing.T) {
	hm := newTestHM(t, "")
	ch := make(chan struct{})
	hm.goRPC(func() {
		<-ch
	})
	// wg.Add(1) has been called — release the goroutine.
	close(ch)
	// Stop waits for wg; if goRPC doesn't defer Done properly this hangs.
	done := make(chan struct{})
	go func() {
		hm.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Stop should return quickly after goroutine exits")
	}
}

// --- saveTrust corrupted marshal is not realistic for this code, skip ---

// --- loadTrust with valid file but non-existent public key encoding should still load ---

func TestLoadTrustParsesRFC3339Timestamps(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "identity.json")
	trustPath := filepath.Join(dir, "trust.json")

	approved := time.Now().Truncate(time.Second).UTC()
	snap := trustSnapshot{
		Trusted: []trustSnapshotEntry{
			{NodeID: 1, PublicKey: "pk1", ApprovedAt: approved.Format(time.RFC3339), Mutual: true, Network: 3},
		},
		Pending: []pendingSnapshotEntry{
			{NodeID: 2, Justification: "why", ReceivedAt: approved.Format(time.RFC3339)},
		},
	}
	data, _ := json.Marshal(snap)
	if err := os.WriteFile(trustPath, data, 0600); err != nil {
		t.Fatalf("write trust.json: %v", err)
	}

	hm := newTestHM(t, idPath)
	tr, ok := hm.trusted[1]
	if !ok {
		t.Fatal("trusted[1] missing")
	}
	if !tr.ApprovedAt.Equal(approved) {
		t.Fatalf("ApprovedAt = %v, want %v", tr.ApprovedAt, approved)
	}
	if tr.Network != 3 {
		t.Fatalf("Network = %d, want 3", tr.Network)
	}
	if _, ok := hm.pending[2]; !ok {
		t.Fatal("pending[2] missing")
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/beacon"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// TestPoloScoreDefault verifies that nodes start with a polo score of 0
func TestPoloScoreDefault(t *testing.T) {
	t.Parallel()

	// Start beacon
	b := beacon.New()
	go b.ListenAndServe(":0")
	select {
	case <-b.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to start")
	}
	defer b.Close()

	// Start local registry for testing
	reg := registry.NewWithStore(b.Addr().String(), "")
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	// Connect to local registry
	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Generate identity and register
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	pubKeyB64 := crypto.EncodePublicKey(id.PublicKey)

	resp, err := rc.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test-owner", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Default polo is 0 — verify via in-process test helper since
	// lookup no longer exposes polo_score (privacy redesign).
	if got := reg.GetPoloScoreForTest(nodeID); got != 0 {
		t.Errorf("expected default polo=0, got %d", got)
	}
	// Lookup must NOT include polo_score.
	lookup, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if _, leaked := lookup["polo_score"]; leaked {
		t.Errorf("lookup leaks polo_score: %v", lookup["polo_score"])
	}
}

// TestPoloScoreUpdate tests updating polo by delta values
func TestPoloScoreUpdate(t *testing.T) {
	t.Parallel()

	// Start beacon
	b := beacon.New()
	go b.ListenAndServe(":0")
	select {
	case <-b.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to start")
	}
	defer b.Close()

	// Start local registry for testing
	reg := registry.NewWithStore(b.Addr().String(), "")
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	// Connect to local registry
	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Generate identity and register
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	pubKeyB64 := crypto.EncodePublicKey(id.PublicKey)

	resp, err := rc.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test-owner", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Polo is now write-only externally — UpdatePoloScore no longer
	// echoes the new score. Readback goes through a separate path
	// (self-read GetPoloScore) or through the gate's observable
	// behavior. We verify the mutations land by reading directly
	// from the server's state since this test runs in-process.
	if _, err := rc.UpdatePoloScore(nodeID, 10); err != nil {
		t.Fatalf("update polo (+10): %v", err)
	}
	if _, err := rc.UpdatePoloScore(nodeID, 5); err != nil {
		t.Fatalf("update polo (+5): %v", err)
	}
	if _, err := rc.UpdatePoloScore(nodeID, -8); err != nil {
		t.Fatalf("update polo (-8): %v", err)
	}

	// Readback via server-state introspection (same process).
	if got := reg.GetPoloScoreForTest(nodeID); got != 7 {
		t.Errorf("after +10+5-8, expected polo=7, got %d", got)
	}

	// Lookup must NOT expose polo_score — privacy invariant.
	lookup, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if _, leaked := lookup["polo_score"]; leaked {
		t.Errorf("lookup leaks polo_score: %v", lookup["polo_score"])
	}
}

// TestPoloScoreSet tests setting polo to specific values
func TestPoloScoreSet(t *testing.T) {
	t.Parallel()

	// Start beacon
	b := beacon.New()
	go b.ListenAndServe(":0")
	select {
	case <-b.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to start")
	}
	defer b.Close()

	// Start local registry for testing
	reg := registry.NewWithStore(b.Addr().String(), "")
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	// Connect to local registry
	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Generate identity and register
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	pubKeyB64 := crypto.EncodePublicKey(id.PublicKey)

	resp, err := rc.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test-owner", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Set polo to 100
	if _, err := rc.SetPoloScore(nodeID, 100); err != nil {
		t.Fatalf("set polo (100): %v", err)
	}
	if got := reg.GetPoloScoreForTest(nodeID); got != 100 {
		t.Errorf("after set=100, got polo=%d", got)
	}

	if _, err := rc.SetPoloScore(nodeID, -50); err != nil {
		t.Fatalf("set polo (-50): %v", err)
	}
	if got := reg.GetPoloScoreForTest(nodeID); got != -50 {
		t.Errorf("after set=-50, got polo=%d", got)
	}

	if _, err := rc.SetPoloScore(nodeID, 0); err != nil {
		t.Fatalf("set polo (0): %v", err)
	}
	if got := reg.GetPoloScoreForTest(nodeID); got != 0 {
		t.Errorf("after set=0, got polo=%d", got)
	}
}

// TestPoloScoreGet tests the dedicated GetPoloScore method
func TestPoloScoreGet(t *testing.T) {
	t.Parallel()

	// Start beacon
	b := beacon.New()
	go b.ListenAndServe(":0")
	select {
	case <-b.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to start")
	}
	defer b.Close()

	// Start local registry for testing
	reg := registry.NewWithStore(b.Addr().String(), "")
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	// Connect to local registry
	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Generate identity and register
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	pubKeyB64 := crypto.EncodePublicKey(id.PublicKey)

	resp, err := rc.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test-owner", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Verify default and post-update polo via the in-process test
	// helper. Over-the-wire GetPoloScore requires caller == target
	// with a signed challenge, which this test's bare registry
	// client doesn't set up.
	if got := reg.GetPoloScoreForTest(nodeID); got != 0 {
		t.Errorf("expected default polo=0, got %d", got)
	}
	if _, err := rc.UpdatePoloScore(nodeID, 42); err != nil {
		t.Fatalf("update polo: %v", err)
	}
	if got := reg.GetPoloScoreForTest(nodeID); got != 42 {
		t.Errorf("expected polo=42, got %d", got)
	}
}

// TestPoloScorePersistence tests that polo scores are persisted across registry restarts
func TestPoloScorePersistence(t *testing.T) {
	t.Parallel()

	tmpDir, err := os.MkdirTemp("/tmp", "w4-polo-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "registry.json")

	// Start beacon
	b := beacon.New()
	go b.ListenAndServe(":0")
	select {
	case <-b.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to start")
	}
	defer b.Close()
	beaconAddr := b.Addr().String()

	// Generate identity
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	pubKeyB64 := crypto.EncodePublicKey(id.PublicKey)

	// Phase 1: Start registry, register node, set polo
	reg1 := registry.NewWithStore(beaconAddr, storePath)
	go reg1.ListenAndServe(":0")
	select {
	case <-reg1.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 1 failed to start")
	}
	regAddr1 := reg1.Addr().String()

	rc1, err := registry.Dial(regAddr1)
	if err != nil {
		t.Fatalf("dial registry 1: %v", err)
	}

	resp, err := rc1.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test-owner", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Set polo to 77
	_, err = rc1.SetPoloScore(nodeID, 77)
	if err != nil {
		t.Fatalf("set polo: %v", err)
	}

	rc1.Close()
	reg1.Close()

	// Verify store file exists
	if _, err := os.Stat(storePath); err != nil {
		t.Fatalf("store file not created: %v", err)
	}

	// Phase 2: Start new registry loading from the same store
	reg2 := registry.NewWithStore(beaconAddr, storePath)
	go reg2.ListenAndServe(":0")
	select {
	case <-reg2.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 2 failed to start")
	}
	defer reg2.Close()
	regAddr2 := reg2.Addr().String()

	rc2, err := registry.Dial(regAddr2)
	if err != nil {
		t.Fatalf("dial registry 2: %v", err)
	}
	defer rc2.Close()

	// Polo is private — cross-node reads are rejected. Use the
	// in-process test helper to verify the stored value survived.
	if got := reg2.GetPoloScoreForTest(nodeID); got != 77 {
		t.Errorf("polo not persisted: expected 77, got %d", got)
	}
}

// TestPoloScoreNonExistentNode tests error handling for non-existent nodes
func TestPoloScoreNonExistentNode(t *testing.T) {
	t.Parallel()

	// Start beacon
	b := beacon.New()
	go b.ListenAndServe(":0")
	select {
	case <-b.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to start")
	}
	defer b.Close()

	// Start local registry for testing
	reg := registry.NewWithStore(b.Addr().String(), "")
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	// Connect to local registry
	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	nonExistentNodeID := uint32(99999)

	// Test UpdatePoloScore on non-existent node
	_, err = rc.UpdatePoloScore(nonExistentNodeID, 10)
	if err == nil {
		t.Error("expected error for UpdatePoloScore on non-existent node")
	}

	// Test SetPoloScore on non-existent node
	_, err = rc.SetPoloScore(nonExistentNodeID, 100)
	if err == nil {
		t.Error("expected error for SetPoloScore on non-existent node")
	}

	// Test GetPoloScore on non-existent node
	_, err = rc.GetPoloScore(nonExistentNodeID)
	if err == nil {
		t.Error("expected error for GetPoloScore on non-existent node")
	}
}

// TestPoloScoreEdgeCases tests edge cases like very large positive/negative values
func TestPoloScoreEdgeCases(t *testing.T) {
	t.Parallel()

	// Start beacon
	b := beacon.New()
	go b.ListenAndServe(":0")
	select {
	case <-b.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to start")
	}
	defer b.Close()

	// Start local registry for testing
	reg := registry.NewWithStore(b.Addr().String(), "")
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	// Connect to local registry
	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Generate identity and register
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	pubKeyB64 := crypto.EncodePublicKey(id.PublicKey)

	resp, err := rc.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test-owner", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Large positive — readback via in-process helper (cross-read denied over wire).
	if _, err := rc.SetPoloScore(nodeID, 1000000); err != nil {
		t.Fatalf("set large positive polo: %v", err)
	}
	if got := reg.GetPoloScoreForTest(nodeID); got != 1000000 {
		t.Errorf("expected polo=1000000, got %d", got)
	}

	// Large negative.
	if _, err := rc.SetPoloScore(nodeID, -1000000); err != nil {
		t.Fatalf("set large negative polo: %v", err)
	}
	if got := reg.GetPoloScoreForTest(nodeID); got != -1000000 {
		t.Errorf("expected polo=-1000000, got %d", got)
	}

	// Clamping: max + 500000 → clamped to maxPoloScore (1_000_000).
	if _, err := rc.SetPoloScore(nodeID, 1000000); err != nil {
		t.Fatalf("set polo: %v", err)
	}
	if _, err := rc.UpdatePoloScore(nodeID, 500000); err != nil {
		t.Fatalf("update polo: %v", err)
	}
	if got := reg.GetPoloScoreForTest(nodeID); got != 1000000 {
		t.Errorf("expected polo=1000000 (clamped), got %d", got)
	}
}

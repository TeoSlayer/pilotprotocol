package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"web4/internal/crypto"
	"web4/pkg/beacon"
	"web4/pkg/registry"
)

// TestKarmaScoreDefault verifies that nodes start with a karma score of 0
func TestKarmaScoreDefault(t *testing.T) {
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

	resp, err := rc.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test-owner")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Lookup node and verify default karma score is 0
	lookup, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	karmaScore, ok := lookup["karma_score"].(float64)
	if !ok {
		t.Fatal("karma_score not found in lookup response")
	}

	if int(karmaScore) != 0 {
		t.Errorf("expected default karma_score=0, got %d", int(karmaScore))
	}
}

// TestKarmaScoreUpdate tests updating karma by delta values
func TestKarmaScoreUpdate(t *testing.T) {
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

	resp, err := rc.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test-owner")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Test positive delta
	updateResp, err := rc.UpdateKarma(nodeID, 10)
	if err != nil {
		t.Fatalf("update karma (+10): %v", err)
	}

	if updateResp["karma_score"].(float64) != 10 {
		t.Errorf("expected karma_score=10 after +10, got %v", updateResp["karma_score"])
	}

	// Test another positive delta
	updateResp, err = rc.UpdateKarma(nodeID, 5)
	if err != nil {
		t.Fatalf("update karma (+5): %v", err)
	}

	if updateResp["karma_score"].(float64) != 15 {
		t.Errorf("expected karma_score=15 after +5, got %v", updateResp["karma_score"])
	}

	// Test negative delta
	updateResp, err = rc.UpdateKarma(nodeID, -8)
	if err != nil {
		t.Fatalf("update karma (-8): %v", err)
	}

	if updateResp["karma_score"].(float64) != 7 {
		t.Errorf("expected karma_score=7 after -8, got %v", updateResp["karma_score"])
	}

	// Verify via lookup
	lookup, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	if lookup["karma_score"].(float64) != 7 {
		t.Errorf("lookup: expected karma_score=7, got %v", lookup["karma_score"])
	}
}

// TestKarmaScoreSet tests setting karma to specific values
func TestKarmaScoreSet(t *testing.T) {
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

	resp, err := rc.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test-owner")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Set karma to 100
	setResp, err := rc.SetKarma(nodeID, 100)
	if err != nil {
		t.Fatalf("set karma (100): %v", err)
	}

	if setResp["karma_score"].(float64) != 100 {
		t.Errorf("expected karma_score=100, got %v", setResp["karma_score"])
	}

	// Set karma to -50
	setResp, err = rc.SetKarma(nodeID, -50)
	if err != nil {
		t.Fatalf("set karma (-50): %v", err)
	}

	if setResp["karma_score"].(float64) != -50 {
		t.Errorf("expected karma_score=-50, got %v", setResp["karma_score"])
	}

	// Set karma to 0
	setResp, err = rc.SetKarma(nodeID, 0)
	if err != nil {
		t.Fatalf("set karma (0): %v", err)
	}

	if setResp["karma_score"].(float64) != 0 {
		t.Errorf("expected karma_score=0, got %v", setResp["karma_score"])
	}

	// Verify via GetKarma
	karma, err := rc.GetKarma(nodeID)
	if err != nil {
		t.Fatalf("get karma: %v", err)
	}

	if karma != 0 {
		t.Errorf("GetKarma: expected 0, got %d", karma)
	}
}

// TestKarmaScoreGet tests the dedicated GetKarma method
func TestKarmaScoreGet(t *testing.T) {
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

	resp, err := rc.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test-owner")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Get default karma
	karma, err := rc.GetKarma(nodeID)
	if err != nil {
		t.Fatalf("get karma: %v", err)
	}

	if karma != 0 {
		t.Errorf("expected default karma=0, got %d", karma)
	}

	// Update and get again
	_, err = rc.UpdateKarma(nodeID, 42)
	if err != nil {
		t.Fatalf("update karma: %v", err)
	}

	karma, err = rc.GetKarma(nodeID)
	if err != nil {
		t.Fatalf("get karma after update: %v", err)
	}

	if karma != 42 {
		t.Errorf("expected karma=42, got %d", karma)
	}
}

// TestKarmaScorePersistence tests that karma scores are persisted across registry restarts
func TestKarmaScorePersistence(t *testing.T) {
	t.Parallel()

	tmpDir, err := os.MkdirTemp("/tmp", "w4-karma-")
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

	// Phase 1: Start registry, register node, set karma
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

	resp, err := rc1.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test-owner")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Set karma to 77
	_, err = rc1.SetKarma(nodeID, 77)
	if err != nil {
		t.Fatalf("set karma: %v", err)
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

	// Verify karma score persisted
	karma, err := rc2.GetKarma(nodeID)
	if err != nil {
		t.Fatalf("get karma after restart: %v", err)
	}

	if karma != 77 {
		t.Errorf("karma not persisted: expected 77, got %d", karma)
	}
}

// TestKarmaScoreNonExistentNode tests error handling for non-existent nodes
func TestKarmaScoreNonExistentNode(t *testing.T) {
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

	// Test UpdateKarma on non-existent node
	_, err = rc.UpdateKarma(nonExistentNodeID, 10)
	if err == nil {
		t.Error("expected error for UpdateKarma on non-existent node")
	}

	// Test SetKarma on non-existent node
	_, err = rc.SetKarma(nonExistentNodeID, 100)
	if err == nil {
		t.Error("expected error for SetKarma on non-existent node")
	}

	// Test GetKarma on non-existent node
	_, err = rc.GetKarma(nonExistentNodeID)
	if err == nil {
		t.Error("expected error for GetKarma on non-existent node")
	}
}

// TestKarmaScoreEdgeCases tests edge cases like very large positive/negative values
func TestKarmaScoreEdgeCases(t *testing.T) {
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

	resp, err := rc.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test-owner")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Test very large positive value
	_, err = rc.SetKarma(nodeID, 1000000)
	if err != nil {
		t.Fatalf("set large positive karma: %v", err)
	}

	karma, err := rc.GetKarma(nodeID)
	if err != nil {
		t.Fatalf("get karma: %v", err)
	}

	if karma != 1000000 {
		t.Errorf("expected karma=1000000, got %d", karma)
	}

	// Test very large negative value
	_, err = rc.SetKarma(nodeID, -1000000)
	if err != nil {
		t.Fatalf("set large negative karma: %v", err)
	}

	karma, err = rc.GetKarma(nodeID)
	if err != nil {
		t.Fatalf("get karma: %v", err)
	}

	if karma != -1000000 {
		t.Errorf("expected karma=-1000000, got %d", karma)
	}

	// Test overflow scenario: start at large value and add more
	_, err = rc.SetKarma(nodeID, 1000000)
	if err != nil {
		t.Fatalf("set karma: %v", err)
	}

	_, err = rc.UpdateKarma(nodeID, 500000)
	if err != nil {
		t.Fatalf("update karma: %v", err)
	}

	karma, err = rc.GetKarma(nodeID)
	if err != nil {
		t.Fatalf("get karma: %v", err)
	}

	if karma != 1500000 {
		t.Errorf("expected karma=1500000, got %d", karma)
	}
}

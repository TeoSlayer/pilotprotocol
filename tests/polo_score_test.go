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

	resp, err := rc.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test-owner")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Lookup node and verify default polo score is 0
	lookup, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	poloScore, ok := lookup["polo_score"].(float64)
	if !ok {
		t.Fatal("polo_score not found in lookup response")
	}

	if int(poloScore) != 0 {
		t.Errorf("expected default polo_score=0, got %d", int(poloScore))
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

	resp, err := rc.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test-owner")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Test positive delta
	updateResp, err := rc.UpdatePoloScore(nodeID, 10)
	if err != nil {
		t.Fatalf("update polo (+10): %v", err)
	}

	if updateResp["polo_score"].(float64) != 10 {
		t.Errorf("expected polo_score=10 after +10, got %v", updateResp["polo_score"])
	}

	// Test another positive delta
	updateResp, err = rc.UpdatePoloScore(nodeID, 5)
	if err != nil {
		t.Fatalf("update polo (+5): %v", err)
	}

	if updateResp["polo_score"].(float64) != 15 {
		t.Errorf("expected polo_score=15 after +5, got %v", updateResp["polo_score"])
	}

	// Test negative delta
	updateResp, err = rc.UpdatePoloScore(nodeID, -8)
	if err != nil {
		t.Fatalf("update polo (-8): %v", err)
	}

	if updateResp["polo_score"].(float64) != 7 {
		t.Errorf("expected polo_score=7 after -8, got %v", updateResp["polo_score"])
	}

	// Verify via lookup
	lookup, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	if lookup["polo_score"].(float64) != 7 {
		t.Errorf("lookup: expected polo_score=7, got %v", lookup["polo_score"])
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

	resp, err := rc.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test-owner")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Set polo to 100
	setResp, err := rc.SetPoloScore(nodeID, 100)
	if err != nil {
		t.Fatalf("set polo (100): %v", err)
	}

	if setResp["polo_score"].(float64) != 100 {
		t.Errorf("expected polo_score=100, got %v", setResp["polo_score"])
	}

	// Set polo to -50
	setResp, err = rc.SetPoloScore(nodeID, -50)
	if err != nil {
		t.Fatalf("set polo (-50): %v", err)
	}

	if setResp["polo_score"].(float64) != -50 {
		t.Errorf("expected polo_score=-50, got %v", setResp["polo_score"])
	}

	// Set polo to 0
	setResp, err = rc.SetPoloScore(nodeID, 0)
	if err != nil {
		t.Fatalf("set polo (0): %v", err)
	}

	if setResp["polo_score"].(float64) != 0 {
		t.Errorf("expected polo_score=0, got %v", setResp["polo_score"])
	}

	// Verify via GetPoloScore
	polo, err := rc.GetPoloScore(nodeID)
	if err != nil {
		t.Fatalf("get polo: %v", err)
	}

	if polo != 0 {
		t.Errorf("GetPoloScore: expected 0, got %d", polo)
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

	resp, err := rc.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test-owner")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Get default polo
	polo, err := rc.GetPoloScore(nodeID)
	if err != nil {
		t.Fatalf("get polo: %v", err)
	}

	if polo != 0 {
		t.Errorf("expected default polo=0, got %d", polo)
	}

	// Update and get again
	_, err = rc.UpdatePoloScore(nodeID, 42)
	if err != nil {
		t.Fatalf("update polo: %v", err)
	}

	polo, err = rc.GetPoloScore(nodeID)
	if err != nil {
		t.Fatalf("get polo after update: %v", err)
	}

	if polo != 42 {
		t.Errorf("expected polo=42, got %d", polo)
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

	resp, err := rc1.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test-owner")
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

	// Verify polo score persisted
	polo, err := rc2.GetPoloScore(nodeID)
	if err != nil {
		t.Fatalf("get polo after restart: %v", err)
	}

	if polo != 77 {
		t.Errorf("polo not persisted: expected 77, got %d", polo)
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

	resp, err := rc.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test-owner")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Test very large positive value
	_, err = rc.SetPoloScore(nodeID, 1000000)
	if err != nil {
		t.Fatalf("set large positive polo: %v", err)
	}

	polo, err := rc.GetPoloScore(nodeID)
	if err != nil {
		t.Fatalf("get polo: %v", err)
	}

	if polo != 1000000 {
		t.Errorf("expected polo=1000000, got %d", polo)
	}

	// Test very large negative value
	_, err = rc.SetPoloScore(nodeID, -1000000)
	if err != nil {
		t.Fatalf("set large negative polo: %v", err)
	}

	polo, err = rc.GetPoloScore(nodeID)
	if err != nil {
		t.Fatalf("get polo: %v", err)
	}

	if polo != -1000000 {
		t.Errorf("expected polo=-1000000, got %d", polo)
	}

	// Test overflow scenario: start at large value and add more
	_, err = rc.SetPoloScore(nodeID, 1000000)
	if err != nil {
		t.Fatalf("set polo: %v", err)
	}

	_, err = rc.UpdatePoloScore(nodeID, 500000)
	if err != nil {
		t.Fatalf("update polo: %v", err)
	}

	polo, err = rc.GetPoloScore(nodeID)
	if err != nil {
		t.Fatalf("get polo: %v", err)
	}

	if polo != 1500000 {
		t.Errorf("expected polo=1500000, got %d", polo)
	}
}

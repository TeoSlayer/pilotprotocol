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

// TestReRegistrationAfterRegistryRestart tests the full persistence contract:
// 1. Create a registry with a store path (temp file)
// 2. Register a node with a known Ed25519 key, get node_id
// 3. Stop registry
// 4. Start a NEW registry loading from the same store path
// 5. Re-register the same Ed25519 key
// 6. Verify the same node_id is returned
func TestReRegistrationAfterRegistryRestart(t *testing.T) {
	t.Parallel()
	tmpDir, err := os.MkdirTemp("/tmp", "w4-rereg-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "registry.json")

	// Start a beacon (needed for registry constructor)
	b := beacon.New()
	go b.ListenAndServe(":0")
	select {
	case <-b.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to start")
	}
	defer b.Close()
	beaconAddr := b.Addr().String()

	// Generate a stable Ed25519 identity
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	pubKeyB64 := crypto.EncodePublicKey(id.PublicKey)

	// --- Phase 1: Start registry, register node, record node_id ---
	reg1 := registry.NewWithStore(beaconAddr, storePath)
	go reg1.ListenAndServe(":0")
	select {
	case <-reg1.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 1 failed to start")
	}
	regAddr1 := reg1.Addr().String()
	t.Logf("registry 1 on %s", regAddr1)

	rc1, err := registry.Dial(regAddr1)
	if err != nil {
		t.Fatalf("dial registry 1: %v", err)
	}

	resp1, err := rc1.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test-owner")
	if err != nil {
		t.Fatalf("register on registry 1: %v", err)
	}
	nodeID1 := uint32(resp1["node_id"].(float64))
	t.Logf("phase 1: registered node_id=%d", nodeID1)

	rc1.Close()

	// --- Phase 2: Stop registry 1 (flushes state to disk) ---
	reg1.Close()
	t.Log("phase 2: registry 1 stopped")

	// Verify store file exists (after close guarantees flush)
	if _, err := os.Stat(storePath); err != nil {
		t.Fatalf("store file not created: %v", err)
	}

	// --- Phase 3: Start NEW registry from same store path ---
	reg2 := registry.NewWithStore(beaconAddr, storePath)
	go reg2.ListenAndServe(":0")
	select {
	case <-reg2.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 2 failed to start")
	}
	defer reg2.Close()
	regAddr2 := reg2.Addr().String()
	t.Logf("registry 2 on %s (loaded from store)", regAddr2)

	// --- Phase 4: Re-register with same Ed25519 key ---
	rc2, err := registry.Dial(regAddr2)
	if err != nil {
		t.Fatalf("dial registry 2: %v", err)
	}
	defer rc2.Close()

	resp2, err := rc2.RegisterWithKey("127.0.0.1:4001", pubKeyB64, "test-owner")
	if err != nil {
		t.Fatalf("re-register on registry 2: %v", err)
	}
	nodeID2 := uint32(resp2["node_id"].(float64))
	t.Logf("phase 4: re-registered node_id=%d", nodeID2)

	// --- Phase 5: Verify same node_id ---
	if nodeID1 != nodeID2 {
		t.Fatalf("node_id mismatch after registry restart: got %d, want %d", nodeID2, nodeID1)
	}
	t.Logf("persistence verified: same node_id=%d after registry restart", nodeID1)

	// Bonus: verify lookup works on the new registry
	lookup, err := rc2.Lookup(nodeID2)
	if err != nil {
		t.Fatalf("lookup after re-register: %v", err)
	}
	if uint32(lookup["node_id"].(float64)) != nodeID1 {
		t.Error("lookup returned wrong node_id")
	}
	t.Logf("lookup confirmed node_id=%d on new registry", nodeID1)
}

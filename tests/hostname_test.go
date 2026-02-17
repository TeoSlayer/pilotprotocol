package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// startTestRegistry starts a registry on a random port and returns the client and cleanup func.
func startTestRegistry(t *testing.T) (*registry.Client, *registry.Server, func()) {
	t.Helper()
	reg := registry.New("127.0.0.1:9001")
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}

	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}

	return rc, reg, func() {
		rc.Close()
		reg.Close()
	}
}

// registerTestNode registers a new node with a fresh identity.
// Returns the node ID and identity (for signing subsequent requests).
func registerTestNode(t *testing.T, rc *registry.Client) (uint32, *crypto.Identity) {
	t.Helper()
	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "")
	if err != nil {
		t.Fatalf("register node: %v", err)
	}
	return uint32(resp["node_id"].(float64)), id
}

func TestHostnameSetAndResolve(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	nodeID, id := registerTestNode(t, rc)
	setClientSigner(rc, id)

	// Set hostname
	resp, err := rc.SetHostname(nodeID, "alice")
	if err != nil {
		t.Fatalf("set hostname: %v", err)
	}
	if resp["hostname"] != "alice" {
		t.Fatalf("expected hostname 'alice', got %v", resp["hostname"])
	}

	// Resolve hostname
	resolved, err := rc.ResolveHostname("alice")
	if err != nil {
		t.Fatalf("resolve hostname: %v", err)
	}
	resolvedID := uint32(resolved["node_id"].(float64))
	if resolvedID != nodeID {
		t.Fatalf("expected node_id %d, got %d", nodeID, resolvedID)
	}
	if resolved["address"] == nil || resolved["address"] == "" {
		t.Fatal("expected address in resolve response")
	}

	// Verify lookup also returns hostname
	lookup, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if lookup["hostname"] != "alice" {
		t.Fatalf("expected hostname 'alice' in lookup, got %v", lookup["hostname"])
	}
}

func TestHostnameUniqueness(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	nodeA, idA := registerTestNode(t, rc)
	nodeB, idB := registerTestNode(t, rc)

	// Set hostname on node A
	setClientSigner(rc, idA)
	_, err := rc.SetHostname(nodeA, "shared-name")
	if err != nil {
		t.Fatalf("set hostname on A: %v", err)
	}

	// Try to set same hostname on node B — should fail
	setClientSigner(rc, idB)
	_, err = rc.SetHostname(nodeB, "shared-name")
	if err == nil {
		t.Fatal("expected error when setting duplicate hostname, got nil")
	}
	t.Logf("correctly rejected duplicate: %v", err)

	// Clear hostname on A
	setClientSigner(rc, idA)
	_, err = rc.SetHostname(nodeA, "")
	if err != nil {
		t.Fatalf("clear hostname on A: %v", err)
	}

	// Now B should be able to claim it
	setClientSigner(rc, idB)
	_, err = rc.SetHostname(nodeB, "shared-name")
	if err != nil {
		t.Fatalf("set hostname on B after clear: %v", err)
	}

	// Resolve should now point to B
	resolved, err := rc.ResolveHostname("shared-name")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if uint32(resolved["node_id"].(float64)) != nodeB {
		t.Fatalf("expected node B (%d), got %d", nodeB, uint32(resolved["node_id"].(float64)))
	}
}

func TestHostnameValidation(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	nodeID, id := registerTestNode(t, rc)
	setClientSigner(rc, id)

	invalid := []string{
		"Alice",           // uppercase
		"hello world",     // space
		"-start",          // starts with hyphen
		"end-",            // ends with hyphen
		"localhost",       // reserved
		"backbone",        // reserved
		"broadcast",       // reserved
		"this-hostname-is-way-too-long-and-exceeds-the-sixty-three-character-limit-by-quite-a-bit",
		"hello@world",     // special char
		"hello.world",     // dot not allowed
	}

	for _, name := range invalid {
		_, err := rc.SetHostname(nodeID, name)
		if err == nil {
			t.Errorf("expected error for hostname %q, got nil", name)
		}
	}

	// Valid hostnames should work
	valid := []string{
		"alice",
		"my-agent",
		"node42",
		"a",
		"a1b2c3",
	}

	for _, name := range valid {
		_, err := rc.SetHostname(nodeID, name)
		if err != nil {
			t.Errorf("expected hostname %q to be valid, got error: %v", name, err)
		}
	}
}

func TestHostnamePersistence(t *testing.T) {
	t.Parallel()
	tmpDir, err := os.MkdirTemp("/tmp", "w4-hostname-persist-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "registry.json")

	// Phase 1: start registry, register node, set hostname
	reg1 := registry.NewWithStore("127.0.0.1:9001", storePath)
	go reg1.ListenAndServe(":0")
	select {
	case <-reg1.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 1 failed to start")
	}

	rc1, err := registry.Dial(reg1.Addr().String())
	if err != nil {
		t.Fatalf("dial registry 1: %v", err)
	}

	id, _ := crypto.GenerateIdentity()
	resp, err := rc1.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))
	setClientSigner(rc1, id)

	_, err = rc1.SetHostname(nodeID, "persistent-alice")
	if err != nil {
		t.Fatalf("set hostname: %v", err)
	}

	rc1.Close()
	reg1.Close()

	// Phase 2: restart from store, verify hostname survives
	reg2 := registry.NewWithStore("127.0.0.1:9001", storePath)
	go reg2.ListenAndServe(":0")
	select {
	case <-reg2.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 2 failed to start")
	}
	defer reg2.Close()

	rc2, err := registry.Dial(reg2.Addr().String())
	if err != nil {
		t.Fatalf("dial registry 2: %v", err)
	}
	defer rc2.Close()

	// Resolve should still work
	resolved, err := rc2.ResolveHostname("persistent-alice")
	if err != nil {
		t.Fatalf("resolve after restart: %v", err)
	}
	if uint32(resolved["node_id"].(float64)) != nodeID {
		t.Fatalf("expected node_id %d after restart, got %d", nodeID, uint32(resolved["node_id"].(float64)))
	}

	// Lookup should show hostname
	lookup, err := rc2.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup after restart: %v", err)
	}
	if lookup["hostname"] != "persistent-alice" {
		t.Fatalf("expected hostname 'persistent-alice' after restart, got %v", lookup["hostname"])
	}
}

func TestHostnameAtRegistration(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	// Register with hostname in one round-trip
	id, _ := crypto.GenerateIdentity()
	resp, err := rc.Send(map[string]interface{}{
		"type":        "register",
		"listen_addr": "",
		"public_key":  crypto.EncodePublicKey(id.PublicKey),
		"hostname":    "bob",
	})
	if err != nil {
		t.Fatalf("register with hostname: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	if resp["hostname"] != "bob" {
		t.Fatalf("expected hostname 'bob' in register response, got %v", resp["hostname"])
	}

	// Resolve should find bob
	resolved, err := rc.ResolveHostname("bob")
	if err != nil {
		t.Fatalf("resolve bob: %v", err)
	}
	if uint32(resolved["node_id"].(float64)) != nodeID {
		t.Fatalf("expected node_id %d, got %d", nodeID, uint32(resolved["node_id"].(float64)))
	}
}

func TestHostnameCleanupOnDeregister(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	nodeID, id := registerTestNode(t, rc)
	setClientSigner(rc, id)

	// Set hostname
	_, err := rc.SetHostname(nodeID, "ephemeral")
	if err != nil {
		t.Fatalf("set hostname: %v", err)
	}

	// Verify resolve works
	_, err = rc.ResolveHostname("ephemeral")
	if err != nil {
		t.Fatalf("resolve before deregister: %v", err)
	}

	// Deregister node
	_, err = rc.Deregister(nodeID)
	if err != nil {
		t.Fatalf("deregister: %v", err)
	}

	// Resolve should now fail
	_, err = rc.ResolveHostname("ephemeral")
	if err == nil {
		t.Fatal("expected resolve to fail after deregister, got nil")
	}
	t.Logf("correctly failed after deregister: %v", err)

	// Another node should be able to claim the freed hostname
	nodeB, idB := registerTestNode(t, rc)
	setClientSigner(rc, idB)
	_, err = rc.SetHostname(nodeB, "ephemeral")
	if err != nil {
		t.Fatalf("set hostname on new node after deregister: %v", err)
	}

	resolved, err := rc.ResolveHostname("ephemeral")
	if err != nil {
		t.Fatalf("resolve after reclaim: %v", err)
	}
	if uint32(resolved["node_id"].(float64)) != nodeB {
		t.Fatalf("expected node B (%d), got %d", nodeB, uint32(resolved["node_id"].(float64)))
	}
}

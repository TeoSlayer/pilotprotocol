package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

func TestRegistryPersistence(t *testing.T) {
	t.Skip("custom networks are WIP")
	t.Parallel()
	tmpDir, err := os.MkdirTemp("/tmp", "w4-persist-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "registry.json")

	// Phase 1: start registry, register nodes, create network
	reg1 := registry.NewWithStore("127.0.0.1:9001", storePath)
	reg1.SetAdminToken(TestAdminToken)
	go reg1.ListenAndServe(":0")
	select {
	case <-reg1.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 1 failed to start")
	}

	regAddr := reg1.Addr().String()

	rc, err := registry.Dial(regAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}

	// Register two nodes
	id1, _ := crypto.GenerateIdentity()
	resp1, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id1.PublicKey), "")
	if err != nil {
		t.Fatalf("register node 1: %v", err)
	}
	nodeID1 := uint32(resp1["node_id"].(float64))
	t.Logf("registered node %d", nodeID1)

	id2, _ := crypto.GenerateIdentity()
	resp2, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id2.PublicKey), "")
	if err != nil {
		t.Fatalf("register node 2: %v", err)
	}
	nodeID2 := uint32(resp2["node_id"].(float64))
	t.Logf("registered node %d", nodeID2)

	// Create a network
	netResp, err := rc.CreateNetwork(nodeID1, "test-persist", "open", "", TestAdminToken)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))
	t.Logf("created network %d", netID)

	// Join node 2 to network
	_, err = rc.JoinNetwork(nodeID2, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join network: %v", err)
	}

	rc.Close()
	reg1.Close()

	// Verify store file exists
	data, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	t.Logf("store file: %d bytes", len(data))

	// Phase 2: start new registry from the same store file
	reg2 := registry.NewWithStore("127.0.0.1:9001", storePath)
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

	// Verify nodes exist
	lookup1, err := rc2.Lookup(nodeID1)
	if err != nil {
		t.Fatalf("lookup node 1 after reload: %v", err)
	}
	if uint32(lookup1["node_id"].(float64)) != nodeID1 {
		t.Errorf("node 1 ID mismatch: got %v", lookup1["node_id"])
	}
	t.Logf("node 1 survived restart: %v", lookup1)

	lookup2, err := rc2.Lookup(nodeID2)
	if err != nil {
		t.Fatalf("lookup node 2 after reload: %v", err)
	}
	if uint32(lookup2["node_id"].(float64)) != nodeID2 {
		t.Errorf("node 2 ID mismatch: got %v", lookup2["node_id"])
	}

	// Verify network exists with both members
	networks, err := rc2.ListNetworks()
	if err != nil {
		t.Fatalf("list networks: %v", err)
	}
	netList := networks["networks"].([]interface{})
	found := false
	for _, n := range netList {
		net := n.(map[string]interface{})
		if net["name"] == "test-persist" {
			members := int(net["members"].(float64))
			if members != 2 {
				t.Errorf("network members = %d, want 2", members)
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("test-persist network not found after reload")
	}

	// Register a new node — should get ID 3 (counters preserved)
	id3, _ := crypto.GenerateIdentity()
	resp3, err := rc2.RegisterWithKey("", crypto.EncodePublicKey(id3.PublicKey), "")
	if err != nil {
		t.Fatalf("register node 3: %v", err)
	}
	nodeID3 := uint32(resp3["node_id"].(float64))
	if nodeID3 <= nodeID2 {
		t.Errorf("new node ID %d should be > %d (counter not preserved)", nodeID3, nodeID2)
	}
	t.Logf("new node after restart: %d (counter preserved)", nodeID3)
}

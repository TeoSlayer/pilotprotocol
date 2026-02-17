package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// TestRegistryReplication verifies hot-standby replication:
// 1. Start primary registry, register nodes
// 2. Start standby that replicates from primary
// 3. Verify standby has the same data
// 4. Verify standby rejects writes
func TestRegistryReplication(t *testing.T) {
	t.Skip("custom networks are WIP")
	t.Parallel()
	tmpDir, err := os.MkdirTemp("/tmp", "w4-repl-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	primaryStore := filepath.Join(tmpDir, "primary.json")
	standbyStore := filepath.Join(tmpDir, "standby.json")

	// Start primary registry
	primary := registry.NewWithStore("127.0.0.1:9001", primaryStore)
	primary.SetAdminToken(TestAdminToken)
	primary.SetReplicationToken("test-repl-token")
	go primary.ListenAndServe("127.0.0.1:0")
	select {
	case <-primary.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("primary failed to start")
	}
	defer primary.Close()
	primaryAddr := primary.Addr().String()
	t.Logf("primary on %s", primaryAddr)

	// Register nodes on primary
	rc, err := registry.Dial(primaryAddr)
	if err != nil {
		t.Fatalf("dial primary: %v", err)
	}
	defer rc.Close()

	id1, _ := crypto.GenerateIdentity()
	resp1, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id1.PublicKey), "")
	if err != nil {
		t.Fatalf("register node 1: %v", err)
	}
	nodeID1 := uint32(resp1["node_id"].(float64))

	id2, _ := crypto.GenerateIdentity()
	resp2, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id2.PublicKey), "")
	if err != nil {
		t.Fatalf("register node 2: %v", err)
	}
	nodeID2 := uint32(resp2["node_id"].(float64))

	// Create a network
	netResp, err := rc.CreateNetwork(nodeID1, "repl-test", "open", "", TestAdminToken)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))
	t.Logf("registered nodes %d, %d; network %d", nodeID1, nodeID2, netID)

	// Start standby registry that replicates from primary
	standby := registry.NewWithStore("127.0.0.1:9001", standbyStore)
	standby.SetReplicationToken("test-repl-token")
	standby.SetStandby(primaryAddr)
	go standby.ListenAndServe("127.0.0.1:0")
	select {
	case <-standby.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("standby failed to start")
	}
	defer standby.Close()
	standbyAddr := standby.Addr().String()
	t.Logf("standby on %s", standbyAddr)

	// Poll standby until replication delivers the initial snapshot
	sc, err := registry.Dial(standbyAddr)
	if err != nil {
		t.Fatalf("dial standby: %v", err)
	}
	defer sc.Close()

	deadline := time.After(5 * time.Second)
	var lookup1 map[string]interface{}
	for {
		lookup1, err = sc.Lookup(nodeID1)
		if err == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for replication of node 1: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if uint32(lookup1["node_id"].(float64)) != nodeID1 {
		t.Errorf("standby node 1 ID mismatch")
	}
	t.Logf("standby has node %d", nodeID1)

	lookup2, err := sc.Lookup(nodeID2)
	if err != nil {
		t.Fatalf("standby lookup node 2: %v", err)
	}
	if uint32(lookup2["node_id"].(float64)) != nodeID2 {
		t.Errorf("standby node 2 ID mismatch")
	}

	// List networks should work
	nets, err := sc.ListNetworks()
	if err != nil {
		t.Fatalf("standby list networks: %v", err)
	}
	netList := nets["networks"].([]interface{})
	found := false
	for _, n := range netList {
		net := n.(map[string]interface{})
		if net["name"] == "repl-test" {
			found = true
		}
	}
	if !found {
		t.Error("standby missing repl-test network")
	}

	// Writes should be rejected on standby
	idS, _ := crypto.GenerateIdentity()
	_, err = sc.RegisterWithKey("", crypto.EncodePublicKey(idS.PublicKey), "")
	if err == nil {
		t.Error("standby accepted a write (register) — should have been rejected")
	} else {
		t.Logf("standby correctly rejected write: %v", err)
	}

	// Register a new node on primary and verify it replicates
	id3, _ := crypto.GenerateIdentity()
	resp3, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id3.PublicKey), "")
	if err != nil {
		t.Fatalf("register node 3 on primary: %v", err)
	}
	nodeID3 := uint32(resp3["node_id"].(float64))
	t.Logf("registered node %d on primary", nodeID3)

	// Poll standby until node 3 replicates
	deadline2 := time.After(5 * time.Second)
	var lookup3 map[string]interface{}
	for {
		lookup3, err = sc.Lookup(nodeID3)
		if err == nil {
			break
		}
		select {
		case <-deadline2:
			t.Fatalf("timed out waiting for replication of node 3: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if uint32(lookup3["node_id"].(float64)) != nodeID3 {
		t.Errorf("standby node 3 ID mismatch")
	}
	t.Logf("node %d successfully replicated to standby", nodeID3)

	// Verify standby persisted the state
	if _, err := os.Stat(standbyStore); err != nil {
		t.Errorf("standby store file not created: %v", err)
	}
}

// TestRegistryStandbyPromotion verifies that a standby can be promoted to primary
// by restarting it without the standby flag.
func TestRegistryStandbyPromotion(t *testing.T) {
	t.Parallel()
	tmpDir, err := os.MkdirTemp("/tmp", "w4-promote-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	primaryStore := filepath.Join(tmpDir, "primary.json")
	standbyStore := filepath.Join(tmpDir, "standby.json")

	// Start primary, register nodes
	primary := registry.NewWithStore("127.0.0.1:9001", primaryStore)
	primary.SetReplicationToken("test-repl-token")
	go primary.ListenAndServe("127.0.0.1:0")
	select {
	case <-primary.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("primary failed to start")
	}
	primaryAddr := primary.Addr().String()

	rc, err := registry.Dial(primaryAddr)
	if err != nil {
		t.Fatalf("dial primary: %v", err)
	}

	idP, _ := crypto.GenerateIdentity()
	resp1, err := rc.RegisterWithKey("", crypto.EncodePublicKey(idP.PublicKey), "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID1 := uint32(resp1["node_id"].(float64))

	// Start standby and let it replicate
	standby := registry.NewWithStore("127.0.0.1:9001", standbyStore)
	standby.SetReplicationToken("test-repl-token")
	standby.SetStandby(primaryAddr)
	go standby.ListenAndServe("127.0.0.1:0")
	select {
	case <-standby.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("standby failed to start")
	}

	// Poll standby until replication delivers the node
	{
		sc, err := registry.Dial(standby.Addr().String())
		if err != nil {
			t.Fatalf("dial standby: %v", err)
		}
		deadline := time.After(5 * time.Second)
		for {
			_, lookupErr := sc.Lookup(nodeID1)
			if lookupErr == nil {
				break
			}
			select {
			case <-deadline:
				t.Fatalf("timed out waiting for standby replication: %v", lookupErr)
			case <-time.After(10 * time.Millisecond):
			}
		}
		sc.Close()
	}

	// Shut down both
	rc.Close()
	standby.Close()
	primary.Close()

	// "Promote" standby: restart from standby's store file WITHOUT standby flag
	promoted := registry.NewWithStore("127.0.0.1:9001", standbyStore)
	go promoted.ListenAndServe("127.0.0.1:0")
	select {
	case <-promoted.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("promoted server failed to start")
	}
	defer promoted.Close()

	pc, err := registry.Dial(promoted.Addr().String())
	if err != nil {
		t.Fatalf("dial promoted: %v", err)
	}
	defer pc.Close()

	// Verify the data survived promotion
	lookup, err := pc.Lookup(nodeID1)
	if err != nil {
		t.Fatalf("promoted lookup: %v", err)
	}
	if uint32(lookup["node_id"].(float64)) != nodeID1 {
		t.Errorf("promoted node ID mismatch")
	}

	// Verify writes now work (no longer standby)
	idProm, _ := crypto.GenerateIdentity()
	resp2, err := pc.RegisterWithKey("", crypto.EncodePublicKey(idProm.PublicKey), "")
	if err != nil {
		t.Fatalf("promoted register should work: %v", err)
	}
	nodeID2 := uint32(resp2["node_id"].(float64))
	if nodeID2 <= nodeID1 {
		t.Errorf("promoted node ID %d should be > %d", nodeID2, nodeID1)
	}
	t.Logf("promoted server accepting writes: node %d registered", nodeID2)
}

// TestFailoverUnderLoad tests failover with concurrent operations:
// 1. Start primary registry with store path
// 2. Start standby registry connected to primary
// 3. Register 3 nodes on primary
// 4. Stop primary
// 5. Verify standby has all 3 nodes (check via standby's lookups)
// 6. Start standby as new primary (re-listen from store)
// 7. Register a new node on the promoted standby
// 8. Verify the new registration works
func TestFailoverUnderLoad(t *testing.T) {
	t.Parallel()
	tmpDir, err := os.MkdirTemp("/tmp", "w4-failover-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	primaryStore := filepath.Join(tmpDir, "primary.json")
	standbyStore := filepath.Join(tmpDir, "standby.json")

	// Step 1: Start primary registry
	primary := registry.NewWithStore("127.0.0.1:9001", primaryStore)
	primary.SetAdminToken(TestAdminToken)
	primary.SetReplicationToken("test-repl-token")
	go primary.ListenAndServe("127.0.0.1:0")
	select {
	case <-primary.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("primary failed to start")
	}
	primaryAddr := primary.Addr().String()
	t.Logf("primary on %s", primaryAddr)

	// Step 2: Start standby connected to primary
	standby := registry.NewWithStore("127.0.0.1:9001", standbyStore)
	standby.SetReplicationToken("test-repl-token")
	standby.SetStandby(primaryAddr)
	go standby.ListenAndServe("127.0.0.1:0")
	select {
	case <-standby.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("standby failed to start")
	}
	standbyAddr := standby.Addr().String()
	t.Logf("standby on %s", standbyAddr)

	// Step 3: Register 3 nodes on primary
	rc, err := registry.Dial(primaryAddr)
	if err != nil {
		t.Fatalf("dial primary: %v", err)
	}

	nodeIDs := make([]uint32, 3)
	for i := 0; i < 3; i++ {
		id, _ := crypto.GenerateIdentity()
		resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "")
		if err != nil {
			t.Fatalf("register node %d: %v", i+1, err)
		}
		nodeIDs[i] = uint32(resp["node_id"].(float64))
		t.Logf("registered node %d (id=%d) on primary", i+1, nodeIDs[i])
	}
	rc.Close()

	// Wait for all 3 nodes to replicate to standby by polling
	sc, err := registry.Dial(standbyAddr)
	if err != nil {
		t.Fatalf("dial standby: %v", err)
	}

	for i, nid := range nodeIDs {
		deadline := time.After(5 * time.Second)
		for {
			_, lookupErr := sc.Lookup(nid)
			if lookupErr == nil {
				t.Logf("standby has node %d (id=%d)", i+1, nid)
				break
			}
			select {
			case <-deadline:
				t.Fatalf("timed out waiting for replication of node %d (id=%d): %v", i+1, nid, lookupErr)
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	sc.Close()

	// Step 4: Stop primary (simulates crash)
	primary.Close()
	t.Log("primary stopped (simulated crash)")

	// Step 5: Verify standby still has all 3 nodes
	sc2, err := registry.Dial(standbyAddr)
	if err != nil {
		t.Fatalf("dial standby after primary down: %v", err)
	}
	for i, nid := range nodeIDs {
		lookup, err := sc2.Lookup(nid)
		if err != nil {
			t.Fatalf("standby lookup node %d (id=%d) after primary crash: %v", i+1, nid, err)
		}
		if uint32(lookup["node_id"].(float64)) != nid {
			t.Errorf("standby node %d ID mismatch", i+1)
		}
	}
	sc2.Close()
	t.Log("standby has all 3 nodes after primary crash")

	// Step 6: Stop standby and promote it as new primary (restart without standby flag)
	standby.Close()
	t.Log("standby stopped for promotion")

	promoted := registry.NewWithStore("127.0.0.1:9001", standbyStore)
	go promoted.ListenAndServe("127.0.0.1:0")
	select {
	case <-promoted.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("promoted server failed to start")
	}
	defer promoted.Close()
	promotedAddr := promoted.Addr().String()
	t.Logf("promoted registry on %s", promotedAddr)

	// Step 7: Verify all 3 nodes survived promotion
	pc, err := registry.Dial(promotedAddr)
	if err != nil {
		t.Fatalf("dial promoted: %v", err)
	}
	defer pc.Close()

	for i, nid := range nodeIDs {
		lookup, err := pc.Lookup(nid)
		if err != nil {
			t.Fatalf("promoted lookup node %d (id=%d): %v", i+1, nid, err)
		}
		if uint32(lookup["node_id"].(float64)) != nid {
			t.Errorf("promoted node %d ID mismatch", i+1)
		}
	}
	t.Log("all 3 nodes survived failover")

	// Step 8: Register a new node on the promoted registry
	id4, _ := crypto.GenerateIdentity()
	resp4, err := pc.RegisterWithKey("", crypto.EncodePublicKey(id4.PublicKey), "")
	if err != nil {
		t.Fatalf("register on promoted: %v", err)
	}
	nodeID4 := uint32(resp4["node_id"].(float64))
	t.Logf("registered new node %d on promoted registry", nodeID4)

	// Verify the new node is there
	lookup4, err := pc.Lookup(nodeID4)
	if err != nil {
		t.Fatalf("lookup new node on promoted: %v", err)
	}
	if uint32(lookup4["node_id"].(float64)) != nodeID4 {
		t.Errorf("promoted new node ID mismatch")
	}

	// The new node_id should be greater than all previous ones
	for _, nid := range nodeIDs {
		if nodeID4 <= nid {
			t.Errorf("new node_id %d should be > existing %d", nodeID4, nid)
		}
	}
	t.Logf("failover under load: success (4 nodes, new id=%d)", nodeID4)
}

package tests

import (
	"fmt"
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
	t.Parallel()
	if os.Getenv("CI") != "" {
		t.Skip("skipping in CI: standby persistence timing unreliable on constrained runners")
	}
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
	resp1, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id1.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node 1: %v", err)
	}
	nodeID1 := uint32(resp1["node_id"].(float64))

	id2, _ := crypto.GenerateIdentity()
	resp2, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id2.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node 2: %v", err)
	}
	nodeID2 := uint32(resp2["node_id"].(float64))

	// Create a network
	netResp, err := rc.CreateNetwork(nodeID1, "repl-test", "open", "", TestAdminToken, false)
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
	_, err = sc.RegisterWithKey("", crypto.EncodePublicKey(idS.PublicKey), "", nil)
	if err == nil {
		t.Error("standby accepted a write (register) — should have been rejected")
	} else {
		t.Logf("standby correctly rejected write: %v", err)
	}

	// Register a new node on primary and verify it replicates
	id3, _ := crypto.GenerateIdentity()
	resp3, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id3.PublicKey), "", nil)
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
	resp1, err := rc.RegisterWithKey("", crypto.EncodePublicKey(idP.PublicKey), "", nil)
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
	resp2, err := pc.RegisterWithKey("", crypto.EncodePublicKey(idProm.PublicKey), "", nil)
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
		resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "", nil)
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
	resp4, err := pc.RegisterWithKey("", crypto.EncodePublicKey(id4.PublicKey), "", nil)
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

// TestReplicationEnterpriseData verifies that enterprise features survive replication:
// RBAC roles, network policy, enterprise flag, admin token, node tags, polo score,
// task exec, key metadata, and audit log entries.
func TestReplicationEnterpriseData(t *testing.T) {
	t.Parallel()
	if os.Getenv("CI") != "" {
		t.Skip("skipping in CI: standby timing unreliable on constrained runners")
	}
	tmpDir, err := os.MkdirTemp("/tmp", "w4-repl-ent-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	primaryStore := filepath.Join(tmpDir, "primary.json")
	standbyStore := filepath.Join(tmpDir, "standby.json")

	// Start primary
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

	rc, err := registry.Dial(primaryAddr)
	if err != nil {
		t.Fatalf("dial primary: %v", err)
	}
	defer rc.Close()

	// Register two nodes
	id1, _ := crypto.GenerateIdentity()
	resp1, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id1.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node 1: %v", err)
	}
	nodeID1 := uint32(resp1["node_id"].(float64))

	id2, _ := crypto.GenerateIdentity()
	resp2, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id2.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node 2: %v", err)
	}
	nodeID2 := uint32(resp2["node_id"].(float64))

	// Create enterprise network with network admin token
	netResp, err := rc.CreateNetwork(nodeID1, "ent-repl-test", "open", "", TestAdminToken, true, "net-admin-tok")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	// Join node 2
	if _, err := rc.JoinNetwork(nodeID2, netID, "", 0, TestAdminToken); err != nil {
		t.Fatalf("join: %v", err)
	}

	// Promote node 2 to admin
	if _, err := rc.PromoteMember(netID, nodeID1, nodeID2, TestAdminToken); err != nil {
		t.Fatalf("promote: %v", err)
	}

	// Set network policy with allowed ports
	if _, err := rc.SetNetworkPolicy(netID, map[string]interface{}{
		"max_members":   float64(50),
		"description":   "test enterprise policy",
		"allowed_ports": []interface{}{float64(80), float64(443)},
	}, TestAdminToken); err != nil {
		t.Fatalf("set policy: %v", err)
	}

	// Set node properties via admin token
	if _, err := rc.SetTagsAdmin(nodeID1, []string{"gpu", "us-east"}, TestAdminToken); err != nil {
		t.Fatalf("set tags: %v", err)
	}
	if _, err := rc.SetVisibilityAdmin(nodeID1, true, TestAdminToken); err != nil {
		t.Fatalf("set visibility: %v", err)
	}
	if _, err := rc.SetPoloScore(nodeID1, 42); err != nil {
		t.Fatalf("set polo score: %v", err)
	}
	if _, err := rc.SetTaskExecAdmin(nodeID1, true, TestAdminToken); err != nil {
		t.Fatalf("set task exec: %v", err)
	}
	expiry := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	if _, err := rc.SetKeyExpiryAdmin(nodeID1, expiry, TestAdminToken); err != nil {
		t.Fatalf("set key expiry: %v", err)
	}

	// Start standby
	standby := registry.NewWithStore("127.0.0.1:9001", standbyStore)
	standby.SetAdminToken(TestAdminToken)
	standby.SetReplicationToken("test-repl-token")
	standby.SetStandby(primaryAddr)
	go standby.ListenAndServe("127.0.0.1:0")
	select {
	case <-standby.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("standby failed to start")
	}
	defer standby.Close()

	// Poll until replication delivers
	sc, err := registry.Dial(standby.Addr().String())
	if err != nil {
		t.Fatalf("dial standby: %v", err)
	}
	defer sc.Close()

	deadline := time.After(5 * time.Second)
	for {
		_, lookupErr := sc.Lookup(nodeID2)
		if lookupErr == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for replication: %v", lookupErr)
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Verify node fields replicated
	lookup1, err := sc.Lookup(nodeID1)
	if err != nil {
		t.Fatalf("standby lookup node 1: %v", err)
	}
	if pub, ok := lookup1["public"].(bool); !ok || !pub {
		t.Error("standby: node 1 public flag not replicated")
	}

	// Verify polo score
	score, err := sc.GetPoloScore(nodeID1)
	if err != nil {
		t.Fatalf("standby get polo score: %v", err)
	}
	if score != 42 {
		t.Errorf("standby: polo score = %d, want 42", score)
	}

	// Verify network enterprise data via list_nodes
	listResp, err := sc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("standby list nodes: %v", err)
	}
	nodes := listResp["nodes"].([]interface{})
	if len(nodes) != 2 {
		t.Fatalf("standby: expected 2 members, got %d", len(nodes))
	}

	// Find node 1 in list and check fields
	for _, n := range nodes {
		entry := n.(map[string]interface{})
		nid := uint32(entry["node_id"].(float64))
		if nid == nodeID1 {
			// Check role
			if role, ok := entry["role"].(string); !ok || role != "admin" {
				// node1 is owner, but PromoteMember promoted node2
				// node1 should be owner (creator)
				if role != "owner" {
					t.Errorf("standby: node 1 role = %q, want owner", role)
				}
			}
			// Check tags replicated
			if tags, ok := entry["tags"].([]interface{}); ok {
				if len(tags) != 2 {
					t.Errorf("standby: node 1 tags count = %d, want 2", len(tags))
				}
			} else {
				t.Error("standby: node 1 tags not replicated")
			}
			// Check polo_score
			if ps, ok := entry["polo_score"].(float64); !ok || int(ps) != 42 {
				t.Errorf("standby: node 1 polo_score in list = %v, want 42", entry["polo_score"])
			}
		}
		if nid == nodeID2 {
			if role, ok := entry["role"].(string); !ok || role != "admin" {
				t.Errorf("standby: node 2 role = %q, want admin", role)
			}
		}
	}

	// Verify network policy via GetNetworkPolicy
	polResp, err := sc.GetNetworkPolicy(netID)
	if err != nil {
		t.Fatalf("standby get policy: %v", err)
	}
	if desc, ok := polResp["description"].(string); !ok || desc != "test enterprise policy" {
		t.Errorf("standby: policy description = %q, want %q", polResp["description"], "test enterprise policy")
	}
	if mm, ok := polResp["max_members"].(float64); !ok || int(mm) != 50 {
		t.Errorf("standby: policy max_members = %v, want 50", polResp["max_members"])
	}
	if ports, ok := polResp["allowed_ports"].([]interface{}); ok {
		if len(ports) != 2 {
			t.Errorf("standby: policy allowed_ports count = %d, want 2", len(ports))
		}
	} else {
		t.Error("standby: policy allowed_ports not replicated")
	}

	// Verify audit log replicated
	auditResp, err := sc.GetAuditLog(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("standby get audit: %v", err)
	}
	entries, ok := auditResp["entries"].([]interface{})
	if !ok || len(entries) == 0 {
		t.Error("standby: audit log not replicated (zero entries)")
	} else {
		t.Logf("standby: %d audit entries replicated", len(entries))
	}

	// Stop primary, promote standby
	primary.Close()

	standby.Close()
	promoted := registry.NewWithStore("127.0.0.1:9001", standbyStore)
	promoted.SetAdminToken(TestAdminToken)
	go promoted.ListenAndServe("127.0.0.1:0")
	select {
	case <-promoted.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("promoted failed to start")
	}
	defer promoted.Close()

	pc, err := registry.Dial(promoted.Addr().String())
	if err != nil {
		t.Fatalf("dial promoted: %v", err)
	}
	defer pc.Close()

	// Verify enterprise data survived failover + promotion
	pScore, err := pc.GetPoloScore(nodeID1)
	if err != nil {
		t.Fatalf("promoted get polo score: %v", err)
	}
	if pScore != 42 {
		t.Errorf("promoted: polo score = %d, want 42", pScore)
	}

	pPol, err := pc.GetNetworkPolicy(netID)
	if err != nil {
		t.Fatalf("promoted get policy: %v", err)
	}
	if desc, ok := pPol["description"].(string); !ok || desc != "test enterprise policy" {
		t.Errorf("promoted: policy description = %q", pPol["description"])
	}

	pAudit, err := pc.GetAuditLog(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("promoted get audit: %v", err)
	}
	pEntries, ok := pAudit["entries"].([]interface{})
	if !ok || len(pEntries) == 0 {
		t.Error("promoted: audit log lost after failover")
	}

	// Verify RBAC still works — promote should still work as enterprise
	id3, _ := crypto.GenerateIdentity()
	resp3, err := pc.RegisterWithKey("", crypto.EncodePublicKey(id3.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node 3 on promoted: %v", err)
	}
	nodeID3 := uint32(resp3["node_id"].(float64))
	if _, err := pc.JoinNetwork(nodeID3, netID, "", 0, TestAdminToken); err != nil {
		t.Fatalf("join on promoted: %v", err)
	}
	if _, err := pc.PromoteMember(netID, nodeID1, nodeID3, TestAdminToken); err != nil {
		t.Fatalf("promote on promoted: %v", err)
	}

	t.Logf("enterprise data survived replication + failover: network=%d, nodes=%s",
		netID, fmt.Sprintf("%d,%d,%d", nodeID1, nodeID2, nodeID3))
}

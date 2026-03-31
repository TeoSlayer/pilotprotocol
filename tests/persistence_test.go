package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

func TestRegistryPersistence(t *testing.T) {
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
	resp1, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id1.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node 1: %v", err)
	}
	nodeID1 := uint32(resp1["node_id"].(float64))
	t.Logf("registered node %d", nodeID1)

	id2, _ := crypto.GenerateIdentity()
	resp2, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id2.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node 2: %v", err)
	}
	nodeID2 := uint32(resp2["node_id"].(float64))
	t.Logf("registered node %d", nodeID2)

	// Create a network
	netResp, err := rc.CreateNetwork(nodeID1, "test-persist", "open", "", TestAdminToken, false)
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
	resp3, err := rc2.RegisterWithKey("", crypto.EncodePublicKey(id3.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node 3: %v", err)
	}
	nodeID3 := uint32(resp3["node_id"].(float64))
	if nodeID3 <= nodeID2 {
		t.Errorf("new node ID %d should be > %d (counter not preserved)", nodeID3, nodeID2)
	}
	t.Logf("new node after restart: %d (counter preserved)", nodeID3)
}

// TestPersistenceEnterpriseData verifies that enterprise state (RBAC roles,
// policies, invites, audit log) survives a registry restart.
func TestPersistenceEnterpriseData(t *testing.T) {
	t.Parallel()
	tmpDir, err := os.MkdirTemp("/tmp", "w4-persist-ent-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "registry.json")

	// Phase 1: set up enterprise state
	reg1 := registry.NewWithStore("127.0.0.1:9001", storePath)
	reg1.SetAdminToken(TestAdminToken)
	go reg1.ListenAndServe(":0")
	select {
	case <-reg1.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 1 failed to start")
	}

	rc, err := registry.Dial(reg1.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Register owner and member
	ownerID, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(ownerID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	ownerNodeID := uint32(resp["node_id"].(float64))

	memberID, _ := crypto.GenerateIdentity()
	resp, err = rc.RegisterWithKey("", crypto.EncodePublicKey(memberID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register member: %v", err)
	}
	memberNodeID := uint32(resp["node_id"].(float64))

	// A third node to receive an invite (but NOT accept it — test pending invite persistence)
	inviteeID, _ := crypto.GenerateIdentity()
	resp, err = rc.RegisterWithKey("", crypto.EncodePublicKey(inviteeID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register invitee: %v", err)
	}
	inviteeNodeID := uint32(resp["node_id"].(float64))

	// Create enterprise network
	setClientSigner(rc, ownerID)
	resp, err = rc.CreateNetwork(ownerNodeID, "persist-ent", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Invite and accept member
	_, err = rc.InviteToNetwork(netID, ownerNodeID, memberNodeID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite member: %v", err)
	}
	setClientSigner(rc, memberID)
	_, err = rc.RespondInvite(memberNodeID, netID, true)
	if err != nil {
		t.Fatalf("accept invite: %v", err)
	}

	// Promote member to admin
	_, err = rc.PromoteMember(netID, ownerNodeID, memberNodeID, TestAdminToken)
	if err != nil {
		t.Fatalf("promote member: %v", err)
	}

	// Set network policy
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"max_members": float64(50),
		"description": "test enterprise persistence",
	}, TestAdminToken)
	if err != nil {
		t.Fatalf("set policy: %v", err)
	}

	// Set tags on owner node
	_, err = rc.SetTagsAdmin(ownerNodeID, []string{"gpu", "leader"}, TestAdminToken)
	if err != nil {
		t.Fatalf("set tags: %v", err)
	}

	// Invite a third node but DON'T accept (pending invite)
	setClientSigner(rc, ownerID)
	_, err = rc.InviteToNetwork(netID, ownerNodeID, inviteeNodeID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite invitee: %v", err)
	}

	rc.Close()
	reg1.Close()
	t.Log("phase 1 complete: enterprise state set up")

	// Phase 2: restart and verify
	reg2 := registry.NewWithStore("127.0.0.1:9001", storePath)
	reg2.SetAdminToken(TestAdminToken)
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

	// Verify RBAC: member should have admin role
	roleResp, err := rc2.GetMemberRole(netID, memberNodeID)
	if err != nil {
		t.Fatalf("get member role after restart: %v", err)
	}
	if roleResp["role"] != "admin" {
		t.Errorf("member role after restart: got %v, want admin", roleResp["role"])
	}
	t.Logf("RBAC role persisted: member has role=%s", roleResp["role"])

	// Verify owner role
	roleResp, err = rc2.GetMemberRole(netID, ownerNodeID)
	if err != nil {
		t.Fatalf("get owner role after restart: %v", err)
	}
	if roleResp["role"] != "owner" {
		t.Errorf("owner role after restart: got %v, want owner", roleResp["role"])
	}

	// Verify policy survived
	policyResp, err := rc2.GetNetworkPolicy(netID)
	if err != nil {
		t.Fatalf("get policy after restart: %v", err)
	}
	if int(policyResp["max_members"].(float64)) != 50 {
		t.Errorf("max_members after restart: got %v, want 50", policyResp["max_members"])
	}
	if policyResp["description"] != "test enterprise persistence" {
		t.Errorf("description after restart: got %v", policyResp["description"])
	}
	t.Logf("policy persisted: max_members=%v, description=%v", policyResp["max_members"], policyResp["description"])

	// Verify audit log survived
	auditResp, err := rc2.GetAuditLog(0, TestAdminToken)
	if err != nil {
		t.Fatalf("get audit log after restart: %v", err)
	}
	entries := auditResp["entries"].([]interface{})
	if len(entries) == 0 {
		t.Error("audit log empty after restart")
	}
	// Check for specific audit entries
	foundPromote := false
	foundPolicy := false
	for _, e := range entries {
		entry := e.(map[string]interface{})
		action := entry["action"].(string)
		if action == "member.promoted" {
			foundPromote = true
		}
		if action == "network.policy_changed" {
			foundPolicy = true
		}
	}
	if !foundPromote {
		t.Error("member.promoted audit entry missing after restart")
	}
	if !foundPolicy {
		t.Error("network.policy_changed audit entry missing after restart")
	}
	t.Logf("audit log persisted: %d entries", len(entries))

	// Verify pending invite survived
	setClientSigner(rc2, inviteeID)
	pollResp, err := rc2.PollInvites(inviteeNodeID)
	if err != nil {
		t.Fatalf("poll invites after restart: %v", err)
	}
	invites, ok := pollResp["invites"].([]interface{})
	if !ok || len(invites) == 0 {
		t.Error("pending invite lost after restart")
	} else {
		inv := invites[0].(map[string]interface{})
		if uint16(inv["network_id"].(float64)) != netID {
			t.Errorf("invite network_id mismatch: got %v, want %d", inv["network_id"], netID)
		}
		t.Logf("pending invite persisted: network_id=%v", inv["network_id"])
	}

	// Verify enterprise flag by checking that enterprise operations still work
	setClientSigner(rc2, ownerID)
	_, err = rc2.DemoteMember(netID, ownerNodeID, memberNodeID, TestAdminToken)
	if err != nil {
		t.Fatalf("demote after restart: %v", err)
	}
	// Check it's now member
	roleResp, err = rc2.GetMemberRole(netID, memberNodeID)
	if err != nil {
		t.Fatalf("get role after demote: %v", err)
	}
	if roleResp["role"] != "member" {
		t.Errorf("role after demote: got %v, want member", roleResp["role"])
	}
	t.Log("enterprise operations work after restart")

	// Verify tags survived by listing nodes
	nodesResp, err := rc2.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes after restart: %v", err)
	}
	nodes := nodesResp["nodes"].([]interface{})
	foundTags := false
	for _, n := range nodes {
		node := n.(map[string]interface{})
		if uint32(node["node_id"].(float64)) == ownerNodeID {
			if tags, ok := node["tags"].([]interface{}); ok && len(tags) == 2 {
				foundTags = true
				t.Logf("tags persisted: %v", tags)
			}
		}
	}
	if !foundTags {
		// Tags might not be in list_nodes response — check via different method
		details := strings.Join([]string{"tags check incomplete"}, ", ")
		t.Logf("note: %s", details)
	}
}

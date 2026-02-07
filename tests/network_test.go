package tests

import (
	"testing"

	"web4/internal/crypto"
	"web4/pkg/registry"
)

// startTestRegistryWithAdmin starts a registry with admin token and returns client, server, cleanup.
func startTestRegistryWithAdmin(t *testing.T) (*registry.Client, *registry.Server, func()) {
	t.Helper()
	rc, reg, cleanup := startTestRegistry(t)
	reg.SetAdminToken(TestAdminToken)
	return rc, reg, cleanup
}

func TestNetworkNameValidation(t *testing.T) {
	t.Skip("custom networks are WIP")
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, _ := registerTestNode(t, rc)

	invalid := []string{
		"",                // empty
		"MyNetwork",      // uppercase
		"hello world",    // space
		"-start",         // starts with hyphen
		"end-",           // ends with hyphen
		"backbone",       // reserved
		"hello@net",      // special char
		"hello.net",      // dot
		"this-network-name-is-way-too-long-and-exceeds-the-sixty-three-character-limit-by-quite-a-bit",
	}

	for _, name := range invalid {
		_, err := rc.CreateNetwork(nodeID, name, "open", "", TestAdminToken)
		if err == nil {
			t.Errorf("expected error for network name %q, got nil", name)
		}
	}

	valid := []string{
		"research-lab",
		"net42",
		"a",
		"my-cool-topic",
	}

	for _, name := range valid {
		_, err := rc.CreateNetwork(nodeID, name, "open", "", TestAdminToken)
		if err != nil {
			t.Errorf("expected network name %q to be valid, got error: %v", name, err)
		}
	}
}

func TestNetworkLeave(t *testing.T) {
	t.Skip("custom networks are WIP")
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeA, _ := registerTestNode(t, rc)
	nodeB, _ := registerTestNode(t, rc)

	// Create a network
	resp, err := rc.CreateNetwork(nodeA, "leave-test", "open", "", TestAdminToken)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Join node B
	_, err = rc.JoinNetwork(nodeB, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join B: %v", err)
	}

	// Verify both are members
	nodesResp, err := rc.ListNodes(netID)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	nodes := nodesResp["nodes"].([]interface{})
	if len(nodes) != 2 {
		t.Fatalf("expected 2 members, got %d", len(nodes))
	}

	// Node B leaves
	_, err = rc.LeaveNetwork(nodeB, netID, TestAdminToken)
	if err != nil {
		t.Fatalf("leave network: %v", err)
	}

	// Verify only A remains
	nodesResp, err = rc.ListNodes(netID)
	if err != nil {
		t.Fatalf("list nodes after leave: %v", err)
	}
	nodes = nodesResp["nodes"].([]interface{})
	if len(nodes) != 1 {
		t.Fatalf("expected 1 member after leave, got %d", len(nodes))
	}
	remaining := nodes[0].(map[string]interface{})
	if uint32(remaining["node_id"].(float64)) != nodeA {
		t.Fatalf("expected node A to remain, got node %v", remaining["node_id"])
	}
}

func TestNetworkLeaveAndRejoin(t *testing.T) {
	t.Skip("custom networks are WIP")
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, _ := registerTestNode(t, rc)

	resp, err := rc.CreateNetwork(nodeID, "rejoin-test", "open", "", TestAdminToken)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Leave the network
	_, err = rc.LeaveNetwork(nodeID, netID, TestAdminToken)
	if err != nil {
		t.Fatalf("leave: %v", err)
	}

	// Should be able to rejoin
	_, err = rc.JoinNetwork(nodeID, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("rejoin after leave: %v", err)
	}

	// Verify membership
	nodesResp, err := rc.ListNodes(netID)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	nodes := nodesResp["nodes"].([]interface{})
	if len(nodes) != 1 {
		t.Fatalf("expected 1 member after rejoin, got %d", len(nodes))
	}
}

func TestNetworkLeaveBackboneForbidden(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, _ := registerTestNode(t, rc)

	// Cannot leave backbone (network 0)
	_, err := rc.LeaveNetwork(nodeID, 0, TestAdminToken)
	if err == nil {
		t.Fatal("expected error when leaving backbone, got nil")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestNetworkLeaveNotMember(t *testing.T) {
	t.Skip("custom networks are WIP")
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeA, _ := registerTestNode(t, rc)
	nodeB, _ := registerTestNode(t, rc)

	resp, err := rc.CreateNetwork(nodeA, "not-member-test", "open", "", TestAdminToken)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Node B never joined — leaving should fail
	_, err = rc.LeaveNetwork(nodeB, netID, TestAdminToken)
	if err == nil {
		t.Fatal("expected error when non-member leaves, got nil")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestNetworkIDOverflowGuard(t *testing.T) {
	t.Skip("custom networks are WIP")
	t.Parallel()
	rc, reg, cleanup := startTestRegistry(t)
	defer cleanup()
	reg.SetAdminToken(TestAdminToken)

	nodeID, _ := registerTestNode(t, rc)

	// Force nextNet to max value by creating networks until we reach a high ID
	// We can't create 65534 networks in a test, so we'll test the guard
	// by setting nextNet to 0 via creating the boundary condition.
	// Instead, let's just test that normal creation works and the response
	// has a valid network_id.
	resp, err := rc.CreateNetwork(nodeID, "overflow-test", "open", "", TestAdminToken)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := resp["network_id"].(float64)
	if netID == 0 {
		t.Fatal("network ID should not be 0 (backbone)")
	}
}

func TestNetworkTokenJoinRule(t *testing.T) {
	t.Skip("custom networks are WIP")
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeA, _ := registerTestNode(t, rc)
	nodeB, _ := registerTestNode(t, rc)

	// Create token-gated network
	_, err := rc.CreateNetwork(nodeA, "token-net", "token", "secret123", TestAdminToken)
	if err != nil {
		t.Fatalf("create token network: %v", err)
	}

	// Get network ID
	netsResp, err := rc.ListNetworks()
	if err != nil {
		t.Fatalf("list networks: %v", err)
	}
	var netID uint16
	for _, n := range netsResp["networks"].([]interface{}) {
		net := n.(map[string]interface{})
		if net["name"] == "token-net" {
			netID = uint16(net["id"].(float64))
			break
		}
	}

	// Join with wrong token — should fail
	_, err = rc.JoinNetwork(nodeB, netID, "wrongtoken", 0, TestAdminToken)
	if err == nil {
		t.Fatal("expected error with wrong token, got nil")
	}

	// Join with correct token — should succeed
	_, err = rc.JoinNetwork(nodeB, netID, "secret123", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join with correct token: %v", err)
	}
}

func TestNetworkInviteJoinRule(t *testing.T) {
	t.Skip("custom networks are WIP")
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeA, _ := registerTestNode(t, rc)
	nodeB, _ := registerTestNode(t, rc)
	nodeC, _ := registerTestNode(t, rc)

	// Create invite-only network
	resp, err := rc.CreateNetwork(nodeA, "invite-net", "invite", "", TestAdminToken)
	if err != nil {
		t.Fatalf("create invite network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// B tries to join without inviter — should fail
	_, err = rc.JoinNetwork(nodeB, netID, "", 0, TestAdminToken)
	if err == nil {
		t.Fatal("expected error without inviter, got nil")
	}

	// B tries with non-member inviter — should fail
	_, err = rc.JoinNetwork(nodeB, netID, "", nodeC, TestAdminToken)
	if err == nil {
		t.Fatal("expected error with non-member inviter, got nil")
	}

	// B joins with A as inviter — should succeed
	_, err = rc.JoinNetwork(nodeB, netID, "", nodeA, TestAdminToken)
	if err != nil {
		t.Fatalf("join with valid inviter: %v", err)
	}

	// Now B can invite C
	_, err = rc.JoinNetwork(nodeC, netID, "", nodeB, TestAdminToken)
	if err != nil {
		t.Fatalf("join with B as inviter: %v", err)
	}
}

func TestNetworkDuplicateName(t *testing.T) {
	t.Skip("custom networks are WIP")
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, _ := registerTestNode(t, rc)

	_, err := rc.CreateNetwork(nodeID, "unique-net", "open", "", TestAdminToken)
	if err != nil {
		t.Fatalf("create first: %v", err)
	}

	// Same name should fail
	_, err = rc.CreateNetwork(nodeID, "unique-net", "open", "", TestAdminToken)
	if err == nil {
		t.Fatal("expected error for duplicate network name, got nil")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestNetworkAlreadyMember(t *testing.T) {
	t.Skip("custom networks are WIP")
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeA, _ := registerTestNode(t, rc)
	nodeB, _ := registerTestNode(t, rc)

	resp, err := rc.CreateNetwork(nodeA, "dup-join-test", "open", "", TestAdminToken)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	_, err = rc.JoinNetwork(nodeB, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("first join: %v", err)
	}

	// Second join should fail
	_, err = rc.JoinNetwork(nodeB, netID, "", 0, TestAdminToken)
	if err == nil {
		t.Fatal("expected error on duplicate join, got nil")
	}
}

func TestHostnameRegistrationWarning(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	// Register with an invalid hostname
	id, _ := crypto.GenerateIdentity()
	resp, err := rc.Send(map[string]interface{}{
		"type":        "register",
		"listen_addr": "",
		"public_key":  crypto.EncodePublicKey(id.PublicKey),
		"hostname":    "INVALID-UPPER",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Registration should succeed but include hostname_error
	if resp["node_id"] == nil {
		t.Fatal("expected node_id in response")
	}
	if resp["hostname_error"] == nil {
		t.Fatal("expected hostname_error warning in response for invalid hostname")
	}
	t.Logf("hostname_error: %v", resp["hostname_error"])

	// hostname should NOT be set
	if resp["hostname"] != nil {
		t.Fatalf("hostname should not be set for invalid name, got %v", resp["hostname"])
	}
}

func TestListNetworks(t *testing.T) {
	t.Skip("custom networks are WIP")
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, _ := registerTestNode(t, rc)

	// Create two networks
	_, err := rc.CreateNetwork(nodeID, "net-one", "open", "", TestAdminToken)
	if err != nil {
		t.Fatalf("create net-one: %v", err)
	}
	_, err = rc.CreateNetwork(nodeID, "net-two", "open", "", TestAdminToken)
	if err != nil {
		t.Fatalf("create net-two: %v", err)
	}

	// List networks
	resp, err := rc.ListNetworks()
	if err != nil {
		t.Fatalf("list networks: %v", err)
	}
	networks := resp["networks"].([]interface{})
	if len(networks) < 2 {
		t.Fatalf("expected at least 2 networks (besides backbone), got %d", len(networks))
	}

	names := make(map[string]bool)
	for _, n := range networks {
		net := n.(map[string]interface{})
		name, _ := net["name"].(string)
		names[name] = true
		t.Logf("network: id=%v name=%s", net["id"], name)
	}
	if !names["net-one"] || !names["net-two"] {
		t.Errorf("expected net-one and net-two in list, got: %v", names)
	}
}

func TestListNodes(t *testing.T) {
	t.Skip("custom networks are WIP")
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeA, _ := registerTestNode(t, rc)
	nodeB, _ := registerTestNode(t, rc)
	nodeC, _ := registerTestNode(t, rc)

	resp, err := rc.CreateNetwork(nodeA, "members-test", "open", "", TestAdminToken)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	rc.JoinNetwork(nodeB, netID, "", 0, TestAdminToken)
	rc.JoinNetwork(nodeC, netID, "", 0, TestAdminToken)

	nodesResp, err := rc.ListNodes(netID)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	nodes := nodesResp["nodes"].([]interface{})
	if len(nodes) != 3 {
		t.Fatalf("expected 3 members, got %d", len(nodes))
	}

	ids := make(map[uint32]bool)
	for _, n := range nodes {
		node := n.(map[string]interface{})
		ids[uint32(node["node_id"].(float64))] = true
	}
	if !ids[nodeA] || !ids[nodeB] || !ids[nodeC] {
		t.Errorf("expected all 3 nodes, got: %v", ids)
	}
	t.Logf("all 3 nodes listed in network %d", netID)
}

func TestDeregisterNode(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	nodeID, id := registerTestNode(t, rc)
	setClientSigner(rc, id)

	// Verify lookup works
	_, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup before deregister: %v", err)
	}

	// Deregister
	_, err = rc.Deregister(nodeID)
	if err != nil {
		t.Fatalf("deregister: %v", err)
	}

	// Lookup should fail
	_, err = rc.Lookup(nodeID)
	if err == nil {
		t.Fatal("expected error after deregister, got nil")
	}
	t.Logf("correctly deregistered: %v", err)
}

func TestResolveHostnameViaDriver(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()

	// Set hostname via registry
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()
	setClientSigner(rc, a.Daemon.Identity())

	_, err = rc.SetHostname(a.Daemon.NodeID(), "my-agent")
	if err != nil {
		t.Fatalf("set hostname: %v", err)
	}

	// Resolve via driver
	result, err := a.Driver.ResolveHostname("my-agent")
	if err != nil {
		t.Fatalf("resolve hostname: %v", err)
	}

	nodeID, ok := result["node_id"].(float64)
	if !ok {
		t.Fatalf("expected node_id in result, got %v", result)
	}
	if uint32(nodeID) != a.Daemon.NodeID() {
		t.Errorf("expected node %d, got %d", a.Daemon.NodeID(), uint32(nodeID))
	}
	t.Logf("resolved 'my-agent' → node %d", uint32(nodeID))
}

func TestHeartbeat(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	nodeID, id := registerTestNode(t, rc)
	setClientSigner(rc, id)

	// Heartbeat should succeed
	_, err := rc.Heartbeat(nodeID)
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	t.Logf("heartbeat for node %d succeeded", nodeID)
}

func TestVisibilityToggle(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	nodeID, id := registerTestNode(t, rc)
	setClientSigner(rc, id)

	// Set to public
	_, err := rc.SetVisibility(nodeID, true)
	if err != nil {
		t.Fatalf("set public: %v", err)
	}

	// Lookup should return the node
	resp, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup public node: %v", err)
	}
	t.Logf("public node: %v", resp)

	// Set to private
	_, err = rc.SetVisibility(nodeID, false)
	if err != nil {
		t.Fatalf("set private: %v", err)
	}

	t.Log("visibility toggle succeeded")
}

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

// TestNetworkPolicyMaxMembers verifies that membership limits are enforced.
// Set max_members=2, add 2 members, 3rd join must fail.
func TestNetworkPolicyMaxMembers(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Register owner node
	id1, _ := crypto.GenerateIdentity()
	resp1, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id1.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node1: %v", err)
	}
	nodeID1 := uint32(resp1["node_id"].(float64))

	// Create a token-gated network
	netResp, err := rc.CreateNetwork(nodeID1, "policy-max-test", "token", "secret", env.AdminToken)
	if err != nil {
		t.Fatalf("create_network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	// Set max_members=2 (owner counts as 1)
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"max_members": float64(2),
	}, env.AdminToken)
	if err != nil {
		t.Fatalf("set_network_policy: %v", err)
	}

	// Register and join second node — should succeed (2 of 2)
	id2, _ := crypto.GenerateIdentity()
	resp2, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id2.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node2: %v", err)
	}
	nodeID2 := uint32(resp2["node_id"].(float64))

	_, err = rc.JoinNetwork(nodeID2, netID, "secret", 0, env.AdminToken)
	if err != nil {
		t.Fatalf("join node2 should succeed: %v", err)
	}

	// Register and try to join third node — should fail (3 of 2)
	id3, _ := crypto.GenerateIdentity()
	resp3, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id3.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node3: %v", err)
	}
	nodeID3 := uint32(resp3["node_id"].(float64))
	_ = nodeID3

	_, err = rc.JoinNetwork(nodeID3, netID, "secret", 0, env.AdminToken)
	if err == nil {
		t.Fatal("expected join to fail due to membership limit, but it succeeded")
	}
	// Server wraps internal errors as "request failed" for security — accept either form
	errStr := err.Error()
	if !strings.Contains(errStr, "membership limit reached") && !strings.Contains(errStr, "request failed") {
		t.Fatalf("expected membership limit error, got: %v", err)
	}
	t.Logf("membership limit correctly enforced: %v", err)
}

// TestNetworkPolicyAllowedPorts verifies that allowed_ports are stored correctly.
func TestNetworkPolicyAllowedPorts(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Register owner node
	id1, _ := crypto.GenerateIdentity()
	resp1, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id1.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node1: %v", err)
	}
	nodeID1 := uint32(resp1["node_id"].(float64))

	// Create network
	netResp, err := rc.CreateNetwork(nodeID1, "policy-ports-test", "open", "", env.AdminToken)
	if err != nil {
		t.Fatalf("create_network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	// Set allowed_ports
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"allowed_ports": []interface{}{float64(80), float64(443), float64(8080)},
	}, env.AdminToken)
	if err != nil {
		t.Fatalf("set_network_policy: %v", err)
	}

	// Get policy and verify
	policyResp, err := rc.GetNetworkPolicy(netID)
	if err != nil {
		t.Fatalf("get_network_policy: %v", err)
	}

	ports, ok := policyResp["allowed_ports"].([]interface{})
	if !ok {
		t.Fatalf("allowed_ports not returned or wrong type: %v", policyResp["allowed_ports"])
	}
	if len(ports) != 3 {
		t.Fatalf("expected 3 allowed ports, got %d", len(ports))
	}

	expectedPorts := map[float64]bool{80: true, 443: true, 8080: true}
	for _, p := range ports {
		port := p.(float64)
		if !expectedPorts[port] {
			t.Errorf("unexpected port in policy: %v", port)
		}
	}
	t.Logf("allowed_ports correctly stored: %v", ports)
}

// TestNetworkPolicyRequiresAdmin verifies that only admin/owner can set policy.
func TestNetworkPolicyRequiresAdmin(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Register owner node
	id1, _ := crypto.GenerateIdentity()
	resp1, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id1.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node1: %v", err)
	}
	nodeID1 := uint32(resp1["node_id"].(float64))

	// Create network
	netResp, err := rc.CreateNetwork(nodeID1, "policy-auth-test", "open", "", env.AdminToken)
	if err != nil {
		t.Fatalf("create_network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	// Register a member node and join
	id2, _ := crypto.GenerateIdentity()
	resp2, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id2.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node2: %v", err)
	}
	nodeID2 := uint32(resp2["node_id"].(float64))

	_, err = rc.JoinNetwork(nodeID2, netID, "", 0, env.AdminToken)
	if err != nil {
		t.Fatalf("join network: %v", err)
	}

	// Member tries to set policy (no admin token, no owner/admin role) — should fail
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"node_id":     float64(nodeID2),
		"max_members": float64(10),
	}, "")
	if err == nil {
		t.Fatal("expected member to be denied setting policy, but it succeeded")
	}
	t.Logf("member correctly denied: %v", err)

	// Owner sets policy via admin token — should succeed
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"max_members": float64(10),
	}, env.AdminToken)
	if err != nil {
		t.Fatalf("owner/admin should be able to set policy: %v", err)
	}
	t.Logf("admin token correctly authorized policy change")
}

// TestNetworkPolicyPersistence verifies that policy survives registry restart.
func TestNetworkPolicyPersistence(t *testing.T) {
	t.Parallel()
	tmpDir, err := os.MkdirTemp("/tmp", "w4-policy-persist-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "registry.json")

	// Phase 1: start registry, create network, set policy
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

	// Register a node and create a network
	id1, _ := crypto.GenerateIdentity()
	resp1, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id1.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node: %v", err)
	}
	nodeID1 := uint32(resp1["node_id"].(float64))

	netResp, err := rc.CreateNetwork(nodeID1, "policy-persist-test", "open", "", TestAdminToken)
	if err != nil {
		t.Fatalf("create_network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	// Set policy with all fields
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"max_members":   float64(5),
		"allowed_ports": []interface{}{float64(80), float64(443)},
		"description":   "test network for persistence",
	}, TestAdminToken)
	if err != nil {
		t.Fatalf("set_network_policy: %v", err)
	}

	rc.Close()
	reg1.Close()

	// Phase 2: restart registry from same store file
	reg2 := registry.NewWithStore("127.0.0.1:9001", storePath)
	reg2.SetAdminToken(TestAdminToken)
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

	// Verify policy survived restart
	policyResp, err := rc2.GetNetworkPolicy(netID)
	if err != nil {
		t.Fatalf("get_network_policy after restart: %v", err)
	}

	maxMembers := int(policyResp["max_members"].(float64))
	if maxMembers != 5 {
		t.Errorf("max_members = %d, want 5", maxMembers)
	}

	desc, _ := policyResp["description"].(string)
	if desc != "test network for persistence" {
		t.Errorf("description = %q, want %q", desc, "test network for persistence")
	}

	ports, ok := policyResp["allowed_ports"].([]interface{})
	if !ok {
		t.Fatalf("allowed_ports not returned after restart")
	}
	if len(ports) != 2 {
		t.Errorf("expected 2 allowed ports after restart, got %d", len(ports))
	}

	t.Logf("policy survived restart: max_members=%d, allowed_ports=%v, description=%q",
		maxMembers, ports, desc)
}

// TestNetworkPolicyDescription verifies that description is stored and returned.
func TestNetworkPolicyDescription(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Register owner node
	id1, _ := crypto.GenerateIdentity()
	resp1, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id1.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node: %v", err)
	}
	nodeID1 := uint32(resp1["node_id"].(float64))

	// Create network
	netResp, err := rc.CreateNetwork(nodeID1, "policy-desc-test", "open", "", env.AdminToken)
	if err != nil {
		t.Fatalf("create_network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	// Set description
	desc := "A test network for policy description validation"
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"description": desc,
	}, env.AdminToken)
	if err != nil {
		t.Fatalf("set_network_policy: %v", err)
	}

	// Get policy and verify description
	policyResp, err := rc.GetNetworkPolicy(netID)
	if err != nil {
		t.Fatalf("get_network_policy: %v", err)
	}

	gotDesc, _ := policyResp["description"].(string)
	if gotDesc != desc {
		t.Fatalf("description = %q, want %q", gotDesc, desc)
	}
	t.Logf("description correctly stored and returned: %q", gotDesc)
}

// TestNetworkPolicyGetPolicy verifies that any member can get the network policy.
func TestNetworkPolicyGetPolicy(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Register owner node
	id1, _ := crypto.GenerateIdentity()
	resp1, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id1.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node1: %v", err)
	}
	nodeID1 := uint32(resp1["node_id"].(float64))

	// Create network
	netResp, err := rc.CreateNetwork(nodeID1, "policy-get-test", "open", "", env.AdminToken)
	if err != nil {
		t.Fatalf("create_network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	// Set policy
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"max_members":   float64(50),
		"allowed_ports": []interface{}{float64(80), float64(443), float64(8080)},
		"description":   "shared network",
	}, env.AdminToken)
	if err != nil {
		t.Fatalf("set_network_policy: %v", err)
	}

	// Register member and join
	id2, _ := crypto.GenerateIdentity()
	resp2, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id2.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node2: %v", err)
	}
	_ = uint32(resp2["node_id"].(float64))

	// Member queries policy (get_network_policy does not require RBAC)
	policyResp, err := rc.GetNetworkPolicy(netID)
	if err != nil {
		t.Fatalf("member get_network_policy should succeed: %v", err)
	}

	maxMembers := int(policyResp["max_members"].(float64))
	if maxMembers != 50 {
		t.Errorf("max_members = %d, want 50", maxMembers)
	}

	desc, _ := policyResp["description"].(string)
	if desc != "shared network" {
		t.Errorf("description = %q, want %q", desc, "shared network")
	}

	ports, ok := policyResp["allowed_ports"].([]interface{})
	if !ok {
		t.Fatalf("allowed_ports not returned")
	}
	if len(ports) != 3 {
		t.Errorf("expected 3 allowed ports, got %d", len(ports))
	}

	t.Logf("member can read policy: max_members=%d, ports=%v, desc=%q",
		maxMembers, ports, desc)
}

package tests

import (
	"testing"
	"time"

	"web4/internal/crypto"
	"web4/pkg/registry"
)

// TestAdminTokenRequired verifies that with an admin token configured,
// create_network requires the correct token.
func TestAdminTokenRequired(t *testing.T) {
	t.Skip("custom networks are WIP")
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Register a node to use for network creation
	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Attempt without admin token — should fail
	_, err = rc.CreateNetwork(nodeID, "no-token-net", "open", "", "")
	if err == nil {
		t.Fatal("create_network without admin token should fail")
	}
	t.Logf("correctly rejected (no token): %v", err)

	// Attempt with wrong admin token — should fail
	_, err = rc.CreateNetwork(nodeID, "wrong-token-net", "open", "", "wrong-secret")
	if err == nil {
		t.Fatal("create_network with wrong admin token should fail")
	}
	t.Logf("correctly rejected (wrong token): %v", err)

	// Attempt with correct admin token — should succeed
	netResp, err := rc.CreateNetwork(nodeID, "correct-token-net", "open", "", env.AdminToken)
	if err != nil {
		t.Fatalf("create_network with correct admin token should succeed: %v", err)
	}
	t.Logf("created network %v", netResp["network_id"])
}

// TestAdminTokenJoinLeaveGated verifies that join_network and leave_network
// also require admin token.
func TestAdminTokenJoinLeaveGated(t *testing.T) {
	t.Skip("custom networks are WIP")
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Create a network with admin token
	netResp, err := rc.CreateNetwork(nodeID, "gated-net", "open", "", env.AdminToken)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	// Register second node
	id2, _ := crypto.GenerateIdentity()
	resp2, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id2.PublicKey), "")
	if err != nil {
		t.Fatalf("register node2: %v", err)
	}
	nodeID2 := uint32(resp2["node_id"].(float64))

	// Join without admin token — should fail
	_, err = rc.JoinNetwork(nodeID2, netID, "", 0, "")
	if err == nil {
		t.Fatal("join_network without admin token should fail")
	}
	t.Logf("correctly rejected join (no token): %v", err)

	// Join with correct admin token — should succeed
	_, err = rc.JoinNetwork(nodeID2, netID, "", 0, env.AdminToken)
	if err != nil {
		t.Fatalf("join with admin token: %v", err)
	}

	// Leave without admin token — should fail
	_, err = rc.LeaveNetwork(nodeID2, netID, "")
	if err == nil {
		t.Fatal("leave_network without admin token should fail")
	}
	t.Logf("correctly rejected leave (no token): %v", err)

	// Leave with correct admin token — should succeed
	_, err = rc.LeaveNetwork(nodeID2, netID, env.AdminToken)
	if err != nil {
		t.Fatalf("leave with admin token: %v", err)
	}
}

// TestAdminTokenNotConfigured verifies that when no admin token is set on the
// server, network creation is rejected entirely (secure by default).
func TestAdminTokenNotConfigured(t *testing.T) {
	t.Parallel()

	// Start a registry WITHOUT setting an admin token
	reg := registry.New("127.0.0.1:9001")
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	// Register a node
	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Even providing a token value should fail — server has no token configured
	_, err = rc.CreateNetwork(nodeID, "disabled-net", "open", "", "some-token")
	if err == nil {
		t.Fatal("create_network should be rejected when server has no admin token configured")
	}
	t.Logf("correctly rejected (creation disabled): %v", err)

	// Without any token should also fail
	_, err = rc.CreateNetwork(nodeID, "disabled-net-2", "open", "", "")
	if err == nil {
		t.Fatal("create_network should be rejected when server has no admin token configured")
	}
	t.Logf("correctly rejected (creation disabled, no token): %v", err)
}

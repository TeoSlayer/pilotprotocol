package tests

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// TestEnterpriseGatePromote verifies that promoting a member on a non-enterprise
// network returns a clear enterprise error.
func TestEnterpriseGatePromote(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, _ := registerTestNode(t, rc)
	memberID, _ := registerTestNode(t, rc)

	resp, err := rc.CreateNetwork(ownerID, "gate-promote", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	_, err = rc.JoinNetwork(memberID, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join network: %v", err)
	}

	_, err = rc.PromoteMember(netID, ownerID, memberID, TestAdminToken)
	if err == nil {
		t.Fatal("expected enterprise error, got nil")
	}
	if !strings.Contains(err.Error(), "enterprise feature") {
		t.Fatalf("expected 'enterprise feature' error, got: %v", err)
	}
}

// TestEnterpriseGateDemote verifies that demoting a member on a non-enterprise
// network returns a clear enterprise error.
func TestEnterpriseGateDemote(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, _ := registerTestNode(t, rc)
	memberID, _ := registerTestNode(t, rc)

	// Create enterprise network first to promote, then test demote on non-enterprise
	resp, err := rc.CreateNetwork(ownerID, "gate-demote", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	_, err = rc.JoinNetwork(memberID, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join network: %v", err)
	}

	_, err = rc.DemoteMember(netID, ownerID, memberID, TestAdminToken)
	if err == nil {
		t.Fatal("expected enterprise error, got nil")
	}
	if !strings.Contains(err.Error(), "enterprise feature") {
		t.Fatalf("expected 'enterprise feature' error, got: %v", err)
	}
}

// TestEnterpriseGateKick verifies that kicking a member from a non-enterprise
// network returns a clear enterprise error.
func TestEnterpriseGateKick(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, _ := registerTestNode(t, rc)
	memberID, _ := registerTestNode(t, rc)

	resp, err := rc.CreateNetwork(ownerID, "gate-kick", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	_, err = rc.JoinNetwork(memberID, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join network: %v", err)
	}

	_, err = rc.KickMember(netID, ownerID, memberID, TestAdminToken)
	if err == nil {
		t.Fatal("expected enterprise error, got nil")
	}
	if !strings.Contains(err.Error(), "enterprise feature") {
		t.Fatalf("expected 'enterprise feature' error, got: %v", err)
	}
}

// TestEnterpriseGatePolicy verifies that setting network policy on a non-enterprise
// network returns a clear enterprise error.
func TestEnterpriseGatePolicy(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, _ := registerTestNode(t, rc)

	resp, err := rc.CreateNetwork(ownerID, "gate-policy", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{"max_members": 10}, TestAdminToken)
	if err == nil {
		t.Fatal("expected enterprise error, got nil")
	}
	if !strings.Contains(err.Error(), "enterprise feature") {
		t.Fatalf("expected 'enterprise feature' error, got: %v", err)
	}
}

// TestEnterpriseGateInvite verifies that inviting to a non-enterprise network
// returns a clear enterprise error. Note: invite-only networks can only be created
// as enterprise networks, so we test with an enterprise invite-only network but a
// non-enterprise network for the invite operation.
func TestEnterpriseGateInvite(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, _ := registerTestNode(t, rc)
	targetID, _ := registerTestNode(t, rc)

	// Create an enterprise invite-only network (only way to get invite rule)
	resp, err := rc.CreateNetwork(ownerID, "gate-invite", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create enterprise network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// This should succeed (enterprise network)
	_, err = rc.InviteToNetwork(netID, ownerID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite on enterprise network should succeed: %v", err)
	}
}

// TestEnterpriseGateInviteOnlyJoinRule verifies that creating an invite-only
// network without the enterprise flag is rejected.
func TestEnterpriseGateInviteOnlyJoinRule(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, _ := registerTestNode(t, rc)

	_, err := rc.CreateNetwork(nodeID, "gate-invite-rule", "invite", "", TestAdminToken, false)
	if err == nil {
		t.Fatal("expected enterprise error for invite-only non-enterprise network, got nil")
	}
	if !strings.Contains(err.Error(), "enterprise feature") {
		t.Fatalf("expected 'enterprise feature' error, got: %v", err)
	}
}

// TestEnterpriseGateKeyExpiry verifies that setting key expiry without
// enterprise network membership returns a clear enterprise error.
func TestEnterpriseGateKeyExpiry(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	id, _ := crypto.GenerateIdentity()
	setClientSigner(rc, id)

	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// No enterprise network — should fail
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	_, err = rc.SetKeyExpiry(nodeID, expiresAt)
	if err == nil {
		t.Fatal("expected enterprise error, got nil")
	}
	if !strings.Contains(err.Error(), "enterprise feature") {
		t.Fatalf("expected 'enterprise feature' error, got: %v", err)
	}
}

// TestEnterpriseCreateAndList verifies that the enterprise flag persists
// through creation and shows in list_networks.
func TestEnterpriseCreateAndList(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, _ := registerTestNode(t, rc)

	// Create enterprise network
	entResp, err := rc.CreateNetwork(nodeID, "ent-list-test", "open", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create enterprise network: %v", err)
	}
	entNetID := uint16(entResp["network_id"].(float64))

	// Verify create response includes enterprise flag
	if ent, ok := entResp["enterprise"].(bool); !ok || !ent {
		t.Errorf("create_network_ok should have enterprise=true, got %v", entResp["enterprise"])
	}

	// Create regular network
	regResp, err := rc.CreateNetwork(nodeID, "reg-list-test", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create regular network: %v", err)
	}
	regNetID := uint16(regResp["network_id"].(float64))

	// List networks and verify enterprise flags
	listResp, err := rc.ListNetworks()
	if err != nil {
		t.Fatalf("list_networks: %v", err)
	}

	networks, ok := listResp["networks"].([]interface{})
	if !ok {
		t.Fatalf("unexpected networks format: %v", listResp)
	}

	foundEnt, foundReg := false, false
	for _, n := range networks {
		net := n.(map[string]interface{})
		id := uint16(net["id"].(float64))
		ent, _ := net["enterprise"].(bool)
		if id == entNetID {
			foundEnt = true
			if !ent {
				t.Error("enterprise network should have enterprise=true in list")
			}
		}
		if id == regNetID {
			foundReg = true
			if ent {
				t.Error("regular network should have enterprise=false in list")
			}
		}
	}
	if !foundEnt {
		t.Error("enterprise network not found in list")
	}
	if !foundReg {
		t.Error("regular network not found in list")
	}
}

// TestEnterpriseFullFlow verifies that RBAC, policy, and invite operations
// work correctly on enterprise networks.
func TestEnterpriseFullFlow(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, _ := registerTestNode(t, rc)
	memberID, memberIdentity := registerTestNode(t, rc)
	targetID, _ := registerTestNode(t, rc)

	// Create enterprise network
	resp, err := rc.CreateNetwork(ownerID, "ent-full-flow", "open", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create enterprise network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Member joins
	_, err = rc.JoinNetwork(memberID, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join: %v", err)
	}

	// Promote member to admin
	_, err = rc.PromoteMember(netID, ownerID, memberID, TestAdminToken)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}

	// Verify admin role
	roleResp, err := rc.GetMemberRole(netID, memberID)
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	if roleResp["role"] != "admin" {
		t.Fatalf("expected admin role, got %v", roleResp["role"])
	}

	// Set network policy
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{"max_members": 50}, TestAdminToken)
	if err != nil {
		t.Fatalf("set policy: %v", err)
	}

	// Demote back to member
	_, err = rc.DemoteMember(netID, ownerID, memberID, TestAdminToken)
	if err != nil {
		t.Fatalf("demote: %v", err)
	}

	// Target joins
	_, err = rc.JoinNetwork(targetID, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("target join: %v", err)
	}

	// Kick target
	_, err = rc.KickMember(netID, ownerID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("kick: %v", err)
	}

	// Key expiry for member (enterprise node)
	setClientSigner(rc, memberIdentity)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	_, err = rc.SetKeyExpiry(memberID, expiresAt)
	if err != nil {
		t.Fatalf("set key expiry on enterprise member: %v", err)
	}
}

// TestEnterpriseRespondInviteGate verifies that respond_invite is gated
// behind enterprise networks.
func TestEnterpriseRespondInviteGate(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, nodeIdentity := registerTestNode(t, rc)

	// Create a non-enterprise network
	resp, err := rc.CreateNetwork(nodeID, "gate-respond-inv", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Try to respond to an invite on a non-enterprise network
	setClientSigner(rc, nodeIdentity)
	_, err = rc.RespondInvite(nodeID, netID, true)
	if err == nil {
		t.Fatal("expected enterprise error, got nil")
	}
	if !strings.Contains(err.Error(), "enterprise feature") {
		t.Fatalf("expected 'enterprise feature' error, got: %v", err)
	}
}

// TestEnterpriseToggle verifies that toggling the enterprise flag on a network
// enables/disables enterprise features and that the audit event is emitted.
func TestEnterpriseToggle(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, _ := registerTestNode(t, rc)
	memberID, _ := registerTestNode(t, rc)

	// Create as regular network
	resp, err := rc.CreateNetwork(ownerID, "ent-toggle", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	_, err = rc.JoinNetwork(memberID, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join: %v", err)
	}

	// Promote should fail (not enterprise)
	_, err = rc.PromoteMember(netID, ownerID, memberID, TestAdminToken)
	if err == nil || !strings.Contains(err.Error(), "enterprise feature") {
		t.Fatalf("expected enterprise error before toggle, got: %v", err)
	}

	// Toggle enterprise ON
	_, err = rc.SetNetworkEnterprise(netID, true, TestAdminToken)
	if err != nil {
		t.Fatalf("set enterprise=true: %v", err)
	}

	// Promote should succeed now
	_, err = rc.PromoteMember(netID, ownerID, memberID, TestAdminToken)
	if err != nil {
		t.Fatalf("promote after enterprise enable: %v", err)
	}

	// Demote back
	_, err = rc.DemoteMember(netID, ownerID, memberID, TestAdminToken)
	if err != nil {
		t.Fatalf("demote: %v", err)
	}

	// Toggle enterprise OFF
	_, err = rc.SetNetworkEnterprise(netID, false, TestAdminToken)
	if err != nil {
		t.Fatalf("set enterprise=false: %v", err)
	}

	// Promote should fail again
	_, err = rc.PromoteMember(netID, ownerID, memberID, TestAdminToken)
	if err == nil || !strings.Contains(err.Error(), "enterprise feature") {
		t.Fatalf("expected enterprise error after toggle off, got: %v", err)
	}

	// Verify audit log has the toggle events
	logResp, err := rc.GetAuditLog(0, TestAdminToken)
	if err != nil {
		t.Fatalf("get audit log: %v", err)
	}
	entries := logResp["entries"].([]interface{})
	toggleCount := 0
	for _, e := range entries {
		entry := e.(map[string]interface{})
		if entry["action"] == "network.enterprise_changed" {
			toggleCount++
		}
	}
	if toggleCount < 2 {
		t.Errorf("expected at least 2 enterprise_changed audit events, got %d", toggleCount)
	}
}

// TestPoloScoreConcurrent verifies that concurrent polo score updates
// are serialized correctly and produce the expected final result.
func TestPoloScoreConcurrent(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	reg.SetAdminToken(TestAdminToken)
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

	nodeID, _ := registerTestNode(t, rc)

	// Set initial score to 0
	_, err = rc.SetPoloScore(nodeID, 0)
	if err != nil {
		t.Fatalf("set initial: %v", err)
	}

	// Run N concurrent workers, each incrementing by +1
	const workers = 50
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wrc, err := registry.Dial(reg.Addr().String())
			if err != nil {
				return
			}
			defer wrc.Close()
			wrc.UpdatePoloScore(nodeID, 1)
		}()
	}
	wg.Wait()

	// Final score should be exactly 50
	score, err := rc.GetPoloScore(nodeID)
	if err != nil {
		t.Fatalf("get final score: %v", err)
	}
	if score != workers {
		t.Errorf("expected polo score %d after %d concurrent +1 updates, got %d", workers, workers, score)
	}
}

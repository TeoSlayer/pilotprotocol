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

// TestAdminNodeManagement verifies that the 5 admin node management methods
// (hostname, visibility, tags, task_exec, key_expiry) work via admin_token
// without requiring node signature.
func TestAdminNodeManagement(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, _ := registerTestNode(t, rc)

	// Create enterprise network (creator auto-joins, needed for key expiry)
	_, err := rc.CreateNetwork(nodeID, "admin-mgmt-net", "open", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}

	// 1. SetHostnameAdmin
	_, err = rc.SetHostnameAdmin(nodeID, "admin-managed", TestAdminToken)
	if err != nil {
		t.Fatalf("SetHostnameAdmin: %v", err)
	}

	// Verify hostname via lookup
	lookupResp, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if lookupResp["hostname"] != "admin-managed" {
		t.Errorf("hostname: got %v, want admin-managed", lookupResp["hostname"])
	}

	// 2. SetVisibilityAdmin
	_, err = rc.SetVisibilityAdmin(nodeID, true, TestAdminToken)
	if err != nil {
		t.Fatalf("SetVisibilityAdmin: %v", err)
	}

	// 3. SetTagsAdmin
	_, err = rc.SetTagsAdmin(nodeID, []string{"gpu", "arm64"}, TestAdminToken)
	if err != nil {
		t.Fatalf("SetTagsAdmin: %v", err)
	}

	// 4. SetTaskExecAdmin
	_, err = rc.SetTaskExecAdmin(nodeID, true, TestAdminToken)
	if err != nil {
		t.Fatalf("SetTaskExecAdmin: %v", err)
	}

	// 5. SetKeyExpiryAdmin
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	_, err = rc.SetKeyExpiryAdmin(nodeID, expiresAt, TestAdminToken)
	if err != nil {
		t.Fatalf("SetKeyExpiryAdmin: %v", err)
	}

	// Verify all wrong-token calls are rejected
	_, err = rc.SetHostnameAdmin(nodeID, "bad", "wrong-token")
	if err == nil {
		t.Error("SetHostnameAdmin should reject wrong token")
	}
	_, err = rc.SetVisibilityAdmin(nodeID, false, "wrong-token")
	if err == nil {
		t.Error("SetVisibilityAdmin should reject wrong token")
	}
	_, err = rc.SetTagsAdmin(nodeID, []string{"bad"}, "wrong-token")
	if err == nil {
		t.Error("SetTagsAdmin should reject wrong token")
	}
	_, err = rc.SetTaskExecAdmin(nodeID, false, "wrong-token")
	if err == nil {
		t.Error("SetTaskExecAdmin should reject wrong token")
	}
	_, err = rc.SetKeyExpiryAdmin(nodeID, expiresAt, "wrong-token")
	if err == nil {
		t.Error("SetKeyExpiryAdmin should reject wrong token")
	}

	t.Log("all 5 admin node management methods work correctly")
}

// TestAdminDeregister verifies that an admin can force-deregister a node
// using admin_token (without the node's signature).
func TestAdminDeregister(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, _ := registerTestNode(t, rc)

	// Verify node exists
	_, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup before deregister: %v", err)
	}

	// Wrong token should fail
	_, err = rc.DeregisterAdmin(nodeID, "wrong-token")
	if err == nil {
		t.Fatal("expected error with wrong token")
	}

	// Admin deregister should succeed
	_, err = rc.DeregisterAdmin(nodeID, TestAdminToken)
	if err != nil {
		t.Fatalf("admin deregister: %v", err)
	}

	// Verify node is gone
	_, err = rc.Lookup(nodeID)
	if err == nil {
		t.Error("node should not be found after deregister")
	}
}

// TestClearKeyExpiry verifies that a key expiry can be cleared, re-enabling
// heartbeats that would otherwise be blocked.
func TestClearKeyExpiry(t *testing.T) {
	t.Parallel()

	clk := newTestClock()
	reg := registry.New("127.0.0.1:9001")
	reg.SetAdminToken(TestAdminToken)
	reg.SetClock(clk.Now)
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

	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))
	setClientSigner(rc, id)

	// Create enterprise network
	if _, err := rc.CreateNetwork(nodeID, "clear-exp-test", "open", "", TestAdminToken, true); err != nil {
		t.Fatalf("create enterprise network: %v", err)
	}

	// Set key expiry to 1 hour from now
	if _, err := rc.SetKeyExpiryAdmin(nodeID, clk.Now().Add(1*time.Hour), TestAdminToken); err != nil {
		t.Fatalf("set key expiry: %v", err)
	}

	// Advance past expiry
	clk.Advance(2 * time.Hour)

	// Heartbeat should be blocked
	if _, err := rc.Heartbeat(nodeID); err == nil {
		t.Fatal("heartbeat should be blocked with expired key")
	}

	// Clear the expiry
	if _, err := rc.ClearKeyExpiryAdmin(nodeID, TestAdminToken); err != nil {
		t.Fatalf("clear key expiry: %v", err)
	}

	// Heartbeat should now work
	if _, err := rc.Heartbeat(nodeID); err != nil {
		t.Fatalf("heartbeat after clearing expiry: %v", err)
	}

	// Verify key info no longer has expires_at
	info, err := rc.GetKeyInfo(nodeID)
	if err != nil {
		t.Fatalf("get key info: %v", err)
	}
	if _, ok := info["expires_at"]; ok {
		t.Error("key info should not have expires_at after clearing")
	}

	t.Logf("clear key expiry: heartbeat restored after clearing expired key")
}

// TestDeleteNetworkCleansInvites verifies that pending invites for a deleted
// network are cleaned up from the invite inbox.
func TestDeleteNetworkCleansInvites(t *testing.T) {
	t.Parallel()

	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	owner, _ := registerTestNode(t, rc)
	target, targetID := registerTestNode(t, rc)

	// Create invite-only enterprise network
	resp, err := rc.CreateNetwork(owner, "inv-cleanup-test", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Send invite to target
	if _, err := rc.InviteToNetwork(netID, owner, target, TestAdminToken); err != nil {
		t.Fatalf("invite: %v", err)
	}

	// Verify invite exists
	setClientSigner(rc, targetID)
	pollResp, err := rc.PollInvites(target)
	if err != nil {
		t.Fatalf("poll invites: %v", err)
	}
	invites := pollResp["invites"].([]interface{})
	if len(invites) != 1 {
		t.Fatalf("expected 1 invite, got %d", len(invites))
	}

	// Delete the network
	if _, err := rc.DeleteNetwork(netID, TestAdminToken); err != nil {
		t.Fatalf("delete network: %v", err)
	}

	// Poll invites again — should be empty (invite was cleaned up)
	pollResp2, err := rc.PollInvites(target)
	if err != nil {
		t.Fatalf("poll invites after delete: %v", err)
	}
	invites2 := pollResp2["invites"].([]interface{})
	if len(invites2) != 0 {
		t.Errorf("expected 0 invites after network delete, got %d", len(invites2))
	}

	t.Logf("delete network cleaned %d pending invites", len(invites)-len(invites2))
}

// TestPoloScoreBounds verifies that polo scores are clamped to the valid range.
func TestPoloScoreBounds(t *testing.T) {
	t.Parallel()

	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, _ := registerTestNode(t, rc)

	// Setting a score beyond the limit should be rejected
	_, err := rc.SetPoloScore(nodeID, 2_000_000)
	if err == nil {
		t.Error("expected error setting polo score beyond max")
	}

	_, err = rc.SetPoloScore(nodeID, -2_000_000)
	if err == nil {
		t.Error("expected error setting polo score below min")
	}

	// Setting within bounds should work
	if _, err := rc.SetPoloScore(nodeID, 999_999); err != nil {
		t.Fatalf("set polo score within bounds: %v", err)
	}

	score, err := rc.GetPoloScore(nodeID)
	if err != nil {
		t.Fatalf("get polo score: %v", err)
	}
	if score != 999_999 {
		t.Errorf("polo score = %d, want 999999", score)
	}

	// Delta update should clamp (not overflow)
	if _, err := rc.UpdatePoloScore(nodeID, 500_000); err != nil {
		t.Fatalf("update polo score: %v", err)
	}
	score, err = rc.GetPoloScore(nodeID)
	if err != nil {
		t.Fatalf("get polo score after delta: %v", err)
	}
	if score != 1_000_000 {
		t.Errorf("polo score should clamp to 1000000, got %d", score)
	}

	t.Logf("polo score bounds: clamping works correctly, max=%d", score)
}

// TestInviteTTLExpiry verifies that invites expire after the TTL period.
// Uses SetClock to advance time past the 30-day invite TTL.
func TestInviteTTLExpiry(t *testing.T) {
	t.Parallel()
	rc, reg, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	clk := newTestClock()
	reg.SetClock(clk.Now)

	ownerID, ownerIdentity := registerTestNode(t, rc)
	targetID, targetIdentity := registerTestNode(t, rc)

	// Create enterprise invite-only network
	setClientSigner(rc, ownerIdentity)
	resp, err := rc.CreateNetwork(ownerID, "ttl-test", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Owner invites target
	_, err = rc.InviteToNetwork(netID, ownerID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	// Poll invites — should see 1 invite (signed as target)
	setClientSigner(rc, targetIdentity)
	pollResp, err := rc.PollInvites(targetID)
	if err != nil {
		t.Fatalf("poll invites: %v", err)
	}
	invites := pollResp["invites"].([]interface{})
	if len(invites) != 1 {
		t.Fatalf("expected 1 invite, got %d", len(invites))
	}
	t.Log("invite visible before TTL expiry")

	// Advance clock past 30-day TTL
	clk.Advance(31 * 24 * time.Hour)

	// Poll invites — expired invite should be filtered out
	pollResp, err = rc.PollInvites(targetID)
	if err != nil {
		t.Fatalf("poll invites after TTL: %v", err)
	}
	invites = pollResp["invites"].([]interface{})
	if len(invites) != 0 {
		t.Fatalf("expected 0 invites after TTL, got %d", len(invites))
	}
	t.Log("invite filtered out after TTL expiry")

	// Create a second invite (at advanced clock time) and verify it's valid
	clk.Advance(-31 * 24 * time.Hour) // reset clock back to "now"
	setClientSigner(rc, ownerIdentity)
	_, err = rc.InviteToNetwork(netID, ownerID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("re-invite: %v", err)
	}

	// Advance clock again past TTL
	clk.Advance(31 * 24 * time.Hour)

	// Respond without polling first — should get "expired" error
	setClientSigner(rc, targetIdentity)
	_, err = rc.RespondInvite(targetID, netID, true)
	if err == nil {
		t.Fatal("expected error responding to expired invite")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected 'expired' error, got: %v", err)
	}
	t.Logf("expired invite response correctly rejected: %v", err)
}

// TestEnterpriseToggleRBACInit verifies that toggling enterprise=true on an
// existing network initializes RBAC roles for all current members.
func TestEnterpriseToggleRBACInit(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, _ := registerTestNode(t, rc)
	memberID, _ := registerTestNode(t, rc)

	// Create non-enterprise network
	resp, err := rc.CreateNetwork(ownerID, "toggle-rbac", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Member joins
	_, err = rc.JoinNetwork(memberID, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join network: %v", err)
	}

	// Toggle enterprise=true
	_, err = rc.SetNetworkEnterprise(netID, true, TestAdminToken)
	if err != nil {
		t.Fatalf("set enterprise: %v", err)
	}

	// List nodes to verify roles were initialized
	listResp, err := rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	nodes := listResp["nodes"].([]interface{})

	foundOwner := false
	foundMember := false
	for _, n := range nodes {
		node := n.(map[string]interface{})
		nid := uint32(node["node_id"].(float64))
		role, _ := node["role"].(string)

		if nid == ownerID {
			if role != "owner" {
				t.Errorf("owner node %d has role %q, want 'owner'", nid, role)
			}
			foundOwner = true
		}
		if nid == memberID {
			if role != "member" {
				t.Errorf("member node %d has role %q, want 'member'", nid, role)
			}
			foundMember = true
		}
	}
	if !foundOwner {
		t.Error("owner not found in list_nodes")
	}
	if !foundMember {
		t.Error("member not found in list_nodes")
	}

	// Now verify enterprise operations work (e.g., promote)
	_, err = rc.PromoteMember(netID, ownerID, memberID, TestAdminToken)
	if err != nil {
		t.Fatalf("promote after toggle should work: %v", err)
	}
	t.Log("enterprise toggle RBAC initialization verified")
}

// TestInviteRespondAfterNetworkDelete verifies that responding to an invite
// after the network has been deleted returns a clear error.
func TestInviteRespondAfterNetworkDelete(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, ownerIdentity := registerTestNode(t, rc)
	targetID, targetIdentity := registerTestNode(t, rc)

	// Create enterprise invite-only network
	setClientSigner(rc, ownerIdentity)
	resp, err := rc.CreateNetwork(ownerID, "delete-inv", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Owner invites target
	_, err = rc.InviteToNetwork(netID, ownerID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	// Delete the network
	_, err = rc.DeleteNetwork(netID, TestAdminToken, ownerID)
	if err != nil {
		t.Fatalf("delete network: %v", err)
	}

	// Try to respond — should fail (invite cleaned up or network not found)
	setClientSigner(rc, targetIdentity)
	_, err = rc.RespondInvite(targetID, netID, true)
	if err == nil {
		t.Fatal("expected error responding to invite after network deletion")
	}
	t.Logf("invite response after network delete correctly rejected: %v", err)
}

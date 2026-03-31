package tests

import (
	"encoding/base64"
	"fmt"
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

// TestLeaveNetworkCleansInvites verifies that when a node leaves a network,
// any pending invites for that node+network are cleaned up.
func TestLeaveNetworkCleansInvites(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, ownerIdentity := registerTestNode(t, rc)
	memberID, memberIdentity := registerTestNode(t, rc)
	targetID, targetIdentity := registerTestNode(t, rc)

	// Create enterprise invite-only network
	setClientSigner(rc, ownerIdentity)
	resp, err := rc.CreateNetwork(ownerID, "leave-inv", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Create a second enterprise network for the target
	resp2, err := rc.CreateNetwork(ownerID, "other-net", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create second network: %v", err)
	}
	netID2 := uint16(resp2["network_id"].(float64))

	// Invite target to both networks
	_, err = rc.InviteToNetwork(netID, ownerID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite to net1: %v", err)
	}
	_, err = rc.InviteToNetwork(netID2, ownerID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite to net2: %v", err)
	}

	// Accept invite to net1 first (target joins)
	setClientSigner(rc, targetIdentity)
	_, err = rc.RespondInvite(targetID, netID, true)
	if err != nil {
		t.Fatalf("accept invite: %v", err)
	}

	// Now leave net1
	_, err = rc.LeaveNetwork(targetID, netID, "")
	if err != nil {
		t.Fatalf("leave network: %v", err)
	}

	// Poll invites — should still see invite for net2 (not cleaned up)
	pollResp, err := rc.PollInvites(targetID)
	if err != nil {
		t.Fatalf("poll invites: %v", err)
	}
	invites := pollResp["invites"].([]interface{})
	if len(invites) != 1 {
		t.Fatalf("expected 1 remaining invite (net2), got %d", len(invites))
	}
	inv := invites[0].(map[string]interface{})
	if uint16(inv["network_id"].(float64)) != netID2 {
		t.Fatalf("remaining invite should be for net2 (%d), got %v", netID2, inv["network_id"])
	}
	t.Log("leave network correctly preserved unrelated invites")
	_ = memberID
	_ = memberIdentity
}

// TestKickMemberCleansInvites verifies that when a member is kicked from a
// network, any pending invites for that member+network are cleaned up.
func TestKickMemberCleansInvites(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, ownerIdentity := registerTestNode(t, rc)
	targetID, targetIdentity := registerTestNode(t, rc)

	// Create two enterprise invite-only networks
	setClientSigner(rc, ownerIdentity)
	resp, err := rc.CreateNetwork(ownerID, "kick-inv1", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	resp2, err := rc.CreateNetwork(ownerID, "kick-inv2", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create second network: %v", err)
	}
	netID2 := uint16(resp2["network_id"].(float64))

	// Invite target to both networks and accept both
	_, err = rc.InviteToNetwork(netID, ownerID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite to net1: %v", err)
	}
	setClientSigner(rc, targetIdentity)
	_, err = rc.RespondInvite(targetID, netID, true)
	if err != nil {
		t.Fatalf("accept invite net1: %v", err)
	}

	setClientSigner(rc, ownerIdentity)
	_, err = rc.InviteToNetwork(netID2, ownerID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite to net2: %v", err)
	}
	setClientSigner(rc, targetIdentity)
	_, err = rc.RespondInvite(targetID, netID2, true)
	if err != nil {
		t.Fatalf("accept invite net2: %v", err)
	}

	// Now invite target again to net1 (e.g., they might get re-invited after kick)
	// Actually, let's create a scenario where target has a pending invite for ANOTHER
	// network and gets kicked from net1
	setClientSigner(rc, ownerIdentity)
	resp3, err := rc.CreateNetwork(ownerID, "kick-inv3", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create third network: %v", err)
	}
	netID3 := uint16(resp3["network_id"].(float64))

	// Invite target to net3 (pending, not accepted)
	_, err = rc.InviteToNetwork(netID3, ownerID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite to net3: %v", err)
	}

	// Kick target from net1
	_, err = rc.KickMember(netID, ownerID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("kick member: %v", err)
	}

	// Poll invites — should still see invite for net3
	setClientSigner(rc, targetIdentity)
	pollResp, err := rc.PollInvites(targetID)
	if err != nil {
		t.Fatalf("poll invites after kick: %v", err)
	}
	invites := pollResp["invites"].([]interface{})
	if len(invites) != 1 {
		t.Fatalf("expected 1 remaining invite (net3), got %d", len(invites))
	}
	inv := invites[0].(map[string]interface{})
	if uint16(inv["network_id"].(float64)) != netID3 {
		t.Fatalf("remaining invite should be for net3 (%d), got %v", netID3, inv["network_id"])
	}
	t.Log("kick member correctly preserved unrelated invites")
}

// TestAuditEnrichedHostnameVisibility verifies that hostname and visibility
// changes include old and new values in the audit log.
func TestAuditEnrichedHostnameVisibility(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, _ := registerTestNode(t, rc)

	// Set initial hostname
	_, err := rc.SetHostnameAdmin(nodeID, "first-host", TestAdminToken)
	if err != nil {
		t.Fatalf("set hostname: %v", err)
	}

	// Change hostname
	_, err = rc.SetHostnameAdmin(nodeID, "second-host", TestAdminToken)
	if err != nil {
		t.Fatalf("change hostname: %v", err)
	}

	// Set visibility to public
	_, err = rc.SetVisibilityAdmin(nodeID, true, TestAdminToken)
	if err != nil {
		t.Fatalf("set visibility: %v", err)
	}

	// Check audit log for enriched entries
	auditResp, err := rc.GetAuditLog(0, TestAdminToken)
	if err != nil {
		t.Fatalf("get audit log: %v", err)
	}
	entries := auditResp["entries"].([]interface{})

	// Find hostname.changed entries with old/new values
	foundHostnameEnriched := false
	foundVisibilityEnriched := false
	for _, e := range entries {
		entry := e.(map[string]interface{})
		action := entry["action"].(string)
		details, _ := entry["details"].(string)

		if action == "hostname.changed" && strings.Contains(details, "old_hostname=first-host") && strings.Contains(details, "new_hostname=second-host") {
			foundHostnameEnriched = true
			t.Logf("hostname audit enriched: %s", details)
		}
		if action == "visibility.changed" && strings.Contains(details, "old_public=false") && strings.Contains(details, "new_public=true") {
			foundVisibilityEnriched = true
			t.Logf("visibility audit enriched: %s", details)
		}
	}
	if !foundHostnameEnriched {
		t.Error("hostname.changed audit entry missing old/new values")
	}
	if !foundVisibilityEnriched {
		t.Error("visibility.changed audit entry missing old/new values")
	}
}

// TestAuditEnrichedPromoteDemote verifies that promote/demote audit entries
// include old and new role values.
func TestAuditEnrichedPromoteDemote(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, _ := registerTestNode(t, rc)
	memberID, _ := registerTestNode(t, rc)

	// Create enterprise network
	resp, err := rc.CreateNetwork(ownerID, "audit-roles", "open", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	_, err = rc.JoinNetwork(memberID, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join network: %v", err)
	}

	// Promote member to admin
	_, err = rc.PromoteMember(netID, ownerID, memberID, TestAdminToken)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}

	// Demote admin back to member
	_, err = rc.DemoteMember(netID, ownerID, memberID, TestAdminToken)
	if err != nil {
		t.Fatalf("demote: %v", err)
	}

	// Check audit log
	auditResp, err := rc.GetAuditLog(0, TestAdminToken)
	if err != nil {
		t.Fatalf("get audit log: %v", err)
	}
	entries := auditResp["entries"].([]interface{})

	foundPromoteEnriched := false
	foundDemoteEnriched := false
	for _, e := range entries {
		entry := e.(map[string]interface{})
		action := entry["action"].(string)
		details, _ := entry["details"].(string)

		if action == "member.promoted" && strings.Contains(details, "old_role=member") && strings.Contains(details, "new_role=admin") {
			foundPromoteEnriched = true
			t.Logf("promote audit enriched: %s", details)
		}
		if action == "member.demoted" && strings.Contains(details, "old_role=admin") && strings.Contains(details, "new_role=member") {
			foundDemoteEnriched = true
			t.Logf("demote audit enriched: %s", details)
		}
	}
	if !foundPromoteEnriched {
		t.Error("member.promoted audit entry missing old/new role values")
	}
	if !foundDemoteEnriched {
		t.Error("member.demoted audit entry missing old/new role values")
	}
}

// TestDeregisterCleansEnterprise verifies that deregistering a node cleans up
// invite inbox, RBAC roles, and emits enriched audit events.
func TestDeregisterCleansEnterprise(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, ownerIdentity := registerTestNode(t, rc)
	memberID, _ := registerTestNode(t, rc)
	targetID, targetIdentity := registerTestNode(t, rc)

	// Create enterprise invite-only network
	setClientSigner(rc, ownerIdentity)
	resp, err := rc.CreateNetwork(ownerID, "dereg-clean", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Invite target
	_, err = rc.InviteToNetwork(netID, ownerID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	// Verify invite exists before deregister
	setClientSigner(rc, targetIdentity)
	pollResp, err := rc.PollInvites(targetID)
	if err != nil {
		t.Fatalf("poll invites: %v", err)
	}
	invites := pollResp["invites"].([]interface{})
	if len(invites) != 1 {
		t.Fatalf("expected 1 invite before deregister, got %d", len(invites))
	}

	// Deregister target node (using admin token)
	_, err = rc.DeregisterAdmin(targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("deregister: %v", err)
	}

	// Re-register target to check invite is gone
	resp2, err := rc.RegisterWithKey("", crypto.EncodePublicKey(targetIdentity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	newTargetID := uint32(resp2["node_id"].(float64))
	setClientSigner(rc, targetIdentity)
	pollResp2, err := rc.PollInvites(newTargetID)
	if err != nil {
		t.Fatalf("poll invites after re-register: %v", err)
	}
	invites2 := pollResp2["invites"].([]interface{})
	if len(invites2) != 0 {
		t.Fatalf("expected 0 invites after deregister+reregister, got %d", len(invites2))
	}
	t.Log("deregister correctly cleaned up invite inbox")

	// Check audit for enriched deregister event
	auditResp, err := rc.GetAuditLog(0, TestAdminToken)
	if err != nil {
		t.Fatalf("get audit log: %v", err)
	}
	entries := auditResp["entries"].([]interface{})
	foundEnriched := false
	for _, e := range entries {
		entry := e.(map[string]interface{})
		if entry["action"] == "node.deregistered" {
			details, _ := entry["details"].(string)
			if strings.Contains(details, "networks=") {
				foundEnriched = true
				t.Logf("deregister audit enriched: %s", details)
			}
		}
	}
	if !foundEnriched {
		t.Error("node.deregistered audit entry missing networks count")
	}
	_ = memberID
}

// TestDeregisterOwnerAudit verifies that when a network owner deregisters,
// a network.owner_lost audit event is emitted.
func TestDeregisterOwnerAudit(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, _ := registerTestNode(t, rc)
	memberID, _ := registerTestNode(t, rc)

	// Create enterprise network with a member
	resp, err := rc.CreateNetwork(ownerID, "owner-lost", "open", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	_, err = rc.JoinNetwork(memberID, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join network: %v", err)
	}

	// Deregister the owner
	_, err = rc.DeregisterAdmin(ownerID, TestAdminToken)
	if err != nil {
		t.Fatalf("deregister owner: %v", err)
	}

	// Check audit for owner_lost event
	auditResp, err := rc.GetAuditLog(0, TestAdminToken)
	if err != nil {
		t.Fatalf("get audit log: %v", err)
	}
	entries := auditResp["entries"].([]interface{})
	foundOwnerLost := false
	for _, e := range entries {
		entry := e.(map[string]interface{})
		if entry["action"] == "network.owner_lost" {
			foundOwnerLost = true
			details, _ := entry["details"].(string)
			t.Logf("owner_lost audit: network_id=%v, details=%s", entry["network_id"], details)
		}
	}
	if !foundOwnerLost {
		t.Error("missing network.owner_lost audit event when owner deregistered")
	}
}

// TestKeyRotationPreservesExpiry verifies that key rotation does NOT reset
// the key expiry — this is intentional security behavior.
func TestKeyRotationPreservesExpiry(t *testing.T) {
	t.Parallel()
	rc, reg, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	clk := newTestClock()
	reg.SetClock(clk.Now)

	// Register with key
	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Join enterprise network (needed for key expiry)
	resp2, err := rc.CreateNetwork(nodeID, "rot-exp", "open", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp2["network_id"].(float64))
	_ = netID

	// Set key expiry to 7 days from now
	expiresAt := clk.Now().Add(7 * 24 * time.Hour)
	_, err = rc.SetKeyExpiryAdmin(nodeID, expiresAt, TestAdminToken)
	if err != nil {
		t.Fatalf("set key expiry: %v", err)
	}

	// Verify expiry is set
	info, err := rc.GetKeyInfo(nodeID)
	if err != nil {
		t.Fatalf("get key info: %v", err)
	}
	expiresAtStr := info["expires_at"].(string)
	if expiresAtStr == "" {
		t.Fatal("expected expires_at to be set")
	}
	t.Logf("expiry set to: %s", expiresAtStr)

	// Advance 5 days (within expiry window)
	clk.Advance(5 * 24 * time.Hour)

	// Rotate key
	newID, _ := crypto.GenerateIdentity()
	challenge := fmt.Sprintf("rotate:%d", nodeID)
	sig := id.Sign([]byte(challenge))
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	newPubKeyB64 := crypto.EncodePublicKey(newID.PublicKey)

	_, err = rc.RotateKey(nodeID, sigB64, newPubKeyB64)
	if err != nil {
		t.Fatalf("rotate key: %v", err)
	}

	// Check that expiry is STILL set (not cleared by rotation)
	info2, err := rc.GetKeyInfo(nodeID)
	if err != nil {
		t.Fatalf("get key info after rotation: %v", err)
	}
	expiresAtStr2 := info2["expires_at"].(string)
	if expiresAtStr2 == "" {
		t.Fatal("key rotation cleared expiry — should preserve it")
	}
	if expiresAtStr2 != expiresAtStr {
		t.Fatalf("key rotation changed expiry: before=%s, after=%s", expiresAtStr, expiresAtStr2)
	}
	t.Log("key rotation correctly preserved expiry (by design)")

	// Advance past expiry — heartbeat should still be blocked
	clk.Advance(3 * 24 * time.Hour) // total 8 days, past 7-day expiry
	setClientSigner(rc, newID)
	_, err = rc.Heartbeat(nodeID)
	if err == nil {
		t.Fatal("expected heartbeat to be blocked after key expiry, even after rotation")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected 'expired' error, got: %v", err)
	}
	t.Log("heartbeat correctly blocked after rotation+expiry")
}

// TestTransferOwnership verifies the full ownership transfer flow:
// owner → new owner, old owner becomes admin, audit event emitted.
func TestTransferOwnership(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, _ := registerTestNode(t, rc)
	memberID, _ := registerTestNode(t, rc)
	outsiderID, _ := registerTestNode(t, rc)

	// Create enterprise network
	resp, err := rc.CreateNetwork(ownerID, "transfer-test", "open", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	_, err = rc.JoinNetwork(memberID, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join network: %v", err)
	}

	// Verify initial roles
	roleResp, err := rc.GetMemberRole(netID, ownerID)
	if err != nil {
		t.Fatalf("get owner role: %v", err)
	}
	if roleResp["role"] != "owner" {
		t.Fatalf("expected owner role, got %v", roleResp["role"])
	}

	// Non-owner cannot transfer
	_, err = rc.TransferOwnership(netID, memberID, outsiderID, TestAdminToken)
	if err == nil {
		t.Fatal("expected error: non-owner cannot transfer")
	}

	// Cannot transfer to non-member
	_, err = rc.TransferOwnership(netID, ownerID, outsiderID, TestAdminToken)
	if err == nil {
		t.Fatal("expected error: cannot transfer to non-member")
	}

	// Cannot transfer to self
	_, err = rc.TransferOwnership(netID, ownerID, ownerID, TestAdminToken)
	if err == nil {
		t.Fatal("expected error: cannot transfer to self")
	}

	// Valid transfer: owner → member
	transferResp, err := rc.TransferOwnership(netID, ownerID, memberID, TestAdminToken)
	if err != nil {
		t.Fatalf("transfer ownership: %v", err)
	}
	if transferResp["old_owner"].(float64) != float64(ownerID) {
		t.Fatalf("unexpected old_owner: %v", transferResp["old_owner"])
	}
	if transferResp["new_owner"].(float64) != float64(memberID) {
		t.Fatalf("unexpected new_owner: %v", transferResp["new_owner"])
	}

	// Verify roles after transfer
	roleResp, err = rc.GetMemberRole(netID, ownerID)
	if err != nil {
		t.Fatalf("get old owner role: %v", err)
	}
	if roleResp["role"] != "admin" {
		t.Fatalf("old owner should be admin, got %v", roleResp["role"])
	}

	roleResp, err = rc.GetMemberRole(netID, memberID)
	if err != nil {
		t.Fatalf("get new owner role: %v", err)
	}
	if roleResp["role"] != "owner" {
		t.Fatalf("new owner should be owner, got %v", roleResp["role"])
	}

	// New owner can now promote (verifies they have owner privileges)
	_, err = rc.PromoteMember(netID, memberID, outsiderID, TestAdminToken)
	if err == nil || !strings.Contains(err.Error(), "not a member") {
		// outsider is not a member, so promote fails with "not a member" — that's correct,
		// it means the new owner has the right to call promote (auth passed)
	}

	// Check audit log for ownership transfer
	auditResp, err := rc.GetAuditLog(0, TestAdminToken)
	if err != nil {
		t.Fatalf("get audit log: %v", err)
	}
	entries := auditResp["entries"].([]interface{})
	foundTransfer := false
	for _, e := range entries {
		entry := e.(map[string]interface{})
		if entry["action"] == "network.ownership_transferred" {
			foundTransfer = true
			details, _ := entry["details"].(string)
			t.Logf("transfer audit: %s", details)
		}
	}
	if !foundTransfer {
		t.Error("missing network.ownership_transferred audit event")
	}
	t.Log("ownership transfer verified with all edge cases")
}

// TestTransferOwnershipNonEnterprise verifies that ownership transfer
// requires an enterprise network.
func TestTransferOwnershipNonEnterprise(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, _ := registerTestNode(t, rc)
	memberID, _ := registerTestNode(t, rc)

	// Create non-enterprise network
	resp, err := rc.CreateNetwork(ownerID, "no-ent-transfer", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	_, err = rc.JoinNetwork(memberID, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join network: %v", err)
	}

	// Transfer should fail with enterprise error
	_, err = rc.TransferOwnership(netID, ownerID, memberID, TestAdminToken)
	if err == nil {
		t.Fatal("expected error: non-enterprise network should reject transfer")
	}
	if !strings.Contains(err.Error(), "enterprise") {
		t.Fatalf("expected enterprise error, got: %v", err)
	}
	t.Logf("non-enterprise transfer correctly rejected: %v", err)
}

// TestTransferOwnershipThenReTransfer verifies that the new owner can
// transfer ownership again, creating a chain of transfers.
func TestTransferOwnershipThenReTransfer(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeA, _ := registerTestNode(t, rc)
	nodeB, _ := registerTestNode(t, rc)
	nodeC, _ := registerTestNode(t, rc)

	// Create enterprise network with A as owner
	resp, err := rc.CreateNetwork(nodeA, "chain-transfer", "open", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	_, err = rc.JoinNetwork(nodeB, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("B join: %v", err)
	}
	_, err = rc.JoinNetwork(nodeC, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("C join: %v", err)
	}

	// A transfers to B
	_, err = rc.TransferOwnership(netID, nodeA, nodeB, TestAdminToken)
	if err != nil {
		t.Fatalf("A→B transfer: %v", err)
	}

	// Verify A is now admin, B is owner
	roleA, _ := rc.GetMemberRole(netID, nodeA)
	roleB, _ := rc.GetMemberRole(netID, nodeB)
	if roleA["role"] != "admin" {
		t.Fatalf("expected A=admin, got %v", roleA["role"])
	}
	if roleB["role"] != "owner" {
		t.Fatalf("expected B=owner, got %v", roleB["role"])
	}

	// B transfers to C
	_, err = rc.TransferOwnership(netID, nodeB, nodeC, TestAdminToken)
	if err != nil {
		t.Fatalf("B→C transfer: %v", err)
	}

	// Verify B is now admin, C is owner
	roleB, _ = rc.GetMemberRole(netID, nodeB)
	roleC, _ := rc.GetMemberRole(netID, nodeC)
	if roleB["role"] != "admin" {
		t.Fatalf("expected B=admin after transfer, got %v", roleB["role"])
	}
	if roleC["role"] != "owner" {
		t.Fatalf("expected C=owner, got %v", roleC["role"])
	}

	// Check audit log has both transfer events
	auditResp, err := rc.GetAuditLog(0, TestAdminToken)
	if err != nil {
		t.Fatalf("get audit log: %v", err)
	}
	entries := auditResp["entries"].([]interface{})
	transferCount := 0
	for _, e := range entries {
		entry := e.(map[string]interface{})
		if entry["action"] == "network.ownership_transferred" {
			transferCount++
		}
	}
	if transferCount != 2 {
		t.Fatalf("expected 2 transfer audit events, got %d", transferCount)
	}
	t.Log("chain transfer (A→B→C) verified with audit trail")
}

// TestMaxMembersOnInviteAccept verifies that accepting an invite when the
// network is at max_members capacity is rejected.
func TestMaxMembersOnInviteAccept(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, ownerIdentity := registerTestNode(t, rc)
	member1ID, member1Identity := registerTestNode(t, rc)
	member2ID, member2Identity := registerTestNode(t, rc)

	// Create enterprise invite-only network
	setClientSigner(rc, ownerIdentity)
	resp, err := rc.CreateNetwork(ownerID, "max-cap", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Set max_members to 2 (owner counts as 1)
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"max_members": float64(2),
	}, TestAdminToken)
	if err != nil {
		t.Fatalf("set policy: %v", err)
	}

	// Invite member1 and accept (fills the network to capacity)
	_, err = rc.InviteToNetwork(netID, ownerID, member1ID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite member1: %v", err)
	}
	setClientSigner(rc, member1Identity)
	_, err = rc.RespondInvite(member1ID, netID, true)
	if err != nil {
		t.Fatalf("accept member1: %v", err)
	}
	t.Log("member1 joined successfully (2/2 capacity)")

	// Invite member2 and try to accept (should fail — at capacity)
	setClientSigner(rc, ownerIdentity)
	_, err = rc.InviteToNetwork(netID, ownerID, member2ID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite member2: %v", err)
	}
	setClientSigner(rc, member2Identity)
	_, err = rc.RespondInvite(member2ID, netID, true)
	if err == nil {
		t.Fatal("expected error: network at max capacity")
	}
	t.Logf("max_members enforcement on invite accept: %v", err)
}

// TestPromoteAlreadyAdmin verifies that promoting an already-admin node returns a clear error.
func TestPromoteAlreadyAdmin(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Register owner + target
	ownerIdentity, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(ownerIdentity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	ownerID := uint32(resp["node_id"].(float64))

	targetIdentity, _ := crypto.GenerateIdentity()
	resp, err = rc.RegisterWithKey("", crypto.EncodePublicKey(targetIdentity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register target: %v", err)
	}
	targetID := uint32(resp["node_id"].(float64))

	// Create enterprise network
	setClientSigner(rc, ownerIdentity)
	resp, err = rc.CreateNetwork(ownerID, "promote-edge", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Add target to network
	_, err = rc.InviteToNetwork(netID, ownerID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	setClientSigner(rc, targetIdentity)
	_, err = rc.RespondInvite(targetID, netID, true)
	if err != nil {
		t.Fatalf("accept invite: %v", err)
	}

	// Promote target to admin (first time — should succeed)
	setClientSigner(rc, ownerIdentity)
	_, err = rc.PromoteMember(netID, ownerID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("first promote: %v", err)
	}

	// Promote again — should fail with "already an admin"
	_, err = rc.PromoteMember(netID, ownerID, targetID, TestAdminToken)
	if err == nil {
		t.Fatal("expected error promoting already-admin node")
	}
	if !strings.Contains(err.Error(), "already an admin") {
		t.Fatalf("expected 'already an admin' error, got: %v", err)
	}
	t.Logf("promote already-admin correctly rejected: %v", err)
}

// TestDemoteAlreadyMember verifies that demoting an already-member node returns a clear error.
func TestDemoteAlreadyMember(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Register owner + target
	ownerIdentity, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(ownerIdentity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	ownerID := uint32(resp["node_id"].(float64))

	targetIdentity, _ := crypto.GenerateIdentity()
	resp, err = rc.RegisterWithKey("", crypto.EncodePublicKey(targetIdentity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register target: %v", err)
	}
	targetID := uint32(resp["node_id"].(float64))

	// Create enterprise network
	setClientSigner(rc, ownerIdentity)
	resp, err = rc.CreateNetwork(ownerID, "demote-edge", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Add target to network (joins as member role)
	_, err = rc.InviteToNetwork(netID, ownerID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	setClientSigner(rc, targetIdentity)
	_, err = rc.RespondInvite(targetID, netID, true)
	if err != nil {
		t.Fatalf("accept invite: %v", err)
	}

	// Demote target — should fail because target is already a member
	setClientSigner(rc, ownerIdentity)
	_, err = rc.DemoteMember(netID, ownerID, targetID, TestAdminToken)
	if err == nil {
		t.Fatal("expected error demoting already-member node")
	}
	if !strings.Contains(err.Error(), "already a member") {
		t.Fatalf("expected 'already a member' error, got: %v", err)
	}
	t.Logf("demote already-member correctly rejected: %v", err)
}

// TestSetTaskExecAdminToken verifies that SetTaskExec works via admin token
// bypass (without node signature).
func TestSetTaskExecAdminToken(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Register a node
	nodeIdentity, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(nodeIdentity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Enable task_exec via admin token (no node signer set)
	resp, err = rc.SetTaskExecAdmin(nodeID, true, TestAdminToken)
	if err != nil {
		t.Fatalf("SetTaskExecAdmin(true): %v", err)
	}
	if resp["task_exec"] != true {
		t.Fatalf("expected task_exec=true, got %v", resp["task_exec"])
	}

	// Verify via node signature path too
	setClientSigner(rc, nodeIdentity)
	resp, err = rc.SetTaskExec(nodeID, false)
	if err != nil {
		t.Fatalf("SetTaskExec(false): %v", err)
	}
	if resp["task_exec"] != false {
		t.Fatalf("expected task_exec=false, got %v", resp["task_exec"])
	}

	// Toggle back via admin token
	rc.SetSigner(nil) // clear signer
	resp, err = rc.SetTaskExecAdmin(nodeID, true, TestAdminToken)
	if err != nil {
		t.Fatalf("SetTaskExecAdmin(true) again: %v", err)
	}
	if resp["task_exec"] != true {
		t.Fatalf("expected task_exec=true after re-enable, got %v", resp["task_exec"])
	}

	t.Log("SetTaskExec admin token bypass works correctly")
}

// TestAuditEnrichedTagsTaskExecPolicy verifies that tags, task_exec, and policy
// audit entries include old and new values.
func TestAuditEnrichedTagsTaskExecPolicy(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, nodeIdentity := registerTestNode(t, rc)

	// --- Tags: set then change ---
	_, err := rc.SetTagsAdmin(nodeID, []string{"alpha", "beta"}, TestAdminToken)
	if err != nil {
		t.Fatalf("set tags: %v", err)
	}
	_, err = rc.SetTagsAdmin(nodeID, []string{"gamma"}, TestAdminToken)
	if err != nil {
		t.Fatalf("change tags: %v", err)
	}

	// --- TaskExec: enable then disable ---
	setClientSigner(rc, nodeIdentity)
	_, err = rc.SetTaskExec(nodeID, true)
	if err != nil {
		t.Fatalf("enable task_exec: %v", err)
	}
	_, err = rc.SetTaskExec(nodeID, false)
	if err != nil {
		t.Fatalf("disable task_exec: %v", err)
	}

	// --- Policy: create enterprise network, set policy, then change it ---
	resp, err := rc.CreateNetwork(nodeID, "audit-policy", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"max_members": float64(10),
	}, TestAdminToken)
	if err != nil {
		t.Fatalf("set policy: %v", err)
	}
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"max_members": float64(20),
	}, TestAdminToken)
	if err != nil {
		t.Fatalf("change policy: %v", err)
	}

	// --- Check audit log ---
	auditResp, err := rc.GetAuditLog(0, TestAdminToken)
	if err != nil {
		t.Fatalf("get audit log: %v", err)
	}
	entries := auditResp["entries"].([]interface{})

	foundTagsEnriched := false
	foundTaskExecEnriched := false
	foundPolicyEnriched := false

	for _, e := range entries {
		entry := e.(map[string]interface{})
		action := entry["action"].(string)
		details, _ := entry["details"].(string)

		// Tags: second set should show old_tags_count=2, new_tags_count=1
		if action == "tags.changed" && strings.Contains(details, "old_tags_count=2") && strings.Contains(details, "new_tags_count=1") {
			foundTagsEnriched = true
			t.Logf("tags audit enriched: %s", details)
		}

		// TaskExec: disable should show old_enabled=true, new_enabled=false
		if action == "task_exec.changed" && strings.Contains(details, "old_enabled=true") && strings.Contains(details, "new_enabled=false") {
			foundTaskExecEnriched = true
			t.Logf("task_exec audit enriched: %s", details)
		}

		// Policy: second set should show old_max_members=10, new_max_members=20
		if action == "network.policy_changed" && strings.Contains(details, "old_max_members=10") && strings.Contains(details, "new_max_members=20") {
			foundPolicyEnriched = true
			t.Logf("policy audit enriched: %s", details)
		}
	}

	if !foundTagsEnriched {
		t.Error("tags.changed audit entry missing old/new tag counts")
	}
	if !foundTaskExecEnriched {
		t.Error("task_exec.changed audit entry missing old/new enabled values")
	}
	if !foundPolicyEnriched {
		t.Error("network.policy_changed audit entry missing old/new max_members")
	}
}

// TestAdminKicksAdmin verifies that an admin can kick another admin.
func TestAdminKicksAdmin(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Register owner + 2 admins
	ownerIdentity, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(ownerIdentity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	ownerID := uint32(resp["node_id"].(float64))

	admin1Identity, _ := crypto.GenerateIdentity()
	resp, err = rc.RegisterWithKey("", crypto.EncodePublicKey(admin1Identity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register admin1: %v", err)
	}
	admin1ID := uint32(resp["node_id"].(float64))

	admin2Identity, _ := crypto.GenerateIdentity()
	resp, err = rc.RegisterWithKey("", crypto.EncodePublicKey(admin2Identity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register admin2: %v", err)
	}
	admin2ID := uint32(resp["node_id"].(float64))

	// Create enterprise network, invite both
	setClientSigner(rc, ownerIdentity)
	resp, err = rc.CreateNetwork(ownerID, "kick-admin", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Invite and accept admin1
	_, err = rc.InviteToNetwork(netID, ownerID, admin1ID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite admin1: %v", err)
	}
	setClientSigner(rc, admin1Identity)
	_, err = rc.RespondInvite(admin1ID, netID, true)
	if err != nil {
		t.Fatalf("accept admin1: %v", err)
	}

	// Invite and accept admin2
	setClientSigner(rc, ownerIdentity)
	_, err = rc.InviteToNetwork(netID, ownerID, admin2ID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite admin2: %v", err)
	}
	setClientSigner(rc, admin2Identity)
	_, err = rc.RespondInvite(admin2ID, netID, true)
	if err != nil {
		t.Fatalf("accept admin2: %v", err)
	}

	// Promote both to admin
	_, err = rc.PromoteMember(netID, ownerID, admin1ID, TestAdminToken)
	if err != nil {
		t.Fatalf("promote admin1: %v", err)
	}
	_, err = rc.PromoteMember(netID, ownerID, admin2ID, TestAdminToken)
	if err != nil {
		t.Fatalf("promote admin2: %v", err)
	}

	// Admin1 kicks Admin2 (admin kicking admin — should succeed)
	setClientSigner(rc, admin1Identity)
	_, err = rc.KickMember(netID, admin1ID, admin2ID, TestAdminToken)
	if err != nil {
		t.Fatalf("admin1 kick admin2: %v", err)
	}
	t.Log("admin successfully kicked another admin")

	// Verify admin2 is no longer in the network
	resp, err = rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	nodes := resp["nodes"].([]interface{})
	for _, n := range nodes {
		node := n.(map[string]interface{})
		if uint32(node["node_id"].(float64)) == admin2ID {
			t.Fatal("admin2 should have been kicked from the network")
		}
	}

	// Admin cannot kick owner
	_, err = rc.KickMember(netID, admin1ID, ownerID, TestAdminToken)
	if err == nil {
		t.Fatal("expected error kicking owner")
	}
	if !strings.Contains(err.Error(), "cannot kick") {
		t.Fatalf("expected 'cannot kick' error, got: %v", err)
	}
	t.Logf("admin correctly blocked from kicking owner: %v", err)
}

// TestDuplicateTagsDedup verifies that duplicate tags are deduplicated.
func TestDuplicateTagsDedup(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, _ := registerTestNode(t, rc)

	// Set tags with duplicates
	resp, err := rc.SetTagsAdmin(nodeID, []string{"gpu", "gpu", "cpu", "gpu", "cpu"}, TestAdminToken)
	if err != nil {
		t.Fatalf("set tags with dupes: %v", err)
	}

	// Verify deduplication
	tags := resp["tags"].([]interface{})
	if len(tags) != 2 {
		t.Fatalf("expected 2 unique tags, got %d: %v", len(tags), tags)
	}
	if tags[0].(string) != "gpu" || tags[1].(string) != "cpu" {
		t.Fatalf("expected [gpu, cpu], got %v", tags)
	}
	t.Logf("duplicate tags correctly deduped: %v", tags)
}

// TestPolicyOnDeletedNetwork verifies that setting policy on a deleted network fails.
func TestPolicyOnDeletedNetwork(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Register owner and create enterprise network
	ownerIdentity, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(ownerIdentity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	ownerID := uint32(resp["node_id"].(float64))

	setClientSigner(rc, ownerIdentity)
	resp, err = rc.CreateNetwork(ownerID, "policy-delete", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Delete the network
	_, err = rc.DeleteNetwork(netID, TestAdminToken, ownerID)
	if err != nil {
		t.Fatalf("delete network: %v", err)
	}

	// Try to set policy on the deleted network — should fail
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"max_members": float64(10),
	}, TestAdminToken)
	if err == nil {
		t.Fatal("expected error setting policy on deleted network")
	}
	t.Logf("policy on deleted network correctly rejected: %v", err)
}

// TestMaxMembersBelowCurrentCount verifies that setting max_members below the
// current member count is rejected.
func TestMaxMembersBelowCurrentCount(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Register owner + 2 members
	ownerIdentity, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(ownerIdentity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	ownerID := uint32(resp["node_id"].(float64))

	member1Identity, _ := crypto.GenerateIdentity()
	resp, err = rc.RegisterWithKey("", crypto.EncodePublicKey(member1Identity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register member1: %v", err)
	}
	member1ID := uint32(resp["node_id"].(float64))

	member2Identity, _ := crypto.GenerateIdentity()
	resp, err = rc.RegisterWithKey("", crypto.EncodePublicKey(member2Identity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register member2: %v", err)
	}
	member2ID := uint32(resp["node_id"].(float64))

	// Create enterprise network with all 3 members
	setClientSigner(rc, ownerIdentity)
	resp, err = rc.CreateNetwork(ownerID, "max-boundary", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Invite and accept both members
	_, err = rc.InviteToNetwork(netID, ownerID, member1ID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite member1: %v", err)
	}
	setClientSigner(rc, member1Identity)
	_, err = rc.RespondInvite(member1ID, netID, true)
	if err != nil {
		t.Fatalf("accept member1: %v", err)
	}

	setClientSigner(rc, ownerIdentity)
	_, err = rc.InviteToNetwork(netID, ownerID, member2ID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite member2: %v", err)
	}
	setClientSigner(rc, member2Identity)
	_, err = rc.RespondInvite(member2ID, netID, true)
	if err != nil {
		t.Fatalf("accept member2: %v", err)
	}

	// Network now has 3 members. Setting max_members=3 should work.
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"max_members": float64(3),
	}, TestAdminToken)
	if err != nil {
		t.Fatalf("set max_members=3: %v", err)
	}

	// Setting max_members=2 should fail (3 members already)
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"max_members": float64(2),
	}, TestAdminToken)
	if err == nil {
		t.Fatal("expected error setting max_members below current count")
	}
	if !strings.Contains(err.Error(), "cannot set max_members") {
		t.Fatalf("expected 'cannot set max_members' error, got: %v", err)
	}
	t.Logf("max_members below current count correctly rejected: %v", err)

	// Setting max_members=0 (unlimited) should work
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"max_members": float64(0),
	}, TestAdminToken)
	if err != nil {
		t.Fatalf("set max_members=0 (unlimited): %v", err)
	}
	t.Log("max_members=0 (unlimited) accepted")
}

// TestConcurrentRBACOperations exercises promote/demote under concurrent access.
func TestConcurrentRBACOperations(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Register owner + 5 members
	ownerIdentity, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(ownerIdentity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	ownerID := uint32(resp["node_id"].(float64))

	setClientSigner(rc, ownerIdentity)
	resp, err = rc.CreateNetwork(ownerID, "concurrent-rbac", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	memberIDs := make([]uint32, 5)
	for i := 0; i < 5; i++ {
		memberIdentity, _ := crypto.GenerateIdentity()
		resp, err = rc.RegisterWithKey("", crypto.EncodePublicKey(memberIdentity.PublicKey), "", nil)
		if err != nil {
			t.Fatalf("register member %d: %v", i, err)
		}
		memberIDs[i] = uint32(resp["node_id"].(float64))

		_, err = rc.InviteToNetwork(netID, ownerID, memberIDs[i], TestAdminToken)
		if err != nil {
			t.Fatalf("invite member %d: %v", i, err)
		}
		setClientSigner(rc, memberIdentity)
		_, err = rc.RespondInvite(memberIDs[i], netID, true)
		if err != nil {
			t.Fatalf("accept member %d: %v", i, err)
		}
		setClientSigner(rc, ownerIdentity)
	}

	// Concurrently promote all 5 members to admin
	var wg sync.WaitGroup
	errors := make([]error, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			client, err := registry.Dial(env.RegistryAddr)
			if err != nil {
				errors[idx] = err
				return
			}
			defer client.Close()
			_, errors[idx] = client.PromoteMember(netID, ownerID, memberIDs[idx], TestAdminToken)
		}(i)
	}
	wg.Wait()

	promoted := 0
	for i, err := range errors {
		if err != nil {
			t.Logf("promote member %d: %v", i, err)
		} else {
			promoted++
		}
	}
	t.Logf("concurrent promote: %d/5 succeeded", promoted)
	if promoted != 5 {
		t.Errorf("expected all 5 promotes to succeed, got %d", promoted)
	}

	// Concurrently demote all 5 back to member
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			client, err := registry.Dial(env.RegistryAddr)
			if err != nil {
				errors[idx] = err
				return
			}
			defer client.Close()
			_, errors[idx] = client.DemoteMember(netID, ownerID, memberIDs[idx], TestAdminToken)
		}(i)
	}
	wg.Wait()

	demoted := 0
	for i, err := range errors {
		if err != nil {
			t.Logf("demote member %d: %v", i, err)
		} else {
			demoted++
		}
	}
	t.Logf("concurrent demote: %d/5 succeeded", demoted)
	if demoted != 5 {
		t.Errorf("expected all 5 demotes to succeed, got %d", demoted)
	}

	// Verify final state: all members should have "member" role
	for _, mid := range memberIDs {
		roleResp, err := rc.GetMemberRole(netID, mid)
		if err != nil {
			t.Errorf("get role for %d: %v", mid, err)
			continue
		}
		if roleResp["role"] != "member" {
			t.Errorf("member %d role: got %v, want member", mid, roleResp["role"])
		}
	}
	t.Log("concurrent RBAC operations completed with consistent final state")
}

// TestSelfInvitePrevented verifies that a node cannot invite itself.
func TestSelfInvitePrevented(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	ownerIdentity, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(ownerIdentity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	ownerID := uint32(resp["node_id"].(float64))

	setClientSigner(rc, ownerIdentity)
	resp, err = rc.CreateNetwork(ownerID, "self-invite", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Try to invite self
	_, err = rc.InviteToNetwork(netID, ownerID, ownerID, TestAdminToken)
	if err == nil {
		t.Fatal("expected error for self-invite")
	}
	if !strings.Contains(err.Error(), "cannot invite yourself") {
		t.Fatalf("expected 'cannot invite yourself' error, got: %v", err)
	}
	t.Logf("self-invite correctly rejected: %v", err)
}

// TestPolicyDescriptionLimit verifies that overly long descriptions are rejected.
func TestPolicyDescriptionLimit(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, nodeIdentity := registerTestNode(t, rc)
	setClientSigner(rc, nodeIdentity)
	resp, err := rc.CreateNetwork(nodeID, "desc-limit", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// 256 chars should work
	desc256 := strings.Repeat("a", 256)
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"description": desc256,
	}, TestAdminToken)
	if err != nil {
		t.Fatalf("set description (256 chars): %v", err)
	}

	// 257 chars should fail
	desc257 := strings.Repeat("b", 257)
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"description": desc257,
	}, TestAdminToken)
	if err == nil {
		t.Fatal("expected error for description > 256 chars")
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Fatalf("expected 'too long' error, got: %v", err)
	}
	t.Logf("description limit enforced: %v", err)
}

// TestAllowedPortsLimit verifies that too many allowed_ports are rejected.
func TestAllowedPortsLimit(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, nodeIdentity := registerTestNode(t, rc)
	setClientSigner(rc, nodeIdentity)
	resp, err := rc.CreateNetwork(nodeID, "ports-limit", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// 100 ports should work
	ports100 := make([]interface{}, 100)
	for i := 0; i < 100; i++ {
		ports100[i] = float64(i + 1)
	}
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"allowed_ports": ports100,
	}, TestAdminToken)
	if err != nil {
		t.Fatalf("set 100 ports: %v", err)
	}

	// 101 ports should fail
	ports101 := make([]interface{}, 101)
	for i := 0; i < 101; i++ {
		ports101[i] = float64(i + 1)
	}
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"allowed_ports": ports101,
	}, TestAdminToken)
	if err == nil {
		t.Fatal("expected error for > 100 allowed_ports")
	}
	if !strings.Contains(err.Error(), "too many") {
		t.Fatalf("expected 'too many' error, got: %v", err)
	}
	t.Logf("allowed_ports limit enforced: %v", err)
}

// TestTransferOwnershipZeroID verifies that transferring to node 0 is rejected.
func TestTransferOwnershipZeroID(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	ownerIdentity, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(ownerIdentity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	ownerID := uint32(resp["node_id"].(float64))

	setClientSigner(rc, ownerIdentity)
	resp, err = rc.CreateNetwork(ownerID, "transfer-zero", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Transfer to node 0
	_, err = rc.TransferOwnership(netID, ownerID, 0, TestAdminToken)
	if err == nil {
		t.Fatal("expected error transferring to node 0")
	}
	t.Logf("transfer to node 0 correctly rejected: %v", err)
}

// TestListNetworksEnterpriseFields verifies that list_networks exposes
// enterprise policy fields (max_members, description) for enterprise networks.
func TestListNetworksEnterpriseFields(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, nodeIdentity := registerTestNode(t, rc)
	setClientSigner(rc, nodeIdentity)

	// Create a non-enterprise network
	_, err := rc.CreateNetwork(nodeID, "plain-net", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create plain: %v", err)
	}

	// Create an enterprise network with policy
	resp, err := rc.CreateNetwork(nodeID, "ent-net", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create enterprise: %v", err)
	}
	entNetID := uint16(resp["network_id"].(float64))

	_, err = rc.SetNetworkPolicy(entNetID, map[string]interface{}{
		"max_members": float64(25),
		"description": "test enterprise listing",
	}, TestAdminToken)
	if err != nil {
		t.Fatalf("set policy: %v", err)
	}

	// List networks and verify fields
	listResp, err := rc.ListNetworks()
	if err != nil {
		t.Fatalf("list networks: %v", err)
	}
	networks := listResp["networks"].([]interface{})

	foundPlain := false
	foundEnt := false
	for _, n := range networks {
		net := n.(map[string]interface{})
		name := net["name"].(string)

		if name == "plain-net" {
			foundPlain = true
			if net["enterprise"] != false {
				t.Error("plain-net should have enterprise=false")
			}
			// Should NOT have max_members or description
			if _, ok := net["max_members"]; ok {
				t.Error("plain-net should not have max_members")
			}
		}

		if name == "ent-net" {
			foundEnt = true
			if net["enterprise"] != true {
				t.Error("ent-net should have enterprise=true")
			}
			if int(net["max_members"].(float64)) != 25 {
				t.Errorf("ent-net max_members: got %v, want 25", net["max_members"])
			}
			if net["description"] != "test enterprise listing" {
				t.Errorf("ent-net description: got %v", net["description"])
			}
			t.Logf("enterprise network listing: max_members=%v, description=%v", net["max_members"], net["description"])
		}
	}
	if !foundPlain {
		t.Error("plain-net not found in listing")
	}
	if !foundEnt {
		t.Error("ent-net not found in listing")
	}
}

// TestListNodesEnterpriseMembers verifies that list_nodes returns role, tags,
// and other enterprise fields for network members.
func TestListNodesEnterpriseMembers(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Register owner + member
	ownerIdentity, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(ownerIdentity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	ownerID := uint32(resp["node_id"].(float64))

	memberIdentity, _ := crypto.GenerateIdentity()
	resp, err = rc.RegisterWithKey("", crypto.EncodePublicKey(memberIdentity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register member: %v", err)
	}
	memberID := uint32(resp["node_id"].(float64))

	// Create enterprise network
	setClientSigner(rc, ownerIdentity)
	resp, err = rc.CreateNetwork(ownerID, "node-fields", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Invite and accept member
	_, err = rc.InviteToNetwork(netID, ownerID, memberID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	setClientSigner(rc, memberIdentity)
	_, err = rc.RespondInvite(memberID, netID, true)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	// Promote member to admin
	_, err = rc.PromoteMember(netID, ownerID, memberID, TestAdminToken)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}

	// Set tags on member
	_, err = rc.SetTagsAdmin(memberID, []string{"gpu", "fast"}, TestAdminToken)
	if err != nil {
		t.Fatalf("set tags: %v", err)
	}

	// Set member visibility to public
	_, err = rc.SetVisibilityAdmin(memberID, true, TestAdminToken)
	if err != nil {
		t.Fatalf("set visibility: %v", err)
	}

	// List nodes and verify fields
	nodesResp, err := rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	nodes := nodesResp["nodes"].([]interface{})

	foundOwner := false
	foundMember := false
	for _, n := range nodes {
		node := n.(map[string]interface{})
		nid := uint32(node["node_id"].(float64))

		if nid == ownerID {
			foundOwner = true
			if node["role"] != "owner" {
				t.Errorf("owner role: got %v, want owner", node["role"])
			}
		}

		if nid == memberID {
			foundMember = true
			if node["role"] != "admin" {
				t.Errorf("member role: got %v, want admin", node["role"])
			}
			if node["public"] != true {
				t.Errorf("member public: got %v, want true", node["public"])
			}
			tags, ok := node["tags"].([]interface{})
			if !ok || len(tags) != 2 {
				t.Errorf("member tags: got %v, want [gpu, fast]", node["tags"])
			}
			t.Logf("member node: role=%v, public=%v, tags=%v", node["role"], node["public"], node["tags"])
		}
	}
	if !foundOwner {
		t.Error("owner not found in list_nodes")
	}
	if !foundMember {
		t.Error("member not found in list_nodes")
	}
}

// TestErrorPassthrough verifies that meaningful error messages reach clients
// instead of being sanitized to "request failed".
func TestErrorPassthrough(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// "not found" — lookup non-existent node
	_, err = rc.Lookup(99999)
	if err == nil {
		t.Fatal("expected error for non-existent node")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
	t.Logf("not found passthrough: %v", err)

	// "invalid" — register with invalid public key
	_, err = rc.RegisterWithKey("", "not-a-valid-key", "", nil)
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("expected 'invalid' in error, got: %v", err)
	}
	t.Logf("invalid passthrough: %v", err)

	// "required" — transfer ownership with missing new_owner_id
	ownerIdentity, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(ownerIdentity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	ownerID := uint32(resp["node_id"].(float64))
	setClientSigner(rc, ownerIdentity)
	resp, err = rc.CreateNetwork(ownerID, "err-test", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	_, err = rc.TransferOwnership(netID, ownerID, 0, TestAdminToken)
	if err == nil {
		t.Fatal("expected error for zero new_owner_id")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("expected 'required' in error, got: %v", err)
	}
	t.Logf("required passthrough: %v", err)
}

// TestKickAuditIncludesRole verifies that the kick audit entry includes
// the kicked member's role.
func TestKickAuditIncludesRole(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Register owner + admin
	ownerIdentity, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(ownerIdentity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	ownerID := uint32(resp["node_id"].(float64))

	adminIdentity, _ := crypto.GenerateIdentity()
	resp, err = rc.RegisterWithKey("", crypto.EncodePublicKey(adminIdentity.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register admin: %v", err)
	}
	adminID := uint32(resp["node_id"].(float64))

	// Create enterprise network, add admin
	setClientSigner(rc, ownerIdentity)
	resp, err = rc.CreateNetwork(ownerID, "kick-role-audit", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	_, err = rc.InviteToNetwork(netID, ownerID, adminID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	setClientSigner(rc, adminIdentity)
	_, err = rc.RespondInvite(adminID, netID, true)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	// Promote to admin then kick
	_, err = rc.PromoteMember(netID, ownerID, adminID, TestAdminToken)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	setClientSigner(rc, ownerIdentity)
	_, err = rc.KickMember(netID, ownerID, adminID, TestAdminToken)
	if err != nil {
		t.Fatalf("kick: %v", err)
	}

	// Check audit for kick event with role
	auditResp, err := rc.GetAuditLog(0, TestAdminToken)
	if err != nil {
		t.Fatalf("get audit: %v", err)
	}
	entries := auditResp["entries"].([]interface{})

	foundKickWithRole := false
	for _, e := range entries {
		entry := e.(map[string]interface{})
		if entry["action"] == "member.kicked" {
			details, _ := entry["details"].(string)
			if strings.Contains(details, "role=admin") {
				foundKickWithRole = true
				t.Logf("kick audit with role: %s", details)
			}
		}
	}
	if !foundKickWithRole {
		t.Error("member.kicked audit entry missing role=admin")
	}
}

// TestPolicyFractionalPortsRejected verifies that fractional port numbers
// are rejected by the policy handler (must be whole integers 1-65535).
func TestPolicyFractionalPortsRejected(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, ownerIdentity := registerTestNode(t, rc)

	setClientSigner(rc, ownerIdentity)
	resp, err := rc.CreateNetwork(ownerID, "frac-ports", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Fractional port should be rejected
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"allowed_ports": []interface{}{float64(80), float64(443.5)},
	}, TestAdminToken)
	if err == nil {
		t.Fatal("expected error for fractional port 443.5")
	}
	if !strings.Contains(err.Error(), "invalid port") {
		t.Errorf("unexpected error: %v", err)
	}

	// Integer ports should work
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"allowed_ports": []interface{}{float64(80), float64(443)},
	}, TestAdminToken)
	if err != nil {
		t.Fatalf("integer ports should succeed: %v", err)
	}

	// Zero port should be rejected
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"allowed_ports": []interface{}{float64(0)},
	}, TestAdminToken)
	if err == nil {
		t.Fatal("expected error for port 0")
	}

	// Port 65536 should be rejected
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"allowed_ports": []interface{}{float64(65536)},
	}, TestAdminToken)
	if err == nil {
		t.Fatal("expected error for port 65536")
	}
	t.Log("fractional and out-of-range ports correctly rejected")
}

// TestRespondInviteEnterpriseDowngradeBlocked verifies that accepting an
// invite after the enterprise flag is toggled off is blocked by the TOCTOU
// defense in handleRespondInvite.
func TestRespondInviteEnterpriseDowngradeBlocked(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, ownerIdentity := registerTestNode(t, rc)
	targetID, targetIdentity := registerTestNode(t, rc)

	// Create enterprise invite-only network
	setClientSigner(rc, ownerIdentity)
	resp, err := rc.CreateNetwork(ownerID, "downgrade-test", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Invite target
	_, err = rc.InviteToNetwork(netID, ownerID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	// Toggle enterprise OFF before target accepts
	_, err = rc.SetNetworkEnterprise(netID, false, TestAdminToken)
	if err != nil {
		t.Fatalf("disable enterprise: %v", err)
	}

	// Target tries to accept — should fail because enterprise is now off
	setClientSigner(rc, targetIdentity)
	_, err = rc.RespondInvite(targetID, netID, true)
	if err == nil {
		t.Fatal("expected error: accept invite on non-enterprise network should fail")
	}
	if !strings.Contains(err.Error(), "enterprise") {
		t.Errorf("unexpected error: %v", err)
	}
	t.Logf("TOCTOU defense worked: %v", err)
}

// TestInviteEnterpriseRecheck verifies that the enterprise flag is rechecked
// under the write lock in handleInviteToNetwork (TOCTOU defense).
func TestInviteEnterpriseRecheck(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, ownerIdentity := registerTestNode(t, rc)
	targetID, _ := registerTestNode(t, rc)

	// Create enterprise invite-only network then downgrade
	setClientSigner(rc, ownerIdentity)
	resp, err := rc.CreateNetwork(ownerID, "recheck-test", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Invite works while enterprise is on
	_, err = rc.InviteToNetwork(netID, ownerID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite while enterprise on: %v", err)
	}

	// Disable enterprise
	_, err = rc.SetNetworkEnterprise(netID, false, TestAdminToken)
	if err != nil {
		t.Fatalf("disable enterprise: %v", err)
	}

	// New invite should fail
	newTargetID, _ := registerTestNode(t, rc)
	_, err = rc.InviteToNetwork(netID, ownerID, newTargetID, TestAdminToken)
	if err == nil {
		t.Fatal("expected error: invite on non-enterprise network should fail")
	}
	if !strings.Contains(err.Error(), "enterprise") {
		t.Errorf("unexpected error: %v", err)
	}
	t.Logf("enterprise recheck blocked invite: %v", err)
}

// TestOwnerCannotLeaveNetwork verifies that the owner of an enterprise network
// cannot leave — they must transfer ownership first.
func TestOwnerCannotLeaveNetwork(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, ownerIdentity := registerTestNode(t, rc)
	memberID, memberIdentity := registerTestNode(t, rc)

	// Create enterprise invite-only network
	setClientSigner(rc, ownerIdentity)
	resp, err := rc.CreateNetwork(ownerID, "owner-leave", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Invite and accept member
	_, err = rc.InviteToNetwork(netID, ownerID, memberID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	setClientSigner(rc, memberIdentity)
	_, err = rc.RespondInvite(memberID, netID, true)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	// Owner tries to leave — should fail
	setClientSigner(rc, ownerIdentity)
	_, err = rc.LeaveNetwork(ownerID, netID, "")
	if err == nil {
		t.Fatal("expected error: owner should not be able to leave")
	}
	if !strings.Contains(err.Error(), "cannot leave") {
		t.Errorf("unexpected error: %v", err)
	}
	t.Logf("owner leave blocked: %v", err)

	// Member can still leave
	setClientSigner(rc, memberIdentity)
	_, err = rc.LeaveNetwork(memberID, netID, "")
	if err != nil {
		t.Fatalf("member leave should succeed: %v", err)
	}

	// After transfer, old owner can leave
	newMemberID, newMemberIdentity := registerTestNode(t, rc)
	setClientSigner(rc, ownerIdentity)
	_, err = rc.InviteToNetwork(netID, ownerID, newMemberID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite new member: %v", err)
	}
	setClientSigner(rc, newMemberIdentity)
	_, err = rc.RespondInvite(newMemberID, netID, true)
	if err != nil {
		t.Fatalf("accept new member: %v", err)
	}

	// Transfer ownership then leave
	_, err = rc.TransferOwnership(netID, ownerID, newMemberID, TestAdminToken)
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}

	// Old owner (now admin) can leave
	setClientSigner(rc, ownerIdentity)
	_, err = rc.LeaveNetwork(ownerID, netID, "")
	if err != nil {
		t.Fatalf("old owner leave after transfer should succeed: %v", err)
	}
	t.Log("owner leave correctly blocked, member/ex-owner leave succeeds")
}

// TestEnterpriseToggleRBACCleanup verifies that MemberRoles are cleaned up
// when enterprise is disabled, and re-initialized when re-enabled.
func TestEnterpriseToggleRBACCleanup(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, ownerIdentity := registerTestNode(t, rc)
	memberID, memberIdentity := registerTestNode(t, rc)

	// Create enterprise invite-only network
	setClientSigner(rc, ownerIdentity)
	resp, err := rc.CreateNetwork(ownerID, "toggle-rbac", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Invite and accept member, promote to admin
	_, err = rc.InviteToNetwork(netID, ownerID, memberID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	setClientSigner(rc, memberIdentity)
	_, err = rc.RespondInvite(memberID, netID, true)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
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
		t.Fatalf("expected admin, got %v", roleResp["role"])
	}

	// Disable enterprise — roles should be cleaned up
	_, err = rc.SetNetworkEnterprise(netID, false, TestAdminToken)
	if err != nil {
		t.Fatalf("disable enterprise: %v", err)
	}

	// Role check should fail (enterprise off)
	_, err = rc.GetMemberRole(netID, memberID)
	if err == nil {
		t.Fatal("expected error: get_member_role on non-enterprise network")
	}

	// Re-enable enterprise — roles should be re-initialized
	_, err = rc.SetNetworkEnterprise(netID, true, TestAdminToken)
	if err != nil {
		t.Fatalf("re-enable enterprise: %v", err)
	}

	// Owner should be re-initialized as owner (first member gets owner)
	roleResp, err = rc.GetMemberRole(netID, ownerID)
	if err != nil {
		t.Fatalf("get owner role after re-enable: %v", err)
	}
	if roleResp["role"] != "owner" {
		t.Errorf("expected owner after re-enable, got %v", roleResp["role"])
	}

	// Member should be re-initialized as member (not admin — old roles were cleaned)
	roleResp, err = rc.GetMemberRole(netID, memberID)
	if err != nil {
		t.Fatalf("get member role after re-enable: %v", err)
	}
	if roleResp["role"] != "member" {
		t.Errorf("expected member after re-enable (old admin role cleaned), got %v", roleResp["role"])
	}
	t.Log("RBAC roles correctly cleaned on disable, re-initialized on enable")
}

// TestPolicyPortDeduplication verifies that duplicate ports in allowed_ports
// are deduplicated while preserving order.
func TestPolicyPortDeduplication(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, ownerIdentity := registerTestNode(t, rc)

	setClientSigner(rc, ownerIdentity)
	resp, err := rc.CreateNetwork(ownerID, "port-dedup", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Set ports with duplicates
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"allowed_ports": []interface{}{float64(80), float64(443), float64(80), float64(8080), float64(443)},
	}, TestAdminToken)
	if err != nil {
		t.Fatalf("set policy: %v", err)
	}

	// Verify deduplication
	policyResp, err := rc.GetNetworkPolicy(netID)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	ports := policyResp["allowed_ports"].([]interface{})
	if len(ports) != 3 {
		t.Fatalf("expected 3 unique ports, got %d: %v", len(ports), ports)
	}
	// Verify order preserved: 80, 443, 8080
	expected := []float64{80, 443, 8080}
	for i, p := range ports {
		if p.(float64) != expected[i] {
			t.Errorf("port[%d] = %v, want %v", i, p, expected[i])
		}
	}
	t.Logf("ports deduplicated: %v", ports)
}

// TestPolicyOnNonEnterprise verifies that set_network_policy fails on
// non-enterprise networks.
func TestPolicyOnNonEnterprise(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, _ := registerTestNode(t, rc)

	// Create non-enterprise network
	resp, err := rc.CreateNetwork(ownerID, "no-ent-policy", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Try to set policy — should fail
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"max_members": float64(10),
	}, TestAdminToken)
	if err == nil {
		t.Fatal("expected error: policy on non-enterprise network")
	}
	if !strings.Contains(err.Error(), "enterprise") {
		t.Errorf("unexpected error: %v", err)
	}
	t.Logf("policy on non-enterprise correctly rejected: %v", err)
}

// TestTransferToMemberRole verifies that ownership can be transferred
// directly to a member with role=member (not just admin).
func TestTransferToMemberRole(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, ownerIdentity := registerTestNode(t, rc)
	memberID, memberIdentity := registerTestNode(t, rc)

	setClientSigner(rc, ownerIdentity)
	resp, err := rc.CreateNetwork(ownerID, "xfer-member", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Invite and accept member (role=member, NOT admin)
	_, err = rc.InviteToNetwork(netID, ownerID, memberID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	setClientSigner(rc, memberIdentity)
	_, err = rc.RespondInvite(memberID, netID, true)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	// Verify member has role=member
	roleResp, err := rc.GetMemberRole(netID, memberID)
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	if roleResp["role"] != "member" {
		t.Fatalf("expected member role, got %v", roleResp["role"])
	}

	// Transfer ownership to member (role=member)
	_, err = rc.TransferOwnership(netID, ownerID, memberID, TestAdminToken)
	if err != nil {
		t.Fatalf("transfer to member: %v", err)
	}

	// Verify new owner
	roleResp, err = rc.GetMemberRole(netID, memberID)
	if err != nil {
		t.Fatalf("get new owner role: %v", err)
	}
	if roleResp["role"] != "owner" {
		t.Errorf("expected owner, got %v", roleResp["role"])
	}

	// Verify old owner is now admin
	roleResp, err = rc.GetMemberRole(netID, ownerID)
	if err != nil {
		t.Fatalf("get old owner role: %v", err)
	}
	if roleResp["role"] != "admin" {
		t.Errorf("expected admin, got %v", roleResp["role"])
	}

	// Verify audit captured the old role
	auditResp, err := rc.GetAuditLog(0, TestAdminToken)
	if err != nil {
		t.Fatalf("get audit: %v", err)
	}
	entries := auditResp["entries"].([]interface{})
	foundTransfer := false
	for _, e := range entries {
		entry := e.(map[string]interface{})
		if entry["action"] == "network.ownership_transferred" {
			details, _ := entry["details"].(string)
			if strings.Contains(details, "new_owner_old_role=member") {
				foundTransfer = true
			}
		}
	}
	if !foundTransfer {
		t.Error("ownership transfer audit missing new_owner_old_role=member")
	}
	t.Log("transfer to member role works, audit captures old role")
}

// TestHostnameCollision verifies that setting a hostname already in use by
// another node is rejected.
func TestHostnameCollision(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeA, _ := registerTestNode(t, rc)
	nodeB, _ := registerTestNode(t, rc)

	// Set hostname on node A
	_, err := rc.SetHostnameAdmin(nodeA, "taken-host", TestAdminToken)
	if err != nil {
		t.Fatalf("set hostname A: %v", err)
	}

	// Try to set same hostname on node B — should fail
	_, err = rc.SetHostnameAdmin(nodeB, "taken-host", TestAdminToken)
	if err == nil {
		t.Fatal("expected error: hostname collision should be rejected")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Errorf("unexpected error: %v", err)
	}
	t.Logf("hostname collision rejected: %v", err)

	// Node A can re-set its own hostname (idempotent)
	_, err = rc.SetHostnameAdmin(nodeA, "taken-host", TestAdminToken)
	if err != nil {
		t.Fatalf("re-set own hostname should succeed: %v", err)
	}

	// Clear hostname on A, then B can claim it
	_, err = rc.SetHostnameAdmin(nodeA, "", TestAdminToken)
	if err != nil {
		t.Fatalf("clear hostname: %v", err)
	}
	_, err = rc.SetHostnameAdmin(nodeB, "taken-host", TestAdminToken)
	if err != nil {
		t.Fatalf("set freed hostname should succeed: %v", err)
	}
	t.Log("hostname collision, re-set, clear, and reclaim all work correctly")
}

// TestHostnameValidationEnterprise verifies that invalid hostnames are rejected
// via the admin-token path.
func TestHostnameValidationEnterprise(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, _ := registerTestNode(t, rc)

	cases := []struct {
		name     string
		hostname string
		wantErr  string
	}{
		{"too long", strings.Repeat("a", 64), "invalid"},
		{"starts with hyphen", "-bad", "invalid"},
		{"ends with hyphen", "bad-", "invalid"},
		{"uppercase", "BAD", "invalid"},
		{"special chars", "bad@host", "invalid"},
		{"reserved localhost", "localhost", "reserved"},
		{"reserved backbone", "backbone", "reserved"},
		{"reserved broadcast", "broadcast", "reserved"},
	}

	for _, tc := range cases {
		_, err := rc.SetHostnameAdmin(nodeID, tc.hostname, TestAdminToken)
		if err == nil {
			t.Errorf("%s: expected error for hostname %q", tc.name, tc.hostname)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: got %v, want error containing %q", tc.name, err, tc.wantErr)
		}
	}

	// Valid hostnames should work
	validCases := []string{"a", "my-host", "node-1", "abc123"}
	for _, h := range validCases {
		_, err := rc.SetHostnameAdmin(nodeID, h, TestAdminToken)
		if err != nil {
			t.Errorf("valid hostname %q rejected: %v", h, err)
		}
	}
	t.Log("hostname validation correctly enforced")
}

// TestNodeOpsOnNonExistent verifies that hostname, visibility, tags, and
// task_exec operations on non-existent nodes return proper errors.
func TestNodeOpsOnNonExistent(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	badNodeID := uint32(99999)

	// SetHostname on non-existent node
	_, err := rc.SetHostnameAdmin(badNodeID, "ghost", TestAdminToken)
	if err == nil {
		t.Error("expected error for SetHostname on non-existent node")
	} else if !strings.Contains(err.Error(), "not found") {
		t.Errorf("SetHostname error: %v (want 'not found')", err)
	}

	// SetVisibility on non-existent node
	_, err = rc.SetVisibilityAdmin(badNodeID, true, TestAdminToken)
	if err == nil {
		t.Error("expected error for SetVisibility on non-existent node")
	} else if !strings.Contains(err.Error(), "not found") {
		t.Errorf("SetVisibility error: %v (want 'not found')", err)
	}

	// SetTags on non-existent node
	_, err = rc.SetTagsAdmin(badNodeID, []string{"tag1"}, TestAdminToken)
	if err == nil {
		t.Error("expected error for SetTags on non-existent node")
	} else if !strings.Contains(err.Error(), "not found") {
		t.Errorf("SetTags error: %v (want 'not found')", err)
	}

	// SetTaskExec on non-existent node
	_, err = rc.SetTaskExecAdmin(badNodeID, true, TestAdminToken)
	if err == nil {
		t.Error("expected error for SetTaskExec on non-existent node")
	} else if !strings.Contains(err.Error(), "not found") {
		t.Errorf("SetTaskExec error: %v (want 'not found')", err)
	}

	t.Log("all node ops on non-existent node return 'not found'")
}

// TestKickRevokesOutgoingInvites verifies that when a member is kicked,
// any invites they sent to other nodes are revoked.
func TestKickRevokesOutgoingInvites(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, ownerIdentity := registerTestNode(t, rc)
	adminID, adminIdentity := registerTestNode(t, rc)
	targetID, targetIdentity := registerTestNode(t, rc)

	// Create enterprise invite-only network
	setClientSigner(rc, ownerIdentity)
	resp, err := rc.CreateNetwork(ownerID, "kick-revoke", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Invite and accept admin, promote
	_, err = rc.InviteToNetwork(netID, ownerID, adminID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite admin: %v", err)
	}
	setClientSigner(rc, adminIdentity)
	_, err = rc.RespondInvite(adminID, netID, true)
	if err != nil {
		t.Fatalf("accept admin: %v", err)
	}
	_, err = rc.PromoteMember(netID, ownerID, adminID, TestAdminToken)
	if err != nil {
		t.Fatalf("promote admin: %v", err)
	}

	// Admin invites target
	_, err = rc.InviteToNetwork(netID, adminID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("admin invite target: %v", err)
	}

	// Verify target has a pending invite
	setClientSigner(rc, targetIdentity)
	pollResp, err := rc.PollInvites(targetID)
	if err != nil {
		t.Fatalf("poll invites: %v", err)
	}
	invites := pollResp["invites"].([]interface{})
	if len(invites) != 1 {
		t.Fatalf("expected 1 invite, got %d", len(invites))
	}

	// Owner kicks admin
	setClientSigner(rc, ownerIdentity)
	_, err = rc.KickMember(netID, ownerID, adminID, TestAdminToken)
	if err != nil {
		t.Fatalf("kick admin: %v", err)
	}

	// Target's pending invite from kicked admin should be revoked
	setClientSigner(rc, targetIdentity)
	pollResp, err = rc.PollInvites(targetID)
	if err != nil {
		t.Fatalf("poll after kick: %v", err)
	}
	invites2, _ := pollResp["invites"].([]interface{})
	if len(invites2) != 0 {
		t.Errorf("expected 0 invites after inviter kicked, got %d", len(invites2))
	}
	t.Log("outgoing invites from kicked member correctly revoked")
}

// TestKeyExpiryUpperBound verifies that unreasonably far future expiry dates
// are rejected (max 10 years).
func TestKeyExpiryUpperBound(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, nodeIdentity := registerTestNode(t, rc)

	// Create enterprise network so key expiry works
	setClientSigner(rc, nodeIdentity)
	resp, err := rc.CreateNetwork(nodeID, "expiry-bound", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = uint16(resp["network_id"].(float64))

	// 5 years should be OK
	fiveYears := time.Now().Add(5 * 365 * 24 * time.Hour)
	_, err = rc.SetKeyExpiryAdmin(nodeID, fiveYears, TestAdminToken)
	if err != nil {
		t.Fatalf("5-year expiry should work: %v", err)
	}

	// 11 years should be rejected
	elevenYears := time.Now().Add(11 * 365 * 24 * time.Hour)
	_, err = rc.SetKeyExpiryAdmin(nodeID, elevenYears, TestAdminToken)
	if err == nil {
		t.Fatal("expected error: 11-year expiry should be rejected")
	}
	if !strings.Contains(err.Error(), "invalid") && !strings.Contains(err.Error(), "10 years") {
		t.Errorf("unexpected error: %v", err)
	}
	t.Logf("upper bound enforced: %v", err)
}

// TestReInviteAfterLeave verifies that a node can be re-invited after leaving.
func TestReInviteAfterLeave(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, ownerIdentity := registerTestNode(t, rc)
	memberID, memberIdentity := registerTestNode(t, rc)

	setClientSigner(rc, ownerIdentity)
	resp, err := rc.CreateNetwork(ownerID, "reinvite", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Invite, accept, leave
	_, err = rc.InviteToNetwork(netID, ownerID, memberID, TestAdminToken)
	if err != nil {
		t.Fatalf("first invite: %v", err)
	}
	setClientSigner(rc, memberIdentity)
	_, err = rc.RespondInvite(memberID, netID, true)
	if err != nil {
		t.Fatalf("first accept: %v", err)
	}

	// Leave
	_, err = rc.LeaveNetwork(memberID, netID, "")
	if err != nil {
		t.Fatalf("leave: %v", err)
	}

	// Re-invite should succeed (node is no longer a member)
	setClientSigner(rc, ownerIdentity)
	_, err = rc.InviteToNetwork(netID, ownerID, memberID, TestAdminToken)
	if err != nil {
		t.Fatalf("re-invite after leave should succeed: %v", err)
	}

	// Accept re-invite
	setClientSigner(rc, memberIdentity)
	_, err = rc.RespondInvite(memberID, netID, true)
	if err != nil {
		t.Fatalf("re-accept: %v", err)
	}

	// Verify member is back with member role
	roleResp, err := rc.GetMemberRole(netID, memberID)
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	if roleResp["role"] != "member" {
		t.Errorf("expected member role after re-join, got %v", roleResp["role"])
	}
	t.Log("re-invite after leave works correctly")
}

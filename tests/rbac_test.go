package tests

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// TestRBACOwnerRole verifies that the creator of a network gets the owner role.
func TestRBACOwnerRole(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Register a node
	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Create a network
	netResp, err := rc.CreateNetwork(nodeID, "rbac-owner-test", "open", "", env.AdminToken, true)
	if err != nil {
		t.Fatalf("create_network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	// Check role
	roleResp, err := rc.GetMemberRole(netID, nodeID)
	if err != nil {
		t.Fatalf("get_member_role: %v", err)
	}
	role, _ := roleResp["role"].(string)
	if role != "owner" {
		t.Fatalf("expected role 'owner', got %q", role)
	}
	t.Logf("creator has role: %s", role)
}

// TestRBACMemberJoin verifies that joining via token gives the member role.
func TestRBACMemberJoin(t *testing.T) {
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
	netResp, err := rc.CreateNetwork(nodeID1, "rbac-join-test", "token", "join-secret", env.AdminToken, true)
	if err != nil {
		t.Fatalf("create_network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	// Register second node
	id2, _ := crypto.GenerateIdentity()
	resp2, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id2.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node2: %v", err)
	}
	nodeID2 := uint32(resp2["node_id"].(float64))

	// Join with token
	_, err = rc.JoinNetwork(nodeID2, netID, "join-secret", 0, env.AdminToken)
	if err != nil {
		t.Fatalf("join_network: %v", err)
	}

	// Check role — should be member
	roleResp, err := rc.GetMemberRole(netID, nodeID2)
	if err != nil {
		t.Fatalf("get_member_role: %v", err)
	}
	role, _ := roleResp["role"].(string)
	if role != "member" {
		t.Fatalf("expected role 'member', got %q", role)
	}
	t.Logf("joiner has role: %s", role)

	// Owner should still be owner
	ownerRole, err := rc.GetMemberRole(netID, nodeID1)
	if err != nil {
		t.Fatalf("get owner role: %v", err)
	}
	if ownerRole["role"].(string) != "owner" {
		t.Fatalf("expected owner role, got %q", ownerRole["role"])
	}
}

// TestRBACPromoteDemote verifies that the owner can promote a member to admin
// and then demote them back to member.
func TestRBACPromoteDemote(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Register owner
	id1, _ := crypto.GenerateIdentity()
	resp1, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id1.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	ownerNodeID := uint32(resp1["node_id"].(float64))

	// Create network
	netResp, err := rc.CreateNetwork(ownerNodeID, "rbac-promote-test", "open", "", env.AdminToken, true)
	if err != nil {
		t.Fatalf("create_network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	// Register member
	id2, _ := crypto.GenerateIdentity()
	resp2, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id2.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register member: %v", err)
	}
	memberNodeID := uint32(resp2["node_id"].(float64))

	// Join network
	_, err = rc.JoinNetwork(memberNodeID, netID, "", 0, env.AdminToken)
	if err != nil {
		t.Fatalf("join_network: %v", err)
	}

	// Promote member to admin (using admin token for owner auth)
	promResp, err := rc.PromoteMember(netID, ownerNodeID, memberNodeID, env.AdminToken)
	if err != nil {
		t.Fatalf("promote_member: %v", err)
	}
	if promResp["role"].(string) != "admin" {
		t.Fatalf("expected promoted role 'admin', got %q", promResp["role"])
	}

	// Verify role is admin
	roleResp, err := rc.GetMemberRole(netID, memberNodeID)
	if err != nil {
		t.Fatalf("get_member_role after promote: %v", err)
	}
	if roleResp["role"].(string) != "admin" {
		t.Fatalf("expected 'admin', got %q", roleResp["role"])
	}

	// Demote admin back to member
	demResp, err := rc.DemoteMember(netID, ownerNodeID, memberNodeID, env.AdminToken)
	if err != nil {
		t.Fatalf("demote_member: %v", err)
	}
	if demResp["role"].(string) != "member" {
		t.Fatalf("expected demoted role 'member', got %q", demResp["role"])
	}

	// Verify role is member again
	roleResp2, err := rc.GetMemberRole(netID, memberNodeID)
	if err != nil {
		t.Fatalf("get_member_role after demote: %v", err)
	}
	if roleResp2["role"].(string) != "member" {
		t.Fatalf("expected 'member', got %q", roleResp2["role"])
	}
	t.Logf("promote/demote cycle completed successfully")
}

// TestRBACAdminCanInvite verifies that admin role can invite to invite-only networks
// but member role cannot.
func TestRBACAdminCanInvite(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Register owner, admin, member, and target nodes
	id1, _ := crypto.GenerateIdentity()
	resp1, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id1.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	ownerID := uint32(resp1["node_id"].(float64))

	id2, _ := crypto.GenerateIdentity()
	resp2, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id2.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register admin: %v", err)
	}
	adminID := uint32(resp2["node_id"].(float64))

	id3, _ := crypto.GenerateIdentity()
	resp3, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id3.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register member: %v", err)
	}
	memberID := uint32(resp3["node_id"].(float64))

	id4, _ := crypto.GenerateIdentity()
	resp4, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id4.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register target: %v", err)
	}
	targetID := uint32(resp4["node_id"].(float64))

	// Create invite-only network
	netResp, err := rc.CreateNetwork(ownerID, "rbac-invite-test", "invite", "", env.AdminToken, true)
	if err != nil {
		t.Fatalf("create_network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	// Use admin token to invite admin-to-be and member-to-be (bootstrapping)
	_, err = rc.InviteToNetwork(netID, ownerID, adminID, env.AdminToken)
	if err != nil {
		t.Fatalf("invite admin: %v", err)
	}
	_, err = rc.InviteToNetwork(netID, ownerID, memberID, env.AdminToken)
	if err != nil {
		t.Fatalf("invite member: %v", err)
	}

	// Accept invites — need signed clients
	rcAdmin := dialWithIdentity(t, env.RegistryAddr, id2, adminID)
	defer rcAdmin.Close()
	_, err = rcAdmin.RespondInvite(adminID, netID, true)
	if err != nil {
		t.Fatalf("admin accept invite: %v", err)
	}

	rcMember := dialWithIdentity(t, env.RegistryAddr, id3, memberID)
	defer rcMember.Close()
	_, err = rcMember.RespondInvite(memberID, netID, true)
	if err != nil {
		t.Fatalf("member accept invite: %v", err)
	}

	// Promote adminID to admin
	_, err = rc.PromoteMember(netID, ownerID, adminID, env.AdminToken)
	if err != nil {
		t.Fatalf("promote admin: %v", err)
	}

	// Admin should be able to invite target using signed client (admin role is sufficient)
	_, err = rcAdmin.InviteToNetwork(netID, adminID, targetID, "")
	if err != nil {
		t.Fatalf("admin invite should succeed: %v", err)
	}

	// Register another target for the member to try inviting
	id5, _ := crypto.GenerateIdentity()
	resp5, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id5.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register target2: %v", err)
	}
	targetID2 := uint32(resp5["node_id"].(float64))

	// Member should NOT be able to invite using signed client (member role is insufficient)
	_, err = rcMember.InviteToNetwork(netID, memberID, targetID2, "")
	if err == nil {
		t.Fatal("member should not be able to invite to network")
	}
	t.Logf("correctly rejected member invite: %v", err)
}

// dialWithIdentity creates a registry client authenticated with the given identity.
func dialWithIdentity(t *testing.T, addr string, id *crypto.Identity, nodeID uint32) *registry.Client {
	t.Helper()
	rc, err := registry.Dial(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	setClientSigner(rc, id)
	return rc
}

// TestRBACOnlyOwnerCanDelete verifies that member and admin cannot delete
// a network, only the owner can.
func TestRBACOnlyOwnerCanDelete(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Register owner
	id1, _ := crypto.GenerateIdentity()
	resp1, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id1.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	ownerID := uint32(resp1["node_id"].(float64))

	// Create network
	netResp, err := rc.CreateNetwork(ownerID, "rbac-delete-test", "open", "", env.AdminToken, true)
	if err != nil {
		t.Fatalf("create_network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	// Register and join a member
	id2, _ := crypto.GenerateIdentity()
	resp2, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id2.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register member: %v", err)
	}
	memberID := uint32(resp2["node_id"].(float64))
	_, err = rc.JoinNetwork(memberID, netID, "", 0, env.AdminToken)
	if err != nil {
		t.Fatalf("join member: %v", err)
	}

	// Register and join an admin
	id3, _ := crypto.GenerateIdentity()
	resp3, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id3.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register admin: %v", err)
	}
	adminID := uint32(resp3["node_id"].(float64))
	_, err = rc.JoinNetwork(adminID, netID, "", 0, env.AdminToken)
	if err != nil {
		t.Fatalf("join admin: %v", err)
	}
	_, err = rc.PromoteMember(netID, ownerID, adminID, env.AdminToken)
	if err != nil {
		t.Fatalf("promote admin: %v", err)
	}

	// Member tries to delete — should fail (no admin token, member role)
	_, err = rc.DeleteNetwork(netID, "", memberID)
	if err == nil {
		t.Fatal("member should not be able to delete network")
	}
	t.Logf("correctly rejected member delete: %v", err)

	// Admin tries to delete — should fail (admin role insufficient, only owner can delete)
	_, err = rc.DeleteNetwork(netID, "", adminID)
	if err == nil {
		t.Fatal("admin should not be able to delete network")
	}
	t.Logf("correctly rejected admin delete: %v", err)

	// Owner deletes — should succeed (using global admin token)
	_, err = rc.DeleteNetwork(netID, env.AdminToken, ownerID)
	if err != nil {
		t.Fatalf("owner delete should succeed: %v", err)
	}
	t.Logf("owner successfully deleted network")
}

// TestRBACKickMember verifies that admin can kick a member but cannot kick the owner.
func TestRBACKickMember(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Register owner
	id1, _ := crypto.GenerateIdentity()
	resp1, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id1.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	ownerID := uint32(resp1["node_id"].(float64))

	// Create network
	netResp, err := rc.CreateNetwork(ownerID, "rbac-kick-test", "open", "", env.AdminToken, true)
	if err != nil {
		t.Fatalf("create_network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	// Register and join admin
	id2, _ := crypto.GenerateIdentity()
	resp2, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id2.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register admin: %v", err)
	}
	adminID := uint32(resp2["node_id"].(float64))
	_, err = rc.JoinNetwork(adminID, netID, "", 0, env.AdminToken)
	if err != nil {
		t.Fatalf("join admin: %v", err)
	}
	_, err = rc.PromoteMember(netID, ownerID, adminID, env.AdminToken)
	if err != nil {
		t.Fatalf("promote admin: %v", err)
	}

	// Register and join member
	id3, _ := crypto.GenerateIdentity()
	resp3, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id3.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register member: %v", err)
	}
	memberID := uint32(resp3["node_id"].(float64))
	_, err = rc.JoinNetwork(memberID, netID, "", 0, env.AdminToken)
	if err != nil {
		t.Fatalf("join member: %v", err)
	}

	// Admin kicks member — should succeed
	_, err = rc.KickMember(netID, adminID, memberID, env.AdminToken)
	if err != nil {
		t.Fatalf("admin kick member should succeed: %v", err)
	}
	t.Logf("admin kicked member successfully")

	// Verify member is no longer in network
	_, err = rc.GetMemberRole(netID, memberID)
	if err == nil {
		t.Fatal("kicked member should not have a role")
	}
	t.Logf("kicked member has no role: %v", err)

	// Admin tries to kick owner — should fail
	_, err = rc.KickMember(netID, adminID, ownerID, env.AdminToken)
	if err == nil {
		t.Fatal("admin should not be able to kick owner")
	}
	t.Logf("correctly rejected kick owner: %v", err)
}

// TestRBACPerNetworkAdminToken verifies that per-network admin tokens grant
// admin access to that specific network only.
func TestRBACPerNetworkAdminToken(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Register a node
	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Create network 1 with per-network admin token
	net1Token := "net1-secret-token"
	net1Resp, err := rc.CreateNetwork(nodeID, "rbac-pertoken-net1", "open", "", env.AdminToken, true, net1Token)
	if err != nil {
		t.Fatalf("create network 1: %v", err)
	}
	net1ID := uint16(net1Resp["network_id"].(float64))

	// Create network 2 without per-network admin token
	net2Resp, err := rc.CreateNetwork(nodeID, "rbac-pertoken-net2", "open", "", env.AdminToken, true)
	if err != nil {
		t.Fatalf("create network 2: %v", err)
	}
	net2ID := uint16(net2Resp["network_id"].(float64))

	// Per-network token should work for rename on network 1 (no node_id, pure token auth)
	_, err = rc.RenameNetwork(net1ID, "rbac-pertoken-renamed", net1Token)
	if err != nil {
		t.Fatalf("rename with per-network token should succeed: %v", err)
	}
	t.Logf("per-network token worked for network 1 rename")

	// Per-network token from net1 should NOT work for network 2 (no node_id, pure token)
	_, err = rc.RenameNetwork(net2ID, "rbac-pertoken-fail", net1Token)
	if err == nil {
		t.Fatal("per-network token from net1 should not work for net2")
	}
	t.Logf("correctly rejected cross-network token: %v", err)

	// Global admin token should work for network 2
	_, err = rc.RenameNetwork(net2ID, "rbac-pertoken-global", env.AdminToken)
	if err != nil {
		t.Fatalf("global admin token should work for any network: %v", err)
	}
	t.Logf("global admin token worked for network 2")

	// Register a second node and join network 1
	id2, _ := crypto.GenerateIdentity()
	resp2, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id2.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node2: %v", err)
	}
	nodeID2 := uint32(resp2["node_id"].(float64))
	_, err = rc.JoinNetwork(nodeID2, net1ID, "", 0, env.AdminToken)
	if err != nil {
		t.Fatalf("join node2 to net1: %v", err)
	}

	// Per-network token should allow kick on network 1 (no node_id, pure token)
	_, err = rc.KickMember(net1ID, 0, nodeID2, net1Token)
	if err != nil {
		t.Fatalf("kick with per-network token should succeed: %v", err)
	}
	t.Logf("per-network token worked for kick on network 1")

	// Register third node and join network 2
	id3, _ := crypto.GenerateIdentity()
	resp3, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id3.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node3: %v", err)
	}
	nodeID3 := uint32(resp3["node_id"].(float64))
	_, err = rc.JoinNetwork(nodeID3, net2ID, "", 0, env.AdminToken)
	if err != nil {
		t.Fatalf("join node3 to net2: %v", err)
	}

	// Per-network token from net1 should NOT allow kick on network 2 (no node_id)
	_, err = rc.KickMember(net2ID, 0, nodeID3, net1Token)
	if err == nil {
		t.Fatal("per-network token from net1 should not work for kick on net2")
	}
	t.Logf("correctly rejected cross-network token for kick: %v", err)
}

// TestRBACInviteAcceptGetsRole verifies that accepting an invite gives member role.
func TestRBACInviteAcceptGetsRole(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Register owner
	id1, _ := crypto.GenerateIdentity()
	resp1, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id1.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	ownerID := uint32(resp1["node_id"].(float64))

	// Register target
	id2, _ := crypto.GenerateIdentity()
	resp2, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id2.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register target: %v", err)
	}
	targetID := uint32(resp2["node_id"].(float64))

	// Create invite-only network
	netResp, err := rc.CreateNetwork(ownerID, "rbac-invite-accept", "invite", "", env.AdminToken, true)
	if err != nil {
		t.Fatalf("create_network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	// Owner invites target (admin token for bootstrap)
	_, err = rc.InviteToNetwork(netID, ownerID, targetID, env.AdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	// Target accepts invite
	rcTarget := dialWithIdentity(t, env.RegistryAddr, id2, targetID)
	defer rcTarget.Close()
	_, err = rcTarget.RespondInvite(targetID, netID, true)
	if err != nil {
		t.Fatalf("accept invite: %v", err)
	}

	// Wait for state to settle
	time.Sleep(50 * time.Millisecond)

	// Check target's role — should be member
	roleResp, err := rc.GetMemberRole(netID, targetID)
	if err != nil {
		t.Fatalf("get_member_role: %v", err)
	}
	if roleResp["role"].(string) != "member" {
		t.Fatalf("expected 'member', got %q", roleResp["role"])
	}
	t.Logf("invited node has role: %s", roleResp["role"])
}

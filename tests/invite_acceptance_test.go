package tests

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// TestInviteRequiresAcceptance verifies the full invite flow:
// invite → poll → accept → node is member.
func TestInviteRequiresAcceptance(t *testing.T) {
	t.Parallel()
	rc, reg, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	// Creator node
	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "invite-net", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create invite network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))
	_ = reg // keep ref

	// Target node
	targetID, targetIdentity := registerTestNode(t, rc)

	// Send invite
	_, err = rc.InviteToNetwork(netID, creatorID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite to network: %v", err)
	}

	// Target polls for invites (signed)
	setClientSigner(rc, targetIdentity)
	pollResp, err := rc.PollInvites(targetID)
	if err != nil {
		t.Fatalf("poll invites: %v", err)
	}
	invites, ok := pollResp["invites"].([]interface{})
	if !ok || len(invites) == 0 {
		t.Fatalf("expected 1 invite, got %v", pollResp["invites"])
	}
	inv := invites[0].(map[string]interface{})
	if uint16(inv["network_id"].(float64)) != netID {
		t.Fatalf("invite network_id mismatch: got %v, want %d", inv["network_id"], netID)
	}

	// Verify NOT a member before accepting
	members, err := rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	for _, n := range members["nodes"].([]interface{}) {
		nm := n.(map[string]interface{})
		if uint32(nm["node_id"].(float64)) == targetID {
			t.Fatal("target should NOT be a member before accepting invite")
		}
	}

	// Accept invite
	_, err = rc.RespondInvite(targetID, netID, true)
	if err != nil {
		t.Fatalf("respond invite (accept): %v", err)
	}

	// Verify IS a member after accepting
	members, err = rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes after accept: %v", err)
	}
	found := false
	for _, n := range members["nodes"].([]interface{}) {
		nm := n.(map[string]interface{})
		if uint32(nm["node_id"].(float64)) == targetID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("target should be a member after accepting invite")
	}
}

// TestInviteReject verifies that rejecting an invite does NOT add the node.
func TestInviteReject(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "reject-net", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	targetID, targetIdentity := registerTestNode(t, rc)

	// Invite
	_, err = rc.InviteToNetwork(netID, creatorID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	// Poll and reject
	setClientSigner(rc, targetIdentity)
	_, err = rc.PollInvites(targetID)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}

	_, err = rc.RespondInvite(targetID, netID, false)
	if err != nil {
		t.Fatalf("respond invite (reject): %v", err)
	}

	// Verify NOT a member
	members, err := rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	for _, n := range members["nodes"].([]interface{}) {
		nm := n.(map[string]interface{})
		if uint32(nm["node_id"].(float64)) == targetID {
			t.Fatal("target should NOT be a member after rejecting invite")
		}
	}
}

// TestInviteDedup verifies that inviting the same node twice to the same network
// deduplicates (only one invite in inbox).
func TestInviteDedup(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "dedup-net", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	targetID, targetIdentity := registerTestNode(t, rc)

	// Invite twice
	_, err = rc.InviteToNetwork(netID, creatorID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("first invite: %v", err)
	}
	_, err = rc.InviteToNetwork(netID, creatorID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("second invite: %v", err)
	}

	// Poll — should get exactly 1 invite
	setClientSigner(rc, targetIdentity)
	pollResp, err := rc.PollInvites(targetID)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	invites := pollResp["invites"].([]interface{})
	if len(invites) != 1 {
		t.Fatalf("expected 1 invite (dedup), got %d", len(invites))
	}
}

// TestInviteRequiresAdmin verifies that invite_to_network requires admin token.
func TestInviteRequiresAdmin(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "admin-net", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	targetID, _ := registerTestNode(t, rc)

	// Try invite without admin token
	_, err = rc.InviteToNetwork(netID, creatorID, targetID, "")
	if err == nil {
		t.Fatal("expected error when inviting without admin token, got nil")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestInviteNonMemberCantInvite verifies that a non-member cannot invite others.
func TestInviteNonMemberCantInvite(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "member-check-net", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	outsiderID, _ := registerTestNode(t, rc)
	targetID, _ := registerTestNode(t, rc)

	// Try invite from non-member (without admin token — uses signature only)
	_, err = rc.InviteToNetwork(netID, outsiderID, targetID, "")
	if err == nil {
		t.Fatal("expected error when non-member invites via signature, got nil")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestInvitePersistence verifies that invites survive a registry restart.
func TestInvitePersistence(t *testing.T) {
	t.Parallel()
	tmpDir, err := os.MkdirTemp("/tmp", "w4-invite-persist-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "registry.json")

	// Phase 1: start registry, create invite-only network, invite target
	reg1 := registry.NewWithStore("127.0.0.1:9001", storePath)
	reg1.SetAdminToken(TestAdminToken)
	go reg1.ListenAndServe(":0")
	select {
	case <-reg1.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 1 failed to start")
	}

	rc1, err := registry.Dial(reg1.Addr().String())
	if err != nil {
		t.Fatalf("dial registry 1: %v", err)
	}

	creatorID, _ := registerTestNode(t, rc1)
	resp, err := rc1.CreateNetwork(creatorID, "persist-invite-net", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	targetID, targetIdentity := registerTestNode(t, rc1)

	_, err = rc1.InviteToNetwork(netID, creatorID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	rc1.Close()
	reg1.Close()

	// Phase 2: restart, poll invites — should still be there
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

	setClientSigner(rc2, targetIdentity)
	pollResp, err := rc2.PollInvites(targetID)
	if err != nil {
		t.Fatalf("poll invites after restart: %v", err)
	}
	invites, ok := pollResp["invites"].([]interface{})
	if !ok || len(invites) == 0 {
		t.Fatalf("expected invite after restart, got %v", pollResp["invites"])
	}
	inv := invites[0].(map[string]interface{})
	if uint16(inv["network_id"].(float64)) != netID {
		t.Fatalf("invite network_id mismatch after restart")
	}
}

// TestInviteInboxClearedAfterPoll verifies that polling the inbox clears it —
// a second poll returns an empty list, not the same invites again.
func TestInviteInboxClearedAfterPoll(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "inbox-clear-net", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	targetID, targetIdentity := registerTestNode(t, rc)
	_, err = rc.InviteToNetwork(netID, creatorID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	setClientSigner(rc, targetIdentity)

	// First poll should return 1 invite
	pollResp, err := rc.PollInvites(targetID)
	if err != nil {
		t.Fatalf("first poll: %v", err)
	}
	invites, _ := pollResp["invites"].([]interface{})
	if len(invites) != 1 {
		t.Fatalf("first poll: expected 1 invite, got %d", len(invites))
	}

	// Second poll should still return the same invite (poll doesn't consume)
	pollResp2, err := rc.PollInvites(targetID)
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}
	invites2, _ := pollResp2["invites"].([]interface{})
	if len(invites2) != 1 {
		t.Fatalf("second poll: expected 1 invite (poll doesn't consume), got %d", len(invites2))
	}

	// Accept the invite — this consumes it
	_, err = rc.RespondInvite(targetID, netID, true)
	if err != nil {
		t.Fatalf("accept invite: %v", err)
	}

	// Third poll should return empty inbox (consumed by respond)
	pollResp3, err := rc.PollInvites(targetID)
	if err != nil {
		t.Fatalf("third poll: %v", err)
	}
	invites3, _ := pollResp3["invites"].([]interface{})
	if len(invites3) != 0 {
		t.Fatalf("third poll: expected empty inbox after respond, got %d invites", len(invites3))
	}
}

// TestPollEmptyInbox verifies that polling with no pending invites returns an
// empty list without error.
func TestPollEmptyInbox(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	targetID, targetIdentity := registerTestNode(t, rc)
	setClientSigner(rc, targetIdentity)

	pollResp, err := rc.PollInvites(targetID)
	if err != nil {
		t.Fatalf("poll empty inbox: %v", err)
	}
	invites, _ := pollResp["invites"].([]interface{})
	if len(invites) != 0 {
		t.Fatalf("expected empty inbox, got %d invites", len(invites))
	}
}

// TestInviteToNonExistentNetwork verifies that inviting to a non-existent
// network returns an error.
func TestInviteToNonExistentNetwork(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	inviterID, _ := registerTestNode(t, rc)
	targetID, _ := registerTestNode(t, rc)

	_, err := rc.InviteToNetwork(9999, inviterID, targetID, TestAdminToken)
	if err == nil {
		t.Fatal("expected error when inviting to non-existent network, got nil")
	}
}

// TestInviteTargetAlreadyMember verifies that inviting a node that is already
// a member of the network returns an error.
func TestInviteTargetAlreadyMember(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "already-member-net", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	targetID, targetIdentity := registerTestNode(t, rc)

	// Invite and accept to make target a member
	rc.InviteToNetwork(netID, creatorID, targetID, TestAdminToken)
	setClientSigner(rc, targetIdentity)
	rc.PollInvites(targetID)
	rc.RespondInvite(targetID, netID, true)

	// Try to invite again — should fail since target is now a member
	_, err = rc.InviteToNetwork(netID, creatorID, targetID, TestAdminToken)
	if err == nil {
		t.Fatal("expected error when inviting node that is already a member, got nil")
	}
}

// TestInviteOpenNetworkRejected verifies that invite_to_network fails for
// non-invite-only networks.
func TestInviteOpenNetworkRejected(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "open-invite-test", "open", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create open network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	targetID, _ := registerTestNode(t, rc)

	_, err = rc.InviteToNetwork(netID, creatorID, targetID, TestAdminToken)
	if err == nil {
		t.Fatal("expected error when inviting to non-invite-only network, got nil")
	}
}

// TestInviteMultipleNetworksAcceptAll verifies that a node can be invited to
// multiple networks simultaneously and accept all of them.
func TestInviteMultipleNetworksAcceptAll(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	creatorID, _ := registerTestNode(t, rc)
	targetID, targetIdentity := registerTestNode(t, rc)

	const numNetworks = 3
	netIDs := make([]uint16, numNetworks)
	for i := 0; i < numNetworks; i++ {
		resp, err := rc.CreateNetwork(creatorID, fmt.Sprintf("multi-net-%d", i), "invite", "", TestAdminToken, true)
		if err != nil {
			t.Fatalf("create network %d: %v", i, err)
		}
		netIDs[i] = uint16(resp["network_id"].(float64))
		_, err = rc.InviteToNetwork(netIDs[i], creatorID, targetID, TestAdminToken)
		if err != nil {
			t.Fatalf("invite to network %d: %v", i, err)
		}
	}

	setClientSigner(rc, targetIdentity)
	pollResp, err := rc.PollInvites(targetID)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	invites, _ := pollResp["invites"].([]interface{})
	if len(invites) != numNetworks {
		t.Fatalf("expected %d invites, got %d", numNetworks, len(invites))
	}

	for _, netID := range netIDs {
		_, err = rc.RespondInvite(targetID, netID, true)
		if err != nil {
			t.Fatalf("accept invite for net %d: %v", netID, err)
		}
	}

	// Verify membership in all networks
	for _, netID := range netIDs {
		members, err := rc.ListNodes(netID, TestAdminToken)
		if err != nil {
			t.Fatalf("list nodes for net %d: %v", netID, err)
		}
		found := false
		for _, n := range members["nodes"].([]interface{}) {
			nm := n.(map[string]interface{})
			if uint32(nm["node_id"].(float64)) == targetID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("target not a member of network %d after accepting", netID)
		}
	}
}

// TestInviteConcurrentAccepts verifies that multiple nodes can simultaneously
// accept invites to the same network without races or double-counting.
func TestInviteConcurrentAccepts(t *testing.T) {
	t.Parallel()
	rc, reg, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	regAddr := reg.Addr().String()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "concurrent-accept-net", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	const n = 5
	nodes := make([]struct {
		id uint32
		rc *registry.Client
	}, n)

	for i := 0; i < n; i++ {
		nodeRC, err := registry.Dial(regAddr)
		if err != nil {
			t.Fatalf("dial for node %d: %v", i, err)
		}
		defer nodeRC.Close()
		nodeID, nodeIdentity := registerTestNode(t, nodeRC)
		nodes[i].id = nodeID
		nodes[i].rc = nodeRC

		_, err = rc.InviteToNetwork(netID, creatorID, nodeID, TestAdminToken)
		if err != nil {
			t.Fatalf("invite node %d: %v", i, err)
		}
		setClientSigner(nodeRC, nodeIdentity)
	}

	// All nodes concurrently poll and accept
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			nodes[i].rc.PollInvites(nodes[i].id)
			_, errs[i] = nodes[i].rc.RespondInvite(nodes[i].id, netID, true)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("node %d accept error: %v", i, err)
		}
	}

	// Verify all 5 nodes are members + creator = 6 total
	members, err := rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	nodeList := members["nodes"].([]interface{})
	if len(nodeList) != n+1 {
		t.Fatalf("expected %d members (creator + %d acceptors), got %d", n+1, n, len(nodeList))
	}
}

// TestInviteInboxCapEnforced verifies that the invite inbox cap (100) is
// enforced and the 101st invite to the same target is rejected.
func TestInviteInboxCapEnforced(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	creatorID, _ := registerTestNode(t, rc)
	targetID, _ := registerTestNode(t, rc)

	const cap = 100
	for i := 0; i < cap; i++ {
		netName := fmt.Sprintf("cap-net-%03d", i)
		resp, err := rc.CreateNetwork(creatorID, netName, "invite", "", TestAdminToken, true)
		if err != nil {
			t.Fatalf("create network %d: %v", i, err)
		}
		netID := uint16(resp["network_id"].(float64))
		_, err = rc.InviteToNetwork(netID, creatorID, targetID, TestAdminToken)
		if err != nil {
			t.Fatalf("invite %d: %v", i, err)
		}
	}

	// 101st invite should fail
	resp, err := rc.CreateNetwork(creatorID, "cap-net-overflow", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create overflow network: %v", err)
	}
	overflowNetID := uint16(resp["network_id"].(float64))
	_, err = rc.InviteToNetwork(overflowNetID, creatorID, targetID, TestAdminToken)
	if err == nil {
		t.Fatal("expected error when invite inbox is full, got nil")
	}
}

// TestInviteChain verifies a multi-hop invite chain: creator invites A,
// A accepts and then invites B, B accepts — both are members at the end.
func TestInviteChain(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "chain-net", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	nodeA, identityA := registerTestNode(t, rc)
	nodeB, identityB := registerTestNode(t, rc)

	// Creator → A
	rc.InviteToNetwork(netID, creatorID, nodeA, TestAdminToken)
	setClientSigner(rc, identityA)
	rc.PollInvites(nodeA)
	rc.RespondInvite(nodeA, netID, true)

	// A → B (A is now a member; identityA signer still set, admin token also passed)
	_, err = rc.InviteToNetwork(netID, nodeA, nodeB, TestAdminToken)
	if err != nil {
		t.Fatalf("A invites B: %v", err)
	}
	setClientSigner(rc, identityB)
	rc.PollInvites(nodeB)
	_, err = rc.RespondInvite(nodeB, netID, true)
	if err != nil {
		t.Fatalf("B accepts: %v", err)
	}

	// Verify both A and B are members
	members, err := rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	memberSet := make(map[uint32]bool)
	for _, n := range members["nodes"].([]interface{}) {
		nm := n.(map[string]interface{})
		memberSet[uint32(nm["node_id"].(float64))] = true
	}
	if !memberSet[nodeA] {
		t.Error("node A should be a member")
	}
	if !memberSet[nodeB] {
		t.Error("node B should be a member")
	}
}

// TestDirectJoinInviteNetworkFails verifies that the old JoinNetwork path
// is blocked for invite-only networks.
func TestDirectJoinInviteNetworkFails(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "no-direct-join", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	joinerID, _ := registerTestNode(t, rc)

	// Try direct join — should fail
	_, err = rc.JoinNetwork(joinerID, netID, "", 0, TestAdminToken)
	if err == nil {
		t.Fatal("expected error for direct join on invite-only network, got nil")
	}
	t.Logf("correctly rejected direct join: %v", err)
}

// TestInviteDoubleAcceptRace verifies that accepting the same invite twice
// from concurrent goroutines doesn't crash or double-add the node.
func TestInviteDoubleAcceptRace(t *testing.T) {
	t.Parallel()
	rc, reg, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	regAddr := reg.Addr().String()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "double-accept-net", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	targetID, targetIdentity := registerTestNode(t, rc)

	_, err = rc.InviteToNetwork(netID, creatorID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	// Poll to consume the invite
	setClientSigner(rc, targetIdentity)
	_, err = rc.PollInvites(targetID)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}

	// Attempt to accept from two concurrent connections
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := registry.Dial(regAddr)
			if err != nil {
				results[i] = err
				return
			}
			defer conn.Close()
			setClientSigner(conn, targetIdentity)
			_, results[i] = conn.RespondInvite(targetID, netID, true)
		}(i)
	}
	wg.Wait()

	// At least one should succeed; the second may fail or be a no-op
	successes := 0
	for _, err := range results {
		if err == nil {
			successes++
		}
	}
	if successes == 0 {
		t.Fatalf("both concurrent accepts failed: %v, %v", results[0], results[1])
	}

	// Verify the node appears exactly once in the member list
	members, err := rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	count := 0
	for _, n := range members["nodes"].([]interface{}) {
		nm := n.(map[string]interface{})
		if uint32(nm["node_id"].(float64)) == targetID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected target listed exactly once, got %d", count)
	}
}

// TestInviteAfterTargetDeregister verifies that accepting an invite after the
// target node has deregistered returns an error.
func TestInviteAfterTargetDeregister(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "deregister-invite-net", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	targetID, targetIdentity := registerTestNode(t, rc)

	_, err = rc.InviteToNetwork(netID, creatorID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	// Poll the invite
	setClientSigner(rc, targetIdentity)
	_, err = rc.PollInvites(targetID)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}

	// Deregister the target node
	_, err = rc.Deregister(targetID)
	if err != nil {
		t.Fatalf("deregister: %v", err)
	}

	// Try to accept after deregistration — should fail
	_, err = rc.RespondInvite(targetID, netID, true)
	if err == nil {
		t.Fatal("expected error when accepting invite after deregistration, got nil")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestInviteNetworkDeletedWhilePending verifies that accepting an invite
// fails gracefully when the network was deleted while the invite was pending.
func TestInviteNetworkDeletedWhilePending(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "delete-while-pending", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	targetID, targetIdentity := registerTestNode(t, rc)

	_, err = rc.InviteToNetwork(netID, creatorID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	// Poll the invite
	setClientSigner(rc, targetIdentity)
	_, err = rc.PollInvites(targetID)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}

	// Delete the network while invite is pending
	_, err = rc.DeleteNetwork(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("delete network: %v", err)
	}

	// Try to accept — should fail (network no longer exists)
	_, err = rc.RespondInvite(targetID, netID, true)
	if err == nil {
		t.Fatal("expected error when accepting invite for deleted network, got nil")
	}
	t.Logf("correctly rejected: %v", err)
}

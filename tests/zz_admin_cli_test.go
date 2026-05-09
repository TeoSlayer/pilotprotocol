// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"testing"
)

func TestAdminCreateNetwork(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, _ := registerTestNode(t, rc)

	// Create a network
	resp, err := rc.CreateNetwork(nodeID, "admin-create-test", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}

	netID := uint16(resp["network_id"].(float64))
	if netID == 0 {
		t.Fatal("expected non-zero network ID")
	}

	// Verify it appears in the list
	listResp, err := rc.ListNetworks()
	if err != nil {
		t.Fatalf("list networks: %v", err)
	}

	nets, _ := listResp["networks"].([]interface{})
	found := false
	for _, n := range nets {
		net, _ := n.(map[string]interface{})
		if net["name"] == "admin-create-test" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("created network not found in list")
	}
}

func TestAdminDeleteNetwork(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, _ := registerTestNode(t, rc)

	// Create a network
	resp, err := rc.CreateNetwork(nodeID, "admin-delete-test", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Delete it
	_, err = rc.DeleteNetwork(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("delete network: %v", err)
	}

	// Verify it's gone from the list
	listResp, err := rc.ListNetworks()
	if err != nil {
		t.Fatalf("list networks: %v", err)
	}

	nets, _ := listResp["networks"].([]interface{})
	for _, n := range nets {
		net, _ := n.(map[string]interface{})
		if net["name"] == "admin-delete-test" {
			t.Fatal("deleted network still appears in list")
		}
	}

	// Verify the creator node is no longer a member
	membersResp, err := rc.ListNodes(netID)
	if err == nil {
		t.Fatal("expected error listing deleted network, got nil")
	}
	_ = membersResp
}

func TestAdminDeleteBackboneFails(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	_, err := rc.DeleteNetwork(0, TestAdminToken)
	if err == nil {
		t.Fatal("expected error deleting backbone, got nil")
	}
}

func TestAdminDeleteNonexistentNetwork(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	// Network 999 doesn't exist
	_, err := rc.DeleteNetwork(999, TestAdminToken)
	if err == nil {
		t.Fatal("expected error deleting non-existent network, got nil")
	}
}

func TestAdminDeleteNetworkRequiresToken(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeID, _ := registerTestNode(t, rc)

	resp, err := rc.CreateNetwork(nodeID, "admin-token-test", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Try to delete without token
	_, err = rc.DeleteNetwork(netID, "")
	if err == nil {
		t.Fatal("expected error deleting without token, got nil")
	}

	// Try with wrong token
	_, err = rc.DeleteNetwork(netID, "wrong-token")
	if err == nil {
		t.Fatal("expected error deleting with wrong token, got nil")
	}

	// Verify network still exists
	listResp, err := rc.ListNetworks()
	if err != nil {
		t.Fatalf("list networks: %v", err)
	}

	nets, _ := listResp["networks"].([]interface{})
	found := false
	for _, n := range nets {
		net, _ := n.(map[string]interface{})
		if net["name"] == "admin-token-test" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("network should still exist after failed delete")
	}
}

func TestAdminListBackboneNodes(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeA, _ := registerTestNode(t, rc)
	nodeB, _ := registerTestNode(t, rc)

	// Without admin token, listing backbone should fail
	_, err := rc.ListNodes(0)
	if err == nil {
		t.Fatal("expected error listing backbone without token, got nil")
	}

	// With admin token, should succeed and include both nodes
	resp, err := rc.ListNodes(0, TestAdminToken)
	if err != nil {
		t.Fatalf("list backbone nodes: %v", err)
	}

	nodes, _ := resp["nodes"].([]interface{})
	if len(nodes) < 2 {
		t.Fatalf("expected at least 2 backbone nodes, got %d", len(nodes))
	}

	foundA, foundB := false, false
	for _, n := range nodes {
		node, _ := n.(map[string]interface{})
		id := uint32(node["node_id"].(float64))
		if id == nodeA {
			foundA = true
		}
		if id == nodeB {
			foundB = true
		}
	}
	if !foundA || !foundB {
		t.Fatalf("missing nodes in backbone listing: foundA=%v foundB=%v", foundA, foundB)
	}
}

func TestAdminAddRemoveNode(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeA, _ := registerTestNode(t, rc)
	nodeB, _ := registerTestNode(t, rc)

	// Create network with nodeA
	resp, err := rc.CreateNetwork(nodeA, "admin-addremove-test", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Add nodeB to the network
	_, err = rc.JoinNetwork(nodeB, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join network: %v", err)
	}

	// Verify nodeB is a member
	membersResp, err := rc.ListNodes(netID)
	if err != nil {
		t.Fatalf("list members: %v", err)
	}
	nodes, _ := membersResp["nodes"].([]interface{})
	if len(nodes) != 2 {
		t.Fatalf("expected 2 members, got %d", len(nodes))
	}

	// Remove nodeB
	_, err = rc.LeaveNetwork(nodeB, netID, TestAdminToken)
	if err != nil {
		t.Fatalf("leave network: %v", err)
	}

	// Verify nodeB is gone
	membersResp, err = rc.ListNodes(netID)
	if err != nil {
		t.Fatalf("list members after remove: %v", err)
	}
	nodes, _ = membersResp["nodes"].([]interface{})
	if len(nodes) != 1 {
		t.Fatalf("expected 1 member after remove, got %d", len(nodes))
	}

	memberID := uint32(nodes[0].(map[string]interface{})["node_id"].(float64))
	if memberID != nodeA {
		t.Fatalf("expected remaining member to be nodeA (%d), got %d", nodeA, memberID)
	}
}

// TestAdminDeleteNetworkCleansMembers verifies that deleting a network
// removes the network from all member nodes' network lists.
func TestAdminDeleteNetworkCleansMembers(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeA, _ := registerTestNode(t, rc)
	nodeB, _ := registerTestNode(t, rc)

	// Create network, add both nodes
	resp, err := rc.CreateNetwork(nodeA, "admin-clean-test", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	_, err = rc.JoinNetwork(nodeB, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join network: %v", err)
	}

	// Delete the network
	_, err = rc.DeleteNetwork(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("delete network: %v", err)
	}

	// Create a new network and add nodeA — this should work without issue
	// (nodeA should no longer think it's in the deleted network)
	resp2, err := rc.CreateNetwork(nodeA, "admin-clean-new", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create replacement network: %v", err)
	}
	newNetID := uint16(resp2["network_id"].(float64))

	_, err = rc.JoinNetwork(nodeB, newNetID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join replacement network: %v", err)
	}
}

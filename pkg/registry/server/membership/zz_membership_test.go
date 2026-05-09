// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

import (
	"fmt"
	"sync"
	"testing"
)

// --------------------------------------------------------------------------
// Test helpers
// --------------------------------------------------------------------------

// testEnv bundles the shared state and a Store wired up with no-op / stub
// callbacks for unit testing.
type testEnv struct {
	mu          sync.RWMutex
	networks    map[uint16]*NetworkInfo
	inviteInbox map[uint32][]*NetworkInvite
	nextNet     uint16

	// stub node registry
	nodes   map[uint32]nodeRecord
	audited []string
	saved   int
	memChg  []uint16
	listInv []uint16

	st *Store
}

type nodeRecord struct {
	networks []uint16
}

func newTestEnv() *testEnv {
	e := &testEnv{
		networks:    make(map[uint16]*NetworkInfo),
		inviteInbox: make(map[uint32][]*NetworkInvite),
		nextNet:     1,
		nodes:       make(map[uint32]nodeRecord),
	}

	e.st = NewStore(
		&e.mu,
		e.networks,
		e.inviteInbox,
		&e.nextNet,
		Callbacks{
			Save: func() { e.saved++ },
			Audit: func(action string, attrs ...any) {
				e.audited = append(e.audited, action)
			},
			RecordWALNetworkCreate: func(netID uint16, name, joinRule, token, adminToken string, enterprise bool, creatorNodeID uint32, createdAt string) {
			},
			RecordWALNetworkJoin:   func(nodeID uint32, netID uint16) {},
			RecordWALNetworkLeave:  func(nodeID uint32, netID uint16) {},
			RecordWALNetworkDelete: func(netID uint16) {},
			InvalidateListNodesCache: func(netID uint16) {
				e.listInv = append(e.listInv, netID)
			},
			PublishMembershipChanged: func(netID uint16) {
				e.memChg = append(e.memChg, netID)
			},
			ApplyRBACPreAssignment: func(netID uint16, nodeID uint32) {},
			RequireAdminToken: func(msg map[string]interface{}) error {
				if tok, _ := msg["admin_token"].(string); tok == "admin" {
					return nil
				}
				return fmt.Errorf("unauthorized")
			},
			RequireNetworkRole: func(msg map[string]interface{}, netID uint16, roles ...Role) error {
				// For testing: admin_token="admin" bypasses RBAC
				if tok, _ := msg["admin_token"].(string); tok == "admin" {
					return nil
				}
				// Check node_id role
				nodeID := jsonUint32(msg, "node_id")
				e.mu.RLock()
				net, ok := e.networks[netID]
				e.mu.RUnlock()
				if !ok {
					return fmt.Errorf("network not found")
				}
				role, has := net.MemberRoles[nodeID]
				if !has {
					return fmt.Errorf("not a member")
				}
				for _, r := range roles {
					if role == r {
						return nil
					}
				}
				return fmt.Errorf("insufficient role")
			},
			RequireEnterprise: func(netID uint16) error {
				e.mu.RLock()
				net, ok := e.networks[netID]
				e.mu.RUnlock()
				if !ok {
					return fmt.Errorf("network not found")
				}
				if !net.Enterprise {
					return fmt.Errorf("enterprise required")
				}
				return nil
			},
			VerifyNodeSignature: func(pubKey []byte, adminToken string, msg map[string]interface{}, challenge string) error {
				return nil // skip sig verification in tests
			},
			AdminToken: func() string { return "admin" },
			NodeExists: func(nodeID uint32) bool {
				_, ok := e.nodes[nodeID]
				return ok
			},
			GetNode: func(nodeID uint32) (pubKey []byte, networks []uint16, externalID string, ok bool) {
				n, ok := e.nodes[nodeID]
				if !ok {
					return nil, nil, "", false
				}
				return nil, n.networks, "", true
			},
			NodeNetworks: func(nodeID uint32) ([]uint16, bool) {
				n, ok := e.nodes[nodeID]
				if !ok {
					return nil, false
				}
				return n.networks, true
			},
			AppendNodeNetwork: func(nodeID uint32, netID uint16) {
				n := e.nodes[nodeID]
				n.networks = append(n.networks, netID)
				e.nodes[nodeID] = n
			},
			RemoveNodeNetwork: func(nodeID uint32, netID uint16) bool {
				n := e.nodes[nodeID]
				for i, id := range n.networks {
					if id == netID {
						n.networks = append(n.networks[:i], n.networks[i+1:]...)
						e.nodes[nodeID] = n
						return true
					}
				}
				return false
			},
			IncInvitesSent:     func() {},
			IncInvitesAccepted: func() {},
			IncInvitesRejected: func() {},
			IncRbacOps:         func(op string) {},
		},
		nil, // use default time.Now
	)
	return e
}

// addNode registers a node in the test environment.
func (e *testEnv) addNode(id uint32) {
	e.nodes[id] = nodeRecord{}
}

// createNetwork is a shortcut that calls HandleCreateNetwork with admin_token.
func (e *testEnv) createNetwork(nodeID uint32, name string) (uint16, error) {
	resp, err := e.st.HandleCreateNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(nodeID),
		"name":        name,
		"join_rule":   "open",
	})
	if err != nil {
		return 0, err
	}
	netID, _ := resp["network_id"].(uint16)
	return netID, nil
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

func TestHandleCreateNetwork(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1)

	netID, err := e.createNetwork(1, "test-net")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if netID == 0 {
		t.Fatal("expected non-zero netID")
	}

	// Network must exist
	e.mu.RLock()
	net, ok := e.networks[netID]
	e.mu.RUnlock()
	if !ok {
		t.Fatal("network not in map after create")
	}
	if net.Name != "test-net" {
		t.Errorf("name = %q, want %q", net.Name, "test-net")
	}
	if net.MemberRoles[1] != RoleOwner {
		t.Errorf("creator role = %q, want %q", net.MemberRoles[1], RoleOwner)
	}

	// Creator must be in its own network list
	nodeNets := e.nodes[1].networks
	found := false
	for _, n := range nodeNets {
		if n == netID {
			found = true
		}
	}
	if !found {
		t.Error("creator node not in network after create")
	}

	// Save must have been called
	if e.saved == 0 {
		t.Error("save not called after create")
	}

	// Audit must have been emitted
	if len(e.audited) == 0 {
		t.Error("audit not called after create")
	}

	// Duplicate name must fail
	_, err = e.createNetwork(1, "test-net")
	if err == nil {
		t.Error("expected error for duplicate network name")
	}

	// Invalid name must fail
	_, err = e.createNetwork(1, "UPPERCASE")
	if err == nil {
		t.Error("expected error for invalid network name")
	}
}

func TestHandleJoinNetwork(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1) // creator
	e.addNode(2) // joiner

	netID, err := e.createNetwork(1, "joinable")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Node 2 joins
	resp, err := e.st.HandleJoinNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(2),
		"network_id":  float64(netID),
	})
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if resp["type"] != "join_network_ok" {
		t.Errorf("resp type = %v, want join_network_ok", resp["type"])
	}

	e.mu.RLock()
	net := e.networks[netID]
	e.mu.RUnlock()

	// Must be in member list
	found := false
	for _, m := range net.Members {
		if m == 2 {
			found = true
		}
	}
	if !found {
		t.Error("joiner not in Members after join")
	}
	if net.MemberRoles[2] != RoleMember {
		t.Errorf("joiner role = %q, want member", net.MemberRoles[2])
	}

	// Duplicate join must fail
	_, err = e.st.HandleJoinNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(2),
		"network_id":  float64(netID),
	})
	if err == nil {
		t.Error("expected error for duplicate join")
	}

	// Joining backbone (netID=0) must fail
	_, err = e.st.HandleJoinNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(2),
		"network_id":  float64(0),
	})
	if err == nil {
		t.Error("expected error for backbone join")
	}
}

func TestHandleLeaveNetwork(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1) // creator
	e.addNode(2) // member

	netID, err := e.createNetwork(1, "leave-test")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Node 2 joins
	_, err = e.st.HandleJoinNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(2),
		"network_id":  float64(netID),
	})
	if err != nil {
		t.Fatalf("join: %v", err)
	}

	// Node 2 leaves
	resp, err := e.st.HandleLeaveNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(2),
		"network_id":  float64(netID),
	})
	if err != nil {
		t.Fatalf("leave: %v", err)
	}
	if resp["type"] != "leave_network_ok" {
		t.Errorf("resp type = %v", resp["type"])
	}

	e.mu.RLock()
	net := e.networks[netID]
	e.mu.RUnlock()

	for _, m := range net.Members {
		if m == 2 {
			t.Error("node 2 still in Members after leave")
		}
	}
	if _, has := net.MemberRoles[2]; has {
		t.Error("node 2 still has role after leave")
	}

	// Leaving a network you're not in must fail
	_, err = e.st.HandleLeaveNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(2),
		"network_id":  float64(netID),
	})
	if err == nil {
		t.Error("expected error for leave by non-member")
	}
}

func TestHandlePromoteMember(t *testing.T) {
	t.Parallel()
	e := newTestEnv()
	e.addNode(1) // owner
	e.addNode(2) // member to promote

	// Create enterprise network
	resp, err := e.st.HandleCreateNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(1),
		"name":        "enterprise-net",
		"join_rule":   "open",
		"enterprise":  true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := resp["network_id"].(uint16)

	// Node 2 joins
	_, err = e.st.HandleJoinNetwork(map[string]interface{}{
		"admin_token": "admin",
		"node_id":     float64(2),
		"network_id":  float64(netID),
	})
	if err != nil {
		t.Fatalf("join: %v", err)
	}

	// Promote node 2 to admin
	pResp, err := e.st.HandlePromoteMember(map[string]interface{}{
		"admin_token":    "admin",
		"node_id":        float64(1), // owner performing promote
		"network_id":     float64(netID),
		"target_node_id": float64(2),
	})
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if pResp["role"] != string(RoleAdmin) {
		t.Errorf("role = %v, want admin", pResp["role"])
	}

	e.mu.RLock()
	role := e.networks[netID].MemberRoles[2]
	e.mu.RUnlock()

	if role != RoleAdmin {
		t.Errorf("stored role = %q, want admin", role)
	}

	// Promoting twice must fail
	_, err = e.st.HandlePromoteMember(map[string]interface{}{
		"admin_token":    "admin",
		"node_id":        float64(1),
		"network_id":     float64(netID),
		"target_node_id": float64(2),
	})
	if err == nil {
		t.Error("expected error for promoting already-admin node")
	}
}

func TestValidateNetworkName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		wantErr bool
	}{
		{"valid-name", false},
		{"abc123", false},
		{"a", false},
		{"", true},
		{"backbone", true},
		{"UPPERCASE", true},
		{"has space", true},
		{"-leading-dash", true},
		{"trailing-dash-", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateNetworkName(tc.name)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateNetworkName(%q) error = %v, wantErr %v", tc.name, err, tc.wantErr)
			}
		})
	}
}

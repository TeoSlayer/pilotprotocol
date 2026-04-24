// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/json"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// --- loadPolicyRunners ---

func TestLoadPolicyRunnersClosedRegistryEarlyReturns(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	rc.Close() // close the client so ListNetworks errors

	d := New(Config{})
	d.regConn = rc

	d.loadPolicyRunners() // must not panic

	d.policyMu.Lock()
	n := len(d.policyRunners)
	d.policyMu.Unlock()
	if n != 0 {
		t.Fatalf("policyRunners = %d, want 0 on closed registry", n)
	}
}

func TestLoadPolicyRunnersSkipsNetworksWithoutExprPolicy(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()
	reg.SetAdminToken("admin-token")

	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("127.0.0.1:5000", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Create a network without setting any expr_policy.
	_, err = rc.CreateNetwork(nodeID, "no-policy-net", "open", "", "admin-token", false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	d := New(Config{})
	d.regConn = rc
	d.setNodeID_testhelper(nodeID)

	d.loadPolicyRunners()

	d.policyMu.Lock()
	n := len(d.policyRunners)
	d.policyMu.Unlock()
	if n != 0 {
		t.Fatalf("policyRunners = %d, want 0 for network without expr_policy", n)
	}
}

func TestLoadPolicyRunnersSkipsNonMemberNetworks(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()
	reg.SetAdminToken("admin-token")

	// Register an "owner" node that creates the network and sets the policy.
	ownerID, _ := crypto.GenerateIdentity()
	ownerResp, err := rc.RegisterWithKey("127.0.0.1:5001", crypto.EncodePublicKey(ownerID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("owner register: %v", err)
	}
	ownerNodeID := uint32(ownerResp["node_id"].(float64))

	createResp, err := rc.CreateNetwork(ownerNodeID, "other-net", "open", "", "admin-token", false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := uint16(createResp["network_id"].(float64))

	policyJSON := json.RawMessage(`{"version":1,"rules":[{"name":"r1","on":"connect","match":"true","actions":[{"type":"allow"}]}]}`)
	if _, err := rc.SetExprPolicy(netID, policyJSON, "admin-token"); err != nil {
		t.Fatalf("set expr_policy: %v", err)
	}

	// Now register the daemon's own node but don't join the network.
	selfID, _ := crypto.GenerateIdentity()
	selfResp, err := rc.RegisterWithKey("127.0.0.1:5002", crypto.EncodePublicKey(selfID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("self register: %v", err)
	}
	selfNodeID := uint32(selfResp["node_id"].(float64))

	d := New(Config{})
	d.regConn = rc
	d.setNodeID_testhelper(selfNodeID)

	d.loadPolicyRunners()

	d.policyMu.Lock()
	n := len(d.policyRunners)
	d.policyMu.Unlock()
	if n != 0 {
		t.Fatalf("policyRunners = %d, want 0 for non-member network", n)
	}
}

func TestLoadPolicyRunnersStartsRunnerForMemberNetworkWithPolicy(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()
	reg.SetAdminToken("admin-token")

	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("127.0.0.1:5003", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	createResp, err := rc.CreateNetwork(nodeID, "member-net", "open", "", "admin-token", false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := uint16(createResp["network_id"].(float64))

	// Valid policy (no cycle clause → runner idles on stopCh, safe to stop)
	policyJSON := json.RawMessage(`{"version":1,"rules":[{"name":"r1","on":"connect","match":"true","actions":[{"type":"allow"}]}]}`)
	if _, err := rc.SetExprPolicy(netID, policyJSON, "admin-token"); err != nil {
		t.Fatalf("set expr_policy: %v", err)
	}

	d := New(Config{})
	d.regConn = rc
	d.setNodeID_testhelper(nodeID)
	defer d.stopPolicyRunners()

	d.loadPolicyRunners()

	d.policyMu.Lock()
	_, ok := d.policyRunners[netID]
	n := len(d.policyRunners)
	d.policyMu.Unlock()
	if !ok {
		t.Fatalf("policyRunner for net %d not started (have %d runners)", netID, n)
	}
}

// --- startManaged ---

func TestStartManagedClosedRegistryEarlyReturns(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	rc.Close() // close so ListNetworks errors

	d := New(Config{})
	d.regConn = rc
	d.startManaged()

	d.managedMu.Lock()
	n := len(d.managed)
	d.managedMu.Unlock()
	if n != 0 {
		t.Fatalf("managed = %d, want 0 on closed registry", n)
	}
}

func TestStartManagedSkipsNetworksWithoutRules(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()
	reg.SetAdminToken("admin-token")

	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("127.0.0.1:5010", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	_, err = rc.CreateNetwork(nodeID, "plain-net", "open", "", "admin-token", false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	d := New(Config{})
	d.regConn = rc
	d.setNodeID_testhelper(nodeID)
	d.startManaged()

	d.managedMu.Lock()
	n := len(d.managed)
	d.managedMu.Unlock()
	if n != 0 {
		t.Fatalf("managed = %d, want 0 for network without rules", n)
	}
}

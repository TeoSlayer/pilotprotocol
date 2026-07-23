// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
	registry "github.com/pilot-protocol/common/registry/wire"
)

// --- startManaged happy-path ---

func validManagedRulesJSON(t *testing.T) string {
	t.Helper()
	rules := registry.NetworkRules{
		Links:   10,
		Cycle:   "24h", // long cycle so ticker never fires during test
		Prune:   2,
		PruneBy: "age",
		Fill:    2,
		FillHow: "random",
	}
	b, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	return string(b)
}

func TestStartManagedStartsEngineForMemberManagedNetwork(t *testing.T) {
	t.Parallel()
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()
	reg.SetAdminToken("admin-token")

	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("127.0.0.1:5100", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	createResp, err := rc.CreateManagedNetwork(nodeID, "managed-net", "open", "", "admin-token", false, validManagedRulesJSON(t))
	if err != nil {
		t.Fatalf("create managed: %v", err)
	}
	netID := uint16(createResp["network_id"].(float64))

	d := New(Config{})
	d.regConn.Store(rc)
	d.setNodeID_testhelper(nodeID)
	defer d.stopManaged()

	d.startManaged()

	d.managedMu.Lock()
	_, ok := d.managed[netID]
	n := len(d.managed)
	d.managedMu.Unlock()
	if !ok {
		t.Fatalf("managed engine for net %d not started (have %d engines)", netID, n)
	}
}

func TestStartManagedSkipsNonMemberManagedNetwork(t *testing.T) {
	t.Parallel()
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()
	reg.SetAdminToken("admin-token")

	// Owner creates the managed network.
	ownerID, _ := crypto.GenerateIdentity()
	ownerResp, err := rc.RegisterWithKey("127.0.0.1:5101", crypto.EncodePublicKey(ownerID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("owner register: %v", err)
	}
	ownerNodeID := uint32(ownerResp["node_id"].(float64))

	_, err = rc.CreateManagedNetwork(ownerNodeID, "other-managed", "open", "", "admin-token", false, validManagedRulesJSON(t))
	if err != nil {
		t.Fatalf("create managed: %v", err)
	}

	// Separate self-node that isn't a member.
	selfID, _ := crypto.GenerateIdentity()
	selfResp, err := rc.RegisterWithKey("127.0.0.1:5102", crypto.EncodePublicKey(selfID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("self register: %v", err)
	}
	selfNodeID := uint32(selfResp["node_id"].(float64))

	d := New(Config{})
	d.regConn.Store(rc)
	d.setNodeID_testhelper(selfNodeID)
	defer d.stopManaged()

	d.startManaged()

	d.managedMu.Lock()
	n := len(d.managed)
	d.managedMu.Unlock()
	if n != 0 {
		t.Fatalf("managed = %d, want 0 for non-member", n)
	}
}

// --- Bootstrap deadlock regression ---

// Bootstrap used to hold me.mu.Lock and then call me.persist() which tries to
// take me.mu.RLock — a classic RWMutex deadlock. Verify that Bootstrap now
// completes within a reasonable time (release lock before persist).
func TestManagedEngineBootstrapDoesNotDeadlockWithPersist(t *testing.T) {
	t.Parallel()
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()
	reg.SetAdminToken("admin-token")

	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("127.0.0.1:5150", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))
	createResp, err := rc.CreateManagedNetwork(nodeID, "bootstrap-test", "open", "", "admin-token", false, validManagedRulesJSON(t))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := uint16(createResp["network_id"].(float64))

	d := New(Config{})
	d.regConn.Store(rc)
	d.setNodeID_testhelper(nodeID)

	rules := &registry.NetworkRules{Links: 10, Cycle: "24h", Prune: 2, PruneBy: "age", Fill: 2, FillHow: "random"}
	me := NewManagedEngine(netID, rules, d)

	done := make(chan error, 1)
	go func() { done <- me.Bootstrap() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Bootstrap err: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Bootstrap deadlocked (persist tried to RLock while Lock held)")
	}
}

// --- autoJoinNetworks happy-path ---

func TestAutoJoinNetworksJoinsConfiguredNetwork(t *testing.T) {
	t.Parallel()
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()
	reg.SetAdminToken("admin-token")

	// Owner creates a network first.
	ownerID, _ := crypto.GenerateIdentity()
	ownerResp, err := rc.RegisterWithKey("127.0.0.1:5200", crypto.EncodePublicKey(ownerID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("owner register: %v", err)
	}
	ownerNodeID := uint32(ownerResp["node_id"].(float64))

	createResp, err := rc.CreateNetwork(ownerNodeID, "auto-join-target", "open", "", "admin-token", false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := uint16(createResp["network_id"].(float64))

	// Self-node registers + will auto-join.
	selfID, _ := crypto.GenerateIdentity()
	selfResp, err := rc.RegisterWithKey("127.0.0.1:5201", crypto.EncodePublicKey(selfID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("self register: %v", err)
	}
	selfNodeID := uint32(selfResp["node_id"].(float64))

	d := New(Config{
		AdminToken: "admin-token",
		Networks:   []uint16{netID},
	})
	d.regConn.Store(rc)
	d.setNodeID_testhelper(selfNodeID)
	d.autoJoinNetworks()

	// Verify membership via Lookup (returns "networks" field with joined netIDs).
	resp, err := rc.Lookup(selfNodeID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	nets, _ := resp["networks"].([]interface{})
	found := false
	for _, raw := range nets {
		if f, ok := raw.(float64); ok && uint16(f) == netID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("self node not a member of network %d after autoJoinNetworks (networks=%v)", netID, nets)
	}
}

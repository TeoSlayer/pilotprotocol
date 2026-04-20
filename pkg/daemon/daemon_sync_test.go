package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// --- syncPolicyRunners ---

func TestSyncPolicyRunnersNilNetworkListEarlyReturn(t *testing.T) {
	d := New(Config{})
	d.syncPolicyRunners([]uint16{5}, nil)
	d.policyMu.Lock()
	_, exists := d.policyRunners[5]
	d.policyMu.Unlock()
	if exists {
		t.Fatal("no runner should be started when networkList is nil")
	}
}

func TestSyncPolicyRunnersSkipsNonMapEntries(t *testing.T) {
	d := New(Config{})
	d.syncPolicyRunners([]uint16{5}, []interface{}{"not-a-map", 12345})
	d.policyMu.Lock()
	_, exists := d.policyRunners[5]
	d.policyMu.Unlock()
	if exists {
		t.Fatal("non-map entries should be skipped")
	}
}

func TestSyncPolicyRunnersSkipsWhenHasPolicyFalse(t *testing.T) {
	d := New(Config{})
	d.syncPolicyRunners([]uint16{5}, []interface{}{
		map[string]interface{}{
			"id":              float64(5),
			"has_expr_policy": false,
		},
	})
	d.policyMu.Lock()
	_, exists := d.policyRunners[5]
	d.policyMu.Unlock()
	if exists {
		t.Fatal("no runner should start when has_expr_policy=false")
	}
}

func TestSyncPolicyRunnersSkipsUnmatchedNetIDs(t *testing.T) {
	d := New(Config{})
	// List has network 99 with policy, but nets=[5] — 99 not in netSet.
	d.syncPolicyRunners([]uint16{5}, []interface{}{
		map[string]interface{}{
			"id":              float64(99),
			"has_expr_policy": true,
		},
	})
	d.policyMu.Lock()
	_, exists5 := d.policyRunners[5]
	_, exists99 := d.policyRunners[99]
	d.policyMu.Unlock()
	if exists5 || exists99 {
		t.Fatal("no runner should start when netID not in local nets list")
	}
}

func TestSyncPolicyRunnersSkipsAlreadyRunning(t *testing.T) {
	d := New(Config{})

	// Pre-seed a runner with pre-closed channels so it won't touch regConn.
	pr := &PolicyRunner{netID: 7, stopCh: make(chan struct{}), done: make(chan struct{})}
	close(pr.stopCh)
	close(pr.done)
	d.policyMu.Lock()
	d.policyRunners[7] = pr
	d.policyMu.Unlock()

	// syncPolicyRunners should see it's running and NOT call GetExprPolicy
	// (we have no regConn; if the "already-running" branch was broken, it would
	// nil-deref on d.regConn.GetExprPolicy).
	d.syncPolicyRunners([]uint16{7}, []interface{}{
		map[string]interface{}{
			"id":              float64(7),
			"has_expr_policy": true,
		},
	})

	d.policyMu.Lock()
	got := d.policyRunners[7]
	d.policyMu.Unlock()
	if got != pr {
		t.Fatal("pre-seeded runner should remain unchanged")
	}
}

// --- syncManagedEngines ---

func TestSyncManagedEnginesNilNetworkListEarlyReturn(t *testing.T) {
	d := New(Config{})
	d.syncManagedEngines([]uint16{5}, nil)
	d.managedMu.Lock()
	_, exists := d.managed[5]
	d.managedMu.Unlock()
	if exists {
		t.Fatal("nil networkList should be early-return")
	}
}

func TestSyncManagedEnginesSkipsWhenRulesAbsent(t *testing.T) {
	d := New(Config{})
	d.syncManagedEngines([]uint16{5}, []interface{}{
		map[string]interface{}{
			"id": float64(5),
			// no "rules" key
		},
	})
	d.managedMu.Lock()
	_, exists := d.managed[5]
	d.managedMu.Unlock()
	if exists {
		t.Fatal("no engine should start when rules absent")
	}
}

func TestSyncManagedEnginesSkipsWhenRulesNil(t *testing.T) {
	d := New(Config{})
	d.syncManagedEngines([]uint16{5}, []interface{}{
		map[string]interface{}{
			"id":    float64(5),
			"rules": nil,
		},
	})
	d.managedMu.Lock()
	_, exists := d.managed[5]
	d.managedMu.Unlock()
	if exists {
		t.Fatal("no engine should start when rules=nil")
	}
}

func TestSyncManagedEnginesSkipsUnmatchedNetIDs(t *testing.T) {
	d := New(Config{})
	d.syncManagedEngines([]uint16{5}, []interface{}{
		map[string]interface{}{
			"id": float64(99),
			"rules": map[string]interface{}{
				"links": 2, "cycle": "1h", "prune": 1, "prune_by": "score", "fill": 1, "fill_how": "random",
			},
		},
	})
	d.managedMu.Lock()
	_, ex5 := d.managed[5]
	_, ex99 := d.managed[99]
	d.managedMu.Unlock()
	if ex5 || ex99 {
		t.Fatal("no engine should start when netID not in nets list")
	}
}

func TestSyncManagedEnginesSkipsInvalidRules(t *testing.T) {
	d := New(Config{})
	d.syncManagedEngines([]uint16{5}, []interface{}{
		map[string]interface{}{
			"id": float64(5),
			"rules": map[string]interface{}{
				"cycle": "1h", // missing links/prune_by/fill_how — ValidateRules fails
			},
		},
	})
	d.managedMu.Lock()
	_, exists := d.managed[5]
	d.managedMu.Unlock()
	if exists {
		t.Fatal("no engine should start when rules fail validation")
	}
}

func TestSyncManagedEnginesSkipsAlreadyRunning(t *testing.T) {
	d := New(Config{})

	// Pre-seed an engine (don't Start it) so the "already running" branch fires.
	engine := &ManagedEngine{netID: 11, stopCh: make(chan struct{}), done: make(chan struct{})}
	close(engine.stopCh)
	close(engine.done)
	d.managedMu.Lock()
	d.managed[11] = engine
	d.managedMu.Unlock()

	d.syncManagedEngines([]uint16{11}, []interface{}{
		map[string]interface{}{
			"id": float64(11),
			"rules": map[string]interface{}{
				"links": 2, "cycle": "1h", "prune": 1, "prune_by": "score", "fill": 1, "fill_how": "random",
			},
		},
	})

	d.managedMu.Lock()
	got := d.managed[11]
	d.managedMu.Unlock()
	if got != engine {
		t.Fatal("pre-seeded engine should remain unchanged")
	}
}

// --- syncMemberTags ---

func TestSyncMemberTagsSkipsBackboneNetworkZero(t *testing.T) {
	d := New(Config{})
	// Pre-seed tags for net 0 so we can detect if sync tries to overwrite.
	d.memberTagsMu.Lock()
	d.memberTags[0] = []string{"preseed"}
	d.memberTagsMu.Unlock()

	d.syncMemberTags([]uint16{0})

	d.memberTagsMu.RLock()
	got := d.memberTags[0]
	d.memberTagsMu.RUnlock()
	if len(got) != 1 || got[0] != "preseed" {
		t.Fatalf("backbone tags mutated: %v", got)
	}
}

func TestSyncMemberTagsClosedRegistryPreservesCachedTags(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	rc.Close() // force GetMemberTags to fail

	d := New(Config{})
	d.regConn = rc
	d.memberTagsMu.Lock()
	d.memberTags[5] = []string{"before"}
	d.memberTagsMu.Unlock()

	d.syncMemberTags([]uint16{5})

	d.memberTagsMu.RLock()
	got := d.memberTags[5]
	d.memberTagsMu.RUnlock()
	if len(got) != 1 || got[0] != "before" {
		t.Fatalf("closed-registry error path should preserve cache; got %v", got)
	}
}

// --- pollRelayedHandshakes ---

func TestPollRelayedHandshakesClosedRegistryIsEarlyReturn(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	rc.Close()

	d := New(Config{})
	d.regConn = rc

	// Must not panic / must not touch handshake state.
	d.pollRelayedHandshakes()

	if c := d.handshakes.PendingCount(); c != 0 {
		t.Fatalf("pending count = %d, want 0", c)
	}
}

func TestPollRelayedHandshakesEmptyResponseNoChanges(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()

	// Register node so PollHandshakes returns an empty-but-valid response.
	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("127.0.0.1:5000", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	d := New(Config{})
	d.regConn = rc
	d.setNodeID_testhelper(nodeID)

	d.pollRelayedHandshakes()

	if c := d.handshakes.PendingCount(); c != 0 {
		t.Fatalf("pending count = %d, want 0 after empty poll", c)
	}
	if peers := d.handshakes.TrustedPeers(); len(peers) != 0 {
		t.Fatalf("trusted count = %d, want 0", len(peers))
	}
}

// --- reRegister ---

func TestReRegisterStoppingEarlyReturnsBeforeRPC(t *testing.T) {
	d := New(Config{})
	// Close stopCh so stopping() returns true immediately.
	close(d.stopCh)
	// No regConn wired — if reRegister didn't early-return, it would panic.
	d.reRegister()
}

// --- syncNetworks ---

func TestSyncNetworksNilRegConnEarlyReturn(t *testing.T) {
	d := New(Config{})
	// regConn is nil — must return without panicking.
	d.syncNetworks()
}

func TestSyncNetworksNodeNetworksNilSkipsBody(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	rc.Close() // Lookup will fail → nodeNetworks returns nil

	d := New(Config{})
	d.regConn = rc

	// Pre-seed a stale netPolicies entry to prove the body was skipped.
	d.netPolicyMu.Lock()
	d.netPolicies[99] = []uint16{80}
	d.netPolicyMu.Unlock()

	d.syncNetworks()

	d.netPolicyMu.RLock()
	p := d.netPolicies[99]
	d.netPolicyMu.RUnlock()
	if len(p) != 1 || p[0] != 80 {
		t.Fatalf("pre-seeded policy lost: %v", p)
	}
}

func TestSyncNetworksClearsStateForRemovedNetworks(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()

	reg.SetAdminToken("admin-token")

	// Register our node.
	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("127.0.0.1:5111", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Create a network and join it so nodeNetworks() returns non-empty.
	createResp, err := rc.CreateNetwork(nodeID, "test-net", "open", "", "admin-token", false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(createResp["network_id"].(float64))

	d := New(Config{})
	d.regConn = rc
	d.setNodeID_testhelper(nodeID)

	// Seed state for a "removed" network (77) that is NOT in registry.
	d.netPolicyMu.Lock()
	d.netPolicies[77] = []uint16{80, 443}
	d.netPolicyMu.Unlock()
	d.memberTagsMu.Lock()
	d.memberTags[77] = []string{"ghost-tag"}
	d.memberTagsMu.Unlock()

	d.syncNetworks()

	// Network 77 is no longer in our registry membership → clearNetworkState ran.
	d.memberTagsMu.RLock()
	tags := d.memberTags[77]
	d.memberTagsMu.RUnlock()
	if len(tags) != 0 {
		t.Fatalf("memberTags[77] should be cleared for removed network, got %v", tags)
	}

	// syncNetworks also replaced netPolicies wholesale via loadNetworkPolicies.
	d.netPolicyMu.RLock()
	_, has77 := d.netPolicies[77]
	d.netPolicyMu.RUnlock()
	if has77 {
		t.Fatalf("netPolicies[77] should be gone for removed network")
	}

	// Sanity: syncNetworks discovered our actual network.
	_ = netID // (just ensuring the network exists in the registry; content of
	// newly-joined network state is validated by separate tests)
}

// --- loop exit paths ---

func TestIdleSweepLoopExitsOnStopCh(t *testing.T) {
	d := New(Config{})
	done := make(chan struct{})
	go func() { d.idleSweepLoop(); close(done) }()

	// Give the loop a moment to enter the select.
	time.Sleep(20 * time.Millisecond)
	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("idleSweepLoop did not exit within 500ms after stopCh close")
	}
}

func TestRelayProbeLoopExitsOnStopCh(t *testing.T) {
	d := New(Config{})
	done := make(chan struct{})
	go func() { d.relayProbeLoop(); close(done) }()

	time.Sleep(20 * time.Millisecond)
	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("relayProbeLoop did not exit within 500ms after stopCh close")
	}
}

func TestNetworkSyncLoopExitsDuringInitialJitter(t *testing.T) {
	d := New(Config{})
	done := make(chan struct{})
	go func() { d.networkSyncLoop(); close(done) }()

	// Close stopCh immediately — the initial jitter select should notice it.
	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("networkSyncLoop did not exit within 1s after stopCh close during initial jitter")
	}
}

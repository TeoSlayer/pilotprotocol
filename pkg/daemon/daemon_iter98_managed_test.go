package daemon

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/policy"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// Iter-98: cover policy_runner executeEvict (0%) + fetchMembers (0%) +
// managed.go ForceCycle (0%) + runCycle (0%) + missing EvaluateActions evict
// dispatch branch. Targets untouched 0% funcs after iter-97's trust executors.

// --- policy_runner.executeEvict ---

func TestExecuteEvictPeerIDZeroEarlyReturn(t *testing.T) {
	pr := &PolicyRunner{
		netID: 1,
		peers: map[uint32]*managedPeer{10: {NodeID: 10}},
	}
	// peer_id missing → int-cast yields 0 → early return, peer 10 untouched.
	pr.executeEvict(map[string]interface{}{})
	if _, ok := pr.peers[10]; !ok {
		t.Fatal("peer 10 was deleted even though peer_id was 0 (early-return branch broken)")
	}
}

func TestExecuteEvictDeletesPeerByID(t *testing.T) {
	pr := &PolicyRunner{
		netID: 1,
		peers: map[uint32]*managedPeer{
			42: {NodeID: 42},
			99: {NodeID: 99},
		},
	}
	pr.executeEvict(map[string]interface{}{"peer_id": 42})
	if _, ok := pr.peers[42]; ok {
		t.Fatal("peer 42 should have been deleted")
	}
	if _, ok := pr.peers[99]; !ok {
		t.Fatal("peer 99 should still be present — executeEvict must not touch other peers")
	}
}

func TestExecuteEvictUnknownPeerIDNoop(t *testing.T) {
	pr := &PolicyRunner{
		netID: 1,
		peers: map[uint32]*managedPeer{1: {NodeID: 1}},
	}
	// Non-existent peer_id — delete(map, nonExistentKey) is a safe no-op in Go.
	pr.executeEvict(map[string]interface{}{"peer_id": 999})
	if len(pr.peers) != 1 {
		t.Fatalf("peers = %d, want 1 (unknown peer_id should noop)", len(pr.peers))
	}
}

// --- EvaluateActions Evict dispatch branch (completes iter 96's uncovered switch cases) ---

func TestEvaluateActionsEvictDirectiveRemovesNamedPeer(t *testing.T) {
	doc := &policy.PolicyDocument{
		Version: 1,
		Rules: []policy.Rule{
			{Name: "evict-on-cycle", On: "cycle", Match: "true", Actions: []policy.Action{
				{Type: policy.ActionEvict},
			}},
		},
	}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	d := New(Config{})
	t.Cleanup(func() { d.handshakes.Stop() })
	pr := &PolicyRunner{
		netID: 1, compiled: cp, daemon: d,
		peers: map[uint32]*managedPeer{
			7: {NodeID: 7, AddedAt: time.Now()},
			8: {NodeID: 8, AddedAt: time.Now()},
		},
	}
	pr.EvaluateActions(policy.EventCycle, map[string]interface{}{
		"peer_id": 7, "network_id": 1, "members": 2,
		"peer_score": 0, "peer_tags": []string{}, "peer_age_s": 1.0,
	})
	if _, ok := pr.peers[7]; ok {
		t.Fatal("peer 7 should have been evicted")
	}
	if _, ok := pr.peers[8]; !ok {
		t.Fatal("peer 8 should have survived")
	}
}

// --- policy_runner.fetchMembers (trivial ID-only wrapper) ---

func TestFetchMembersReturnsRegistryMemberIDs(t *testing.T) {
	reg, rc := startTestRegistry(t)
	t.Cleanup(func() { reg.Close() })
	t.Cleanup(func() { rc.Close() })
	reg.SetAdminToken("admin-token")

	selfID, _ := crypto.GenerateIdentity()
	selfResp, err := rc.RegisterWithKey("127.0.0.1:7300", crypto.EncodePublicKey(selfID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	selfNodeID := uint32(selfResp["node_id"].(float64))

	// Two more nodes registered and joined the same network.
	peerIDs := []uint32{}
	for i := 0; i < 2; i++ {
		pid, _ := crypto.GenerateIdentity()
		resp, err := rc.RegisterWithKey("127.0.0.1:73"+itoaSimple(10+i), crypto.EncodePublicKey(pid.PublicKey), "", nil)
		if err != nil {
			t.Fatalf("peer register: %v", err)
		}
		peerIDs = append(peerIDs, uint32(resp["node_id"].(float64)))
	}
	createResp, err := rc.CreateNetwork(selfNodeID, "fm-net", "open", "", "admin-token", false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := uint16(createResp["network_id"].(float64))
	for _, pid := range peerIDs {
		if _, err := rc.JoinNetwork(pid, netID, "", 0, "admin-token"); err != nil {
			t.Fatalf("join: %v", err)
		}
	}

	d := New(Config{AdminToken: "admin-token"})
	d.regConn = rc
	d.identity = selfID
	d.setNodeID_testhelper(selfNodeID)
	t.Cleanup(func() { d.handshakes.Stop() })

	pr := &PolicyRunner{netID: netID, daemon: d, peers: map[uint32]*managedPeer{}}
	ids, err := pr.fetchMembers()
	if err != nil {
		t.Fatalf("fetchMembers: %v", err)
	}
	// Self + 2 peers = 3 members total.
	if len(ids) != 3 {
		t.Fatalf("len(ids) = %d, want 3", len(ids))
	}
	seen := map[uint32]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	if !seen[selfNodeID] {
		t.Fatal("fetchMembers missing self")
	}
	for _, pid := range peerIDs {
		if !seen[pid] {
			t.Fatalf("fetchMembers missing peer %d", pid)
		}
	}
}

// --- managed.ManagedEngine.ForceCycle + runCycle ---

func TestManagedEngineForceCycleProducesPrunedAndFilledResult(t *testing.T) {
	reg, rc := startTestRegistry(t)
	t.Cleanup(func() { reg.Close() })
	t.Cleanup(func() { rc.Close() })
	reg.SetAdminToken("admin-token")

	selfID, _ := crypto.GenerateIdentity()
	selfResp, err := rc.RegisterWithKey("127.0.0.1:7400", crypto.EncodePublicKey(selfID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	selfNodeID := uint32(selfResp["node_id"].(float64))
	// Register + join 3 other nodes so fill has candidates.
	peerIDs := []uint32{}
	for i := 0; i < 3; i++ {
		pid, _ := crypto.GenerateIdentity()
		resp, err := rc.RegisterWithKey("127.0.0.1:74"+itoaSimple(10+i), crypto.EncodePublicKey(pid.PublicKey), "", nil)
		if err != nil {
			t.Fatalf("peer register: %v", err)
		}
		peerIDs = append(peerIDs, uint32(resp["node_id"].(float64)))
	}
	rules := &registry.NetworkRules{
		Links: 3, Cycle: "24h", Prune: 1, PruneBy: "age",
		Fill: 2, FillHow: "random",
	}
	rulesJSON, _ := json.Marshal(rules)
	createResp, err := rc.CreateManagedNetwork(selfNodeID, "mc-net", "open", "", "admin-token", false, string(rulesJSON))
	if err != nil {
		t.Fatalf("create managed: %v", err)
	}
	netID := uint16(createResp["network_id"].(float64))
	for _, pid := range peerIDs {
		if _, err := rc.JoinNetwork(pid, netID, "", 0, "admin-token"); err != nil {
			t.Fatalf("peer join: %v", err)
		}
	}

	d := New(Config{AdminToken: "admin-token"})
	d.regConn = rc
	d.identity = selfID
	d.setNodeID_testhelper(selfNodeID)
	t.Cleanup(func() { d.handshakes.Stop() })

	me := NewManagedEngine(netID, rules, d)
	// Seed one peer so prune has something to remove.
	me.peers[55] = &managedPeer{NodeID: 55, AddedAt: time.Now().Add(-48 * time.Hour)}

	result := me.ForceCycle()
	if result == nil {
		t.Fatal("ForceCycle returned nil result")
	}
	// Result must have pruned + filled + peers + network_id keys.
	for _, key := range []string{"pruned", "filled", "peers", "network_id"} {
		if _, ok := result[key]; !ok {
			t.Fatalf("ForceCycle result missing key %q: %v", key, result)
		}
	}
	// netID roundtrip — registered as uint16, surfaces through runCycle as uint16.
	if gotNetID, ok := result["network_id"].(uint16); !ok || gotNetID != netID {
		t.Fatalf("network_id = %v, want %d", result["network_id"], netID)
	}
}

func TestManagedEngineRunCycleMemberFetchErrorPopulatesError(t *testing.T) {
	// Use a real reg to construct the ManagedEngine, then close rc so the
	// in-cycle fetchMembers() call fails — runCycle should return a map with
	// the "error" key populated instead of panicking.
	reg, rc := startTestRegistry(t)
	t.Cleanup(func() { reg.Close() })
	reg.SetAdminToken("admin-token")

	selfID, _ := crypto.GenerateIdentity()
	selfResp, err := rc.RegisterWithKey("127.0.0.1:7500", crypto.EncodePublicKey(selfID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	selfNodeID := uint32(selfResp["node_id"].(float64))
	rules := &registry.NetworkRules{
		Links: 3, Cycle: "24h", Prune: 0, PruneBy: "age",
		Fill: 0, FillHow: "random",
	}
	rulesJSON, _ := json.Marshal(rules)
	createResp, err := rc.CreateManagedNetwork(selfNodeID, "err-net", "open", "", "admin-token", false, string(rulesJSON))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := uint16(createResp["network_id"].(float64))

	d := New(Config{AdminToken: "admin-token"})
	d.regConn = rc
	d.identity = selfID
	d.setNodeID_testhelper(selfNodeID)
	t.Cleanup(func() { d.handshakes.Stop() })

	me := NewManagedEngine(netID, rules, d)

	// Now close the registry client so ListNodes fails.
	rc.Close()

	result := me.ForceCycle()
	if result == nil {
		t.Fatal("ForceCycle returned nil even on fetch error")
	}
	if _, hasErr := result["error"]; !hasErr {
		t.Fatalf("expected 'error' key in result when fetchMembers fails, got %v", result)
	}
	// pruned should be 0 since we had no peers seeded and member-fetch failed before fill.
	if got, _ := result["pruned"].(int); got != 0 {
		t.Fatalf("pruned = %d, want 0 on member-fetch error", got)
	}
}

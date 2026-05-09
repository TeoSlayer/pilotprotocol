// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testPolicy() *PolicyDocument {
	return &PolicyDocument{
		Version: 1,
		Config: map[string]interface{}{
			"max_peers": 10,
			"cycle":     "1h",
		},
		Rules: []Rule{
			{Name: "allow-80", On: "connect", Match: "port == 80", Actions: []Action{{Type: ActionAllow}}},
			{Name: "deny-all", On: "connect", Match: "true", Actions: []Action{{Type: ActionDeny}}},
			{Name: "cycle-prune-fill", On: "cycle", Match: "true", Actions: []Action{
				{Type: ActionPrune, Params: map[string]interface{}{"count": 2, "by": "age"}},
			}},
		},
	}
}

func compileTestPolicy(t *testing.T) *CompiledPolicy {
	t.Helper()
	cp, err := Compile(testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

func TestPolicyRunnerStatus(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)

	pr := &PolicyRunner{
		netID:    1,
		compiled: cp,
		peers:    map[uint32]*managedPeer{100: {NodeID: 100}},
		joinedAt: time.Now(),
		cycleNum: 3,
	}

	status := pr.Status()
	if status["network_id"] != uint16(1) {
		t.Errorf("network_id = %v, want 1", status["network_id"])
	}
	if status["peers"] != 1 {
		t.Errorf("peers = %v, want 1", status["peers"])
	}
	if status["engine"] != "policy" {
		t.Errorf("engine = %v, want 'policy'", status["engine"])
	}
	if status["cycle_num"] != 3 {
		t.Errorf("cycle_num = %v, want 3", status["cycle_num"])
	}
	if status["cycle"] != "1h" {
		t.Errorf("cycle = %v, want '1h'", status["cycle"])
	}
	if status["max_peers"] != 10 {
		t.Errorf("max_peers = %v, want 10", status["max_peers"])
	}
}

func TestPolicyRunnerEvaluateGate(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)

	pr := &PolicyRunner{
		netID:    1,
		compiled: cp,
		peers:    map[uint32]*managedPeer{},
	}

	// Port 80 should be allowed
	allowed := pr.EvaluateGate(EventConnect, map[string]interface{}{
		"port": 80, "peer_id": 1, "network_id": 1,
		"peer_tags": []string{}, "peer_age_s": 0.0, "members": 0,
	})
	if !allowed {
		t.Fatal("expected port 80 to be allowed")
	}

	// Port 22 should be denied
	denied := pr.EvaluateGate(EventConnect, map[string]interface{}{
		"port": 22, "peer_id": 1, "network_id": 1,
		"peer_tags": []string{}, "peer_age_s": 0.0, "members": 0,
	})
	if denied {
		t.Fatal("expected port 22 to be denied")
	}
}

func TestPolicyRunnerApplyMembershipDiffJoinAddsTag(t *testing.T) {
	t.Parallel()
	// Policy that tags peers on join.
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "tag-join", On: EventJoin, Match: "true", Actions: []Action{
				{Type: ActionTag, Params: map[string]interface{}{"add": []interface{}{"joined"}}},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	pr := &PolicyRunner{
		netID:    1,
		compiled: cp,
		peers:    map[uint32]*managedPeer{},
	}

	// Myself=999; new members 42 and 43 joined.
	fetched := []fetchedMember{
		{ID: 999},
		{ID: 42, Tags: []string{"blue"}},
		{ID: 43},
	}
	pr.applyMembershipDiff(fetched, 999)

	if len(pr.peers) != 2 {
		t.Fatalf("peers = %d, want 2", len(pr.peers))
	}
	if len(pr.peers[42].RegistryTags) != 1 || pr.peers[42].RegistryTags[0] != "blue" {
		t.Errorf("peer 42 registry_tags = %v, want [blue]", pr.peers[42].RegistryTags)
	}
}

func TestPolicyRunnerApplyMembershipDiffLeaveRemovesPeer(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)

	pr := &PolicyRunner{
		netID:    1,
		compiled: cp,
		peers: map[uint32]*managedPeer{
			42: {NodeID: 42, AddedAt: time.Now()},
			43: {NodeID: 43, AddedAt: time.Now()},
		},
	}

	// 42 is gone; 43 is still there.
	fetched := []fetchedMember{
		{ID: 999},
		{ID: 43},
	}
	pr.applyMembershipDiff(fetched, 999)

	if _, ok := pr.peers[42]; ok {
		t.Fatal("peer 42 should be removed after leave")
	}
	if _, ok := pr.peers[43]; !ok {
		t.Fatal("peer 43 should remain")
	}
}

func TestPolicyRunnerApplyMembershipDiffJoinDenyEvictsPeer(t *testing.T) {
	t.Parallel()
	// Policy that denies every join.
	doc := &PolicyDocument{
		Version:        1,
		DefaultVerdict: "allow",
		Rules: []Rule{
			{Name: "deny-join", On: EventJoin, Match: "true", Actions: []Action{
				{Type: ActionDeny},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	pr := &PolicyRunner{
		netID:    1,
		compiled: cp,
		peers:    map[uint32]*managedPeer{},
		runtime:  &fakeRuntime{},
	}

	fetched := []fetchedMember{
		{ID: 999},
		{ID: 42},
	}
	pr.applyMembershipDiff(fetched, 999)

	if _, ok := pr.peers[42]; ok {
		t.Fatal("peer 42 should be evicted after deny-join")
	}
}

func TestPolicyRunnerExecutePrune(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)

	now := time.Now()
	pr := &PolicyRunner{
		netID:    1,
		compiled: cp,
		peers: map[uint32]*managedPeer{
			100: {NodeID: 100, AddedAt: now.Add(-5 * time.Hour)},
			200: {NodeID: 200, AddedAt: now.Add(-4 * time.Hour)},
			300: {NodeID: 300, AddedAt: now.Add(-3 * time.Hour)},
			400: {NodeID: 400, AddedAt: now.Add(-2 * time.Hour)},
			500: {NodeID: 500, AddedAt: now.Add(-1 * time.Hour)},
		},
	}

	pr.executePrune(Directive{
		Type:   DirectivePrune,
		Rule:   "test",
		Params: map[string]interface{}{"count": 2, "by": "age"},
	})

	// 100 (oldest) and 200 (second oldest) should be pruned
	if _, exists := pr.peers[100]; exists {
		t.Error("peer 100 (oldest) should have been pruned")
	}
	if _, exists := pr.peers[200]; exists {
		t.Error("peer 200 (second oldest) should have been pruned")
	}
	if len(pr.peers) != 3 {
		t.Errorf("peers = %d, want 3", len(pr.peers))
	}
}

func TestPolicyRunnerExecutePruneByAge(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)

	now := time.Now()
	pr := &PolicyRunner{
		netID:    1,
		compiled: cp,
		peers: map[uint32]*managedPeer{
			100: {NodeID: 100, AddedAt: now.Add(-3 * time.Hour)},
			200: {NodeID: 200, AddedAt: now.Add(-1 * time.Hour)},
			300: {NodeID: 300, AddedAt: now},
		},
	}

	pr.executePrune(Directive{
		Type:   DirectivePrune,
		Rule:   "test",
		Params: map[string]interface{}{"count": 1, "by": "age"},
	})

	if _, exists := pr.peers[100]; exists {
		t.Error("peer 100 (oldest) should have been pruned")
	}
	if len(pr.peers) != 2 {
		t.Errorf("peers = %d, want 2", len(pr.peers))
	}
}

func TestPolicyRunnerExecuteEvictWhere(t *testing.T) {
	t.Parallel()

	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "evict-bad", On: "cycle", Match: "true", Actions: []Action{
				{Type: ActionEvictWhere, Params: map[string]interface{}{"match": `has_tag(peer_tags, "bad")`}},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	pr := &PolicyRunner{
		netID:    1,
		compiled: cp,
		peers: map[uint32]*managedPeer{
			100: {NodeID: 100, AddedAt: now, Tags: []string{"bad"}},
			200: {NodeID: 200, AddedAt: now},
			300: {NodeID: 300, AddedAt: now, Tags: []string{"bad"}},
		},
	}

	pr.executeEvictWhere(Directive{
		Type:   DirectiveEvictWhere,
		Rule:   "evict-bad",
		Params: map[string]interface{}{"match": `has_tag(peer_tags, "bad")`},
	}, 0)

	// Peers 100 and 300 (tagged "bad") should be evicted
	if _, exists := pr.peers[100]; exists {
		t.Error("peer 100 (tagged bad) should have been evicted")
	}
	if _, exists := pr.peers[300]; exists {
		t.Error("peer 300 (tagged bad) should have been evicted")
	}
	if _, exists := pr.peers[200]; !exists {
		t.Error("peer 200 should remain")
	}
}

func TestPolicyRunnerExecuteTag(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)

	pr := &PolicyRunner{
		netID:    1,
		compiled: cp,
		peers: map[uint32]*managedPeer{
			100: {NodeID: 100, AddedAt: time.Now(), Tags: []string{"existing"}},
		},
	}

	// Add tags
	pr.executeTag(Directive{
		Type:   DirectiveTag,
		Rule:   "test",
		Params: map[string]interface{}{"add": []interface{}{"new", "elite"}},
	}, map[string]interface{}{"peer_id": 100})

	tags := pr.peers[100].Tags
	if len(tags) != 3 {
		t.Fatalf("tags = %v, want 3 tags", tags)
	}

	// Remove tag
	pr.executeTag(Directive{
		Type:   DirectiveTag,
		Rule:   "test",
		Params: map[string]interface{}{"remove": []interface{}{"existing"}},
	}, map[string]interface{}{"peer_id": 100})

	tags = pr.peers[100].Tags
	if len(tags) != 2 {
		t.Fatalf("tags = %v, want 2 tags after removal", tags)
	}
	for _, tag := range tags {
		if tag == "existing" {
			t.Error("tag 'existing' should have been removed")
		}
	}
}

func TestPolicyRunnerPersistAndLoad(t *testing.T) {
	t.Parallel()

	cp := compileTestPolicy(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "policy_1.json")

	pr := &PolicyRunner{
		netID:    1,
		compiled: cp,
		joinedAt: time.Now().Truncate(time.Second),
		cycleNum: 5,
		peers: map[uint32]*managedPeer{
			100: {NodeID: 100, Tags: []string{"elite"}, AddedAt: time.Now().Truncate(time.Second)},
			200: {NodeID: 200, AddedAt: time.Now().Truncate(time.Second)},
		},
		path: path,
	}

	pr.persist()

	// Verify file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("persist file should exist")
	}

	// Load into a new runner
	pr2 := &PolicyRunner{
		netID:    1,
		compiled: cp,
		peers:    make(map[uint32]*managedPeer),
		path:     path,
	}
	if err := pr2.load(); err != nil {
		t.Fatalf("load() error: %v", err)
	}

	if len(pr2.peers) != 2 {
		t.Errorf("loaded peers = %d, want 2", len(pr2.peers))
	}
	if pr2.peers[100].Tags[0] != "elite" {
		t.Errorf("peer 100 tags = %v, want [elite]", pr2.peers[100].Tags)
	}
	if pr2.cycleNum != 5 {
		t.Errorf("cycleNum = %d, want 5", pr2.cycleNum)
	}
}

func TestPolicySnapshotJSON(t *testing.T) {
	t.Parallel()

	snap := policySnapshot{
		NetworkID: 42,
		Peers: map[uint32]*managedPeer{
			100: {NodeID: 100, Tags: []string{"test"}},
		},
		JoinedAt: time.Now().Format(time.RFC3339),
		CycleNum: 7,
	}

	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var loaded policySnapshot
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if loaded.NetworkID != 42 {
		t.Errorf("NetworkID = %d, want 42", loaded.NetworkID)
	}
	if loaded.CycleNum != 7 {
		t.Errorf("CycleNum = %d, want 7", loaded.CycleNum)
	}
	if loaded.Peers[100].Tags[0] != "test" {
		t.Errorf("Tags = %v, want [test]", loaded.Peers[100].Tags)
	}
}

func TestManagedPeerTagHelpers(t *testing.T) {
	t.Parallel()

	p := &managedPeer{NodeID: 1}

	// tags() on nil
	if got := p.tags(); len(got) != 0 {
		t.Errorf("tags() on nil = %v, want empty", got)
	}

	// addTag
	p.addTag("a")
	p.addTag("b")
	p.addTag("a") // duplicate
	if len(p.Tags) != 2 {
		t.Errorf("Tags = %v, want [a, b]", p.Tags)
	}

	// removeTag
	p.removeTag("a")
	if len(p.Tags) != 1 || p.Tags[0] != "b" {
		t.Errorf("Tags = %v, want [b]", p.Tags)
	}

	// removeTag non-existent
	p.removeTag("z")
	if len(p.Tags) != 1 {
		t.Errorf("Tags = %v, want [b]", p.Tags)
	}
}

// TestEvaluatePortGateRegistryTagsVisible ensures that RegistryTags (network
// member tags set via the registry and stored by applyMembershipDiff) are
// visible in peer_tags during gate evaluation — the regression that caused
// TestDataExchangePolicy to fail when service-tagged peers were denied.
func TestEvaluatePortGateRegistryTagsVisible(t *testing.T) {
	t.Parallel()

	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "allow-service", On: EventConnect, Match: `has_tag(peer_tags, "service")`, Actions: []Action{
				{Type: ActionAllow},
			}},
			{Name: "deny-rest", On: EventConnect, Match: "true", Actions: []Action{
				{Type: ActionDeny},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	pr := &PolicyRunner{
		netID:    1,
		compiled: cp,
		peers: map[uint32]*managedPeer{
			// peer 42 has "service" as a registry tag (from member list, not policy engine)
			42: {NodeID: 42, AddedAt: time.Now(), RegistryTags: []string{"service"}},
			// peer 99 has no tags — should be denied
			99: {NodeID: 99, AddedAt: time.Now()},
		},
	}

	// service-tagged peer must be allowed even with empty nodeInfoTags and empty Tags
	if !pr.EvaluatePortGate(EventConnect, 80, 42, 0, "in", nil, nil) {
		t.Error("service peer should be allowed via RegistryTags but was denied")
	}
	// untagged peer must be denied
	if pr.EvaluatePortGate(EventConnect, 80, 99, 0, "in", nil, nil) {
		t.Error("untagged peer should be denied but was allowed")
	}
}

func TestParamInt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params map[string]interface{}
		key    string
		want   int
	}{
		{"float64", map[string]interface{}{"count": 10.0}, "count", 10},
		{"int", map[string]interface{}{"count": 5}, "count", 5},
		{"missing", map[string]interface{}{}, "count", 0},
		{"nil params", nil, "count", 0},
		{"string value", map[string]interface{}{"count": "bad"}, "count", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := paramInt(tt.params, tt.key)
			if got != tt.want {
				t.Errorf("paramInt() = %d, want %d", got, tt.want)
			}
		})
	}
}

package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/policy"
)

func testPolicy() *policy.PolicyDocument {
	return &policy.PolicyDocument{
		Version: 1,
		Config: map[string]interface{}{
			"max_peers": 10,
			"cycle":     "1h",
		},
		Rules: []policy.Rule{
			{Name: "allow-80", On: "connect", Match: "port == 80", Actions: []policy.Action{{Type: policy.ActionAllow}}},
			{Name: "deny-all", On: "connect", Match: "true", Actions: []policy.Action{{Type: policy.ActionDeny}}},
			{Name: "score-data", On: "datagram", Match: "size > 0", Actions: []policy.Action{
				{Type: policy.ActionScore, Params: map[string]interface{}{"delta": 1, "topic": "activity"}},
			}},
			{Name: "cycle-prune-fill", On: "cycle", Match: "true", Actions: []policy.Action{
				{Type: policy.ActionPrune, Params: map[string]interface{}{"count": 2, "by": "score"}},
			}},
		},
	}
}

func compileTestPolicy(t *testing.T) *policy.CompiledPolicy {
	t.Helper()
	cp, err := policy.Compile(testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

func TestPolicyRunnerScore(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)

	pr := &PolicyRunner{
		netID:    1,
		compiled: cp,
		peers: map[uint32]*managedPeer{
			100: {NodeID: 100, AddedAt: time.Now()},
			200: {NodeID: 200, AddedAt: time.Now()},
		},
	}

	if err := pr.Score(100, 5, ""); err != nil {
		t.Fatalf("Score() error: %v", err)
	}
	if pr.peers[100].Score != 5 {
		t.Errorf("Score = %d, want 5", pr.peers[100].Score)
	}

	if err := pr.Score(100, -2, "quality"); err != nil {
		t.Fatalf("Score() error: %v", err)
	}
	if pr.peers[100].Score != 3 {
		t.Errorf("Score = %d, want 3", pr.peers[100].Score)
	}
	if pr.peers[100].Topics["quality"] != -2 {
		t.Errorf("Topic score = %d, want -2", pr.peers[100].Topics["quality"])
	}

	// Score non-existent peer
	if err := pr.Score(999, 1, ""); err == nil {
		t.Fatal("expected error for non-existent peer")
	}
}

func TestPolicyRunnerRankings(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)

	pr := &PolicyRunner{
		netID:    1,
		compiled: cp,
		peers: map[uint32]*managedPeer{
			100: {NodeID: 100, Score: 10, AddedAt: time.Now()},
			200: {NodeID: 200, Score: 50, AddedAt: time.Now(), Tags: []string{"elite"}},
			300: {NodeID: 300, Score: 30, AddedAt: time.Now()},
		},
	}

	rankings := pr.Rankings()
	if len(rankings) != 3 {
		t.Fatalf("Rankings() = %d entries, want 3", len(rankings))
	}

	// Check descending score order: 200 (50) > 300 (30) > 100 (10)
	if rankings[0]["node_id"] != uint32(200) {
		t.Errorf("rank 1 = node %v, want 200", rankings[0]["node_id"])
	}
	if rankings[1]["node_id"] != uint32(300) {
		t.Errorf("rank 2 = node %v, want 300", rankings[1]["node_id"])
	}
	if rankings[2]["node_id"] != uint32(100) {
		t.Errorf("rank 3 = node %v, want 100", rankings[2]["node_id"])
	}

	// Tags should be included
	tags, ok := rankings[0]["tags"]
	if !ok {
		t.Error("expected tags field on ranked peer 200")
	}
	tagSlice, _ := tags.([]string)
	if len(tagSlice) != 1 || tagSlice[0] != "elite" {
		t.Errorf("tags = %v, want [elite]", tags)
	}
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
	allowed := pr.EvaluateGate(policy.EventConnect, map[string]interface{}{
		"port": 80, "peer_id": 1, "network_id": 1,
		"peer_score": 0, "peer_tags": []string{}, "peer_age_s": 0.0, "members": 0,
	})
	if !allowed {
		t.Fatal("expected port 80 to be allowed")
	}

	// Port 22 should be denied
	denied := pr.EvaluateGate(policy.EventConnect, map[string]interface{}{
		"port": 22, "peer_id": 1, "network_id": 1,
		"peer_score": 0, "peer_tags": []string{}, "peer_age_s": 0.0, "members": 0,
	})
	if denied {
		t.Fatal("expected port 22 to be denied")
	}
}

func TestPolicyRunnerEvaluateGateWithScoring(t *testing.T) {
	t.Parallel()

	// Policy that scores on datagram and allows all
	doc := &policy.PolicyDocument{
		Version: 1,
		Rules: []policy.Rule{
			{Name: "score", On: "datagram", Match: "size > 0", Actions: []policy.Action{
				{Type: policy.ActionScore, Params: map[string]interface{}{"delta": 5, "topic": "data"}},
			}},
		},
	}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	pr := &PolicyRunner{
		netID:    1,
		compiled: cp,
		peers:    map[uint32]*managedPeer{42: {NodeID: 42, AddedAt: time.Now()}},
	}

	// EvaluateGate for datagram should auto-score the peer
	allowed := pr.EvaluateGate(policy.EventDatagram, map[string]interface{}{
		"port": 1001, "peer_id": 42, "network_id": 1, "size": 100, "direction": "in",
	})
	if !allowed {
		t.Fatal("expected default allow (no deny rule)")
	}

	// Check that scoring happened
	pr.mu.RLock()
	p := pr.peers[42]
	pr.mu.RUnlock()

	if p.Score != 5 {
		t.Errorf("score = %d, want 5 (side-effect scoring)", p.Score)
	}
	if p.Topics["data"] != 5 {
		t.Errorf("topic 'data' = %d, want 5", p.Topics["data"])
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
			100: {NodeID: 100, Score: 10, AddedAt: now},
			200: {NodeID: 200, Score: 50, AddedAt: now},
			300: {NodeID: 300, Score: 30, AddedAt: now},
			400: {NodeID: 400, Score: 5, AddedAt: now},
			500: {NodeID: 500, Score: 20, AddedAt: now},
		},
	}

	pr.executePrune(policy.Directive{
		Type:   policy.DirectivePrune,
		Rule:   "test",
		Params: map[string]interface{}{"count": 2, "by": "score"},
	})

	// 400 (5) and 100 (10) should be pruned (lowest scores)
	if _, exists := pr.peers[400]; exists {
		t.Error("peer 400 (score=5) should have been pruned")
	}
	if _, exists := pr.peers[100]; exists {
		t.Error("peer 100 (score=10) should have been pruned")
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

	pr.executePrune(policy.Directive{
		Type:   policy.DirectivePrune,
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

	doc := &policy.PolicyDocument{
		Version: 1,
		Rules: []policy.Rule{
			{Name: "evict-bad", On: "cycle", Match: "true", Actions: []policy.Action{
				{Type: policy.ActionEvictWhere, Params: map[string]interface{}{"match": "peer_score < -10"}},
			}},
		},
	}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	pr := &PolicyRunner{
		netID:    1,
		compiled: cp,
		peers: map[uint32]*managedPeer{
			100: {NodeID: 100, Score: -50, AddedAt: now},
			200: {NodeID: 200, Score: 20, AddedAt: now},
			300: {NodeID: 300, Score: -20, AddedAt: now},
		},
	}

	pr.executeEvictWhere(policy.Directive{
		Type:   policy.DirectiveEvictWhere,
		Rule:   "evict-bad",
		Params: map[string]interface{}{"match": "peer_score < -10"},
	}, 0)

	// Peers 100 (-50) and 300 (-20) should be evicted
	if _, exists := pr.peers[100]; exists {
		t.Error("peer 100 (score=-50) should have been evicted")
	}
	if _, exists := pr.peers[300]; exists {
		t.Error("peer 300 (score=-20) should have been evicted")
	}
	if _, exists := pr.peers[200]; !exists {
		t.Error("peer 200 (score=20) should remain")
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
	pr.executeTag(policy.Directive{
		Type:   policy.DirectiveTag,
		Rule:   "test",
		Params: map[string]interface{}{"add": []interface{}{"new", "elite"}},
	}, map[string]interface{}{"peer_id": 100})

	tags := pr.peers[100].Tags
	if len(tags) != 3 {
		t.Fatalf("tags = %v, want 3 tags", tags)
	}

	// Remove tag
	pr.executeTag(policy.Directive{
		Type:   policy.DirectiveTag,
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
			100: {NodeID: 100, Score: 42, Tags: []string{"elite"}, AddedAt: time.Now().Truncate(time.Second)},
			200: {NodeID: 200, Score: -5, Topics: map[string]int{"quality": -5}, AddedAt: time.Now().Truncate(time.Second)},
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
	if pr2.peers[100].Score != 42 {
		t.Errorf("peer 100 score = %d, want 42", pr2.peers[100].Score)
	}
	if pr2.peers[100].Tags[0] != "elite" {
		t.Errorf("peer 100 tags = %v, want [elite]", pr2.peers[100].Tags)
	}
	if pr2.peers[200].Topics["quality"] != -5 {
		t.Errorf("peer 200 topic score = %d, want -5", pr2.peers[200].Topics["quality"])
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
			100: {NodeID: 100, Score: 10, Tags: []string{"test"}},
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

func TestEvaluatePortPolicyWithRunner(t *testing.T) {
	t.Parallel()

	cp := compileTestPolicy(t)
	d := &Daemon{
		netPolicies:   make(map[uint16][]uint16),
		policyRunners: make(map[uint16]*PolicyRunner),
	}

	pr := &PolicyRunner{
		netID:    1,
		compiled: cp,
		peers:    map[uint32]*managedPeer{},
	}
	d.policyRunners[1] = pr

	// Port 80 allowed by policy
	if !d.evaluatePortPolicy(policy.EventConnect, 1, 80, 100, 0, "") {
		t.Error("port 80 should be allowed by policy runner")
	}

	// Port 22 denied by policy
	if d.evaluatePortPolicy(policy.EventConnect, 1, 22, 100, 0, "") {
		t.Error("port 22 should be denied by policy runner")
	}

	// Network without runner falls back to legacy (no restrictions = allow all)
	if !d.evaluatePortPolicy(policy.EventConnect, 99, 22, 100, 0, "") {
		t.Error("port 22 on network 99 should be allowed (no policy, no port restriction)")
	}
}

func TestEvaluatePortPolicyFallbackToLegacy(t *testing.T) {
	t.Parallel()

	d := &Daemon{
		netPolicies: map[uint16][]uint16{
			2: {80, 443},
		},
		policyRunners: make(map[uint16]*PolicyRunner),
	}

	// Network 2 has legacy port allowlist, no policy runner
	if !d.evaluatePortPolicy(policy.EventConnect, 2, 80, 100, 0, "") {
		t.Error("port 80 should be allowed by legacy allowlist")
	}
	if d.evaluatePortPolicy(policy.EventConnect, 2, 22, 100, 0, "") {
		t.Error("port 22 should be denied by legacy allowlist")
	}
}

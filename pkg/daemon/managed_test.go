package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

func testRules() *registry.NetworkRules {
	return &registry.NetworkRules{
		Links:   5,
		Cycle:   "1h",
		Prune:   2,
		PruneBy: "score",
		Fill:    2,
		FillHow: "random",
		Grace:   "10m",
	}
}

func TestValidateRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rules   *registry.NetworkRules
		wantErr bool
	}{
		{"nil rules", nil, false},
		{"valid", testRules(), false},
		{"zero links", &registry.NetworkRules{Links: 0, Cycle: "1h", PruneBy: "score", FillHow: "random"}, true},
		{"missing cycle", &registry.NetworkRules{Links: 5, PruneBy: "score", FillHow: "random"}, true},
		{"invalid cycle", &registry.NetworkRules{Links: 5, Cycle: "bad", PruneBy: "score", FillHow: "random"}, true},
		{"cycle too short", &registry.NetworkRules{Links: 5, Cycle: "30s", PruneBy: "score", FillHow: "random"}, true},
		{"prune exceeds links", &registry.NetworkRules{Links: 5, Cycle: "1h", Prune: 10, PruneBy: "score", FillHow: "random"}, true},
		{"unknown prune_by", &registry.NetworkRules{Links: 5, Cycle: "1h", Prune: 2, PruneBy: "unknown", FillHow: "random"}, true},
		{"unknown fill_how", &registry.NetworkRules{Links: 5, Cycle: "1h", Prune: 2, PruneBy: "score", FillHow: "magic"}, true},
		{"valid age strategy", &registry.NetworkRules{Links: 5, Cycle: "1h", Prune: 2, PruneBy: "age", FillHow: "random"}, false},
		{"valid activity strategy", &registry.NetworkRules{Links: 5, Cycle: "1h", Prune: 2, PruneBy: "activity", FillHow: "random"}, false},
		{"invalid grace", &registry.NetworkRules{Links: 5, Cycle: "1h", Prune: 2, PruneBy: "score", FillHow: "random", Grace: "bad"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := registry.ValidateRules(tt.rules)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRules() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseRules(t *testing.T) {
	t.Parallel()

	raw := `{"links":100,"cycle":"24h","prune":10,"prune_by":"score","fill":10,"fill_how":"random","grace":"48h"}`
	r, err := registry.ParseRules(raw)
	if err != nil {
		t.Fatalf("ParseRules() error: %v", err)
	}
	if r.Links != 100 {
		t.Errorf("Links = %d, want 100", r.Links)
	}
	if r.Cycle != "24h" {
		t.Errorf("Cycle = %q, want 24h", r.Cycle)
	}
	if r.PruneBy != "score" {
		t.Errorf("PruneBy = %q, want score", r.PruneBy)
	}
	if r.Grace != "48h" {
		t.Errorf("Grace = %q, want 48h", r.Grace)
	}
}

func TestParseRulesInvalid(t *testing.T) {
	t.Parallel()

	_, err := registry.ParseRules(`not json`)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}

	_, err = registry.ParseRules(`{"links":0}`)
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestManagedPeerScoring(t *testing.T) {
	t.Parallel()

	me := &ManagedEngine{
		netID: 1,
		rules: testRules(),
		peers: map[uint32]*managedPeer{
			100: {NodeID: 100, AddedAt: time.Now()},
			200: {NodeID: 200, AddedAt: time.Now()},
		},
	}

	if err := me.Score(100, 5, ""); err != nil {
		t.Fatalf("Score() error: %v", err)
	}
	if me.peers[100].Score != 5 {
		t.Errorf("Score = %d, want 5", me.peers[100].Score)
	}

	if err := me.Score(100, -2, "quality"); err != nil {
		t.Fatalf("Score() error: %v", err)
	}
	if me.peers[100].Score != 3 {
		t.Errorf("Score = %d, want 3", me.peers[100].Score)
	}
	if me.peers[100].Topics["quality"] != -2 {
		t.Errorf("Topic score = %d, want -2", me.peers[100].Topics["quality"])
	}

	// Score non-existent peer
	if err := me.Score(999, 1, ""); err == nil {
		t.Fatal("expected error for non-existent peer")
	}
}

func TestManagedRankings(t *testing.T) {
	t.Parallel()

	me := &ManagedEngine{
		netID: 1,
		rules: testRules(),
		peers: map[uint32]*managedPeer{
			100: {NodeID: 100, Score: 10, AddedAt: time.Now()},
			200: {NodeID: 200, Score: 50, AddedAt: time.Now()},
			300: {NodeID: 300, Score: 30, AddedAt: time.Now()},
		},
	}

	rankings := me.Rankings()
	if len(rankings) != 3 {
		t.Fatalf("Rankings() = %d entries, want 3", len(rankings))
	}

	// Check order: 200 (50) > 300 (30) > 100 (10)
	if rankings[0]["node_id"] != uint32(200) {
		t.Errorf("rank 1 = node %v, want 200", rankings[0]["node_id"])
	}
	if rankings[1]["node_id"] != uint32(300) {
		t.Errorf("rank 2 = node %v, want 300", rankings[1]["node_id"])
	}
	if rankings[2]["node_id"] != uint32(100) {
		t.Errorf("rank 3 = node %v, want 100", rankings[2]["node_id"])
	}
}

func TestManagedStatus(t *testing.T) {
	t.Parallel()

	me := &ManagedEngine{
		netID:    1,
		rules:    testRules(),
		peers:    map[uint32]*managedPeer{100: {NodeID: 100}},
		joinedAt: time.Now(),
	}

	status := me.Status()
	if status["network_id"] != uint16(1) {
		t.Errorf("network_id = %v, want 1", status["network_id"])
	}
	if status["peers"] != 1 {
		t.Errorf("peers = %v, want 1", status["peers"])
	}
	if status["max_links"] != 5 {
		t.Errorf("max_links = %v, want 5", status["max_links"])
	}
}

func TestManagedPruneByScore(t *testing.T) {
	t.Parallel()

	now := time.Now()
	me := &ManagedEngine{
		netID: 1,
		rules: &registry.NetworkRules{
			Links:   5,
			Cycle:   "1h",
			Prune:   2,
			PruneBy: "score",
			Fill:    0,
			FillHow: "random",
		},
		peers: map[uint32]*managedPeer{
			100: {NodeID: 100, Score: 10, AddedAt: now},
			200: {NodeID: 200, Score: 50, AddedAt: now},
			300: {NodeID: 300, Score: 30, AddedAt: now},
			400: {NodeID: 400, Score: 5, AddedAt: now},
			500: {NodeID: 500, Score: 20, AddedAt: now},
		},
	}

	ranked := me.rankedPeers()
	pruned := me.prune(ranked)

	if pruned != 2 {
		t.Errorf("pruned = %d, want 2", pruned)
	}

	// 400 (5) and 100 (10) should be pruned
	if _, exists := me.peers[400]; exists {
		t.Error("peer 400 (score=5) should have been pruned")
	}
	if _, exists := me.peers[100]; exists {
		t.Error("peer 100 (score=10) should have been pruned")
	}
	// 200, 300, 500 should remain
	if _, exists := me.peers[200]; !exists {
		t.Error("peer 200 (score=50) should remain")
	}
	if _, exists := me.peers[300]; !exists {
		t.Error("peer 300 (score=30) should remain")
	}
	if _, exists := me.peers[500]; !exists {
		t.Error("peer 500 (score=20) should remain")
	}
}

func TestManagedPruneByAge(t *testing.T) {
	t.Parallel()

	now := time.Now()
	me := &ManagedEngine{
		netID: 1,
		rules: &registry.NetworkRules{
			Links:   5,
			Cycle:   "1h",
			Prune:   1,
			PruneBy: "age",
			Fill:    0,
			FillHow: "random",
		},
		peers: map[uint32]*managedPeer{
			100: {NodeID: 100, AddedAt: now.Add(-3 * time.Hour)},
			200: {NodeID: 200, AddedAt: now.Add(-1 * time.Hour)},
			300: {NodeID: 300, AddedAt: now},
		},
	}

	ranked := me.rankedPeers()
	pruned := me.prune(ranked)

	if pruned != 1 {
		t.Errorf("pruned = %d, want 1", pruned)
	}
	if _, exists := me.peers[100]; exists {
		t.Error("peer 100 (oldest) should have been pruned")
	}
}

func TestManagedPruneGracePeriod(t *testing.T) {
	t.Parallel()

	now := time.Now()
	me := &ManagedEngine{
		netID: 1,
		rules: &registry.NetworkRules{
			Links:   5,
			Cycle:   "1h",
			Prune:   2,
			PruneBy: "score",
			Fill:    0,
			FillHow: "random",
			Grace:   "1h",
		},
		peers: map[uint32]*managedPeer{
			100: {NodeID: 100, Score: 1, AddedAt: now.Add(-2 * time.Hour)}, // past grace
			200: {NodeID: 200, Score: 2, AddedAt: now},                      // in grace
			300: {NodeID: 300, Score: 3, AddedAt: now},                      // in grace
		},
	}

	ranked := me.rankedPeers()
	pruned := me.prune(ranked)

	// Only peer 100 is past grace and has lowest score
	if pruned != 1 {
		t.Errorf("pruned = %d, want 1 (grace should protect others)", pruned)
	}
	if _, exists := me.peers[100]; exists {
		t.Error("peer 100 should have been pruned (past grace)")
	}
	if _, exists := me.peers[200]; !exists {
		t.Error("peer 200 should be protected by grace period")
	}
}

func TestManagedFill(t *testing.T) {
	t.Parallel()

	me := &ManagedEngine{
		netID: 1,
		rules: &registry.NetworkRules{
			Links:   5,
			Cycle:   "1h",
			Prune:   0,
			PruneBy: "score",
			Fill:    3,
			FillHow: "random",
		},
		peers: map[uint32]*managedPeer{
			100: {NodeID: 100, AddedAt: time.Now()},
		},
		daemon: &Daemon{
			nodeID: 999, // our own ID
		},
	}

	members := []uint32{100, 200, 300, 400, 500, 999}
	filled := me.fill(members)

	if filled != 3 {
		t.Errorf("filled = %d, want 3", filled)
	}
	if len(me.peers) != 4 { // 1 existing + 3 new
		t.Errorf("total peers = %d, want 4", len(me.peers))
	}

	// Existing peer should still be there
	if _, exists := me.peers[100]; !exists {
		t.Error("existing peer 100 should remain")
	}

	// Our own ID should not be added
	if _, exists := me.peers[999]; exists {
		t.Error("should not add own node ID to managed set")
	}
}

func TestManagedFillRespectsLinksLimit(t *testing.T) {
	t.Parallel()

	me := &ManagedEngine{
		netID: 1,
		rules: &registry.NetworkRules{
			Links:   3,
			Cycle:   "1h",
			Prune:   0,
			PruneBy: "score",
			Fill:    10, // wants 10 but links limit is 3
			FillHow: "random",
		},
		peers: map[uint32]*managedPeer{
			100: {NodeID: 100, AddedAt: time.Now()},
		},
		daemon: &Daemon{nodeID: 999},
	}

	members := []uint32{100, 200, 300, 400, 500, 600, 700, 999}
	filled := me.fill(members)

	if filled != 2 { // links=3, have 1, can add 2
		t.Errorf("filled = %d, want 2 (limited by links)", filled)
	}
	if len(me.peers) != 3 {
		t.Errorf("total peers = %d, want 3", len(me.peers))
	}
}

func TestManagedPersistAndLoad(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "managed_1.json")

	me := &ManagedEngine{
		netID:    1,
		rules:    testRules(),
		joinedAt: time.Now().Truncate(time.Second),
		peers: map[uint32]*managedPeer{
			100: {NodeID: 100, Score: 42, AddedAt: time.Now().Truncate(time.Second)},
			200: {NodeID: 200, Score: -5, Topics: map[string]int{"quality": -5}, AddedAt: time.Now().Truncate(time.Second)},
		},
		path: path,
	}

	me.persist()

	// Verify file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("persist file should exist")
	}

	// Load into new engine
	me2 := &ManagedEngine{
		netID: 1,
		rules: testRules(),
		peers: make(map[uint32]*managedPeer),
		path:  path,
	}
	if err := me2.load(); err != nil {
		t.Fatalf("load() error: %v", err)
	}

	if len(me2.peers) != 2 {
		t.Errorf("loaded peers = %d, want 2", len(me2.peers))
	}
	if me2.peers[100].Score != 42 {
		t.Errorf("peer 100 score = %d, want 42", me2.peers[100].Score)
	}
	if me2.peers[200].Topics["quality"] != -5 {
		t.Errorf("peer 200 topic score = %d, want -5", me2.peers[200].Topics["quality"])
	}
}

func TestManagedSnapshotJSON(t *testing.T) {
	t.Parallel()

	snap := managedSnapshot{
		NetworkID: 42,
		Peers: map[uint32]*managedPeer{
			100: {NodeID: 100, Score: 10},
		},
		JoinedAt: time.Now().Format(time.RFC3339),
	}

	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var loaded managedSnapshot
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if loaded.NetworkID != 42 {
		t.Errorf("NetworkID = %d, want 42", loaded.NetworkID)
	}
}

func TestIsPortAllowed(t *testing.T) {
	t.Parallel()

	d := &Daemon{
		netPolicies: map[uint16][]uint16{
			1: {80, 443, 1001}, // network 1: only web + data exchange
			2: {7},             // network 2: echo only
			// network 0 (backbone): no entry = all ports allowed
		},
	}

	tests := []struct {
		name    string
		netID   uint16
		port    uint16
		allowed bool
	}{
		{"backbone_any_port", 0, 9999, true},
		{"net1_allowed_80", 1, 80, true},
		{"net1_allowed_443", 1, 443, true},
		{"net1_allowed_1001", 1, 1001, true},
		{"net1_blocked_22", 1, 22, false},
		{"net1_blocked_7", 1, 7, false},
		{"net2_allowed_7", 2, 7, true},
		{"net2_blocked_80", 2, 80, false},
		{"unknown_net_all_allowed", 99, 12345, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := d.isPortAllowed(tt.netID, tt.port)
			if got != tt.allowed {
				t.Errorf("isPortAllowed(%d, %d) = %v, want %v", tt.netID, tt.port, got, tt.allowed)
			}
		})
	}
}

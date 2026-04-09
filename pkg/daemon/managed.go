package daemon

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/fsutil"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// ManagedEngine runs the managed network cycle for a single network.
// It maintains a local peer set, scores, and runs periodic prune/fill cycles.
// All state is daemon-local — the registry only stores the rules.
type ManagedEngine struct {
	netID  uint16
	rules  *registry.NetworkRules
	daemon *Daemon

	mu       sync.RWMutex
	peers    map[uint32]*managedPeer // nodeID -> peer state
	joinedAt time.Time               // when this node joined the managed network

	stopCh chan struct{}
	done   chan struct{}
	path   string // persistence path (~/.pilot/managed_<netID>.json)
}

// managedPeer tracks a single managed peer's state.
type managedPeer struct {
	NodeID   uint32         `json:"node_id"`
	Score    int            `json:"score"`
	Topics   map[string]int `json:"topics,omitempty"` // per-topic scores
	Tags     []string       `json:"tags,omitempty"`   // peer tags (policy engine)
	AddedAt  time.Time      `json:"added_at"`
	LastSeen time.Time      `json:"last_seen"`
}

// managedSnapshot is the JSON format persisted to disk.
type managedSnapshot struct {
	NetworkID uint16                  `json:"network_id"`
	Peers     map[uint32]*managedPeer `json:"peers"`
	JoinedAt  string                  `json:"joined_at"`
	CycleNum  int                     `json:"cycle_num"`
}

// NewManagedEngine creates a managed engine for a network.
// It loads persisted state if available, or bootstraps from the member list.
func NewManagedEngine(netID uint16, rules *registry.NetworkRules, d *Daemon) *ManagedEngine {
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".pilot", fmt.Sprintf("managed_%d.json", netID))

	me := &ManagedEngine{
		netID:    netID,
		rules:    rules,
		daemon:   d,
		peers:    make(map[uint32]*managedPeer),
		joinedAt: time.Now(),
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
		path:     path,
	}

	if err := me.load(); err != nil {
		slog.Debug("managed: no persisted state, will bootstrap", "network_id", netID, "err", err)
	}

	return me
}

// Start begins the cycle loop. Should be called after construction.
func (me *ManagedEngine) Start() {
	go me.cycleLoop()
	slog.Info("managed engine started", "network_id", me.netID, "rules", me.rules)
}

// Stop signals the cycle loop to exit and waits for it.
func (me *ManagedEngine) Stop() {
	select {
	case <-me.stopCh:
	default:
		close(me.stopCh)
	}
	<-me.done
}

// Bootstrap populates the managed set from the network member list.
// Called on first join or when persisted state is empty.
func (me *ManagedEngine) Bootstrap() error {
	members, err := me.fetchMembers()
	if err != nil {
		return fmt.Errorf("managed bootstrap: %w", err)
	}

	myID := me.daemon.NodeID()
	var candidates []uint32
	for _, id := range members {
		if id != myID {
			candidates = append(candidates, id)
		}
	}

	// Shuffle and pick up to rules.Links peers
	rand.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})
	limit := me.rules.Links
	if limit > len(candidates) {
		limit = len(candidates)
	}

	me.mu.Lock()
	defer me.mu.Unlock()

	now := time.Now()
	for _, id := range candidates[:limit] {
		if _, exists := me.peers[id]; !exists {
			me.peers[id] = &managedPeer{
				NodeID:  id,
				AddedAt: now,
			}
		}
	}

	me.persist()
	slog.Info("managed: bootstrapped", "network_id", me.netID, "peers", len(me.peers), "available", len(candidates))
	return nil
}

// Score adjusts a peer's score by delta. Optional topic scoping.
func (me *ManagedEngine) Score(nodeID uint32, delta int, topic string) error {
	me.mu.Lock()
	defer me.mu.Unlock()

	p, ok := me.peers[nodeID]
	if !ok {
		return fmt.Errorf("peer %d not in managed set for network %d", nodeID, me.netID)
	}

	p.Score += delta
	p.LastSeen = time.Now()

	if topic != "" {
		if p.Topics == nil {
			p.Topics = make(map[string]int)
		}
		p.Topics[topic] += delta
	}

	return nil
}

// Status returns a summary of the managed engine state.
func (me *ManagedEngine) Status() map[string]interface{} {
	me.mu.RLock()
	defer me.mu.RUnlock()

	return map[string]interface{}{
		"network_id": me.netID,
		"peers":      len(me.peers),
		"max_links":  me.rules.Links,
		"cycle":      me.rules.Cycle,
		"prune":      me.rules.Prune,
		"prune_by":   me.rules.PruneBy,
		"fill":       me.rules.Fill,
		"fill_how":   me.rules.FillHow,
		"grace":      me.rules.Grace,
		"joined_at":  me.joinedAt.Format(time.RFC3339),
	}
}

// Rankings returns all managed peers sorted by score descending.
func (me *ManagedEngine) Rankings() []map[string]interface{} {
	me.mu.RLock()
	defer me.mu.RUnlock()

	type entry struct {
		peer *managedPeer
	}
	var entries []entry
	for _, p := range me.peers {
		entries = append(entries, entry{peer: p})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].peer.Score > entries[j].peer.Score
	})

	result := make([]map[string]interface{}, 0, len(entries))
	for rank, e := range entries {
		m := map[string]interface{}{
			"rank":     rank + 1,
			"node_id":  e.peer.NodeID,
			"score":    e.peer.Score,
			"added_at": e.peer.AddedAt.Format(time.RFC3339),
		}
		if !e.peer.LastSeen.IsZero() {
			m["last_seen"] = e.peer.LastSeen.Format(time.RFC3339)
		}
		if len(e.peer.Topics) > 0 {
			m["topics"] = e.peer.Topics
		}
		result = append(result, m)
	}
	return result
}

// ForceCycle runs a cycle immediately, outside the timer.
func (me *ManagedEngine) ForceCycle() map[string]interface{} {
	return me.runCycle()
}

// cycleLoop is the main background goroutine.
func (me *ManagedEngine) cycleLoop() {
	defer close(me.done)

	// Bootstrap if we have no peers
	me.mu.RLock()
	needBootstrap := len(me.peers) == 0
	me.mu.RUnlock()
	if needBootstrap {
		if err := me.Bootstrap(); err != nil {
			slog.Warn("managed: bootstrap failed", "network_id", me.netID, "err", err)
		}
	}

	cycleDur, _ := time.ParseDuration(me.rules.Cycle) // validated at creation
	ticker := time.NewTicker(cycleDur)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			me.runCycle()
		case <-me.stopCh:
			return
		}
	}
}

// runCycle executes one prune/fill cycle.
func (me *ManagedEngine) runCycle() map[string]interface{} {
	me.mu.Lock()

	// 1. Rank peers
	ranked := me.rankedPeers()

	// 2. Prune bottom N
	pruned := me.prune(ranked)

	me.mu.Unlock()

	// 3. Fetch current members (needs network call, do outside lock)
	members, err := me.fetchMembers()
	if err != nil {
		slog.Warn("managed: cycle fill failed (member list)", "network_id", me.netID, "err", err)
		return map[string]interface{}{
			"pruned": pruned,
			"filled": 0,
			"error":  err.Error(),
		}
	}

	me.mu.Lock()
	// 4. Fill with random new peers
	filled := me.fill(members)

	peerCount := len(me.peers)
	me.mu.Unlock()

	me.persist()

	result := map[string]interface{}{
		"network_id": me.netID,
		"pruned":     pruned,
		"filled":     filled,
		"peers":      peerCount,
	}

	slog.Info("managed: cycle complete", "network_id", me.netID, "pruned", pruned, "filled", filled, "peers", peerCount)

	me.daemon.webhook.Emit("managed.cycle", result)

	return result
}

// rankedPeers returns peers sorted according to the prune strategy.
// Caller must hold me.mu.
func (me *ManagedEngine) rankedPeers() []*managedPeer {
	peers := make([]*managedPeer, 0, len(me.peers))
	for _, p := range me.peers {
		peers = append(peers, p)
	}

	switch me.rules.PruneBy {
	case "score":
		// Ascending: lowest score first (pruned first)
		sort.Slice(peers, func(i, j int) bool {
			return peers[i].Score < peers[j].Score
		})
	case "age":
		// Oldest first (earliest AddedAt pruned first)
		sort.Slice(peers, func(i, j int) bool {
			return peers[i].AddedAt.Before(peers[j].AddedAt)
		})
	case "activity":
		// Least recently seen first (earliest LastSeen pruned first)
		sort.Slice(peers, func(i, j int) bool {
			return peers[i].LastSeen.Before(peers[j].LastSeen)
		})
	}

	return peers
}

// prune removes the bottom N peers from the managed set.
// Returns the number actually pruned. Caller must hold me.mu.
func (me *ManagedEngine) prune(ranked []*managedPeer) int {
	toPrune := me.rules.Prune
	if toPrune > len(ranked) {
		toPrune = len(ranked)
	}

	// Check grace period: don't prune peers added within grace window
	var graceDur time.Duration
	if me.rules.Grace != "" {
		graceDur, _ = time.ParseDuration(me.rules.Grace)
	}

	pruned := 0
	now := time.Now()
	for i := 0; i < toPrune && i < len(ranked); i++ {
		p := ranked[i]
		if graceDur > 0 && now.Sub(p.AddedAt) < graceDur {
			continue // still in grace period
		}
		delete(me.peers, p.NodeID)
		pruned++
	}
	return pruned
}

// fill adds up to rules.Fill new random peers not already in the managed set.
// Returns the number actually added. Caller must hold me.mu.
func (me *ManagedEngine) fill(members []uint32) int {
	myID := me.daemon.NodeID()

	var candidates []uint32
	for _, id := range members {
		if id == myID {
			continue
		}
		if _, exists := me.peers[id]; exists {
			continue
		}
		candidates = append(candidates, id)
	}

	rand.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})

	// Respect links limit
	available := me.rules.Links - len(me.peers)
	if available < 0 {
		available = 0
	}
	toFill := me.rules.Fill
	if toFill > available {
		toFill = available
	}
	if toFill > len(candidates) {
		toFill = len(candidates)
	}

	now := time.Now()
	for _, id := range candidates[:toFill] {
		me.peers[id] = &managedPeer{
			NodeID:  id,
			AddedAt: now,
		}
	}
	return toFill
}

// fetchMembers calls list_nodes on the registry for this network.
func (me *ManagedEngine) fetchMembers() ([]uint32, error) {
	resp, err := me.daemon.regConn.ListNodes(me.netID, me.daemon.config.AdminToken)
	if err != nil {
		return nil, err
	}

	nodesRaw, ok := resp["nodes"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected list_nodes response")
	}

	var members []uint32
	for _, n := range nodesRaw {
		if m, ok := n.(map[string]interface{}); ok {
			if id, ok := m["node_id"].(float64); ok {
				members = append(members, uint32(id))
			}
		}
	}
	return members, nil
}

// persist saves the managed state to disk.
func (me *ManagedEngine) persist() {
	me.mu.RLock()
	snap := managedSnapshot{
		NetworkID: me.netID,
		Peers:     me.peers,
		JoinedAt:  me.joinedAt.Format(time.RFC3339),
	}
	me.mu.RUnlock()

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		slog.Warn("managed: persist marshal failed", "network_id", me.netID, "err", err)
		return
	}

	// Ensure directory exists
	dir := filepath.Dir(me.path)
	os.MkdirAll(dir, 0700)

	if err := fsutil.AtomicWrite(me.path, data); err != nil {
		slog.Warn("managed: persist write failed", "network_id", me.netID, "err", err)
	}
}

// load reads persisted state from disk.
func (me *ManagedEngine) load() error {
	data, err := os.ReadFile(me.path)
	if err != nil {
		return err
	}

	var snap managedSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}

	me.peers = snap.Peers
	if me.peers == nil {
		me.peers = make(map[uint32]*managedPeer)
	}
	if t, err := time.Parse(time.RFC3339, snap.JoinedAt); err == nil {
		me.joinedAt = t
	}

	slog.Info("managed: loaded persisted state", "network_id", me.netID, "peers", len(me.peers))
	return nil
}

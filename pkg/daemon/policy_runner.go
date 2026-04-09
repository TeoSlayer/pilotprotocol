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
	"github.com/TeoSlayer/pilotprotocol/pkg/policy"
)

// PolicyRunner manages a compiled policy for a single network.
// It holds per-peer state (scores, tags), runs cycle timers, and
// evaluates policy rules against protocol events.
type PolicyRunner struct {
	netID    uint16
	compiled *policy.CompiledPolicy
	daemon   *Daemon

	mu       sync.RWMutex
	peers    map[uint32]*managedPeer // reuse managedPeer from managed.go
	joinedAt time.Time
	cycleNum int

	stopCh chan struct{}
	done   chan struct{}
	path   string // persistence path (~/.pilot/policy_<netID>.json)
}

// policySnapshot is the JSON format persisted to disk.
type policySnapshot struct {
	NetworkID uint16                  `json:"network_id"`
	Peers     map[uint32]*managedPeer `json:"peers"`
	JoinedAt  string                  `json:"joined_at"`
	CycleNum  int                     `json:"cycle_num"`
}

// NewPolicyRunner creates a policy runner for a network with the given compiled policy.
func NewPolicyRunner(netID uint16, cp *policy.CompiledPolicy, d *Daemon) *PolicyRunner {
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".pilot", fmt.Sprintf("policy_%d.json", netID))

	pr := &PolicyRunner{
		netID:    netID,
		compiled: cp,
		daemon:   d,
		peers:    make(map[uint32]*managedPeer),
		joinedAt: time.Now(),
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
		path:     path,
	}

	if err := pr.load(); err != nil {
		slog.Debug("policy: no persisted state, will bootstrap", "network_id", netID, "err", err)
	}

	return pr
}

// Start begins the cycle loop if the policy has cycle rules.
func (pr *PolicyRunner) Start() {
	go pr.cycleLoop()
	slog.Info("policy runner started", "network_id", pr.netID)
}

// Stop signals the cycle loop to exit and waits for it.
func (pr *PolicyRunner) Stop() {
	select {
	case <-pr.stopCh:
	default:
		close(pr.stopCh)
	}
	<-pr.done
}

// Policy returns the compiled policy.
func (pr *PolicyRunner) Policy() *policy.CompiledPolicy {
	return pr.compiled
}

// EvaluateGate evaluates a gate event (connect, dial, datagram) and returns
// true if allowed, false if denied.
func (pr *PolicyRunner) EvaluateGate(eventType policy.EventType, ctx map[string]interface{}) bool {
	dirs, err := pr.compiled.Evaluate(eventType, ctx)
	if err != nil {
		slog.Warn("policy: gate eval error", "network_id", pr.netID, "event", eventType, "err", err)
		return true // fail open on error
	}

	// Execute side effects (score, tag, etc.) before the verdict
	for _, d := range dirs {
		switch d.Type {
		case policy.DirectiveAllow:
			return true
		case policy.DirectiveDeny:
			return false
		case policy.DirectiveScore:
			pr.executeScore(d, ctx)
		case policy.DirectiveTag:
			pr.executeTag(d, ctx)
		case policy.DirectiveLog:
			pr.executeLog(d)
		case policy.DirectiveWebhook:
			pr.executeWebhook(d)
		}
	}
	return true // default allow
}

// EvaluateActions evaluates an action event (cycle, join, leave).
func (pr *PolicyRunner) EvaluateActions(eventType policy.EventType, ctx map[string]interface{}) {
	dirs, err := pr.compiled.Evaluate(eventType, ctx)
	if err != nil {
		slog.Warn("policy: action eval error", "network_id", pr.netID, "event", eventType, "err", err)
		return
	}

	for i, d := range dirs {
		switch d.Type {
		case policy.DirectiveScore:
			pr.executeScore(d, ctx)
		case policy.DirectiveTag:
			pr.executeTag(d, ctx)
		case policy.DirectiveEvict:
			pr.executeEvict(ctx)
		case policy.DirectiveEvictWhere:
			pr.executeEvictWhere(d, i)
		case policy.DirectivePrune:
			pr.executePrune(d)
		case policy.DirectiveFill:
			pr.executeFill(d)
		case policy.DirectiveLog:
			pr.executeLog(d)
		case policy.DirectiveWebhook:
			pr.executeWebhook(d)
		}
	}
}

// --- Action executors ---

func (pr *PolicyRunner) executeScore(d policy.Directive, ctx map[string]interface{}) {
	peerID, _ := ctx["peer_id"].(int)
	if peerID == 0 {
		return
	}
	delta := paramInt(d.Params, "delta")
	topic, _ := d.Params["topic"].(string)

	pr.mu.Lock()
	defer pr.mu.Unlock()

	p, ok := pr.peers[uint32(peerID)]
	if !ok {
		// Auto-add peer if not in managed set
		p = &managedPeer{NodeID: uint32(peerID), AddedAt: time.Now()}
		pr.peers[uint32(peerID)] = p
	}
	p.Score += delta
	p.LastSeen = time.Now()
	if topic != "" {
		if p.Topics == nil {
			p.Topics = make(map[string]int)
		}
		p.Topics[topic] += delta
	}
}

func (pr *PolicyRunner) executeTag(d policy.Directive, ctx map[string]interface{}) {
	peerID, _ := ctx["peer_id"].(int)
	if peerID == 0 {
		return
	}

	pr.mu.Lock()
	defer pr.mu.Unlock()

	p, ok := pr.peers[uint32(peerID)]
	if !ok {
		return
	}

	if addRaw, ok := d.Params["add"]; ok {
		if tags, ok := addRaw.([]interface{}); ok {
			for _, t := range tags {
				if s, ok := t.(string); ok {
					p.addTag(s)
				}
			}
		}
	}
	if removeRaw, ok := d.Params["remove"]; ok {
		if tags, ok := removeRaw.([]interface{}); ok {
			for _, t := range tags {
				if s, ok := t.(string); ok {
					p.removeTag(s)
				}
			}
		}
	}
}

func (pr *PolicyRunner) executeEvict(ctx map[string]interface{}) {
	peerID, _ := ctx["peer_id"].(int)
	if peerID == 0 {
		return
	}
	pr.mu.Lock()
	delete(pr.peers, uint32(peerID))
	pr.mu.Unlock()
}

func (pr *PolicyRunner) executeEvictWhere(d policy.Directive, actionIdx int) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	var toEvict []uint32
	for _, p := range pr.peers {
		peerCtx := map[string]interface{}{
			"peer_id":    int(p.NodeID),
			"peer_score": p.Score,
			"peer_tags":  p.tags(),
			"peer_age_s": time.Since(p.AddedAt).Seconds(),
			"last_seen":  float64(p.LastSeen.Unix()),
		}
		ok, err := pr.compiled.EvaluatePeerExpr(d.Rule, actionIdx, peerCtx)
		if err != nil {
			slog.Warn("policy: evict_where eval error", "rule", d.Rule, "err", err)
			continue
		}
		if ok {
			toEvict = append(toEvict, p.NodeID)
		}
	}

	for _, id := range toEvict {
		delete(pr.peers, id)
	}
	if len(toEvict) > 0 {
		slog.Info("policy: evicted peers", "network_id", pr.netID, "count", len(toEvict), "rule", d.Rule)
	}
}

func (pr *PolicyRunner) executePrune(d policy.Directive) {
	count := paramInt(d.Params, "count")
	by, _ := d.Params["by"].(string)
	if by == "" {
		by = "score"
	}

	pr.mu.Lock()
	defer pr.mu.Unlock()

	ranked := pr.rankedPeers(by)
	pruned := 0
	for i := 0; i < count && i < len(ranked); i++ {
		delete(pr.peers, ranked[i].NodeID)
		pruned++
	}
	if pruned > 0 {
		slog.Info("policy: pruned peers", "network_id", pr.netID, "count", pruned, "rule", d.Rule)
	}
}

func (pr *PolicyRunner) executeFill(d policy.Directive) {
	count := paramInt(d.Params, "count")

	fetched := pr.fetchMembersWithTags()
	if fetched == nil {
		slog.Warn("policy: fill failed (member list)", "network_id", pr.netID)
		return
	}

	pr.mu.Lock()
	defer pr.mu.Unlock()

	myID := pr.daemon.NodeID()
	type candidate struct {
		id   uint32
		tags []string
	}
	var candidates []candidate
	for _, f := range fetched {
		if f.ID == myID {
			continue
		}
		if p, exists := pr.peers[f.ID]; exists {
			// Refresh tags for existing peers
			p.Tags = f.Tags
			continue
		}
		candidates = append(candidates, candidate{id: f.ID, tags: f.Tags})
	}

	rand.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})

	maxPeers := pr.compiled.MaxPeers()
	if maxPeers > 0 {
		available := maxPeers - len(pr.peers)
		if available < 0 {
			available = 0
		}
		if count > available {
			count = available
		}
	}
	if count > len(candidates) {
		count = len(candidates)
	}

	now := time.Now()
	for _, c := range candidates[:count] {
		pr.peers[c.id] = &managedPeer{NodeID: c.id, AddedAt: now, Tags: c.tags}
	}
	if count > 0 {
		slog.Info("policy: filled peers", "network_id", pr.netID, "count", count, "rule", d.Rule)
	}
}

func (pr *PolicyRunner) executeLog(d policy.Directive) {
	msg, _ := d.Params["message"].(string)
	level, _ := d.Params["level"].(string)
	switch level {
	case "warn":
		slog.Warn("policy: "+msg, "network_id", pr.netID, "rule", d.Rule)
	default:
		slog.Info("policy: "+msg, "network_id", pr.netID, "rule", d.Rule)
	}
}

func (pr *PolicyRunner) executeWebhook(d policy.Directive) {
	event, _ := d.Params["event"].(string)
	data, _ := d.Params["data"].(map[string]interface{})
	if data == nil {
		data = map[string]interface{}{}
	}
	data["network_id"] = pr.netID
	data["rule"] = d.Rule
	pr.daemon.webhook.Emit("policy."+event, data)
}

// --- Cycle loop ---

func (pr *PolicyRunner) cycleLoop() {
	defer close(pr.done)

	// Always bootstrap from registry to refresh peer list and tags.
	// Persisted state preserves scores/history, but membership and tags
	// may have changed since last run.
	if err := pr.bootstrap(); err != nil {
		slog.Warn("policy: bootstrap failed", "network_id", pr.netID, "err", err)
	}

	cycleStr, _ := pr.compiled.CycleDuration()
	if cycleStr == "" {
		// No cycle configured — just idle until stopped
		<-pr.stopCh
		return
	}

	cycleDur, err := time.ParseDuration(cycleStr)
	if err != nil || cycleDur < time.Minute {
		cycleDur = 24 * time.Hour
	}

	ticker := time.NewTicker(cycleDur)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pr.runCycle()
		case <-pr.stopCh:
			return
		}
	}
}

func (pr *PolicyRunner) runCycle() map[string]interface{} {
	pr.mu.Lock()
	pr.cycleNum++
	peerCount := len(pr.peers)
	cycleNum := pr.cycleNum
	pr.mu.Unlock()

	ctx := map[string]interface{}{
		"network_id": int(pr.netID),
		"members":    peerCount,
		"peer_count": peerCount,
		"cycle_num":  cycleNum,
	}

	pr.EvaluateActions(policy.EventCycle, ctx)

	pr.persist()

	pr.mu.RLock()
	finalPeers := len(pr.peers)
	pr.mu.RUnlock()

	result := map[string]interface{}{
		"network_id": pr.netID,
		"cycle_num":  cycleNum,
		"peers":      finalPeers,
	}

	slog.Info("policy: cycle complete", "network_id", pr.netID, "cycle_num", cycleNum, "peers", finalPeers)
	pr.daemon.webhook.Emit("policy.cycle", result)

	return result
}

// --- Peer state methods (compatibility with ManagedEngine interface) ---

// Score adjusts a peer's score by delta. Optional topic scoping.
func (pr *PolicyRunner) Score(nodeID uint32, delta int, topic string) error {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	p, ok := pr.peers[nodeID]
	if !ok {
		return fmt.Errorf("peer %d not in policy set for network %d", nodeID, pr.netID)
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

// Status returns a summary of the policy runner state.
func (pr *PolicyRunner) Status() map[string]interface{} {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	status := map[string]interface{}{
		"network_id": pr.netID,
		"peers":      len(pr.peers),
		"cycle_num":  pr.cycleNum,
		"joined_at":  pr.joinedAt.Format(time.RFC3339),
		"engine":     "policy",
	}

	cycle, _ := pr.compiled.CycleDuration()
	if cycle != "" {
		status["cycle"] = cycle
	}
	if mp := pr.compiled.MaxPeers(); mp > 0 {
		status["max_peers"] = mp
	}
	return status
}

// Rankings returns all managed peers sorted by score descending.
func (pr *PolicyRunner) Rankings() []map[string]interface{} {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	type entry struct {
		peer *managedPeer
	}
	var entries []entry
	for _, p := range pr.peers {
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
		if len(e.peer.Tags) > 0 {
			m["tags"] = e.peer.Tags
		}
		result = append(result, m)
	}
	return result
}

// ForceCycle runs a cycle immediately.
func (pr *PolicyRunner) ForceCycle() map[string]interface{} {
	return pr.runCycle()
}

// --- Internal helpers ---

func (pr *PolicyRunner) bootstrap() error {
	fetched := pr.fetchMembersWithTags()
	if fetched == nil {
		return fmt.Errorf("policy bootstrap: failed to fetch members")
	}

	// Build tag lookup for candidates
	tagMap := make(map[uint32][]string, len(fetched))
	myID := pr.daemon.NodeID()
	var candidates []uint32
	for _, f := range fetched {
		tagMap[f.ID] = f.Tags
		if f.ID != myID {
			candidates = append(candidates, f.ID)
		}
	}

	rand.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})

	maxPeers := pr.compiled.MaxPeers()
	limit := len(candidates)
	if maxPeers > 0 && limit > maxPeers {
		limit = maxPeers
	}

	pr.mu.Lock()
	now := time.Now()
	for _, id := range candidates[:limit] {
		if _, exists := pr.peers[id]; !exists {
			pr.peers[id] = &managedPeer{NodeID: id, AddedAt: now, Tags: tagMap[id]}
		} else {
			pr.peers[id].Tags = tagMap[id]
		}
	}
	peerCount := len(pr.peers)
	pr.mu.Unlock()

	pr.persist()
	slog.Info("policy: bootstrapped", "network_id", pr.netID, "peers", peerCount, "available", len(candidates))
	return nil
}

// fetchedMember holds a member's ID and admin-assigned tags from ListNodes.
type fetchedMember struct {
	ID   uint32
	Tags []string
}

func (pr *PolicyRunner) fetchMembers() ([]uint32, error) {
	fetched := pr.fetchMembersWithTags()
	ids := make([]uint32, len(fetched))
	for i, f := range fetched {
		ids[i] = f.ID
	}
	return ids, nil
}

// fetchMembersWithTags returns member IDs and their admin-assigned tags.
// Also updates the daemon's local member tags cache for the local node.
func (pr *PolicyRunner) fetchMembersWithTags() []fetchedMember {
	resp, err := pr.daemon.regConn.ListNodes(pr.netID, pr.daemon.config.AdminToken)
	if err != nil {
		slog.Warn("policy: fetchMembers failed", "network_id", pr.netID, "err", err)
		return nil
	}

	nodesRaw, ok := resp["nodes"].([]interface{})
	if !ok {
		return nil
	}

	myID := pr.daemon.NodeID()
	var members []fetchedMember
	for _, n := range nodesRaw {
		m, ok := n.(map[string]interface{})
		if !ok {
			continue
		}
		id, ok := m["node_id"].(float64)
		if !ok {
			continue
		}
		nodeID := uint32(id)
		var tags []string
		if rawTags, ok := m["member_tags"].([]interface{}); ok {
			for _, rt := range rawTags {
				if t, ok := rt.(string); ok {
					tags = append(tags, t)
				}
			}
		}
		members = append(members, fetchedMember{ID: nodeID, Tags: tags})

		// Cache local node's member tags on the daemon
		if nodeID == myID {
			pr.daemon.SetMemberTags(pr.netID, tags)
		}
	}
	return members
}

func (pr *PolicyRunner) rankedPeers(by string) []*managedPeer {
	peers := make([]*managedPeer, 0, len(pr.peers))
	for _, p := range pr.peers {
		peers = append(peers, p)
	}

	switch by {
	case "score":
		sort.Slice(peers, func(i, j int) bool {
			return peers[i].Score < peers[j].Score
		})
	case "age":
		sort.Slice(peers, func(i, j int) bool {
			return peers[i].AddedAt.Before(peers[j].AddedAt)
		})
	case "activity":
		sort.Slice(peers, func(i, j int) bool {
			return peers[i].LastSeen.Before(peers[j].LastSeen)
		})
	}
	return peers
}

func (pr *PolicyRunner) persist() {
	pr.mu.RLock()
	snap := policySnapshot{
		NetworkID: pr.netID,
		Peers:     pr.peers,
		JoinedAt:  pr.joinedAt.Format(time.RFC3339),
		CycleNum:  pr.cycleNum,
	}
	pr.mu.RUnlock()

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		slog.Warn("policy: persist marshal failed", "network_id", pr.netID, "err", err)
		return
	}

	dir := filepath.Dir(pr.path)
	os.MkdirAll(dir, 0700)

	if err := fsutil.AtomicWrite(pr.path, data); err != nil {
		slog.Warn("policy: persist write failed", "network_id", pr.netID, "err", err)
	}
}

func (pr *PolicyRunner) load() error {
	data, err := os.ReadFile(pr.path)
	if err != nil {
		return err
	}

	var snap policySnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}

	pr.peers = snap.Peers
	if pr.peers == nil {
		pr.peers = make(map[uint32]*managedPeer)
	}
	pr.cycleNum = snap.CycleNum
	if t, err := time.Parse(time.RFC3339, snap.JoinedAt); err == nil {
		pr.joinedAt = t
	}

	slog.Info("policy: loaded persisted state", "network_id", pr.netID, "peers", len(pr.peers))
	return nil
}

// --- helpers ---

func paramInt(params map[string]interface{}, key string) int {
	v, ok := params[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	}
	return 0
}

// Tag helpers on managedPeer

func (p *managedPeer) tags() []string {
	if p.Tags == nil {
		return []string{}
	}
	return p.Tags
}

func (p *managedPeer) addTag(tag string) {
	for _, t := range p.Tags {
		if t == tag {
			return
		}
	}
	p.Tags = append(p.Tags, tag)
}

func (p *managedPeer) removeTag(tag string) {
	for i, t := range p.Tags {
		if t == tag {
			p.Tags = append(p.Tags[:i], p.Tags[i+1:]...)
			return
		}
	}
}

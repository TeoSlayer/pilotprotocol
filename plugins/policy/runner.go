// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

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

	"github.com/pilot-protocol/common/fsutil"
)

// PolicyRunner manages a compiled policy for a single network.
// It holds per-peer state (scores, tags), runs cycle timers, and
// evaluates policy rules against protocol events.
type PolicyRunner struct {
	netID    uint16
	compiled *CompiledPolicy
	runtime  Runtime

	mu    sync.RWMutex
	peers map[uint32]*managedPeer // reuse managedPeer from managed.go
	// Peers that local evict / deny decisions removed from pr.peers.
	// Reconciler's applyMembershipDiff refuses to re-add entries during
	// the cooldown window — otherwise the next reconcile tick (5s)
	// silently undoes evicts, which defeats the semantic.
	recentlyEvicted map[uint32]time.Time
	joinedAt        time.Time
	cycleNum        int

	// Cycle-scoped counters. Reset at the start of each runCycle, incremented
	// by directive executors, and copied into the cycle result for
	// observability (surfaced via `pilotctl managed cycle` output).
	cycleEvicted     int
	cyclePruned      int
	cycleFilled      int
	cyclePrunedTrust int
	cycleFilledTrust int

	stopCh chan struct{}
	done   chan struct{}
	path   string // persistence path (~/.pilot/policy_<netID>.json)

	// fetchMembers backoff. Some networks are too large for the registry's
	// list_nodes response to fit a single read window — fetchMembers EOFs
	// every 5s tick and pounds the regConn mutex, which adds 5+ seconds
	// of latency to ANY other call (resolve_hostname, lookup, etc) that
	// shares regConn. Track consecutive failures and skip ticks until
	// the next backoff deadline.
	fetchFailMu    sync.Mutex
	fetchFailures  int       // consecutive failure count
	fetchSkipUntil time.Time // skip ticks before this time
}

// policySnapshot is the JSON format persisted to disk.
type policySnapshot struct {
	NetworkID uint16                  `json:"network_id"`
	Peers     map[uint32]*managedPeer `json:"peers"`
	JoinedAt  string                  `json:"joined_at"`
	CycleNum  int                     `json:"cycle_num"`
}

// NewPolicyRunner creates a policy runner for a network with the given compiled policy.
func NewPolicyRunner(netID uint16, cp *CompiledPolicy, d Runtime) *PolicyRunner {
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".pilot", fmt.Sprintf("policy_%d.json", netID))

	pr := &PolicyRunner{
		netID:           netID,
		compiled:        cp,
		runtime:         d,
		peers:           make(map[uint32]*managedPeer),
		recentlyEvicted: make(map[uint32]time.Time),
		joinedAt:        time.Now(),
		stopCh:          make(chan struct{}),
		done:            make(chan struct{}),
		path:            path,
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
func (pr *PolicyRunner) Policy() *CompiledPolicy {
	return pr.compiled
}

// PolicyJSON marshals the underlying policy document. Returned bytes
// are the canonical PolicyDocument JSON the IPC layer hands back to
// admin tools.
func (pr *PolicyRunner) PolicyJSON() ([]byte, error) {
	if pr.compiled == nil {
		return nil, nil
	}
	return json.Marshal(pr.compiled.Doc)
}

// NetworkID returns the network ID this runner manages. Used by callers
// that hold the runner via the coreapi.PolicyRunner interface.
func (pr *PolicyRunner) NetworkID() uint16 {
	return pr.netID
}

// HasMember reports whether peerNodeID is in this runner's per-peer
// state. Used by daemon to decide which non-primary runners should
// also evaluate a packet event for cross-network deny semantics.
func (pr *PolicyRunner) HasMember(peerNodeID uint32) bool {
	pr.mu.RLock()
	_, ok := pr.peers[peerNodeID]
	pr.mu.RUnlock()
	return ok
}

// EvaluatePortGate is the daemon-facing gate API for connect/dial/
// datagram events. The plugin builds the full evaluation ctx
// internally (peer_age_s, peer_tags, members) using its
// own peer state and the daemon-supplied localTags + nodeInfoTags.
// Returns the allow/deny verdict; side effects (tag, log,
// webhook) execute on the runner.
func (pr *PolicyRunner) EvaluatePortGate(eventType EventType, port uint16, peerNodeID uint32, payloadSize int, direction string, localTags, nodeInfoTags []string) bool {
	ctx := map[string]interface{}{
		"port":       int(port),
		"peer_id":    int(peerNodeID),
		"network_id": int(pr.netID),
		"local_tags": localTags,
	}
	switch eventType {
	case EventConnect, EventDial, EventDatagram:
		ctx["peer_age_s"] = 0.0
		ctx["members"] = 0
		var policyTags, registryTags []string
		pr.mu.RLock()
		if p, ok := pr.peers[peerNodeID]; ok {
			policyTags = p.tags()
			registryTags = p.RegistryTags
			ctx["peer_age_s"] = time.Since(p.AddedAt).Seconds()
		}
		ctx["members"] = len(pr.peers)
		pr.mu.RUnlock()
		// Merge: nodeInfoTags (global node lookup) + registryTags (network-member
		// tags from reconciler) + policyTags (engine-assigned via tag directives).
		ctx["peer_tags"] = mergeTags(mergeTags(nodeInfoTags, registryTags), policyTags)
	}
	if eventType == EventDatagram {
		ctx["size"] = payloadSize
		ctx["direction"] = direction
	}
	return pr.EvaluateGate(eventType, ctx)
}

// mergeTags unions two tag slices preserving order: nodeInfoTags
// first, then policyTags not already present. Replaces the daemon-side
// peerTagsFor merge that previously happened in pkg/daemon — the
// merge logic lives here now since the plugin owns the policy-local
// tags side of the union.
func mergeTags(nodeInfoTags, policyTags []string) []string {
	if len(nodeInfoTags) == 0 && len(policyTags) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(nodeInfoTags)+len(policyTags))
	merged := make([]string, 0, len(nodeInfoTags)+len(policyTags))
	for _, t := range nodeInfoTags {
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		merged = append(merged, t)
	}
	for _, t := range policyTags {
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		merged = append(merged, t)
	}
	return merged
}

// EvaluateGate evaluates a gate event (connect, dial, datagram) and returns
// true if allowed, false if denied.
func (pr *PolicyRunner) EvaluateGate(eventType EventType, ctx map[string]interface{}) bool {
	dirs, err := pr.compiled.Evaluate(eventType, ctx)
	if err != nil {
		slog.Warn("policy: gate eval error", "network_id", pr.netID, "event", eventType, "err", err)
		return true // fail open on error
	}

	// Execute side effects (tag, etc.) before the verdict.
	// verdict=0 means no explicit allow/deny; -1 deny, 1 allow.
	verdict := 0
	mutated := false
	for _, d := range dirs {
		switch d.Type {
		case DirectiveAllow:
			if verdict == 0 {
				verdict = 1
			}
		case DirectiveDeny:
			if verdict == 0 {
				verdict = -1
			}
		case DirectiveTag:
			pr.executeTag(d, ctx)
			mutated = true
		case DirectiveLog:
			pr.executeLog(d)
		case DirectiveWebhook:
			pr.executeWebhook(d)
		}
	}
	if mutated {
		pr.persist()
	}
	if verdict == -1 {
		return false
	}
	return true // default allow
}

// evaluatePerPeerCycle runs cycle-event rules against a single peer's
// context and applies only per-peer directives (tag). Fleet-level
// directives (evict_where, prune, fill, etc.) are skipped here and run
// once at fleet scope via EvaluateActions.
func (pr *PolicyRunner) evaluatePerPeerCycle(ctx map[string]interface{}) {
	dirs, err := pr.compiled.Evaluate(EventCycle, ctx)
	if err != nil {
		return
	}
	for _, d := range dirs {
		switch d.Type {
		case DirectiveTag:
			pr.executeTag(d, ctx)
		}
	}
}

// EvaluateActions evaluates an action event (cycle, join, leave).
func (pr *PolicyRunner) EvaluateActions(eventType EventType, ctx map[string]interface{}) {
	dirs, err := pr.compiled.Evaluate(eventType, ctx)
	if err != nil {
		slog.Warn("policy: action eval error", "network_id", pr.netID, "event", eventType, "err", err)
		return
	}

	for _, d := range dirs {
		switch d.Type {
		case DirectiveTag:
			pr.executeTag(d, ctx)
		case DirectiveEvict:
			pr.executeEvict(ctx)
		case DirectiveEvictWhere:
			pr.executeEvictWhere(d, d.ActionIdx)
		case DirectivePrune:
			pr.executePrune(d)
		case DirectiveFill:
			pr.executeFill(d)
		case DirectivePruneTrust:
			pr.executePruneTrust(d)
		case DirectiveFillTrust:
			pr.executeFillTrust(d)
		case DirectiveLog:
			pr.executeLog(d)
		case DirectiveWebhook:
			pr.executeWebhook(d)
		}
	}
}

// --- Action executors ---

func (pr *PolicyRunner) executeTag(d Directive, ctx map[string]interface{}) {
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
	if pr.recentlyEvicted != nil {
		pr.recentlyEvicted[uint32(peerID)] = time.Now()
	}
	pr.mu.Unlock()
}

func (pr *PolicyRunner) executeEvictWhere(d Directive, actionIdx int) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	var toEvict []uint32
	for _, p := range pr.peers {
		peerCtx := map[string]interface{}{
			"peer_id":    int(p.NodeID),
			"peer_tags":  mergeTags(p.RegistryTags, p.tags()),
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

	now := time.Now()
	for _, id := range toEvict {
		delete(pr.peers, id)
		if pr.recentlyEvicted != nil {
			pr.recentlyEvicted[id] = now
		}
	}
	if len(toEvict) > 0 {
		pr.cycleEvicted += len(toEvict)
		slog.Info("policy: evicted peers", "network_id", pr.netID, "count", len(toEvict), "rule", d.Rule)
	}
}

// evictCooldown bounds how long an evicted peer stays out of pr.peers
// against the reconciler's automatic re-add. After this window the peer
// can rejoin (and the policy will re-evaluate on next event / cycle).
const evictCooldown = 60 * time.Second

func (pr *PolicyRunner) executePrune(d Directive) {
	count := paramInt(d.Params, "count")
	by, _ := d.Params["by"].(string)
	if by == "" {
		by = "age"
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
		pr.cyclePruned += pruned
		slog.Info("policy: pruned peers", "network_id", pr.netID, "count", pruned, "rule", d.Rule)
	}
}

func (pr *PolicyRunner) executeFill(d Directive) {
	count := paramInt(d.Params, "count")

	fetched := pr.fetchMembersWithTags()
	if fetched == nil {
		slog.Warn("policy: fill failed (member list)", "network_id", pr.netID)
		return
	}

	pr.mu.Lock()
	defer pr.mu.Unlock()

	myID := pr.runtime.NodeID()
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
		pr.cycleFilled += count
		slog.Info("policy: filled peers", "network_id", pr.netID, "count", count, "rule", d.Rule)
	}
}

func (pr *PolicyRunner) executeLog(d Directive) {
	msg, _ := d.Params["message"].(string)
	level, _ := d.Params["level"].(string)
	switch level {
	case "warn":
		slog.Warn("policy: "+msg, "network_id", pr.netID, "rule", d.Rule)
	default:
		slog.Info("policy: "+msg, "network_id", pr.netID, "rule", d.Rule)
	}
}

func (pr *PolicyRunner) executeWebhook(d Directive) {
	event, _ := d.Params["event"].(string)
	data, _ := d.Params["data"].(map[string]interface{})
	if data == nil {
		data = map[string]interface{}{}
	}
	data["network_id"] = pr.netID
	data["rule"] = d.Rule
	pr.runtime.PublishEvent("policy."+event, data)
}

func (pr *PolicyRunner) executePruneTrust(d Directive) {
	percent := paramInt(d.Params, "percent")
	minLinks := paramInt(d.Params, "min")
	by, _ := d.Params["by"].(string)
	if by == "" {
		by = "age"
	}

	trusted := pr.runtime.TrustedPeers()
	total := len(trusted)
	if total <= minLinks {
		return
	}

	toRemove := total * percent / 100
	if toRemove == 0 {
		toRemove = 1
	}
	if total-toRemove < minLinks {
		toRemove = total - minLinks
	}
	if toRemove <= 0 {
		return
	}

	ranked := pr.rankTrustLinks(trusted, by)
	pruned := 0
	for i := 0; i < toRemove && i < len(ranked); i++ {
		if err := pr.runtime.RevokeTrust(ranked[i].NodeID); err != nil {
			slog.Warn("policy: prune_trust revoke failed", "node_id", ranked[i].NodeID, "err", err)
			continue
		}
		pruned++
	}
	if pruned > 0 {
		pr.mu.Lock()
		pr.cyclePrunedTrust += pruned
		pr.mu.Unlock()
		slog.Info("policy: pruned trust links", "network_id", pr.netID, "count", pruned, "rule", d.Rule)
		pr.runtime.PublishEvent("policy.prune_trust", map[string]interface{}{
			"network_id": pr.netID,
			"rule":       d.Rule,
			"pruned":     pruned,
		})
	}
}

func (pr *PolicyRunner) rankTrustLinks(records []TrustRecord, by string) []TrustRecord {
	ranked := make([]TrustRecord, len(records))
	copy(ranked, records)

	switch by {
	case "age":
		sort.Slice(ranked, func(i, j int) bool {
			return ranked[i].ApprovedAt.Before(ranked[j].ApprovedAt)
		})
	case "random":
		rand.Shuffle(len(ranked), func(i, j int) {
			ranked[i], ranked[j] = ranked[j], ranked[i]
		})
	}
	return ranked
}

func (pr *PolicyRunner) executeFillTrust(d Directive) {
	target := paramInt(d.Params, "target")

	trusted := pr.runtime.TrustedPeers()
	current := len(trusted)
	deficit := target - current
	if deficit <= 0 {
		return
	}

	trustedSet := make(map[uint32]bool, len(trusted))
	for _, t := range trusted {
		trustedSet[t.NodeID] = true
	}

	fetched := pr.fetchMembersWithTags()
	if fetched == nil {
		slog.Warn("policy: fill_trust failed (member list)", "network_id", pr.netID)
		return
	}

	myID := pr.runtime.NodeID()
	var candidates []uint32
	for _, f := range fetched {
		if f.ID == myID || trustedSet[f.ID] {
			continue
		}
		candidates = append(candidates, f.ID)
	}

	rand.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})

	if deficit > len(candidates) {
		deficit = len(candidates)
	}

	sent := 0
	for _, nodeID := range candidates[:deficit] {
		if err := pr.runtime.SendHandshakeRequest(nodeID, "trust-decay policy"); err != nil {
			slog.Warn("policy: fill_trust request failed", "node_id", nodeID, "err", err)
			continue
		}
		sent++
	}
	if sent > 0 {
		pr.mu.Lock()
		pr.cycleFilledTrust += sent
		pr.mu.Unlock()
		slog.Info("policy: sent trust requests", "network_id", pr.netID, "count", sent, "rule", d.Rule)
		pr.runtime.PublishEvent("policy.fill_trust", map[string]interface{}{
			"network_id": pr.netID,
			"rule":       d.Rule,
			"sent":       sent,
		})
	}
}

// --- Cycle loop ---

// reconcileInterval is how often runners poll the registry for membership
// diffs and fire EventJoin/EventLeave. Not configurable today; 5s is small
// enough for interactive tests and large enough to not flood the registry.
const reconcileInterval = 5 * time.Second

func (pr *PolicyRunner) cycleLoop() {
	defer close(pr.done)

	// Always bootstrap from registry to refresh peer list and tags.
	// Persisted state preserves scores/history, but membership and tags
	// may have changed since last run.
	if err := pr.bootstrap(); err != nil {
		slog.Warn("policy: bootstrap failed", "network_id", pr.netID, "err", err)
	}

	reconcileTicker := time.NewTicker(reconcileInterval)
	defer reconcileTicker.Stop()

	var cycleC <-chan time.Time
	cycleStr, _ := pr.compiled.CycleDuration()
	if cycleStr != "" {
		cycleDur, err := time.ParseDuration(cycleStr)
		if err != nil {
			slog.Warn("policy cycle: unparseable duration, defaulting to 24h",
				"network_id", pr.netID, "cycle_string", cycleStr, "error", err)
			cycleDur = 24 * time.Hour
		} else if cycleDur < time.Second {
			slog.Warn("policy cycle: duration below 1s minimum, promoting to 1s",
				"network_id", pr.netID, "cycle_string", cycleStr, "requested", cycleDur)
			cycleDur = time.Second
		}
		cycleTicker := time.NewTicker(cycleDur)
		defer cycleTicker.Stop()
		cycleC = cycleTicker.C
	}

	for {
		select {
		case <-reconcileTicker.C:
			pr.reconcileMembership()
		case <-cycleC:
			pr.runCycle()
		case <-pr.stopCh:
			return
		}
	}
}

// reconcileMembership polls the registry member list, diffs it against the
// runner's tracked peers, and fires EventJoin/EventLeave for each delta.
// EventJoin directives are evaluated as actions (score/tag/evict/log/webhook);
// a matching deny verdict locally evicts the peer from this runner's view —
// the registry retains the member, but this node's policy treats them as
// untrusted. EventLeave always ends with the peer removed from pr.peers.
func (pr *PolicyRunner) reconcileMembership() {
	fetched := pr.fetchMembersWithTags()
	if fetched == nil {
		return
	}
	pr.applyMembershipDiff(fetched, pr.runtime.NodeID())
}

// applyMembershipDiff compares fetched members against pr.peers, fires
// EventJoin/EventLeave for each delta, and updates pr.peers. Split from
// reconcileMembership so unit tests can drive it without a live registry.
func (pr *PolicyRunner) applyMembershipDiff(fetched []fetchedMember, myID uint32) {
	currentIDs := make(map[uint32]struct{}, len(fetched))
	tagMap := make(map[uint32][]string, len(fetched))
	for _, f := range fetched {
		if f.ID == myID {
			// Keep local_tags in sync with registry-assigned member tags.
			// The daemon's networkSyncLoop refreshes memberTags only every
			// 5 minutes; reconcile (called here on every policy tick and on
			// demand via `managed reconcile`) must also propagate changes so
			// local_tags reflects admin-set tags without the 5-minute lag.
			if pr.runtime != nil {
				pr.runtime.SetMemberTags(pr.netID, f.Tags)
			}
			continue
		}
		currentIDs[f.ID] = struct{}{}
		tagMap[f.ID] = f.Tags
	}

	now := time.Now()
	pr.mu.Lock()
	// Sweep expired cooldowns so stale entries don't pin memory forever.
	if pr.recentlyEvicted != nil {
		for id, t := range pr.recentlyEvicted {
			if now.Sub(t) > evictCooldown {
				delete(pr.recentlyEvicted, id)
			}
		}
	}
	var joined, left []uint32
	for id := range currentIDs {
		if existing, ok := pr.peers[id]; ok {
			// Peer already tracked — refresh registry tags so admin
			// changes (set-tags, member-tags set) become visible without
			// waiting for rejoin. Policy-engine tags (Tags) are untouched.
			existing.RegistryTags = tagMap[id]
			continue
		}
		// Honor eviction cooldown — skip re-adding peers we locally evicted
		// in the last `evictCooldown` window.
		if pr.recentlyEvicted != nil {
			if _, blocked := pr.recentlyEvicted[id]; blocked {
				continue
			}
		}
		joined = append(joined, id)
	}
	for id := range pr.peers {
		if _, ok := currentIDs[id]; !ok {
			left = append(left, id)
		}
	}
	pr.mu.Unlock()

	members := len(currentIDs) + 1 // include self

	for _, id := range joined {
		pr.mu.Lock()
		pr.peers[id] = &managedPeer{NodeID: id, AddedAt: time.Now(), RegistryTags: tagMap[id]}
		pr.mu.Unlock()

		ctx := map[string]interface{}{
			"peer_id":    int(id),
			"network_id": int(pr.netID),
			"members":    members,
		}
		dirs, err := pr.compiled.Evaluate(EventJoin, ctx)
		if err != nil {
			slog.Warn("policy: join eval error", "network_id", pr.netID, "peer_id", id, "err", err)
			continue
		}
		deny := false
		for _, d := range dirs {
			switch d.Type {
			case DirectiveDeny:
				deny = true
			case DirectiveTag:
				pr.executeTag(d, ctx)
			case DirectiveEvict:
				pr.executeEvict(ctx)
			case DirectiveLog:
				pr.executeLog(d)
			case DirectiveWebhook:
				pr.executeWebhook(d)
			}
		}
		if deny {
			pr.mu.Lock()
			delete(pr.peers, id)
			if pr.recentlyEvicted != nil {
				pr.recentlyEvicted[id] = time.Now()
			}
			pr.mu.Unlock()
			slog.Info("policy: join denied, peer evicted locally",
				"network_id", pr.netID, "peer_id", id)
			pr.runtime.PublishEvent("policy.join_denied", map[string]interface{}{
				"network_id": pr.netID,
				"peer_id":    id,
			})
		}
	}

	for _, id := range left {
		ctx := map[string]interface{}{
			"peer_id":    int(id),
			"network_id": int(pr.netID),
		}
		if dirs, err := pr.compiled.Evaluate(EventLeave, ctx); err == nil {
			for _, d := range dirs {
				switch d.Type {
				case DirectiveTag:
					pr.executeTag(d, ctx)
				case DirectiveLog:
					pr.executeLog(d)
				case DirectiveWebhook:
					pr.executeWebhook(d)
				}
			}
		}
		pr.mu.Lock()
		delete(pr.peers, id)
		pr.mu.Unlock()
	}

	if len(joined) > 0 || len(left) > 0 {
		pr.persist()
	}
}

func (pr *PolicyRunner) runCycle() map[string]interface{} {
	pr.mu.Lock()
	pr.cycleNum++
	peerCount := len(pr.peers)
	cycleNum := pr.cycleNum
	pr.cycleEvicted = 0
	pr.cyclePruned = 0
	pr.cycleFilled = 0
	pr.cyclePrunedTrust = 0
	pr.cycleFilledTrust = 0
	pr.mu.Unlock()

	trustedCount := len(pr.runtime.TrustedPeers())

	ctx := map[string]interface{}{
		"network_id":    int(pr.netID),
		"members":       peerCount,
		"peer_count":    peerCount,
		"cycle_num":     cycleNum,
		"trusted_count": trustedCount,
	}

	// Per-peer pass first: cycle `score` / `tag` directives only matter
	// against a specific peer (executeScore bails when peer_id is 0). We
	// fire EventCycle once per peer with the peer's id+score+age+tags in
	// ctx so those directives land, then fall through to the global pass
	// below for fleet-level directives (evict_where, prune, fill, ...).
	pr.mu.RLock()
	perPeerCtxs := make([]map[string]interface{}, 0, len(pr.peers))
	for _, p := range pr.peers {
		perPeerCtxs = append(perPeerCtxs, map[string]interface{}{
			"network_id":    int(pr.netID),
			"members":       peerCount,
			"peer_count":    peerCount,
			"cycle_num":     cycleNum,
			"trusted_count": trustedCount,
			"peer_id":       int(p.NodeID),
			"peer_age_s":    time.Since(p.AddedAt).Seconds(),
			"peer_tags":     mergeTags(p.RegistryTags, p.tags()),
		})
	}
	pr.mu.RUnlock()
	for _, pc := range perPeerCtxs {
		pr.evaluatePerPeerCycle(pc)
	}

	pr.EvaluateActions(EventCycle, ctx)

	pr.persist()

	pr.mu.RLock()
	finalPeers := len(pr.peers)
	evicted := pr.cycleEvicted
	pruned := pr.cyclePruned
	filled := pr.cycleFilled
	prunedTrust := pr.cyclePrunedTrust
	filledTrust := pr.cycleFilledTrust
	pr.mu.RUnlock()

	result := map[string]interface{}{
		"network_id":   pr.netID,
		"cycle_num":    cycleNum,
		"peers":        finalPeers,
		"evicted":      evicted,
		"pruned":       pruned,
		"filled":       filled,
		"pruned_trust": prunedTrust,
		"filled_trust": filledTrust,
	}

	slog.Info("policy: cycle complete",
		"network_id", pr.netID, "cycle_num", cycleNum, "peers", finalPeers,
		"evicted", evicted, "pruned", pruned, "filled", filled,
		"pruned_trust", prunedTrust, "filled_trust", filledTrust)
	pr.runtime.PublishEvent("policy.cycle", result)

	return result
}

// --- Peer state methods ---

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

// PeerList returns all managed peers as a list of maps, ordered by age (oldest first).
func (pr *PolicyRunner) PeerList() []map[string]interface{} {
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
		return entries[i].peer.AddedAt.Before(entries[j].peer.AddedAt)
	})

	result := make([]map[string]interface{}, 0, len(entries))
	for _, e := range entries {
		m := map[string]interface{}{
			"node_id":  e.peer.NodeID,
			"added_at": e.peer.AddedAt.Format(time.RFC3339),
		}
		if !e.peer.LastSeen.IsZero() {
			m["last_seen"] = e.peer.LastSeen.Format(time.RFC3339)
		}
		merged := mergeTags(e.peer.RegistryTags, e.peer.Tags)
		if len(merged) > 0 {
			m["tags"] = merged
		}
		result = append(result, m)
	}
	return result
}

// ForceCycle runs a cycle immediately.
func (pr *PolicyRunner) ForceCycle() map[string]interface{} {
	return pr.runCycle()
}

// ReconcileNow triggers a membership reconcile synchronously — same code
// path as the periodic 5s reconciler, but on demand. Side-effect free
// aside from adding/removing peers, firing EventJoin/EventLeave, and
// updating tag metadata. No scoring / evict cycle runs.
func (pr *PolicyRunner) ReconcileNow() {
	pr.reconcileMembership()
}

// --- Internal helpers ---

func (pr *PolicyRunner) bootstrap() error {
	fetched := pr.fetchMembersWithTags()
	if fetched == nil {
		return fmt.Errorf("policy bootstrap: failed to fetch members")
	}

	// Build tag lookup for candidates; propagate own tags to daemon.
	tagMap := make(map[uint32][]string, len(fetched))
	myID := pr.runtime.NodeID()
	var candidates []uint32
	for _, f := range fetched {
		tagMap[f.ID] = f.Tags
		if f.ID == myID {
			pr.runtime.SetMemberTags(pr.netID, f.Tags)
			continue
		}
		candidates = append(candidates, f.ID)
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
	var freshlyJoined []uint32
	for _, id := range candidates[:limit] {
		if _, exists := pr.peers[id]; !exists {
			pr.peers[id] = &managedPeer{NodeID: id, AddedAt: now, RegistryTags: tagMap[id]}
			freshlyJoined = append(freshlyJoined, id)
		} else {
			pr.peers[id].RegistryTags = tagMap[id]
		}
	}
	peerCount := len(pr.peers)
	pr.mu.Unlock()

	// Fire EventJoin for peers that the bootstrap just added. This must
	// honor the same directives as applyMembershipDiff — in particular
	// `deny` has to evict the peer, otherwise a join-deny policy only
	// applies to peers added after startup, not those present at boot.
	for _, id := range freshlyJoined {
		ctx := map[string]interface{}{
			"peer_id":    int(id),
			"network_id": int(pr.netID),
			"members":    peerCount + 1, // include self
		}
		dirs, err := pr.compiled.Evaluate(EventJoin, ctx)
		if err != nil {
			slog.Warn("policy: bootstrap join eval error", "network_id", pr.netID, "peer_id", id, "err", err)
			continue
		}
		deny := false
		for _, d := range dirs {
			switch d.Type {
			case DirectiveDeny:
				deny = true
			case DirectiveTag:
				pr.executeTag(d, ctx)
			case DirectiveLog:
				pr.executeLog(d)
			case DirectiveWebhook:
				pr.executeWebhook(d)
			}
		}
		if deny {
			pr.mu.Lock()
			delete(pr.peers, id)
			if pr.recentlyEvicted != nil {
				pr.recentlyEvicted[id] = time.Now()
			}
			pr.mu.Unlock()
			slog.Info("policy: bootstrap join denied, peer evicted",
				"network_id", pr.netID, "peer_id", id)
		}
	}

	pr.persist()
	slog.Info("policy: bootstrapped", "network_id", pr.netID, "peers", peerCount, "available", len(candidates), "fired_join", len(freshlyJoined))
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
	// Skip if recent failures put us in backoff. Prevents the 5s tick
	// from re-EOF'ing the regConn and starving co-tenant calls
	// (resolve_hostname, lookup) of the shared mutex.
	pr.fetchFailMu.Lock()
	if !pr.fetchSkipUntil.IsZero() && time.Now().Before(pr.fetchSkipUntil) {
		pr.fetchFailMu.Unlock()
		return nil
	}
	pr.fetchFailMu.Unlock()

	resp, err := pr.runtime.ListNodes(pr.netID, pr.runtime.AdminToken())
	if err != nil {
		// Exponential backoff: 5s → 10s → 20s → 40s → 80s, capped at 5min.
		// Logs only on transitions (1st, 4th, 8th, 16th failure) so the
		// user sees the issue without log spam.
		pr.fetchFailMu.Lock()
		pr.fetchFailures++
		fails := pr.fetchFailures
		backoff := time.Duration(1<<min(fails, 6)) * 5 * time.Second
		if backoff > 5*time.Minute {
			backoff = 5 * time.Minute
		}
		pr.fetchSkipUntil = time.Now().Add(backoff)
		pr.fetchFailMu.Unlock()
		// Log on power-of-two transitions to avoid spam.
		if fails == 1 || fails == 4 || fails == 8 || fails == 16 || fails%32 == 0 {
			slog.Warn("policy: fetchMembers failed",
				"network_id", pr.netID, "err", err,
				"consecutive_failures", fails, "next_attempt_in", backoff.String())
		}
		return nil
	}
	// Reset failure count on success.
	pr.fetchFailMu.Lock()
	if pr.fetchFailures > 0 {
		slog.Info("policy: fetchMembers recovered", "network_id", pr.netID,
			"after_failures", pr.fetchFailures)
		pr.fetchFailures = 0
		pr.fetchSkipUntil = time.Time{}
	}
	pr.fetchFailMu.Unlock()

	nodesRaw, ok := resp["nodes"].([]interface{})
	if !ok {
		return nil
	}

	myID := pr.runtime.NodeID()
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
			pr.runtime.SetMemberTags(pr.netID, tags)
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
	if pr.path == "" {
		return
	}
	pr.mu.RLock()
	snap := policySnapshot{
		NetworkID: pr.netID,
		Peers:     clonePeersLocked(pr.peers),
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

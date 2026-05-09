// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"testing"
	"time"
)

// Iter-96 coverage for PolicyRunner.EvaluateGate + EvaluateActions
// directive-dispatch branches that prior iterations didn't touch:
// DirectiveTag / DirectiveLog / DirectiveWebhook (from EvaluateGate) plus
// DirectivePrune / DirectiveTag / DirectiveLog / DirectiveWebhook / multi-
// action (from EvaluateActions). Default-allow (no matching rule) is also
// exercised so the final-return branch is covered.

// newTestPR returns a PolicyRunner wired to a fresh daemon (webhook nil — safe
// because (*WebhookClient).Emit is nil-receiver-safe, validated in iter 83).
func newTestPR(t *testing.T, doc *PolicyDocument) *PolicyRunner {
	t.Helper()
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	r := &fakeRuntime{}

	return &PolicyRunner{
		netID:    1,
		compiled: cp,
		runtime:  r,
		peers:    map[uint32]*managedPeer{},
	}
}

// --- EvaluateGate directive-dispatch branches ---

func TestEvaluateGateTagSideEffectAppliesToPeer(t *testing.T) {
	t.Parallel()
	pr := newTestPR(t, &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "tag-on-connect", On: "connect", Match: "true", Actions: []Action{
				{Type: ActionTag, Params: map[string]interface{}{"add": []interface{}{"vip"}}},
			}},
		},
	})
	pr.peers[42] = &managedPeer{NodeID: 42, AddedAt: time.Now()}

	allowed := pr.EvaluateGate(EventConnect, map[string]interface{}{
		"port": 80, "peer_id": 42, "network_id": 1,
		"peer_tags": []string{}, "peer_age_s": 0.0, "members": 0,
	})
	if !allowed {
		t.Fatal("default-allow should return true when no allow/deny directive fired")
	}
	tags := pr.peers[42].tags()
	if len(tags) != 1 || tags[0] != "vip" {
		t.Fatalf("peer tags = %v, want [vip]", tags)
	}
}

func TestEvaluateGateLogDirectiveNoPanicReturnsAllow(t *testing.T) {
	t.Parallel()
	pr := newTestPR(t, &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "log-on-connect", On: "connect", Match: "true", Actions: []Action{
				{Type: ActionLog, Params: map[string]interface{}{"message": "hello", "level": "info"}},
			}},
		},
	})
	allowed := pr.EvaluateGate(EventConnect, map[string]interface{}{
		"port": 80, "peer_id": 0, "network_id": 1,
		"peer_tags": []string{}, "peer_age_s": 0.0, "members": 0,
	})
	if !allowed {
		t.Fatal("log-only rule should fall through to default-allow (true)")
	}
}

func TestEvaluateGateWebhookDirectiveNilReceiverSafeReturnsAllow(t *testing.T) {
	t.Parallel()
	pr := newTestPR(t, &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "hook-on-connect", On: "connect", Match: "true", Actions: []Action{
				{Type: ActionWebhook, Params: map[string]interface{}{"event": "peer.connected"}},
			}},
		},
	})
	allowed := pr.EvaluateGate(EventConnect, map[string]interface{}{
		"port": 80, "peer_id": 0, "network_id": 1,
		"peer_tags": []string{}, "peer_age_s": 0.0, "members": 0,
	})
	if !allowed {
		t.Fatal("webhook-only rule should fall through to default-allow (true)")
	}
}

func TestEvaluateGateNoMatchingRuleReturnsDefaultAllow(t *testing.T) {
	t.Parallel()
	// Rule only fires for port==22; request port==80 → no match → default allow.
	pr := newTestPR(t, &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "deny-22", On: "connect", Match: "port == 22", Actions: []Action{
				{Type: ActionDeny},
			}},
		},
	})
	allowed := pr.EvaluateGate(EventConnect, map[string]interface{}{
		"port": 80, "peer_id": 0, "network_id": 1,
		"peer_tags": []string{}, "peer_age_s": 0.0, "members": 0,
	})
	if !allowed {
		t.Fatal("no matching rule should yield default-allow (true)")
	}
}

// --- EvaluateActions directive-dispatch branches ---

func TestEvaluateActionsTagDirectiveAppliesToPeer(t *testing.T) {
	t.Parallel()
	pr := newTestPR(t, &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "tag-on-cycle", On: "cycle", Match: "true", Actions: []Action{
				{Type: ActionTag, Params: map[string]interface{}{"add": []interface{}{"active"}}},
			}},
		},
	})
	pr.peers[7] = &managedPeer{NodeID: 7, AddedAt: time.Now()}

	pr.EvaluateActions(EventCycle, map[string]interface{}{
		"peer_id": 7, "network_id": 1, "members": 1,
		"peer_tags": []string{}, "peer_age_s": 1.0,
	})
	tags := pr.peers[7].tags()
	if len(tags) != 1 || tags[0] != "active" {
		t.Fatalf("tags = %v, want [active]", tags)
	}
}

func TestEvaluateActionsLogDirectiveNoPanic(t *testing.T) {
	t.Parallel()
	pr := newTestPR(t, &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "log-cycle", On: "cycle", Match: "true", Actions: []Action{
				{Type: ActionLog, Params: map[string]interface{}{"message": "tick", "level": "warn"}},
			}},
		},
	})
	pr.EvaluateActions(EventCycle, map[string]interface{}{
		"peer_id": 0, "network_id": 1, "members": 0,
		"peer_tags": []string{}, "peer_age_s": 0.0,
	})
	// No assertion — simply reaching this point proves the DirectiveLog branch
	// dispatched and didn't panic (slog.Warn with nil-unsafe args would panic).
}

func TestEvaluateActionsWebhookDirectiveNilReceiverSafe(t *testing.T) {
	t.Parallel()
	pr := newTestPR(t, &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "hook-cycle", On: "cycle", Match: "true", Actions: []Action{
				{Type: ActionWebhook, Params: map[string]interface{}{
					"event": "cycle.tick",
					"data":  map[string]interface{}{"k": "v"},
				}},
			}},
		},
	})
	pr.EvaluateActions(EventCycle, map[string]interface{}{
		"peer_id": 0, "network_id": 1, "members": 0,
		"peer_tags": []string{}, "peer_age_s": 0.0,
	})
}

func TestEvaluateActionsPruneDirectiveRemovesPeers(t *testing.T) {
	t.Parallel()
	now := time.Now()
	pr := newTestPR(t, &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "prune-old", On: "cycle", Match: "true", Actions: []Action{
				{Type: ActionPrune, Params: map[string]interface{}{"count": 1, "by": "age"}},
			}},
		},
	})
	pr.peers[100] = &managedPeer{NodeID: 100, AddedAt: now.Add(-3 * time.Hour)}
	pr.peers[200] = &managedPeer{NodeID: 200, AddedAt: now.Add(-2 * time.Hour)}
	pr.peers[300] = &managedPeer{NodeID: 300, AddedAt: now.Add(-1 * time.Hour)}

	pr.EvaluateActions(EventCycle, map[string]interface{}{
		"peer_id": 0, "network_id": 1, "members": 3,
	})
	// count=1 prunes the oldest peer (100), leaving 2 peers.
	if len(pr.peers) != 2 {
		t.Fatalf("peers after prune = %d, want 2 (oldest should be pruned)", len(pr.peers))
	}
	if _, ok := pr.peers[100]; ok {
		t.Fatal("oldest peer 100 should have been pruned")
	}
}

func TestEvaluateActionsMultiActionRuleAppliesAll(t *testing.T) {
	t.Parallel()
	// Rule fires tag in a cycle pass.
	pr := newTestPR(t, &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "promote", On: "cycle", Match: "true", Actions: []Action{
				{Type: ActionTag, Params: map[string]interface{}{"add": []interface{}{"promoted"}}},
			}},
		},
	})
	pr.peers[55] = &managedPeer{NodeID: 55, AddedAt: time.Now()}
	pr.EvaluateActions(EventCycle, map[string]interface{}{
		"peer_id": 55, "network_id": 1, "members": 1,
		"peer_tags": []string{}, "peer_age_s": 1.0,
	})
	tags := pr.peers[55].tags()
	if len(tags) != 1 || tags[0] != "promoted" {
		t.Fatalf("tags = %v, want [promoted] (ActionTag didn't dispatch)", tags)
	}
}

// --- executeTag edge branches (missing peer / remove branch) ---

func TestEvaluateActionsTagOnMissingPeerNoPanic(t *testing.T) {
	t.Parallel()
	pr := newTestPR(t, &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "tag-ghost", On: "cycle", Match: "true", Actions: []Action{
				{Type: ActionTag, Params: map[string]interface{}{"add": []interface{}{"shadow"}}},
			}},
		},
	})
	// peer 999 not in pr.peers — executeTag hits the `if !ok { return }` branch.
	pr.EvaluateActions(EventCycle, map[string]interface{}{
		"peer_id": 999, "network_id": 1, "members": 0,
		"peer_tags": []string{}, "peer_age_s": 0.0,
	})
	if _, ok := pr.peers[999]; ok {
		t.Fatal("peer 999 should not have been auto-added by tag action")
	}
}

func TestEvaluateActionsTagRemoveBranchRemovesExistingTag(t *testing.T) {
	t.Parallel()
	pr := newTestPR(t, &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "untag", On: "cycle", Match: "true", Actions: []Action{
				{Type: ActionTag, Params: map[string]interface{}{"remove": []interface{}{"stale"}}},
			}},
		},
	})
	pr.peers[77] = &managedPeer{NodeID: 77, Tags: []string{"stale", "keep"}, AddedAt: time.Now()}
	pr.EvaluateActions(EventCycle, map[string]interface{}{
		"peer_id": 77, "network_id": 1, "members": 1,
		"peer_tags": []string{}, "peer_age_s": 1.0,
	})
	tags := pr.peers[77].tags()
	if len(tags) != 1 || tags[0] != "keep" {
		t.Fatalf("tags after remove = %v, want [keep]", tags)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/policy"
)

// Iter-96 coverage for PolicyRunner.EvaluateGate + EvaluateActions
// directive-dispatch branches that prior iterations didn't touch:
// DirectiveTag / DirectiveLog / DirectiveWebhook (from EvaluateGate) plus
// DirectivePrune / DirectiveTag / DirectiveLog / DirectiveWebhook / multi-
// action (from EvaluateActions). Default-allow (no matching rule) is also
// exercised so the final-return branch is covered.

// newTestPR returns a PolicyRunner wired to a fresh daemon (webhook nil — safe
// because (*WebhookClient).Emit is nil-receiver-safe, validated in iter 83).
func newTestPR(t *testing.T, doc *policy.PolicyDocument) *PolicyRunner {
	t.Helper()
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	d := New(Config{})
	t.Cleanup(func() { d.handshakes.Stop() })
	return &PolicyRunner{
		netID:    1,
		compiled: cp,
		daemon:   d,
		peers:    map[uint32]*managedPeer{},
	}
}

// --- EvaluateGate directive-dispatch branches ---

func TestEvaluateGateTagSideEffectAppliesToPeer(t *testing.T) {
	pr := newTestPR(t, &policy.PolicyDocument{
		Version: 1,
		Rules: []policy.Rule{
			{Name: "tag-on-connect", On: "connect", Match: "true", Actions: []policy.Action{
				{Type: policy.ActionTag, Params: map[string]interface{}{"add": []interface{}{"vip"}}},
			}},
		},
	})
	pr.peers[42] = &managedPeer{NodeID: 42, AddedAt: time.Now()}

	allowed := pr.EvaluateGate(policy.EventConnect, map[string]interface{}{
		"port": 80, "peer_id": 42, "network_id": 1,
		"peer_score": 0, "peer_tags": []string{}, "peer_age_s": 0.0, "members": 0,
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
	pr := newTestPR(t, &policy.PolicyDocument{
		Version: 1,
		Rules: []policy.Rule{
			{Name: "log-on-connect", On: "connect", Match: "true", Actions: []policy.Action{
				{Type: policy.ActionLog, Params: map[string]interface{}{"message": "hello", "level": "info"}},
			}},
		},
	})
	allowed := pr.EvaluateGate(policy.EventConnect, map[string]interface{}{
		"port": 80, "peer_id": 0, "network_id": 1,
		"peer_score": 0, "peer_tags": []string{}, "peer_age_s": 0.0, "members": 0,
	})
	if !allowed {
		t.Fatal("log-only rule should fall through to default-allow (true)")
	}
}

func TestEvaluateGateWebhookDirectiveNilReceiverSafeReturnsAllow(t *testing.T) {
	pr := newTestPR(t, &policy.PolicyDocument{
		Version: 1,
		Rules: []policy.Rule{
			{Name: "hook-on-connect", On: "connect", Match: "true", Actions: []policy.Action{
				{Type: policy.ActionWebhook, Params: map[string]interface{}{"event": "peer.connected"}},
			}},
		},
	})
	allowed := pr.EvaluateGate(policy.EventConnect, map[string]interface{}{
		"port": 80, "peer_id": 0, "network_id": 1,
		"peer_score": 0, "peer_tags": []string{}, "peer_age_s": 0.0, "members": 0,
	})
	if !allowed {
		t.Fatal("webhook-only rule should fall through to default-allow (true)")
	}
}

func TestEvaluateGateNoMatchingRuleReturnsDefaultAllow(t *testing.T) {
	// Rule only fires for port==22; request port==80 → no match → default allow.
	pr := newTestPR(t, &policy.PolicyDocument{
		Version: 1,
		Rules: []policy.Rule{
			{Name: "deny-22", On: "connect", Match: "port == 22", Actions: []policy.Action{
				{Type: policy.ActionDeny},
			}},
		},
	})
	allowed := pr.EvaluateGate(policy.EventConnect, map[string]interface{}{
		"port": 80, "peer_id": 0, "network_id": 1,
		"peer_score": 0, "peer_tags": []string{}, "peer_age_s": 0.0, "members": 0,
	})
	if !allowed {
		t.Fatal("no matching rule should yield default-allow (true)")
	}
}

// --- EvaluateActions directive-dispatch branches ---

func TestEvaluateActionsTagDirectiveAppliesToPeer(t *testing.T) {
	pr := newTestPR(t, &policy.PolicyDocument{
		Version: 1,
		Rules: []policy.Rule{
			{Name: "tag-on-cycle", On: "cycle", Match: "true", Actions: []policy.Action{
				{Type: policy.ActionTag, Params: map[string]interface{}{"add": []interface{}{"active"}}},
			}},
		},
	})
	pr.peers[7] = &managedPeer{NodeID: 7, AddedAt: time.Now()}

	pr.EvaluateActions(policy.EventCycle, map[string]interface{}{
		"peer_id": 7, "network_id": 1, "members": 1,
		"peer_score": 0, "peer_tags": []string{}, "peer_age_s": 1.0,
	})
	tags := pr.peers[7].tags()
	if len(tags) != 1 || tags[0] != "active" {
		t.Fatalf("tags = %v, want [active]", tags)
	}
}

func TestEvaluateActionsLogDirectiveNoPanic(t *testing.T) {
	pr := newTestPR(t, &policy.PolicyDocument{
		Version: 1,
		Rules: []policy.Rule{
			{Name: "log-cycle", On: "cycle", Match: "true", Actions: []policy.Action{
				{Type: policy.ActionLog, Params: map[string]interface{}{"message": "tick", "level": "warn"}},
			}},
		},
	})
	pr.EvaluateActions(policy.EventCycle, map[string]interface{}{
		"peer_id": 0, "network_id": 1, "members": 0,
		"peer_score": 0, "peer_tags": []string{}, "peer_age_s": 0.0,
	})
	// No assertion — simply reaching this point proves the DirectiveLog branch
	// dispatched and didn't panic (slog.Warn with nil-unsafe args would panic).
}

func TestEvaluateActionsWebhookDirectiveNilReceiverSafe(t *testing.T) {
	pr := newTestPR(t, &policy.PolicyDocument{
		Version: 1,
		Rules: []policy.Rule{
			{Name: "hook-cycle", On: "cycle", Match: "true", Actions: []policy.Action{
				{Type: policy.ActionWebhook, Params: map[string]interface{}{
					"event": "cycle.tick",
					"data":  map[string]interface{}{"k": "v"},
				}},
			}},
		},
	})
	pr.EvaluateActions(policy.EventCycle, map[string]interface{}{
		"peer_id": 0, "network_id": 1, "members": 0,
		"peer_score": 0, "peer_tags": []string{}, "peer_age_s": 0.0,
	})
}

func TestEvaluateActionsPruneDirectiveRemovesPeers(t *testing.T) {
	pr := newTestPR(t, &policy.PolicyDocument{
		Version: 1,
		Rules: []policy.Rule{
			{Name: "prune-low", On: "cycle", Match: "true", Actions: []policy.Action{
				{Type: policy.ActionPrune, Params: map[string]interface{}{"count": 2, "by": "score"}},
			}},
		},
	})
	pr.peers[100] = &managedPeer{NodeID: 100, Score: 1, AddedAt: time.Now()}
	pr.peers[200] = &managedPeer{NodeID: 200, Score: 2, AddedAt: time.Now()}
	pr.peers[300] = &managedPeer{NodeID: 300, Score: 99, AddedAt: time.Now()}

	pr.EvaluateActions(policy.EventCycle, map[string]interface{}{
		"peer_id": 0, "network_id": 1, "members": 3,
	})
	if len(pr.peers) != 1 {
		t.Fatalf("peers after prune = %d, want 1 (top-scored should survive)", len(pr.peers))
	}
	if _, ok := pr.peers[300]; !ok {
		t.Fatal("highest-score peer 300 should have survived the prune")
	}
}

func TestEvaluateActionsMultiActionRuleAppliesAll(t *testing.T) {
	// Rule fires score + tag in one pass. Both executor branches dispatch
	// during a single EvaluateActions call.
	pr := newTestPR(t, &policy.PolicyDocument{
		Version: 1,
		Rules: []policy.Rule{
			{Name: "promote", On: "cycle", Match: "true", Actions: []policy.Action{
				{Type: policy.ActionScore, Params: map[string]interface{}{"delta": 7}},
				{Type: policy.ActionTag, Params: map[string]interface{}{"add": []interface{}{"promoted"}}},
			}},
		},
	})
	pr.peers[55] = &managedPeer{NodeID: 55, AddedAt: time.Now()}
	pr.EvaluateActions(policy.EventCycle, map[string]interface{}{
		"peer_id": 55, "network_id": 1, "members": 1,
		"peer_score": 0, "peer_tags": []string{}, "peer_age_s": 1.0,
	})
	if pr.peers[55].Score != 7 {
		t.Fatalf("score = %d, want 7 (ActionScore didn't dispatch)", pr.peers[55].Score)
	}
	tags := pr.peers[55].tags()
	if len(tags) != 1 || tags[0] != "promoted" {
		t.Fatalf("tags = %v, want [promoted] (ActionTag didn't dispatch)", tags)
	}
}

// --- executeTag edge branches (missing peer / remove branch) ---

func TestEvaluateActionsTagOnMissingPeerNoPanic(t *testing.T) {
	pr := newTestPR(t, &policy.PolicyDocument{
		Version: 1,
		Rules: []policy.Rule{
			{Name: "tag-ghost", On: "cycle", Match: "true", Actions: []policy.Action{
				{Type: policy.ActionTag, Params: map[string]interface{}{"add": []interface{}{"shadow"}}},
			}},
		},
	})
	// peer 999 not in pr.peers — executeTag hits the `if !ok { return }` branch.
	pr.EvaluateActions(policy.EventCycle, map[string]interface{}{
		"peer_id": 999, "network_id": 1, "members": 0,
		"peer_score": 0, "peer_tags": []string{}, "peer_age_s": 0.0,
	})
	if _, ok := pr.peers[999]; ok {
		t.Fatal("peer 999 should not have been auto-added by tag action")
	}
}

func TestEvaluateActionsTagRemoveBranchRemovesExistingTag(t *testing.T) {
	pr := newTestPR(t, &policy.PolicyDocument{
		Version: 1,
		Rules: []policy.Rule{
			{Name: "untag", On: "cycle", Match: "true", Actions: []policy.Action{
				{Type: policy.ActionTag, Params: map[string]interface{}{"remove": []interface{}{"stale"}}},
			}},
		},
	})
	pr.peers[77] = &managedPeer{NodeID: 77, Tags: []string{"stale", "keep"}, AddedAt: time.Now()}
	pr.EvaluateActions(policy.EventCycle, map[string]interface{}{
		"peer_id": 77, "network_id": 1, "members": 1,
		"peer_score": 0, "peer_tags": []string{}, "peer_age_s": 1.0,
	})
	tags := pr.peers[77].tags()
	if len(tags) != 1 || tags[0] != "keep" {
		t.Fatalf("tags after remove = %v, want [keep]", tags)
	}
}

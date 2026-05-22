// SPDX-License-Identifier: AGPL-3.0-or-later

package policy_test

import (
	"encoding/json"
	"testing"

	registry "github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
	policy "github.com/pilot-protocol/policy/policylang"
)

func TestParseValidPolicy(t *testing.T) {
	t.Parallel()
	raw := `{
		"version": 1,
		"rules": [
			{"name": "r1", "on": "connect", "match": "port == 80", "actions": [{"type": "allow"}]}
		]
	}`
	doc, err := policy.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version != 1 {
		t.Fatalf("version = %d, want 1", doc.Version)
	}
	if len(doc.Rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(doc.Rules))
	}
}

func TestParseInvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := policy.Parse([]byte(`{bad json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestValidateVersionMismatch(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 99, Rules: []policy.Rule{{Name: "r", On: "connect", Match: "true", Actions: []policy.Action{{Type: policy.ActionAllow}}}}}
	if err := policy.Validate(doc); err == nil {
		t.Fatal("expected error for version mismatch")
	}
}

func TestValidateNoRules(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{}}
	if err := policy.Validate(doc); err == nil {
		t.Fatal("expected error for empty rules")
	}
}

func TestValidateDuplicateNames(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "dup", On: "connect", Match: "true", Actions: []policy.Action{{Type: policy.ActionAllow}}},
		{Name: "dup", On: "connect", Match: "true", Actions: []policy.Action{{Type: policy.ActionDeny}}},
	}}
	if err := policy.Validate(doc); err == nil {
		t.Fatal("expected error for duplicate rule names")
	}
}

func TestValidateUnknownEventType(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "r", On: "unknown", Match: "true", Actions: []policy.Action{{Type: policy.ActionAllow}}},
	}}
	if err := policy.Validate(doc); err == nil {
		t.Fatal("expected error for unknown event type")
	}
}

func TestValidateEmptyMatch(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "r", On: "connect", Match: "", Actions: []policy.Action{{Type: policy.ActionAllow}}},
	}}
	if err := policy.Validate(doc); err == nil {
		t.Fatal("expected error for empty match")
	}
}

func TestValidateNoActions(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "r", On: "connect", Match: "true", Actions: []policy.Action{}},
	}}
	if err := policy.Validate(doc); err == nil {
		t.Fatal("expected error for empty actions")
	}
}

func TestValidateUnknownAction(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "r", On: "connect", Match: "true", Actions: []policy.Action{{Type: "teleport"}}},
	}}
	if err := policy.Validate(doc); err == nil {
		t.Fatal("expected error for unknown action")
	}
}

func TestValidateCycleConfig(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{
		Version: 1,
		Config:  map[string]interface{}{"cycle": "500ms"},
		Rules:   []policy.Rule{{Name: "r", On: "cycle", Match: "true", Actions: []policy.Action{{Type: policy.ActionLog, Params: map[string]interface{}{"message": "tick"}}}}},
	}
	if err := policy.Validate(doc); err == nil {
		t.Fatal("expected error for cycle < 1s")
	}

	doc.Config["cycle"] = "5s"
	if err := policy.Validate(doc); err != nil {
		t.Fatalf("unexpected error for valid cycle: %v", err)
	}
}

// --- Compile tests ---

func TestCompileValidPolicy(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "allow-80", On: "connect", Match: "port == 80", Actions: []policy.Action{{Type: policy.ActionAllow}}},
		{Name: "deny-all", On: "connect", Match: "true", Actions: []policy.Action{{Type: policy.ActionDeny}}},
	}}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}
	if cp.RuleCount() != 2 {
		t.Fatalf("compiled rules = %d, want 2", cp.RuleCount())
	}
}

func TestCompileBadExpression(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "bad", On: "connect", Match: "port %%% invalid", Actions: []policy.Action{{Type: policy.ActionAllow}}},
	}}
	_, err := policy.Compile(doc)
	if err == nil {
		t.Fatal("expected compile error for invalid expression")
	}
}

func TestCompileEvictWhereSubExpression(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "evict-bad", On: "cycle", Match: "true", Actions: []policy.Action{
			{Type: policy.ActionEvictWhere, Params: map[string]interface{}{"match": "peer_age_s > 100"}},
		}},
	}}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}
	if cp.PeerProgramCount() != 1 {
		t.Fatalf("peerPrograms = %d, want 1", cp.PeerProgramCount())
	}
}

// --- Evaluate gate tests ---

func TestEvaluateGateAllow(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "allow-80", On: "connect", Match: "port == 80", Actions: []policy.Action{{Type: policy.ActionAllow}}},
		{Name: "deny-all", On: "connect", Match: "true", Actions: []policy.Action{{Type: policy.ActionDeny}}},
	}}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	dirs, err := cp.Evaluate(policy.EventConnect, map[string]interface{}{
		"port":       80,
		"peer_id":    1234,
		"network_id": 1,
		"peer_tags":  []string{},
		"peer_age_s": 0.0,
		"members":    10,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(dirs) == 0 {
		t.Fatal("expected at least one directive")
	}
	last := dirs[len(dirs)-1]
	if last.Type != policy.DirectiveAllow {
		t.Fatalf("verdict = %d, want DirectiveAllow", last.Type)
	}
	if last.Rule != "allow-80" {
		t.Fatalf("rule = %q, want 'allow-80'", last.Rule)
	}
}

func TestEvaluateGateDeny(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "allow-80", On: "connect", Match: "port == 80", Actions: []policy.Action{{Type: policy.ActionAllow}}},
		{Name: "deny-all", On: "connect", Match: "true", Actions: []policy.Action{{Type: policy.ActionDeny}}},
	}}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	dirs, err := cp.Evaluate(policy.EventConnect, map[string]interface{}{
		"port":       443,
		"peer_id":    1234,
		"network_id": 1,
		"peer_tags":  []string{},
		"peer_age_s": 0.0,
		"members":    10,
	})
	if err != nil {
		t.Fatal(err)
	}

	verdict := findVerdict(dirs)
	if verdict == nil {
		t.Fatal("expected verdict")
	}
	if verdict.Type != policy.DirectiveDeny {
		t.Fatalf("verdict = %d, want DirectiveDeny", verdict.Type)
	}
}

func TestValidateDefaultVerdictInvalid(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{
		Version:        1,
		DefaultVerdict: "maybe",
		Rules: []policy.Rule{
			{Name: "r", On: "connect", Match: "true", Actions: []policy.Action{{Type: policy.ActionAllow}}},
		},
	}
	if err := policy.Validate(doc); err == nil {
		t.Fatal("expected error for invalid default_verdict")
	}
}

func TestEvaluateGateDefaultDeny(t *testing.T) {
	t.Parallel()
	// No rules match, default_verdict=deny → default deny
	doc := &policy.PolicyDocument{
		Version:        1,
		DefaultVerdict: "deny",
		Rules: []policy.Rule{
			{Name: "allow-80", On: "connect", Match: "port == 80", Actions: []policy.Action{{Type: policy.ActionAllow}}},
		},
	}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	dirs, err := cp.Evaluate(policy.EventConnect, map[string]interface{}{
		"port":       999,
		"peer_id":    1,
		"network_id": 1,
		"peer_tags":  []string{},
		"peer_age_s": 0.0,
		"members":    1,
	})
	if err != nil {
		t.Fatal(err)
	}

	verdict := findVerdict(dirs)
	if verdict == nil {
		t.Fatal("expected default verdict")
	}
	if verdict.Type != policy.DirectiveDeny {
		t.Fatalf("verdict = %d, want DirectiveDeny (default-deny)", verdict.Type)
	}
	if verdict.Rule != "_default" {
		t.Fatalf("rule = %q, want '_default'", verdict.Rule)
	}
}

func TestEvaluateGateDefaultAllow(t *testing.T) {
	t.Parallel()
	// No rules match → default allow
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "allow-80", On: "connect", Match: "port == 80", Actions: []policy.Action{{Type: policy.ActionAllow}}},
	}}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	dirs, err := cp.Evaluate(policy.EventConnect, map[string]interface{}{
		"port":       999,
		"peer_id":    1,
		"network_id": 1,
		"peer_tags":  []string{},
		"peer_age_s": 0.0,
		"members":    1,
	})
	if err != nil {
		t.Fatal(err)
	}

	verdict := findVerdict(dirs)
	if verdict == nil {
		t.Fatal("expected default verdict")
	}
	if verdict.Type != policy.DirectiveAllow {
		t.Fatalf("verdict = %d, want DirectiveAllow (default)", verdict.Type)
	}
	if verdict.Rule != "_default" {
		t.Fatalf("rule = %q, want '_default'", verdict.Rule)
	}
}

func TestEvaluateGateSideEffectsBeforeVerdict(t *testing.T) {
	t.Parallel()
	// A tag action before a deny verdict: both should be returned
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "track", On: "connect", Match: "true", Actions: []policy.Action{
			{Type: policy.ActionTag, Params: map[string]interface{}{"add": []interface{}{"seen"}}},
		}},
		{Name: "deny-all", On: "connect", Match: "true", Actions: []policy.Action{{Type: policy.ActionDeny}}},
	}}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	dirs, err := cp.Evaluate(policy.EventConnect, map[string]interface{}{
		"port":       80,
		"peer_id":    1,
		"network_id": 1,
		"peer_tags":  []string{},
		"peer_age_s": 0.0,
		"members":    1,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(dirs) != 2 {
		t.Fatalf("directives = %d, want 2 (tag + deny)", len(dirs))
	}
	if dirs[0].Type != policy.DirectiveTag {
		t.Fatalf("dirs[0] = %v, want DirectiveTag", dirs[0].Type)
	}
	if dirs[1].Type != policy.DirectiveDeny {
		t.Fatalf("dirs[1] = %v, want DirectiveDeny", dirs[1].Type)
	}
}

func TestEvaluateGatePortIn(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "allow-ports", On: "connect", Match: "port in [80, 443, 1001]", Actions: []policy.Action{{Type: policy.ActionAllow}}},
		{Name: "deny-rest", On: "connect", Match: "true", Actions: []policy.Action{{Type: policy.ActionDeny}}},
	}}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	ctx := func(port int) map[string]interface{} {
		return map[string]interface{}{
			"port": port, "peer_id": 1, "network_id": 1,
			"peer_tags": []string{}, "peer_age_s": 0.0, "members": 1,
		}
	}

	for _, port := range []int{80, 443, 1001} {
		dirs, err := cp.Evaluate(policy.EventConnect, ctx(port))
		if err != nil {
			t.Fatalf("port %d: %v", port, err)
		}
		v := findVerdict(dirs)
		if v.Type != policy.DirectiveAllow {
			t.Fatalf("port %d: verdict = %d, want allow", port, v.Type)
		}
	}

	for _, port := range []int{22, 8080, 1002} {
		dirs, err := cp.Evaluate(policy.EventConnect, ctx(port))
		if err != nil {
			t.Fatalf("port %d: %v", port, err)
		}
		v := findVerdict(dirs)
		if v.Type != policy.DirectiveDeny {
			t.Fatalf("port %d: verdict = %d, want deny", port, v.Type)
		}
	}
}

// --- Evaluate action tests ---

func TestEvaluateActionsCycleEvent(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "prune-fill", On: "cycle", Match: "true", Actions: []policy.Action{
			{Type: policy.ActionPrune, Params: map[string]interface{}{"count": 10, "by": "score"}},
			{Type: policy.ActionFill, Params: map[string]interface{}{"count": 10, "how": "random"}},
		}},
		{Name: "evict-bad", On: "cycle", Match: "peer_count > 5", Actions: []policy.Action{
			{Type: policy.ActionEvictWhere, Params: map[string]interface{}{"match": "peer_age_s > 100"}},
		}},
	}}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	ctx := map[string]interface{}{
		"network_id": 1,
		"members":    20,
		"peer_count": 10,
		"cycle_num":  1,
	}
	dirs, err := cp.Evaluate(policy.EventCycle, ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Both rules match: prune + fill + evict_where = 3 directives
	if len(dirs) != 3 {
		t.Fatalf("directives = %d, want 3", len(dirs))
	}
	if dirs[0].Type != policy.DirectivePrune {
		t.Fatalf("dirs[0] = %d, want Prune", dirs[0].Type)
	}
	if dirs[1].Type != policy.DirectiveFill {
		t.Fatalf("dirs[1] = %d, want Fill", dirs[1].Type)
	}
	if dirs[2].Type != policy.DirectiveEvictWhere {
		t.Fatalf("dirs[2] = %d, want EvictWhere", dirs[2].Type)
	}
}

func TestEvaluateActionsNoMatch(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "r1", On: "cycle", Match: "peer_count > 100", Actions: []policy.Action{
			{Type: policy.ActionPrune, Params: map[string]interface{}{"count": 5, "by": "score"}},
		}},
	}}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	dirs, err := cp.Evaluate(policy.EventCycle, map[string]interface{}{
		"network_id": 1, "members": 5, "peer_count": 3, "cycle_num": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) != 0 {
		t.Fatalf("directives = %d, want 0", len(dirs))
	}
}

func TestEvaluateDatagramEvent(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "allow-data", On: "datagram", Match: "port == 1001 && size > 0", Actions: []policy.Action{{Type: policy.ActionAllow}}},
		{Name: "deny-rest", On: "datagram", Match: "true", Actions: []policy.Action{{Type: policy.ActionDeny}}},
	}}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	// Allowed: port 1001 with data
	dirs, err := cp.Evaluate(policy.EventDatagram, map[string]interface{}{
		"port": 1001, "peer_id": 1, "network_id": 1, "size": 100, "direction": "in",
	})
	if err != nil {
		t.Fatal(err)
	}
	v := findVerdict(dirs)
	if v.Type != policy.DirectiveAllow {
		t.Fatalf("datagram 1001: verdict = %d, want allow", v.Type)
	}

	// Denied: port 80
	dirs, err = cp.Evaluate(policy.EventDatagram, map[string]interface{}{
		"port": 80, "peer_id": 1, "network_id": 1, "size": 100, "direction": "in",
	})
	if err != nil {
		t.Fatal(err)
	}
	v = findVerdict(dirs)
	if v.Type != policy.DirectiveDeny {
		t.Fatalf("datagram 80: verdict = %d, want deny", v.Type)
	}
}

// --- EvaluatePeerExpr tests ---

func TestEvaluatePeerExpr(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "evict-old", On: "cycle", Match: "true", Actions: []policy.Action{
			{Type: policy.ActionEvictWhere, Params: map[string]interface{}{"match": "peer_age_s > 100"}},
		}},
	}}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	// Old peer: should match
	ok, err := cp.EvaluatePeerExpr("evict-old", 0, map[string]interface{}{
		"peer_id": 1, "peer_tags": []string{}, "peer_age_s": 200.0, "last_seen": 0.0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected peer with age 200 to match evict_where")
	}

	// Young peer: should not match
	ok, err = cp.EvaluatePeerExpr("evict-old", 0, map[string]interface{}{
		"peer_id": 2, "peer_tags": []string{}, "peer_age_s": 10.0, "last_seen": 0.0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected peer with age 10 to NOT match evict_where")
	}
}

// --- Custom function tests ---

func TestHasTag(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "allow-elite", On: "connect", Match: `has_tag(peer_tags, "elite")`, Actions: []policy.Action{{Type: policy.ActionAllow}}},
		{Name: "deny-rest", On: "connect", Match: "true", Actions: []policy.Action{{Type: policy.ActionDeny}}},
	}}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	ctx := func(tags []string) map[string]interface{} {
		return map[string]interface{}{
			"port": 80, "peer_id": 1, "network_id": 1,
			"peer_tags": tags, "peer_age_s": 0.0, "members": 1,
		}
	}

	dirs, _ := cp.Evaluate(policy.EventConnect, ctx([]string{"elite", "trusted"}))
	if findVerdict(dirs).Type != policy.DirectiveAllow {
		t.Fatal("expected allow for elite peer")
	}

	dirs, _ = cp.Evaluate(policy.EventConnect, ctx([]string{"newbie"}))
	if findVerdict(dirs).Type != policy.DirectiveDeny {
		t.Fatal("expected deny for non-elite peer")
	}
}

// --- HasRulesFor tests ---

func TestHasRulesFor(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "r1", On: "connect", Match: "true", Actions: []policy.Action{{Type: policy.ActionAllow}}},
	}}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	if !cp.HasRulesFor(policy.EventConnect) {
		t.Fatal("expected true for connect")
	}
	if cp.HasRulesFor(policy.EventCycle) {
		t.Fatal("expected false for cycle")
	}
}

// --- Config helpers ---

func TestCycleDuration(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{
		Version: 1,
		Config:  map[string]interface{}{"cycle": "24h", "grace": "1h"},
		Rules:   []policy.Rule{{Name: "r1", On: "cycle", Match: "true", Actions: []policy.Action{{Type: policy.ActionLog, Params: map[string]interface{}{"message": "tick"}}}}},
	}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}
	cycle, grace := cp.CycleDuration()
	if cycle != "24h" {
		t.Fatalf("cycle = %q, want '24h'", cycle)
	}
	if grace != "1h" {
		t.Fatalf("grace = %q, want '1h'", grace)
	}
}

func TestMaxPeers(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{
		Version: 1,
		Config:  map[string]interface{}{"max_peers": 100.0}, // JSON numbers are float64
		Rules:   []policy.Rule{{Name: "r1", On: "cycle", Match: "true", Actions: []policy.Action{{Type: policy.ActionLog, Params: map[string]interface{}{"message": "tick"}}}}},
	}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}
	if cp.MaxPeers() != 100 {
		t.Fatalf("max_peers = %d, want 100", cp.MaxPeers())
	}
}

// --- JSON round-trip test ---

func TestPolicyDocumentRoundTrip(t *testing.T) {
	t.Parallel()
	original := &policy.PolicyDocument{
		Version: 1,
		Config:  map[string]interface{}{"cycle": "24h", "max_peers": 100.0},
		Rules: []policy.Rule{
			{Name: "allow-80", On: "connect", Match: "port == 80", Actions: []policy.Action{{Type: policy.ActionAllow}}},
			{Name: "cycle-prune", On: "cycle", Match: "true", Actions: []policy.Action{
				{Type: policy.ActionPrune, Params: map[string]interface{}{"count": 10.0, "by": "age"}},
				{Type: policy.ActionFill, Params: map[string]interface{}{"count": 10.0, "how": "random"}},
			}},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}

	doc, err := policy.Parse(data)
	if err != nil {
		t.Fatal(err)
	}

	// Must compile successfully
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	if cp.RuleCount() != 2 {
		t.Fatalf("rules = %d, want 2", cp.RuleCount())
	}
}

// --- Dial event test ---

func TestEvaluateDialEvent(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "allow-http", On: "dial", Match: "port in [80, 443]", Actions: []policy.Action{{Type: policy.ActionAllow}}},
		{Name: "deny-rest", On: "dial", Match: "true", Actions: []policy.Action{{Type: policy.ActionDeny}}},
	}}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	dirs, _ := cp.Evaluate(policy.EventDial, map[string]interface{}{
		"port": 443, "peer_id": 1, "network_id": 1,
	})
	if findVerdict(dirs).Type != policy.DirectiveAllow {
		t.Fatal("expected allow for port 443 dial")
	}

	dirs, _ = cp.Evaluate(policy.EventDial, map[string]interface{}{
		"port": 22, "peer_id": 1, "network_id": 1,
	})
	if findVerdict(dirs).Type != policy.DirectiveDeny {
		t.Fatal("expected deny for port 22 dial")
	}
}

// --- Join/Leave event tests ---

func TestEvaluateJoinLeaveEvents(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "log-join", On: "join", Match: "true", Actions: []policy.Action{
			{Type: policy.ActionLog, Params: map[string]interface{}{"message": "peer joined"}},
		}},
		{Name: "log-leave", On: "leave", Match: "true", Actions: []policy.Action{
			{Type: policy.ActionLog, Params: map[string]interface{}{"message": "peer left"}},
		}},
	}}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	dirs, err := cp.Evaluate(policy.EventJoin, map[string]interface{}{
		"peer_id": 1, "network_id": 1, "members": 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) != 1 || dirs[0].Type != policy.DirectiveLog {
		t.Fatal("expected log directive for join event")
	}

	dirs, err = cp.Evaluate(policy.EventLeave, map[string]interface{}{
		"peer_id": 1, "network_id": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) != 1 || dirs[0].Type != policy.DirectiveLog {
		t.Fatal("expected log directive for leave event")
	}
}

// --- Edge cases ---

func TestEventTypeFiltering(t *testing.T) {
	t.Parallel()
	// Rules for different events should not interfere
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "connect-allow", On: "connect", Match: "true", Actions: []policy.Action{{Type: policy.ActionAllow}}},
		{Name: "cycle-prune", On: "cycle", Match: "true", Actions: []policy.Action{
			{Type: policy.ActionPrune, Params: map[string]interface{}{"count": 5, "by": "score"}},
		}},
	}}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	// Evaluate connect: should only get connect rules
	dirs, _ := cp.Evaluate(policy.EventConnect, map[string]interface{}{
		"port": 80, "peer_id": 1, "network_id": 1,
		"peer_tags": []string{}, "peer_age_s": 0.0, "members": 1,
	})
	if len(dirs) != 1 || dirs[0].Type != policy.DirectiveAllow {
		t.Fatal("expected only connect-allow directive")
	}

	// Evaluate cycle: should only get cycle rules
	dirs, _ = cp.Evaluate(policy.EventCycle, map[string]interface{}{
		"network_id": 1, "members": 10, "peer_count": 8, "cycle_num": 1,
	})
	if len(dirs) != 1 || dirs[0].Type != policy.DirectivePrune {
		t.Fatal("expected only cycle-prune directive")
	}
}

func TestMultipleActionsPerRule(t *testing.T) {
	t.Parallel()
	doc := &policy.PolicyDocument{Version: 1, Rules: []policy.Rule{
		{Name: "multi", On: "connect", Match: "true", Actions: []policy.Action{
			{Type: policy.ActionLog, Params: map[string]interface{}{"message": "connect", "level": "info"}},
			{Type: policy.ActionTag, Params: map[string]interface{}{"add": []string{"seen"}}},
			{Type: policy.ActionAllow},
		}},
	}}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	dirs, _ := cp.Evaluate(policy.EventConnect, map[string]interface{}{
		"port": 80, "peer_id": 1, "network_id": 1,
		"peer_tags": []string{}, "peer_age_s": 0.0, "members": 1,
	})
	if len(dirs) != 3 {
		t.Fatalf("directives = %d, want 3", len(dirs))
	}
	if dirs[0].Type != policy.DirectiveLog {
		t.Fatalf("dirs[0] = %d, want Log", dirs[0].Type)
	}
	if dirs[1].Type != policy.DirectiveTag {
		t.Fatalf("dirs[1] = %d, want Tag", dirs[1].Type)
	}
	if dirs[2].Type != policy.DirectiveAllow {
		t.Fatalf("dirs[2] = %d, want Allow", dirs[2].Type)
	}
}

// --- Backward compatibility bridge tests ---

func TestRulesToPolicy(t *testing.T) {
	t.Parallel()
	rules := &registry.NetworkRules{
		Links:   20,
		Cycle:   "24h",
		Prune:   5,
		PruneBy: "score",
		Fill:    5,
		FillHow: "random",
		Grace:   "1h",
	}

	raw, err := registry.RulesToPolicy(rules)
	if err != nil {
		t.Fatal(err)
	}
	if raw == nil {
		t.Fatal("expected non-nil policy")
	}

	doc, err := policy.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	// Check config
	if cp.MaxPeers() != 20 {
		t.Fatalf("max_peers = %d, want 20", cp.MaxPeers())
	}
	cycle, grace := cp.CycleDuration()
	if cycle != "24h" {
		t.Fatalf("cycle = %q, want '24h'", cycle)
	}
	if grace != "1h" {
		t.Fatalf("grace = %q, want '1h'", grace)
	}

	// Should have cycle rules
	if !cp.HasRulesFor(policy.EventCycle) {
		t.Fatal("expected cycle rules")
	}

	// Evaluate cycle: should produce prune + fill
	dirs, err := cp.Evaluate(policy.EventCycle, map[string]interface{}{
		"network_id": 1, "members": 20, "peer_count": 15, "cycle_num": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) != 2 {
		t.Fatalf("cycle directives = %d, want 2", len(dirs))
	}
	if dirs[0].Type != policy.DirectivePrune {
		t.Fatalf("dirs[0] = %d, want Prune", dirs[0].Type)
	}
	if dirs[1].Type != policy.DirectiveFill {
		t.Fatalf("dirs[1] = %d, want Fill", dirs[1].Type)
	}
}

func TestRulesToPolicyNil(t *testing.T) {
	t.Parallel()
	raw, err := registry.RulesToPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	if raw != nil {
		t.Fatal("expected nil for nil rules")
	}
}

func TestAllowedPortsToPolicy(t *testing.T) {
	t.Parallel()
	raw, err := registry.AllowedPortsToPolicy([]uint16{80, 443, 1001})
	if err != nil {
		t.Fatal(err)
	}
	if raw == nil {
		t.Fatal("expected non-nil policy")
	}

	doc, err := policy.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	// Test connect gate: port 80 should be allowed
	dirs, _ := cp.Evaluate(policy.EventConnect, map[string]interface{}{
		"port": 80, "peer_id": 1, "network_id": 1,
		"peer_tags": []string{}, "peer_age_s": 0.0, "members": 1,
	})
	if findVerdict(dirs).Type != policy.DirectiveAllow {
		t.Fatal("expected allow for port 80")
	}

	// Test connect gate: port 22 should be denied
	dirs, _ = cp.Evaluate(policy.EventConnect, map[string]interface{}{
		"port": 22, "peer_id": 1, "network_id": 1,
		"peer_tags": []string{}, "peer_age_s": 0.0, "members": 1,
	})
	if findVerdict(dirs).Type != policy.DirectiveDeny {
		t.Fatal("expected deny for port 22")
	}

	// Test datagram gate: port 1001 should be allowed
	dirs, _ = cp.Evaluate(policy.EventDatagram, map[string]interface{}{
		"port": 1001, "peer_id": 1, "network_id": 1, "size": 100, "direction": "in",
	})
	if findVerdict(dirs).Type != policy.DirectiveAllow {
		t.Fatal("expected allow for datagram port 1001")
	}

	// Test dial gate: port 443 should be allowed
	dirs, _ = cp.Evaluate(policy.EventDial, map[string]interface{}{
		"port": 443, "peer_id": 1, "network_id": 1,
	})
	if findVerdict(dirs).Type != policy.DirectiveAllow {
		t.Fatal("expected allow for dial port 443")
	}

	// Test dial gate: port 22 should be denied
	dirs, _ = cp.Evaluate(policy.EventDial, map[string]interface{}{
		"port": 22, "peer_id": 1, "network_id": 1,
	})
	if findVerdict(dirs).Type != policy.DirectiveDeny {
		t.Fatal("expected deny for dial port 22")
	}
}

func TestAllowedPortsToPolicyEmpty(t *testing.T) {
	t.Parallel()
	raw, err := registry.AllowedPortsToPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	if raw != nil {
		t.Fatal("expected nil for empty ports")
	}
}

// --- helpers ---

func findVerdict(dirs []policy.Directive) *policy.Directive {
	for i := range dirs {
		if dirs[i].Type == policy.DirectiveAllow || dirs[i].Type == policy.DirectiveDeny {
			return &dirs[i]
		}
	}
	return nil
}

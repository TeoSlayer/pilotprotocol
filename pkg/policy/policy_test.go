package policy

import (
	"encoding/json"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

func TestParseValidPolicy(t *testing.T) {
	raw := `{
		"version": 1,
		"rules": [
			{"name": "r1", "on": "connect", "match": "port == 80", "actions": [{"type": "allow"}]}
		]
	}`
	doc, err := Parse([]byte(raw))
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
	_, err := Parse([]byte(`{bad json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestValidateVersionMismatch(t *testing.T) {
	doc := &PolicyDocument{Version: 99, Rules: []Rule{{Name: "r", On: "connect", Match: "true", Actions: []Action{{Type: ActionAllow}}}}}
	if err := Validate(doc); err == nil {
		t.Fatal("expected error for version mismatch")
	}
}

func TestValidateNoRules(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{}}
	if err := Validate(doc); err == nil {
		t.Fatal("expected error for empty rules")
	}
}

func TestValidateDuplicateNames(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "dup", On: "connect", Match: "true", Actions: []Action{{Type: ActionAllow}}},
		{Name: "dup", On: "connect", Match: "true", Actions: []Action{{Type: ActionDeny}}},
	}}
	if err := Validate(doc); err == nil {
		t.Fatal("expected error for duplicate rule names")
	}
}

func TestValidateUnknownEventType(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "r", On: "unknown", Match: "true", Actions: []Action{{Type: ActionAllow}}},
	}}
	if err := Validate(doc); err == nil {
		t.Fatal("expected error for unknown event type")
	}
}

func TestValidateEmptyMatch(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "r", On: "connect", Match: "", Actions: []Action{{Type: ActionAllow}}},
	}}
	if err := Validate(doc); err == nil {
		t.Fatal("expected error for empty match")
	}
}

func TestValidateNoActions(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "r", On: "connect", Match: "true", Actions: []Action{}},
	}}
	if err := Validate(doc); err == nil {
		t.Fatal("expected error for empty actions")
	}
}

func TestValidateScoreRequiresDelta(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "r", On: "connect", Match: "true", Actions: []Action{{Type: ActionScore}}},
	}}
	if err := Validate(doc); err == nil {
		t.Fatal("expected error for score without delta")
	}
}

func TestValidateUnknownAction(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "r", On: "connect", Match: "true", Actions: []Action{{Type: "teleport"}}},
	}}
	if err := Validate(doc); err == nil {
		t.Fatal("expected error for unknown action")
	}
}

func TestValidateCycleConfig(t *testing.T) {
	doc := &PolicyDocument{
		Version: 1,
		Config:  map[string]interface{}{"cycle": "30s"},
		Rules:   []Rule{{Name: "r", On: "cycle", Match: "true", Actions: []Action{{Type: ActionLog, Params: map[string]interface{}{"message": "tick"}}}}},
	}
	if err := Validate(doc); err == nil {
		t.Fatal("expected error for cycle < 1m")
	}

	doc.Config["cycle"] = "1h"
	if err := Validate(doc); err != nil {
		t.Fatalf("unexpected error for valid cycle: %v", err)
	}
}

// --- Compile tests ---

func TestCompileValidPolicy(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "allow-80", On: "connect", Match: "port == 80", Actions: []Action{{Type: ActionAllow}}},
		{Name: "deny-all", On: "connect", Match: "true", Actions: []Action{{Type: ActionDeny}}},
	}}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(cp.rules) != 2 {
		t.Fatalf("compiled rules = %d, want 2", len(cp.rules))
	}
}

func TestCompileBadExpression(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "bad", On: "connect", Match: "port %%% invalid", Actions: []Action{{Type: ActionAllow}}},
	}}
	_, err := Compile(doc)
	if err == nil {
		t.Fatal("expected compile error for invalid expression")
	}
}

func TestCompileEvictWhereSubExpression(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "evict-bad", On: "cycle", Match: "true", Actions: []Action{
			{Type: ActionEvictWhere, Params: map[string]interface{}{"match": "peer_score < -50"}},
		}},
	}}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(cp.peerPrograms) != 1 {
		t.Fatalf("peerPrograms = %d, want 1", len(cp.peerPrograms))
	}
}

// --- Evaluate gate tests ---

func TestEvaluateGateAllow(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "allow-80", On: "connect", Match: "port == 80", Actions: []Action{{Type: ActionAllow}}},
		{Name: "deny-all", On: "connect", Match: "true", Actions: []Action{{Type: ActionDeny}}},
	}}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	dirs, err := cp.Evaluate(EventConnect, map[string]interface{}{
		"port":       80,
		"peer_id":    1234,
		"network_id": 1,
		"peer_score": 0,
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
	if last.Type != DirectiveAllow {
		t.Fatalf("verdict = %d, want DirectiveAllow", last.Type)
	}
	if last.Rule != "allow-80" {
		t.Fatalf("rule = %q, want 'allow-80'", last.Rule)
	}
}

func TestEvaluateGateDeny(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "allow-80", On: "connect", Match: "port == 80", Actions: []Action{{Type: ActionAllow}}},
		{Name: "deny-all", On: "connect", Match: "true", Actions: []Action{{Type: ActionDeny}}},
	}}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	dirs, err := cp.Evaluate(EventConnect, map[string]interface{}{
		"port":       443,
		"peer_id":    1234,
		"network_id": 1,
		"peer_score": 0,
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
	if verdict.Type != DirectiveDeny {
		t.Fatalf("verdict = %d, want DirectiveDeny", verdict.Type)
	}
}

func TestEvaluateGateDefaultAllow(t *testing.T) {
	// No rules match → default allow
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "allow-80", On: "connect", Match: "port == 80", Actions: []Action{{Type: ActionAllow}}},
	}}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	dirs, err := cp.Evaluate(EventConnect, map[string]interface{}{
		"port":       999,
		"peer_id":    1,
		"network_id": 1,
		"peer_score": 0,
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
	if verdict.Type != DirectiveAllow {
		t.Fatalf("verdict = %d, want DirectiveAllow (default)", verdict.Type)
	}
	if verdict.Rule != "_default" {
		t.Fatalf("rule = %q, want '_default'", verdict.Rule)
	}
}

func TestEvaluateGateSideEffectsBeforeVerdict(t *testing.T) {
	// A score action before a deny verdict: both should be returned
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "track", On: "connect", Match: "true", Actions: []Action{
			{Type: ActionScore, Params: map[string]interface{}{"delta": 1}},
		}},
		{Name: "deny-all", On: "connect", Match: "true", Actions: []Action{{Type: ActionDeny}}},
	}}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	dirs, err := cp.Evaluate(EventConnect, map[string]interface{}{
		"port":       80,
		"peer_id":    1,
		"network_id": 1,
		"peer_score": 0,
		"peer_tags":  []string{},
		"peer_age_s": 0.0,
		"members":    1,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(dirs) != 2 {
		t.Fatalf("directives = %d, want 2 (score + deny)", len(dirs))
	}
	if dirs[0].Type != DirectiveScore {
		t.Fatalf("dirs[0] = %d, want DirectiveScore", dirs[0].Type)
	}
	if dirs[1].Type != DirectiveDeny {
		t.Fatalf("dirs[1] = %d, want DirectiveDeny", dirs[1].Type)
	}
}

func TestEvaluateGatePortIn(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "allow-ports", On: "connect", Match: "port in [80, 443, 1001]", Actions: []Action{{Type: ActionAllow}}},
		{Name: "deny-rest", On: "connect", Match: "true", Actions: []Action{{Type: ActionDeny}}},
	}}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	ctx := func(port int) map[string]interface{} {
		return map[string]interface{}{
			"port": port, "peer_id": 1, "network_id": 1,
			"peer_score": 0, "peer_tags": []string{}, "peer_age_s": 0.0, "members": 1,
		}
	}

	for _, port := range []int{80, 443, 1001} {
		dirs, err := cp.Evaluate(EventConnect, ctx(port))
		if err != nil {
			t.Fatalf("port %d: %v", port, err)
		}
		v := findVerdict(dirs)
		if v.Type != DirectiveAllow {
			t.Fatalf("port %d: verdict = %d, want allow", port, v.Type)
		}
	}

	for _, port := range []int{22, 8080, 1002} {
		dirs, err := cp.Evaluate(EventConnect, ctx(port))
		if err != nil {
			t.Fatalf("port %d: %v", port, err)
		}
		v := findVerdict(dirs)
		if v.Type != DirectiveDeny {
			t.Fatalf("port %d: verdict = %d, want deny", port, v.Type)
		}
	}
}

// --- Evaluate action tests ---

func TestEvaluateActionsCycleEvent(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "prune-fill", On: "cycle", Match: "true", Actions: []Action{
			{Type: ActionPrune, Params: map[string]interface{}{"count": 10, "by": "score"}},
			{Type: ActionFill, Params: map[string]interface{}{"count": 10, "how": "random"}},
		}},
		{Name: "evict-bad", On: "cycle", Match: "peer_count > 5", Actions: []Action{
			{Type: ActionEvictWhere, Params: map[string]interface{}{"match": "peer_score < -50"}},
		}},
	}}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	ctx := map[string]interface{}{
		"network_id": 1,
		"members":    20,
		"peer_count": 10,
		"cycle_num":  1,
	}
	dirs, err := cp.Evaluate(EventCycle, ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Both rules match: prune + fill + evict_where = 3 directives
	if len(dirs) != 3 {
		t.Fatalf("directives = %d, want 3", len(dirs))
	}
	if dirs[0].Type != DirectivePrune {
		t.Fatalf("dirs[0] = %d, want Prune", dirs[0].Type)
	}
	if dirs[1].Type != DirectiveFill {
		t.Fatalf("dirs[1] = %d, want Fill", dirs[1].Type)
	}
	if dirs[2].Type != DirectiveEvictWhere {
		t.Fatalf("dirs[2] = %d, want EvictWhere", dirs[2].Type)
	}
}

func TestEvaluateActionsNoMatch(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "r1", On: "cycle", Match: "peer_count > 100", Actions: []Action{
			{Type: ActionPrune, Params: map[string]interface{}{"count": 5, "by": "score"}},
		}},
	}}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	dirs, err := cp.Evaluate(EventCycle, map[string]interface{}{
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
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "allow-data", On: "datagram", Match: "port == 1001 && size > 0", Actions: []Action{{Type: ActionAllow}}},
		{Name: "deny-rest", On: "datagram", Match: "true", Actions: []Action{{Type: ActionDeny}}},
	}}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	// Allowed: port 1001 with data
	dirs, err := cp.Evaluate(EventDatagram, map[string]interface{}{
		"port": 1001, "peer_id": 1, "network_id": 1, "size": 100, "direction": "in",
	})
	if err != nil {
		t.Fatal(err)
	}
	v := findVerdict(dirs)
	if v.Type != DirectiveAllow {
		t.Fatalf("datagram 1001: verdict = %d, want allow", v.Type)
	}

	// Denied: port 80
	dirs, err = cp.Evaluate(EventDatagram, map[string]interface{}{
		"port": 80, "peer_id": 1, "network_id": 1, "size": 100, "direction": "in",
	})
	if err != nil {
		t.Fatal(err)
	}
	v = findVerdict(dirs)
	if v.Type != DirectiveDeny {
		t.Fatalf("datagram 80: verdict = %d, want deny", v.Type)
	}
}

// --- EvaluatePeerExpr tests ---

func TestEvaluatePeerExpr(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "evict-bad", On: "cycle", Match: "true", Actions: []Action{
			{Type: ActionEvictWhere, Params: map[string]interface{}{"match": "peer_score < -50"}},
		}},
	}}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	// Bad peer: should match
	ok, err := cp.EvaluatePeerExpr("evict-bad", 0, map[string]interface{}{
		"peer_id": 1, "peer_score": -100, "peer_tags": []string{}, "peer_age_s": 0.0, "last_seen": 0.0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected peer with score -100 to match evict_where")
	}

	// Good peer: should not match
	ok, err = cp.EvaluatePeerExpr("evict-bad", 0, map[string]interface{}{
		"peer_id": 2, "peer_score": 50, "peer_tags": []string{}, "peer_age_s": 0.0, "last_seen": 0.0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected peer with score 50 to NOT match evict_where")
	}
}

// --- Custom function tests ---

func TestHasTag(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "allow-elite", On: "connect", Match: `has_tag(peer_tags, "elite")`, Actions: []Action{{Type: ActionAllow}}},
		{Name: "deny-rest", On: "connect", Match: "true", Actions: []Action{{Type: ActionDeny}}},
	}}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	ctx := func(tags []string) map[string]interface{} {
		return map[string]interface{}{
			"port": 80, "peer_id": 1, "network_id": 1,
			"peer_score": 0, "peer_tags": tags, "peer_age_s": 0.0, "members": 1,
		}
	}

	dirs, _ := cp.Evaluate(EventConnect, ctx([]string{"elite", "trusted"}))
	if findVerdict(dirs).Type != DirectiveAllow {
		t.Fatal("expected allow for elite peer")
	}

	dirs, _ = cp.Evaluate(EventConnect, ctx([]string{"newbie"}))
	if findVerdict(dirs).Type != DirectiveDeny {
		t.Fatal("expected deny for non-elite peer")
	}
}

// --- HasRulesFor tests ---

func TestHasRulesFor(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "r1", On: "connect", Match: "true", Actions: []Action{{Type: ActionAllow}}},
	}}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	if !cp.HasRulesFor(EventConnect) {
		t.Fatal("expected true for connect")
	}
	if cp.HasRulesFor(EventCycle) {
		t.Fatal("expected false for cycle")
	}
}

// --- Config helpers ---

func TestCycleDuration(t *testing.T) {
	doc := &PolicyDocument{
		Version: 1,
		Config:  map[string]interface{}{"cycle": "24h", "grace": "1h"},
		Rules:   []Rule{{Name: "r1", On: "cycle", Match: "true", Actions: []Action{{Type: ActionLog, Params: map[string]interface{}{"message": "tick"}}}}},
	}
	cp, err := Compile(doc)
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
	doc := &PolicyDocument{
		Version: 1,
		Config:  map[string]interface{}{"max_peers": 100.0}, // JSON numbers are float64
		Rules:   []Rule{{Name: "r1", On: "cycle", Match: "true", Actions: []Action{{Type: ActionLog, Params: map[string]interface{}{"message": "tick"}}}}},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}
	if cp.MaxPeers() != 100 {
		t.Fatalf("max_peers = %d, want 100", cp.MaxPeers())
	}
}

// --- JSON round-trip test ---

func TestPolicyDocumentRoundTrip(t *testing.T) {
	original := &PolicyDocument{
		Version: 1,
		Config:  map[string]interface{}{"cycle": "24h", "max_peers": 100.0},
		Rules: []Rule{
			{Name: "allow-80", On: "connect", Match: "port == 80", Actions: []Action{{Type: ActionAllow}}},
			{Name: "score-data", On: "datagram", Match: "size > 0", Actions: []Action{
				{Type: ActionScore, Params: map[string]interface{}{"delta": 1.0, "topic": "activity"}},
			}},
			{Name: "cycle-prune", On: "cycle", Match: "true", Actions: []Action{
				{Type: ActionPrune, Params: map[string]interface{}{"count": 10.0, "by": "score"}},
				{Type: ActionFill, Params: map[string]interface{}{"count": 10.0, "how": "random"}},
			}},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}

	doc, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}

	// Must compile successfully
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	if len(cp.rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(cp.rules))
	}
}

// --- Dial event test ---

func TestEvaluateDialEvent(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "allow-http", On: "dial", Match: "port in [80, 443]", Actions: []Action{{Type: ActionAllow}}},
		{Name: "deny-rest", On: "dial", Match: "true", Actions: []Action{{Type: ActionDeny}}},
	}}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	dirs, _ := cp.Evaluate(EventDial, map[string]interface{}{
		"port": 443, "peer_id": 1, "network_id": 1,
	})
	if findVerdict(dirs).Type != DirectiveAllow {
		t.Fatal("expected allow for port 443 dial")
	}

	dirs, _ = cp.Evaluate(EventDial, map[string]interface{}{
		"port": 22, "peer_id": 1, "network_id": 1,
	})
	if findVerdict(dirs).Type != DirectiveDeny {
		t.Fatal("expected deny for port 22 dial")
	}
}

// --- Join/Leave event tests ---

func TestEvaluateJoinLeaveEvents(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "log-join", On: "join", Match: "true", Actions: []Action{
			{Type: ActionLog, Params: map[string]interface{}{"message": "peer joined"}},
		}},
		{Name: "log-leave", On: "leave", Match: "true", Actions: []Action{
			{Type: ActionLog, Params: map[string]interface{}{"message": "peer left"}},
		}},
	}}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	dirs, err := cp.Evaluate(EventJoin, map[string]interface{}{
		"peer_id": 1, "network_id": 1, "members": 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) != 1 || dirs[0].Type != DirectiveLog {
		t.Fatal("expected log directive for join event")
	}

	dirs, err = cp.Evaluate(EventLeave, map[string]interface{}{
		"peer_id": 1, "network_id": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) != 1 || dirs[0].Type != DirectiveLog {
		t.Fatal("expected log directive for leave event")
	}
}

// --- Edge cases ---

func TestEventTypeFiltering(t *testing.T) {
	// Rules for different events should not interfere
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "connect-allow", On: "connect", Match: "true", Actions: []Action{{Type: ActionAllow}}},
		{Name: "cycle-prune", On: "cycle", Match: "true", Actions: []Action{
			{Type: ActionPrune, Params: map[string]interface{}{"count": 5, "by": "score"}},
		}},
	}}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	// Evaluate connect: should only get connect rules
	dirs, _ := cp.Evaluate(EventConnect, map[string]interface{}{
		"port": 80, "peer_id": 1, "network_id": 1,
		"peer_score": 0, "peer_tags": []string{}, "peer_age_s": 0.0, "members": 1,
	})
	if len(dirs) != 1 || dirs[0].Type != DirectiveAllow {
		t.Fatal("expected only connect-allow directive")
	}

	// Evaluate cycle: should only get cycle rules
	dirs, _ = cp.Evaluate(EventCycle, map[string]interface{}{
		"network_id": 1, "members": 10, "peer_count": 8, "cycle_num": 1,
	})
	if len(dirs) != 1 || dirs[0].Type != DirectivePrune {
		t.Fatal("expected only cycle-prune directive")
	}
}

func TestMultipleActionsPerRule(t *testing.T) {
	doc := &PolicyDocument{Version: 1, Rules: []Rule{
		{Name: "multi", On: "connect", Match: "true", Actions: []Action{
			{Type: ActionScore, Params: map[string]interface{}{"delta": 1}},
			{Type: ActionTag, Params: map[string]interface{}{"add": []string{"seen"}}},
			{Type: ActionAllow},
		}},
	}}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	dirs, _ := cp.Evaluate(EventConnect, map[string]interface{}{
		"port": 80, "peer_id": 1, "network_id": 1,
		"peer_score": 0, "peer_tags": []string{}, "peer_age_s": 0.0, "members": 1,
	})
	if len(dirs) != 3 {
		t.Fatalf("directives = %d, want 3", len(dirs))
	}
	if dirs[0].Type != DirectiveScore {
		t.Fatalf("dirs[0] = %d, want Score", dirs[0].Type)
	}
	if dirs[1].Type != DirectiveTag {
		t.Fatalf("dirs[1] = %d, want Tag", dirs[1].Type)
	}
	if dirs[2].Type != DirectiveAllow {
		t.Fatalf("dirs[2] = %d, want Allow", dirs[2].Type)
	}
}

// --- Backward compatibility bridge tests ---

func TestRulesToPolicy(t *testing.T) {
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

	doc, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	cp, err := Compile(doc)
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
	if !cp.HasRulesFor(EventCycle) {
		t.Fatal("expected cycle rules")
	}
	if !cp.HasRulesFor(EventDatagram) {
		t.Fatal("expected datagram rules (score)")
	}

	// Evaluate cycle: should produce prune + fill
	dirs, err := cp.Evaluate(EventCycle, map[string]interface{}{
		"network_id": 1, "members": 20, "peer_count": 15, "cycle_num": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) != 2 {
		t.Fatalf("cycle directives = %d, want 2", len(dirs))
	}
	if dirs[0].Type != DirectivePrune {
		t.Fatalf("dirs[0] = %d, want Prune", dirs[0].Type)
	}
	if dirs[1].Type != DirectiveFill {
		t.Fatalf("dirs[1] = %d, want Fill", dirs[1].Type)
	}
}

func TestRulesToPolicyNil(t *testing.T) {
	raw, err := registry.RulesToPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	if raw != nil {
		t.Fatal("expected nil for nil rules")
	}
}

func TestAllowedPortsToPolicy(t *testing.T) {
	raw, err := registry.AllowedPortsToPolicy([]uint16{80, 443, 1001})
	if err != nil {
		t.Fatal(err)
	}
	if raw == nil {
		t.Fatal("expected non-nil policy")
	}

	doc, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	cp, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}

	// Test connect gate: port 80 should be allowed
	dirs, _ := cp.Evaluate(EventConnect, map[string]interface{}{
		"port": 80, "peer_id": 1, "network_id": 1,
		"peer_score": 0, "peer_tags": []string{}, "peer_age_s": 0.0, "members": 1,
	})
	if findVerdict(dirs).Type != DirectiveAllow {
		t.Fatal("expected allow for port 80")
	}

	// Test connect gate: port 22 should be denied
	dirs, _ = cp.Evaluate(EventConnect, map[string]interface{}{
		"port": 22, "peer_id": 1, "network_id": 1,
		"peer_score": 0, "peer_tags": []string{}, "peer_age_s": 0.0, "members": 1,
	})
	if findVerdict(dirs).Type != DirectiveDeny {
		t.Fatal("expected deny for port 22")
	}

	// Test datagram gate: port 1001 should be allowed
	dirs, _ = cp.Evaluate(EventDatagram, map[string]interface{}{
		"port": 1001, "peer_id": 1, "network_id": 1, "size": 100, "direction": "in",
	})
	if findVerdict(dirs).Type != DirectiveAllow {
		t.Fatal("expected allow for datagram port 1001")
	}

	// Test dial gate: port 443 should be allowed
	dirs, _ = cp.Evaluate(EventDial, map[string]interface{}{
		"port": 443, "peer_id": 1, "network_id": 1,
	})
	if findVerdict(dirs).Type != DirectiveAllow {
		t.Fatal("expected allow for dial port 443")
	}

	// Test dial gate: port 22 should be denied
	dirs, _ = cp.Evaluate(EventDial, map[string]interface{}{
		"port": 22, "peer_id": 1, "network_id": 1,
	})
	if findVerdict(dirs).Type != DirectiveDeny {
		t.Fatal("expected deny for dial port 22")
	}
}

func TestAllowedPortsToPolicyEmpty(t *testing.T) {
	raw, err := registry.AllowedPortsToPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	if raw != nil {
		t.Fatal("expected nil for empty ports")
	}
}

// --- helpers ---

func findVerdict(dirs []Directive) *Directive {
	for i := range dirs {
		if dirs[i].Type == DirectiveAllow || dirs[i].Type == DirectiveDeny {
			return &dirs[i]
		}
	}
	return nil
}

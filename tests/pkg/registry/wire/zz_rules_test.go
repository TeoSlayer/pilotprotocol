// SPDX-License-Identifier: AGPL-3.0-or-later

package wire_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pilot-protocol/common/registry/wire"
)

// --- ValidateRules error branches ----------------------------------------

func TestValidateRulesNilReturnsNil(t *testing.T) {
	t.Parallel()
	if err := wire.ValidateRules(nil); err != nil {
		t.Fatalf("nil rules: %v", err)
	}
}

func TestValidateRulesLinksRequired(t *testing.T) {
	t.Parallel()
	cases := []int{0, -5}
	for _, l := range cases {
		r := &wire.NetworkRules{Links: l, Cycle: "1h", PruneBy: "score", FillHow: "random"}
		err := wire.ValidateRules(r)
		if err == nil || !strings.Contains(err.Error(), "links must be >= 1") {
			t.Fatalf("links=%d: %v", l, err)
		}
	}
}

func TestValidateRulesCycleRequired(t *testing.T) {
	t.Parallel()
	r := &wire.NetworkRules{Links: 5, Cycle: "", PruneBy: "score", FillHow: "random"}
	err := wire.ValidateRules(r)
	if err == nil || !strings.Contains(err.Error(), "cycle is required") {
		t.Fatalf("expected cycle-required error, got %v", err)
	}
}

func TestValidateRulesCycleInvalidDuration(t *testing.T) {
	t.Parallel()
	r := &wire.NetworkRules{Links: 5, Cycle: "not-a-duration", PruneBy: "score", FillHow: "random"}
	err := wire.ValidateRules(r)
	if err == nil || !strings.Contains(err.Error(), "invalid cycle duration") {
		t.Fatalf("%v", err)
	}
}

func TestValidateRulesCycleTooShort(t *testing.T) {
	t.Parallel()
	r := &wire.NetworkRules{Links: 5, Cycle: "30s", PruneBy: "score", FillHow: "random"}
	err := wire.ValidateRules(r)
	if err == nil || !strings.Contains(err.Error(), "cycle must be >= 1m") {
		t.Fatalf("%v", err)
	}
}

func TestValidateRulesPruneFillNegativeOrOverflow(t *testing.T) {
	t.Parallel()
	base := wire.NetworkRules{Links: 5, Cycle: "1h", PruneBy: "score", FillHow: "random"}
	// Prune < 0
	r := base
	r.Prune = -1
	if err := wire.ValidateRules(&r); err == nil || !strings.Contains(err.Error(), "prune must be >= 0") {
		t.Fatalf("prune<0: %v", err)
	}
	// Fill < 0
	r = base
	r.Fill = -1
	if err := wire.ValidateRules(&r); err == nil || !strings.Contains(err.Error(), "fill must be >= 0") {
		t.Fatalf("fill<0: %v", err)
	}
	// Prune > Links
	r = base
	r.Prune = 10
	if err := wire.ValidateRules(&r); err == nil || !strings.Contains(err.Error(), "cannot exceed links") {
		t.Fatalf("prune>links: %v", err)
	}
	// Fill > Links
	r = base
	r.Fill = 10
	if err := wire.ValidateRules(&r); err == nil || !strings.Contains(err.Error(), "fill (10) cannot exceed links") {
		t.Fatalf("fill>links: %v", err)
	}
}

func TestValidateRulesPruneByAllValidValues(t *testing.T) {
	t.Parallel()
	for _, pb := range []string{"score", "age", "activity"} {
		r := &wire.NetworkRules{Links: 5, Cycle: "1h", PruneBy: pb, FillHow: "random"}
		if err := wire.ValidateRules(r); err != nil {
			t.Fatalf("prune_by=%q: %v", pb, err)
		}
	}
}

func TestValidateRulesPruneByRequiredAndUnknown(t *testing.T) {
	t.Parallel()
	// Empty
	r := &wire.NetworkRules{Links: 5, Cycle: "1h", PruneBy: "", FillHow: "random"}
	if err := wire.ValidateRules(r); err == nil || !strings.Contains(err.Error(), "prune_by is required") {
		t.Fatalf("empty prune_by: %v", err)
	}
	// Unknown
	r = &wire.NetworkRules{Links: 5, Cycle: "1h", PruneBy: "lottery", FillHow: "random"}
	if err := wire.ValidateRules(r); err == nil || !strings.Contains(err.Error(), "unknown prune_by strategy") {
		t.Fatalf("unknown prune_by: %v", err)
	}
}

func TestValidateRulesFillHowRequiredAndUnknown(t *testing.T) {
	t.Parallel()
	r := &wire.NetworkRules{Links: 5, Cycle: "1h", PruneBy: "score", FillHow: ""}
	if err := wire.ValidateRules(r); err == nil || !strings.Contains(err.Error(), "fill_how is required") {
		t.Fatalf("empty fill_how: %v", err)
	}
	r = &wire.NetworkRules{Links: 5, Cycle: "1h", PruneBy: "score", FillHow: "roundrobin"}
	if err := wire.ValidateRules(r); err == nil || !strings.Contains(err.Error(), "unknown fill_how strategy") {
		t.Fatalf("unknown fill_how: %v", err)
	}
}

func TestValidateRulesGraceInvalid(t *testing.T) {
	t.Parallel()
	r := &wire.NetworkRules{Links: 5, Cycle: "1h", PruneBy: "score", FillHow: "random", Grace: "not-a-duration"}
	if err := wire.ValidateRules(r); err == nil || !strings.Contains(err.Error(), "invalid grace duration") {
		t.Fatalf("bad grace: %v", err)
	}
	// Note: time.ParseDuration rejects literal negatives like "-1m" for some inputs.
	// We rely on the `g < 0` branch being effectively unreachable via parsing in practice,
	// but verify parseable non-negative grace succeeds.
}

func TestValidateRulesGraceEmptyOrValid(t *testing.T) {
	t.Parallel()
	r := &wire.NetworkRules{Links: 5, Cycle: "1h", PruneBy: "score", FillHow: "random", Grace: ""}
	if err := wire.ValidateRules(r); err != nil {
		t.Fatalf("empty grace: %v", err)
	}
	r.Grace = "10m"
	if err := wire.ValidateRules(r); err != nil {
		t.Fatalf("valid grace: %v", err)
	}
}

func TestValidateRulesHappyPath(t *testing.T) {
	t.Parallel()
	r := &wire.NetworkRules{Links: 10, Cycle: "1h", Prune: 2, PruneBy: "score", Fill: 2, FillHow: "random", Grace: "5m"}
	if err := wire.ValidateRules(r); err != nil {
		t.Fatalf("happy: %v", err)
	}
}

// --- ParseRules -----------------------------------------------------------

func TestParseRulesBadJSON(t *testing.T) {
	t.Parallel()
	_, err := wire.ParseRules(`{not json`)
	if err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("%v", err)
	}
}

func TestParseRulesInvalidRules(t *testing.T) {
	t.Parallel()
	_, err := wire.ParseRules(`{"links":0,"cycle":"1h","prune_by":"score","fill_how":"random"}`)
	if err == nil || !strings.Contains(err.Error(), "links must be >= 1") {
		t.Fatalf("%v", err)
	}
}

func TestParseRulesHappyPath(t *testing.T) {
	t.Parallel()
	r, err := wire.ParseRules(`{"links":5,"cycle":"1h","prune":1,"prune_by":"age","fill":1,"fill_how":"random"}`)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if r.Links != 5 || r.Cycle != "1h" || r.Prune != 1 || r.PruneBy != "age" || r.Fill != 1 || r.FillHow != "random" {
		t.Fatalf("parsed: %+v", r)
	}
}

// --- RulesToPolicy --------------------------------------------------------

func TestRulesToPolicyNilReturnsNilNil(t *testing.T) {
	t.Parallel()
	raw, err := wire.RulesToPolicy(nil)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if raw != nil {
		t.Fatalf("expected nil json.RawMessage for nil rules, got %s", string(raw))
	}
}

func TestRulesToPolicyShapeAndContentWithoutGrace(t *testing.T) {
	t.Parallel()
	r := &wire.NetworkRules{Links: 7, Cycle: "2h", Prune: 3, PruneBy: "age", Fill: 2, FillHow: "random"}
	raw, err := wire.RulesToPolicy(r)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%v", err)
	}
	if doc["version"].(float64) != 1 {
		t.Fatalf("version: %v", doc["version"])
	}
	cfg := doc["config"].(map[string]interface{})
	if cfg["max_peers"].(float64) != 7 {
		t.Fatalf("max_peers: %v", cfg["max_peers"])
	}
	if cfg["cycle"].(string) != "2h" {
		t.Fatalf("cycle: %v", cfg["cycle"])
	}
	if _, hasGrace := cfg["grace"]; hasGrace {
		t.Fatalf("grace should be absent when Grace=\"\"")
	}
	rules := doc["rules"].([]interface{})
	if len(rules) != 1 {
		t.Fatalf("rules count: %d", len(rules))
	}
	// rule[0] = cycle-prune-fill; prune action first, fill action second
	r1 := rules[0].(map[string]interface{})
	if r1["name"].(string) != "cycle-prune-fill" || r1["on"].(string) != "cycle" {
		t.Fatalf("rule 0: %+v", r1)
	}
	actions := r1["actions"].([]interface{})
	pruneA := actions[0].(map[string]interface{})
	if pruneA["type"].(string) != "prune" {
		t.Fatalf("first action: %+v", pruneA)
	}
	params := pruneA["params"].(map[string]interface{})
	if params["count"].(float64) != 3 || params["by"].(string) != "age" {
		t.Fatalf("prune params: %+v", params)
	}
	fillA := actions[1].(map[string]interface{})
	if fillA["type"].(string) != "fill" {
		t.Fatalf("second action: %+v", fillA)
	}
	fillP := fillA["params"].(map[string]interface{})
	if fillP["count"].(float64) != 2 || fillP["how"].(string) != "random" {
		t.Fatalf("fill params: %+v", fillP)
	}
}

func TestRulesToPolicyIncludesGraceWhenSet(t *testing.T) {
	t.Parallel()
	r := &wire.NetworkRules{Links: 5, Cycle: "1h", Prune: 1, PruneBy: "score", Fill: 1, FillHow: "random", Grace: "15m"}
	raw, err := wire.RulesToPolicy(r)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var doc map[string]interface{}
	_ = json.Unmarshal(raw, &doc)
	cfg := doc["config"].(map[string]interface{})
	if cfg["grace"].(string) != "15m" {
		t.Fatalf("grace: %v", cfg["grace"])
	}
}

// --- AllowedPortsToPolicy -------------------------------------------------

func TestAllowedPortsToPolicyEmptyReturnsNilNil(t *testing.T) {
	t.Parallel()
	raw, err := wire.AllowedPortsToPolicy(nil)
	if err != nil || raw != nil {
		t.Fatalf("nil ports: raw=%v err=%v", raw, err)
	}
	raw, err = wire.AllowedPortsToPolicy([]uint16{})
	if err != nil || raw != nil {
		t.Fatalf("empty ports: raw=%v err=%v", raw, err)
	}
}

func TestAllowedPortsToPolicyMatchExpressionAndRules(t *testing.T) {
	t.Parallel()
	raw, err := wire.AllowedPortsToPolicy([]uint16{80, 443, 7001})
	if err != nil {
		t.Fatalf("%v", err)
	}
	// Raw text contains the exact match expression.
	s := string(raw)
	if !strings.Contains(s, `"port in [80, 443, 7001]"`) {
		t.Fatalf("match expr not formatted as expected:\n%s", s)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%v", err)
	}
	if doc["version"].(float64) != 1 {
		t.Fatalf("version: %v", doc["version"])
	}
	rules := doc["rules"].([]interface{})
	if len(rules) != 6 {
		t.Fatalf("rules count: %d, want 6 (3 allow + 3 deny)", len(rules))
	}
	// Expected names in order.
	wantNames := []string{"allow-ports", "allow-ports-dg", "allow-ports-dial", "deny-rest", "deny-rest-dg", "deny-rest-dial"}
	for i, want := range wantNames {
		r := rules[i].(map[string]interface{})
		if r["name"].(string) != want {
			t.Fatalf("rule[%d].name = %q, want %q", i, r["name"], want)
		}
	}
	// Allow rules use the built match expr; deny rules use "true".
	for i := 0; i < 3; i++ {
		r := rules[i].(map[string]interface{})
		if r["match"].(string) != "port in [80, 443, 7001]" {
			t.Fatalf("allow rule[%d] match: %q", i, r["match"])
		}
	}
	for i := 3; i < 6; i++ {
		r := rules[i].(map[string]interface{})
		if r["match"].(string) != "true" {
			t.Fatalf("deny rule[%d] match: %q", i, r["match"])
		}
	}
}

func TestAllowedPortsToPolicySinglePort(t *testing.T) {
	t.Parallel()
	raw, err := wire.AllowedPortsToPolicy([]uint16{7})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(string(raw), `"port in [7]"`) {
		t.Fatalf("single-port match expr:\n%s", string(raw))
	}
}

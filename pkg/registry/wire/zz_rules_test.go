// SPDX-License-Identifier: AGPL-3.0-or-later

package wire_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

// --- ValidateRules ---

func TestValidateRulesNil(t *testing.T) {
	t.Parallel()
	if err := wire.ValidateRules(nil); err != nil {
		t.Errorf("ValidateRules(nil) = %v, want nil", err)
	}
}

func TestValidateRulesValid(t *testing.T) {
	t.Parallel()
	r := &wire.NetworkRules{
		Links:   10,
		Cycle:   "24h",
		Prune:   3,
		PruneBy: "score",
		Fill:    3,
		FillHow: "random",
	}
	if err := wire.ValidateRules(r); err != nil {
		t.Errorf("ValidateRules valid rule = %v, want nil", err)
	}
}

func TestValidateRulesValidWithGrace(t *testing.T) {
	t.Parallel()
	r := &wire.NetworkRules{
		Links: 5, Cycle: "1h", Prune: 1, PruneBy: "age",
		Fill: 1, FillHow: "random", Grace: "30m",
	}
	if err := wire.ValidateRules(r); err != nil {
		t.Errorf("ValidateRules with grace = %v, want nil", err)
	}
}

func TestValidateRulesInvalid(t *testing.T) {
	t.Parallel()
	base := wire.NetworkRules{
		Links: 10, Cycle: "24h", Prune: 2, PruneBy: "score", Fill: 2, FillHow: "random",
	}
	cases := []struct {
		name   string
		mutate func(*wire.NetworkRules)
		errSub string
	}{
		{"links zero", func(r *wire.NetworkRules) { r.Links = 0 }, "links"},
		{"cycle empty", func(r *wire.NetworkRules) { r.Cycle = "" }, "cycle"},
		{"cycle too short", func(r *wire.NetworkRules) { r.Cycle = "30s" }, "cycle"},
		{"cycle invalid", func(r *wire.NetworkRules) { r.Cycle = "bogus" }, "cycle"},
		{"prune negative", func(r *wire.NetworkRules) { r.Prune = -1 }, "prune"},
		{"fill negative", func(r *wire.NetworkRules) { r.Fill = -1 }, "fill"},
		{"prune exceeds links", func(r *wire.NetworkRules) { r.Prune = 20 }, "prune"},
		{"fill exceeds links", func(r *wire.NetworkRules) { r.Fill = 20 }, "fill"},
		{"prune_by empty", func(r *wire.NetworkRules) { r.PruneBy = "" }, "prune_by"},
		{"prune_by unknown", func(r *wire.NetworkRules) { r.PruneBy = "random" }, "prune_by"},
		{"fill_how empty", func(r *wire.NetworkRules) { r.FillHow = "" }, "fill_how"},
		{"fill_how unknown", func(r *wire.NetworkRules) { r.FillHow = "oldest" }, "fill_how"},
		{"grace invalid", func(r *wire.NetworkRules) { r.Grace = "not-a-duration" }, "grace"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.mutate(&r)
			err := wire.ValidateRules(&r)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errSub)
			}
			if !strings.Contains(err.Error(), tc.errSub) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.errSub)
			}
		})
	}
}

// --- ParseRules ---

func TestParseRulesValid(t *testing.T) {
	t.Parallel()
	raw := `{"links":8,"cycle":"12h","prune":2,"prune_by":"activity","fill":2,"fill_how":"random"}`
	r, err := wire.ParseRules(raw)
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	if r.Links != 8 || r.Cycle != "12h" || r.PruneBy != "activity" {
		t.Errorf("unexpected result: %+v", r)
	}
}

func TestParseRulesInvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := wire.ParseRules("{not json}")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseRulesFailsValidation(t *testing.T) {
	t.Parallel()
	_, err := wire.ParseRules(`{"links":0,"cycle":"1h","prune":0,"prune_by":"score","fill":0,"fill_how":"random"}`)
	if err == nil {
		t.Fatal("expected validation error for links=0")
	}
}

// --- RulesToPolicy ---

func TestRulesToPolicyNil(t *testing.T) {
	t.Parallel()
	out, err := wire.RulesToPolicy(nil)
	if err != nil {
		t.Fatalf("RulesToPolicy(nil) = %v", err)
	}
	if out != nil {
		t.Errorf("expected nil output for nil input, got %s", out)
	}
}

func TestRulesToPolicyValid(t *testing.T) {
	t.Parallel()
	r := &wire.NetworkRules{
		Links: 5, Cycle: "6h", Prune: 2, PruneBy: "score", Fill: 2, FillHow: "random",
	}
	out, err := wire.RulesToPolicy(r)
	if err != nil {
		t.Fatalf("RulesToPolicy: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if doc["version"].(float64) != 1 {
		t.Error("expected version 1")
	}
	cfg := doc["config"].(map[string]interface{})
	if cfg["max_peers"].(float64) != 5 {
		t.Errorf("max_peers: got %v want 5", cfg["max_peers"])
	}
}

func TestRulesToPolicyIncludesGrace(t *testing.T) {
	t.Parallel()
	r := &wire.NetworkRules{
		Links: 3, Cycle: "24h", Prune: 1, PruneBy: "age",
		Fill: 1, FillHow: "random", Grace: "2h",
	}
	out, err := wire.RulesToPolicy(r)
	if err != nil {
		t.Fatalf("RulesToPolicy: %v", err)
	}
	var doc map[string]interface{}
	_ = json.Unmarshal(out, &doc)
	cfg := doc["config"].(map[string]interface{})
	if cfg["grace"] != "2h" {
		t.Errorf("grace not present in policy config: %v", cfg)
	}
}

// --- AllowedPortsToPolicy ---

func TestAllowedPortsToPolicyNil(t *testing.T) {
	t.Parallel()
	out, err := wire.AllowedPortsToPolicy(nil)
	if err != nil {
		t.Fatalf("AllowedPortsToPolicy(nil): %v", err)
	}
	if out != nil {
		t.Error("expected nil for empty port list")
	}
}

func TestAllowedPortsToPolicyValid(t *testing.T) {
	t.Parallel()
	ports := []uint16{80, 443, 8080}
	out, err := wire.AllowedPortsToPolicy(ports)
	if err != nil {
		t.Fatalf("AllowedPortsToPolicy: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	rules := doc["rules"].([]interface{})
	if len(rules) == 0 {
		t.Error("expected at least one rule")
	}
	// The match expression should reference all three ports.
	first := rules[0].(map[string]interface{})
	match := first["match"].(string)
	for _, p := range []string{"80", "443", "8080"} {
		if !strings.Contains(match, p) {
			t.Errorf("match expression %q does not contain port %s", match, p)
		}
	}
}

func TestAllowedPortsToPolicySinglePort(t *testing.T) {
	t.Parallel()
	out, err := wire.AllowedPortsToPolicy([]uint16{22})
	if err != nil {
		t.Fatalf("AllowedPortsToPolicy single: %v", err)
	}
	if !strings.Contains(string(out), "22") {
		t.Errorf("policy JSON does not reference port 22: %s", out)
	}
}

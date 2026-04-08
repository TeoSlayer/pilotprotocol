package registry

import (
	"encoding/json"
	"fmt"
	"time"
)

// NetworkRules defines the managed network ruleset. When set on a NetworkInfo,
// the network becomes "managed" — daemon-local link lifecycle is governed by
// these rules. The registry only stores and distributes the rules; all cycle
// logic runs inside each daemon.
type NetworkRules struct {
	Links   int    `json:"links"`            // max managed peers per node
	Cycle   string `json:"cycle"`            // Go duration: "24h", "1h"
	Prune   int    `json:"prune"`            // how many to drop per cycle
	PruneBy string `json:"prune_by"`         // "score", "age", "activity"
	Fill    int    `json:"fill"`             // how many to add per cycle
	FillHow string `json:"fill_how"`         // "random"
	Grace   string `json:"grace,omitempty"`  // grace period for new members
}

// ValidateRules checks that a NetworkRules is well-formed. Returns nil if valid.
func ValidateRules(r *NetworkRules) error {
	if r == nil {
		return nil
	}
	if r.Links < 1 {
		return fmt.Errorf("rules: links must be >= 1 (got %d)", r.Links)
	}
	if r.Cycle == "" {
		return fmt.Errorf("rules: cycle is required")
	}
	d, err := time.ParseDuration(r.Cycle)
	if err != nil {
		return fmt.Errorf("rules: invalid cycle duration %q: %w", r.Cycle, err)
	}
	if d < 1*time.Minute {
		return fmt.Errorf("rules: cycle must be >= 1m (got %s)", r.Cycle)
	}
	if r.Prune < 0 {
		return fmt.Errorf("rules: prune must be >= 0 (got %d)", r.Prune)
	}
	if r.Fill < 0 {
		return fmt.Errorf("rules: fill must be >= 0 (got %d)", r.Fill)
	}
	if r.Prune > r.Links {
		return fmt.Errorf("rules: prune (%d) cannot exceed links (%d)", r.Prune, r.Links)
	}
	if r.Fill > r.Links {
		return fmt.Errorf("rules: fill (%d) cannot exceed links (%d)", r.Fill, r.Links)
	}

	switch r.PruneBy {
	case "score", "age", "activity":
		// valid
	case "":
		return fmt.Errorf("rules: prune_by is required")
	default:
		return fmt.Errorf("rules: unknown prune_by strategy %q (want score|age|activity)", r.PruneBy)
	}

	switch r.FillHow {
	case "random":
		// valid
	case "":
		return fmt.Errorf("rules: fill_how is required")
	default:
		return fmt.Errorf("rules: unknown fill_how strategy %q (want random)", r.FillHow)
	}

	if r.Grace != "" {
		g, err := time.ParseDuration(r.Grace)
		if err != nil {
			return fmt.Errorf("rules: invalid grace duration %q: %w", r.Grace, err)
		}
		if g < 0 {
			return fmt.Errorf("rules: grace must be >= 0")
		}
	}

	return nil
}

// ParseRules unmarshals a JSON string into NetworkRules and validates it.
func ParseRules(raw string) (*NetworkRules, error) {
	var r NetworkRules
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil, fmt.Errorf("rules: invalid JSON: %w", err)
	}
	if err := ValidateRules(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// RulesToPolicy converts a NetworkRules struct into a PolicyDocument JSON
// (json.RawMessage). This provides backward compatibility: existing managed
// networks continue to work through the policy engine.
func RulesToPolicy(r *NetworkRules) (json.RawMessage, error) {
	if r == nil {
		return nil, nil
	}

	type action struct {
		Type   string                 `json:"type"`
		Params map[string]interface{} `json:"params,omitempty"`
	}
	type rule struct {
		Name    string   `json:"name"`
		On      string   `json:"on"`
		Match   string   `json:"match"`
		Actions []action `json:"actions"`
	}
	type policyDoc struct {
		Version int                    `json:"version"`
		Config  map[string]interface{} `json:"config,omitempty"`
		Rules   []rule                 `json:"rules"`
	}

	doc := policyDoc{
		Version: 1,
		Config: map[string]interface{}{
			"max_peers": r.Links,
			"cycle":     r.Cycle,
		},
		Rules: []rule{
			{
				Name:  "score-activity",
				On:    "datagram",
				Match: "size > 0",
				Actions: []action{
					{Type: "score", Params: map[string]interface{}{"delta": 1, "topic": "activity"}},
				},
			},
			{
				Name:  "cycle-prune-fill",
				On:    "cycle",
				Match: "true",
				Actions: []action{
					{Type: "prune", Params: map[string]interface{}{"count": r.Prune, "by": r.PruneBy}},
					{Type: "fill", Params: map[string]interface{}{"count": r.Fill, "how": r.FillHow}},
				},
			},
		},
	}

	if r.Grace != "" {
		doc.Config["grace"] = r.Grace
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("rules-to-policy: %w", err)
	}
	return json.RawMessage(data), nil
}

// AllowedPortsToPolicy converts a port allowlist into a PolicyDocument JSON
// (json.RawMessage). This replaces the old AllowedPorts mechanism with
// equivalent policy rules.
func AllowedPortsToPolicy(ports []uint16) (json.RawMessage, error) {
	if len(ports) == 0 {
		return nil, nil
	}

	// Build match expression: "port in [80, 443, 1001]"
	var buf []byte
	buf = append(buf, "port in ["...)
	for i, p := range ports {
		if i > 0 {
			buf = append(buf, ", "...)
		}
		buf = fmt.Appendf(buf, "%d", p)
	}
	buf = append(buf, ']')
	matchExpr := string(buf)

	type action struct {
		Type string `json:"type"`
	}
	type rule struct {
		Name    string   `json:"name"`
		On      string   `json:"on"`
		Match   string   `json:"match"`
		Actions []action `json:"actions"`
	}
	type policyDoc struct {
		Version int    `json:"version"`
		Rules   []rule `json:"rules"`
	}

	doc := policyDoc{
		Version: 1,
		Rules: []rule{
			{Name: "allow-ports", On: "connect", Match: matchExpr, Actions: []action{{Type: "allow"}}},
			{Name: "allow-ports-dg", On: "datagram", Match: matchExpr, Actions: []action{{Type: "allow"}}},
			{Name: "allow-ports-dial", On: "dial", Match: matchExpr, Actions: []action{{Type: "allow"}}},
			{Name: "deny-rest", On: "connect", Match: "true", Actions: []action{{Type: "deny"}}},
			{Name: "deny-rest-dg", On: "datagram", Match: "true", Actions: []action{{Type: "deny"}}},
			{Name: "deny-rest-dial", On: "dial", Match: "true", Actions: []action{{Type: "deny"}}},
		},
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("ports-to-policy: %w", err)
	}
	return json.RawMessage(data), nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

// Package policy implements the registry's network-policy and expression-policy
// handlers. It is extracted from pkg/registry/server as part of the R2.4
// registry decomposition.
//
// Thread safety: all exported methods are safe for concurrent use; locking is
// delegated to the Read/Write callbacks supplied by the parent server.
package policy

import (
	"encoding/json"
	"fmt"
	"log/slog"
)

// NetworkPolicy defines constraints and metadata for a network.
// Field shape mirrors server.NetworkPolicy for mechanical adoption.
type NetworkPolicy struct {
	MaxMembers   int      `json:"max_members"`   // 0 = unlimited
	AllowedPorts []uint16 `json:"allowed_ports"` // empty = all ports allowed
	Description  string   `json:"description"`   // human-readable description
}

// ExprPolicy holds the raw JSON bytes for a programmable expression-policy
// document (nil = none set).
type ExprPolicy = json.RawMessage

// NetworkState is the policy-relevant snapshot of a network returned by PolicyReader.
type NetworkState struct {
	Policy      NetworkPolicy
	Expr        ExprPolicy
	MemberCount int // current member count for max_members enforcement
}

// PolicyReader reads the current NetworkState for a network.
// Implementations must be safe for concurrent use and must acquire whatever
// locks are needed internally.
type PolicyReader func(netID uint16) (NetworkState, error)

// PolicyWriter persists an updated NetworkPolicy and ExprPolicy for a network.
// Passing a nil expr clears any existing expression-policy document.
// Implementations must be safe for concurrent use and must acquire whatever
// locks are needed internally.
type PolicyWriter func(netID uint16, policy NetworkPolicy, expr ExprPolicy) error

// AuthChecker verifies that the requester is allowed to mutate the named
// network's policy (owner/admin role or admin token). Returning a non-nil
// error rejects the request.
type AuthChecker func(msg map[string]interface{}, netID uint16) error

// EnterpriseChecker verifies that the given network has the Enterprise flag.
// Returning a non-nil error rejects the request.
type EnterpriseChecker func(netID uint16) error

// Callbacks bundles the side-effect functions the Store calls on state changes.
// All functions must be safe for concurrent use.
type Callbacks struct {
	// Save triggers a debounced snapshot write.
	Save func()
	// Audit records an audit log entry.
	Audit func(action string, attrs ...any)
	// IncPolicyChanges increments the pilot_policy_changes_total counter.
	IncPolicyChanges func()
}

// Store holds the network-policy handler logic and delegates state mutations
// via PolicyReader / PolicyWriter callbacks.
type Store struct {
	read       PolicyReader
	write      PolicyWriter
	auth       AuthChecker
	enterprise EnterpriseChecker
	cb         Callbacks
}

// NewStore creates a ready-to-use policy Store.
func NewStore(read PolicyReader, write PolicyWriter, auth AuthChecker, enterprise EnterpriseChecker, cb Callbacks) *Store {
	return &Store{read: read, write: write, auth: auth, enterprise: enterprise, cb: cb}
}

// jsonUint16 extracts a uint16 from a JSON-decoded map. JSON numbers unmarshal
// as float64, so we cast explicitly. Returns 0 on miss or out-of-range.
func jsonUint16(msg map[string]interface{}, key string) uint16 {
	if v, ok := msg[key].(float64); ok {
		if v < 0 || v > 65535 {
			return 0
		}
		return uint16(v)
	}
	return 0
}

// HandleSetNetworkPolicy sets or updates a network's policy constraints.
// Requires owner or admin role (or global/per-network admin token).
// Enterprise gate applies: only enterprise networks may have policies.
func (st *Store) HandleSetNetworkPolicy(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")

	if err := st.auth(msg, netID); err != nil {
		return nil, err
	}

	if err := st.enterprise(netID); err != nil {
		return nil, err
	}

	state, err := st.read(netID)
	if err != nil {
		return nil, err
	}

	oldPolicy := state.Policy
	policy := state.Policy

	if v, ok := msg["max_members"].(float64); ok {
		if v < 0 || v > 10000 || v != float64(int(v)) {
			return nil, fmt.Errorf("invalid max_members (must be integer 0-10000)")
		}
		newMax := int(v)
		if newMax > 0 && state.MemberCount > newMax {
			return nil, fmt.Errorf("cannot set max_members to %d: network already has %d members", newMax, state.MemberCount)
		}
		policy.MaxMembers = newMax
	}

	if v, ok := msg["allowed_ports"].([]interface{}); ok {
		if len(v) > 100 {
			return nil, fmt.Errorf("too many allowed_ports (max 100)")
		}
		policy.AllowedPorts = nil
		seen := make(map[uint16]bool, len(v))
		for _, p := range v {
			port, ok := p.(float64)
			if !ok || port < 1 || port > 65535 || port != float64(int(port)) {
				return nil, fmt.Errorf("invalid port number in allowed_ports (must be integer 1-65535)")
			}
			p16 := uint16(port)
			if !seen[p16] {
				seen[p16] = true
				policy.AllowedPorts = append(policy.AllowedPorts, p16)
			}
		}
	}

	if v, ok := msg["description"].(string); ok {
		if len(v) > 256 {
			return nil, fmt.Errorf("policy description too long (max 256 chars)")
		}
		policy.Description = v
	}

	if err := st.write(netID, policy, state.Expr); err != nil {
		return nil, err
	}

	st.cb.Save()

	slog.Info("network policy updated", "network_id", netID, "max_members", policy.MaxMembers,
		"allowed_ports", policy.AllowedPorts, "description", policy.Description)
	st.cb.Audit("network.policy_changed", "network_id", netID,
		"old_max_members", oldPolicy.MaxMembers, "new_max_members", policy.MaxMembers,
		"old_allowed_ports_count", len(oldPolicy.AllowedPorts), "new_allowed_ports_count", len(policy.AllowedPorts))
	st.cb.IncPolicyChanges()

	return map[string]interface{}{
		"type":          "set_network_policy_ok",
		"network_id":    netID,
		"max_members":   policy.MaxMembers,
		"allowed_ports": policy.AllowedPorts,
		"description":   policy.Description,
	}, nil
}

// HandleGetNetworkPolicy returns the policy for a given network.
// Any caller may query the policy (no role check required).
func (st *Store) HandleGetNetworkPolicy(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")

	state, err := st.read(netID)
	if err != nil {
		return nil, err
	}

	// Convert AllowedPorts to []interface{} for JSON round-trip compatibility.
	var ports []interface{}
	for _, p := range state.Policy.AllowedPorts {
		ports = append(ports, float64(p))
	}
	if ports == nil {
		ports = []interface{}{}
	}

	return map[string]interface{}{
		"type":          "get_network_policy_ok",
		"network_id":    netID,
		"max_members":   state.Policy.MaxMembers,
		"allowed_ports": ports,
		"description":   state.Policy.Description,
	}, nil
}

// HandleSetExprPolicy sets or replaces the programmable expression-policy for
// a network. Requires owner or admin role (or global/per-network admin token).
func (st *Store) HandleSetExprPolicy(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")

	if err := st.auth(msg, netID); err != nil {
		return nil, err
	}

	state, err := st.read(netID)
	if err != nil {
		return nil, err
	}

	var policyData json.RawMessage
	if v, ok := msg["expr_policy"].(string); ok {
		if v == "" || v == "null" {
			// Clear policy.
			if err := st.write(netID, state.Policy, nil); err != nil {
				return nil, err
			}
			st.cb.Save()
			slog.Info("expr policy cleared", "network_id", netID)
			st.cb.Audit("network.expr_policy_cleared", "network_id", netID)
			return map[string]interface{}{
				"type":       "set_expr_policy_ok",
				"network_id": netID,
				"cleared":    true,
			}, nil
		}
		policyData = json.RawMessage(v)
	} else if v, ok := msg["expr_policy"].(map[string]interface{}); ok {
		b, _ := json.Marshal(v)
		policyData = json.RawMessage(b)
	} else {
		return nil, fmt.Errorf("expr_policy field is required")
	}

	var check struct {
		Version int             `json:"version"`
		Rules   json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(policyData, &check); err != nil {
		return nil, fmt.Errorf("expr_policy: invalid JSON: %w", err)
	}
	if check.Version != 1 {
		return nil, fmt.Errorf("expr_policy: unsupported version %d (want 1)", check.Version)
	}
	if len(check.Rules) == 0 || string(check.Rules) == "null" {
		return nil, fmt.Errorf("expr_policy: at least one rule is required")
	}

	if err := st.write(netID, state.Policy, policyData); err != nil {
		return nil, err
	}
	st.cb.Save()

	slog.Info("expr policy set", "network_id", netID, "size", len(policyData))
	st.cb.Audit("network.expr_policy_set", "network_id", netID, "size", len(policyData))

	return map[string]interface{}{
		"type":       "set_expr_policy_ok",
		"network_id": netID,
	}, nil
}

// HandleGetExprPolicy returns the programmable expression-policy for a network.
func (st *Store) HandleGetExprPolicy(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")

	state, err := st.read(netID)
	if err != nil {
		return nil, err
	}

	resp := map[string]interface{}{
		"type":       "get_expr_policy_ok",
		"network_id": netID,
	}
	if len(state.Expr) > 0 {
		resp["expr_policy"] = json.RawMessage(state.Expr)
	}
	return resp, nil
}

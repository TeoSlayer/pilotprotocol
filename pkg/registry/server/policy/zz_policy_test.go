// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// --- test helpers ---

// networkEntry is the in-memory representation of a network for the stub.
type networkEntry struct {
	policy     NetworkPolicy
	expr       ExprPolicy
	enterprise bool
	members    int
}

// stubStore is an in-memory policy store used in tests.
type stubStore struct {
	networks map[uint16]*networkEntry
	authErr  error // if non-nil, auth always returns this error
}

func newStubStore() *stubStore {
	return &stubStore{networks: make(map[uint16]*networkEntry)}
}

func (s *stubStore) addNetwork(id uint16, enterprise bool) {
	s.networks[id] = &networkEntry{enterprise: enterprise}
}

func (s *stubStore) addNetworkWithMembers(id uint16, enterprise bool, memberCount int) {
	s.networks[id] = &networkEntry{enterprise: enterprise, members: memberCount}
}

func (s *stubStore) read(netID uint16) (NetworkState, error) {
	n, ok := s.networks[netID]
	if !ok {
		return NetworkState{}, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}
	return NetworkState{
		Policy:      n.policy,
		Expr:        n.expr,
		MemberCount: n.members,
	}, nil
}

func (s *stubStore) write(netID uint16, p NetworkPolicy, expr ExprPolicy) error {
	n, ok := s.networks[netID]
	if !ok {
		return fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}
	n.policy = p
	n.expr = expr
	return nil
}

func (s *stubStore) auth(_ map[string]interface{}, _ uint16) error {
	return s.authErr
}

func (s *stubStore) enterprise(netID uint16) error {
	n, ok := s.networks[netID]
	if !ok {
		return fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}
	if !n.enterprise {
		return fmt.Errorf("enterprise feature: requires enterprise network")
	}
	return nil
}

// newTestStore builds a Store backed by the stub; returns it along with an
// audit log slice for assertions.
func newTestStore(stub *stubStore) (*Store, *[]string) {
	audited := &[]string{}
	st := NewStore(
		stub.read,
		stub.write,
		stub.auth,
		stub.enterprise,
		Callbacks{
			Save:             func() {},
			Audit:            func(action string, attrs ...any) { *audited = append(*audited, action) },
			IncPolicyChanges: func() {},
		},
	)
	return st, audited
}

// --- HandleSetNetworkPolicy / HandleGetNetworkPolicy round-trip ---

func TestSetGetNetworkPolicy_RoundTrip(t *testing.T) {
	t.Parallel()
	stub := newStubStore()
	stub.addNetwork(1, true) // enterprise network
	st, _ := newTestStore(stub)

	// Set max_members=50, allowed_ports=[80,443], description="test net"
	_, err := st.HandleSetNetworkPolicy(map[string]interface{}{
		"network_id":    float64(1),
		"max_members":   float64(50),
		"allowed_ports": []interface{}{float64(80), float64(443)},
		"description":   "test net",
	})
	if err != nil {
		t.Fatalf("HandleSetNetworkPolicy: %v", err)
	}

	resp, err := st.HandleGetNetworkPolicy(map[string]interface{}{
		"network_id": float64(1),
	})
	if err != nil {
		t.Fatalf("HandleGetNetworkPolicy: %v", err)
	}

	if resp["type"] != "get_network_policy_ok" {
		t.Errorf("unexpected type: %v", resp["type"])
	}
	if resp["max_members"] != 50 {
		t.Errorf("max_members: got %v, want 50", resp["max_members"])
	}
	if resp["description"] != "test net" {
		t.Errorf("description: got %v, want 'test net'", resp["description"])
	}
	ports, _ := resp["allowed_ports"].([]interface{})
	if len(ports) != 2 {
		t.Errorf("allowed_ports length: got %d, want 2", len(ports))
	}
}

// --- HandleSetExprPolicy / HandleGetExprPolicy round-trip ---

func TestSetGetExprPolicy_RoundTrip(t *testing.T) {
	t.Parallel()
	stub := newStubStore()
	stub.addNetwork(2, false) // regular network (no enterprise gate for expr policy)
	st, audited := newTestStore(stub)

	exprDoc := `{"version":1,"rules":[{"action":"allow"}]}`

	_, err := st.HandleSetExprPolicy(map[string]interface{}{
		"network_id":  float64(2),
		"expr_policy": exprDoc,
	})
	if err != nil {
		t.Fatalf("HandleSetExprPolicy: %v", err)
	}

	if len(*audited) == 0 || (*audited)[0] != "network.expr_policy_set" {
		t.Errorf("expected audit 'network.expr_policy_set', got %v", *audited)
	}

	resp, err := st.HandleGetExprPolicy(map[string]interface{}{
		"network_id": float64(2),
	})
	if err != nil {
		t.Fatalf("HandleGetExprPolicy: %v", err)
	}

	if resp["type"] != "get_expr_policy_ok" {
		t.Errorf("unexpected type: %v", resp["type"])
	}

	raw, ok := resp["expr_policy"].(json.RawMessage)
	if !ok {
		t.Fatalf("expr_policy missing from response or wrong type: %T", resp["expr_policy"])
	}

	var got map[string]interface{}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal expr_policy: %v", err)
	}
	if got["version"] != float64(1) {
		t.Errorf("version: got %v, want 1", got["version"])
	}
}

// --- Invalid network error ---

func TestSetNetworkPolicy_InvalidNetwork(t *testing.T) {
	t.Parallel()
	stub := newStubStore()
	// No networks registered — any netID should fail.
	st, _ := newTestStore(stub)

	_, err := st.HandleSetNetworkPolicy(map[string]interface{}{
		"network_id":  float64(99),
		"max_members": float64(10),
	})
	if err == nil {
		t.Fatal("expected error for unknown network, got nil")
	}
}

func TestGetNetworkPolicy_InvalidNetwork(t *testing.T) {
	t.Parallel()
	stub := newStubStore()
	st, _ := newTestStore(stub)

	_, err := st.HandleGetNetworkPolicy(map[string]interface{}{
		"network_id": float64(99),
	})
	if err == nil {
		t.Fatal("expected error for unknown network, got nil")
	}
}

// --- Expr policy clear ---

func TestSetExprPolicy_Clear(t *testing.T) {
	t.Parallel()
	stub := newStubStore()
	stub.addNetwork(3, false)
	st, audited := newTestStore(stub)

	// First set a policy.
	_, err := st.HandleSetExprPolicy(map[string]interface{}{
		"network_id":  float64(3),
		"expr_policy": `{"version":1,"rules":[{"action":"allow"}]}`,
	})
	if err != nil {
		t.Fatalf("set: %v", err)
	}

	// Now clear it with empty string.
	resp, err := st.HandleSetExprPolicy(map[string]interface{}{
		"network_id":  float64(3),
		"expr_policy": "",
	})
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if resp["cleared"] != true {
		t.Errorf("expected cleared=true, got %v", resp["cleared"])
	}

	// Verify cleared.
	gr, err := st.HandleGetExprPolicy(map[string]interface{}{
		"network_id": float64(3),
	})
	if err != nil {
		t.Fatalf("get after clear: %v", err)
	}
	if _, present := gr["expr_policy"]; present {
		t.Errorf("expected expr_policy absent after clear, got %v", gr["expr_policy"])
	}

	// Check audit trail contains both set and clear events.
	if len(*audited) < 2 {
		t.Fatalf("expected at least 2 audit entries, got %d", len(*audited))
	}
	if (*audited)[len(*audited)-1] != "network.expr_policy_cleared" {
		t.Errorf("last audit: got %q, want 'network.expr_policy_cleared'", (*audited)[len(*audited)-1])
	}
}

// --- Validation: invalid max_members ---

func TestSetNetworkPolicy_InvalidMaxMembers(t *testing.T) {
	t.Parallel()
	stub := newStubStore()
	stub.addNetwork(4, true)
	st, _ := newTestStore(stub)

	_, err := st.HandleSetNetworkPolicy(map[string]interface{}{
		"network_id":  float64(4),
		"max_members": float64(-1), // negative invalid
	})
	if err == nil {
		t.Fatal("expected error for negative max_members")
	}
}

// --- Validation: max_members lower than current member count ---

func TestSetNetworkPolicy_MaxMembersTooLow(t *testing.T) {
	t.Parallel()
	stub := newStubStore()
	stub.addNetworkWithMembers(6, true, 10) // 10 current members
	st, _ := newTestStore(stub)

	_, err := st.HandleSetNetworkPolicy(map[string]interface{}{
		"network_id":  float64(6),
		"max_members": float64(5), // would evict members
	})
	if err == nil {
		t.Fatal("expected error when max_members < current member count")
	}
}

// --- Validation: invalid expr_policy version ---

func TestSetExprPolicy_BadVersion(t *testing.T) {
	t.Parallel()
	stub := newStubStore()
	stub.addNetwork(5, false)
	st, _ := newTestStore(stub)

	_, err := st.HandleSetExprPolicy(map[string]interface{}{
		"network_id":  float64(5),
		"expr_policy": `{"version":2,"rules":[{"action":"allow"}]}`,
	})
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

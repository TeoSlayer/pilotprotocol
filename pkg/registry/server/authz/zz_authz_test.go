// SPDX-License-Identifier: AGPL-3.0-or-later

package authz_test

import (
	"errors"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry/server/authz"
)

// --- stubs ---

type stubNetworkReader struct {
	networks map[uint16]struct {
		adminToken string
		enterprise bool
		roles      map[uint32]authz.Role
	}
}

func newStubNetworkReader() *stubNetworkReader {
	return &stubNetworkReader{
		networks: make(map[uint16]struct {
			adminToken string
			enterprise bool
			roles      map[uint32]authz.Role
		}),
	}
}

func (s *stubNetworkReader) addNetwork(netID uint16, adminToken string, enterprise bool, roles map[uint32]authz.Role) {
	s.networks[netID] = struct {
		adminToken string
		enterprise bool
		roles      map[uint32]authz.Role
	}{adminToken: adminToken, enterprise: enterprise, roles: roles}
}

func (s *stubNetworkReader) GetNetworkAdminToken(netID uint16) (string, bool) {
	n, ok := s.networks[netID]
	return n.adminToken, ok
}

func (s *stubNetworkReader) GetMemberRole(netID uint16, nodeID uint32) (authz.Role, bool) {
	n, ok := s.networks[netID]
	if !ok {
		return "", false
	}
	role, has := n.roles[nodeID]
	return role, has
}

func (s *stubNetworkReader) IsEnterpriseNetwork(netID uint16) (bool, bool) {
	n, ok := s.networks[netID]
	return n.enterprise, ok
}

type stubNodeReader struct {
	nodes map[uint32][]uint16
}

func (s *stubNodeReader) GetNodeNetworks(nodeID uint32) ([]uint16, bool) {
	nets, ok := s.nodes[nodeID]
	return nets, ok
}

// --- RequireAdminToken tests ---

func TestRequireAdminToken_Pass(t *testing.T) {
	t.Parallel()
	c := authz.NewChecker("secret123", "")
	msg := map[string]interface{}{"admin_token": "secret123"}
	if err := c.RequireAdminToken(msg); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestRequireAdminToken_Fail_WrongToken(t *testing.T) {
	t.Parallel()
	c := authz.NewChecker("secret123", "")
	msg := map[string]interface{}{"admin_token": "wrongtoken"}
	if err := c.RequireAdminToken(msg); err == nil {
		t.Fatal("expected error for wrong token, got nil")
	}
}

func TestRequireAdminToken_Fail_EmptyConfiguredToken(t *testing.T) {
	t.Parallel()
	c := authz.NewChecker("", "")
	msg := map[string]interface{}{"admin_token": "anything"}
	err := c.RequireAdminToken(msg)
	if err == nil {
		t.Fatal("expected error when no admin token configured")
	}
}

func TestCheckAdminToken_Bool(t *testing.T) {
	t.Parallel()
	c := authz.NewChecker("tok", "")
	if !c.CheckAdminToken(map[string]interface{}{"admin_token": "tok"}) {
		t.Fatal("expected true")
	}
	if c.CheckAdminToken(map[string]interface{}{"admin_token": "bad"}) {
		t.Fatal("expected false")
	}
}

// --- RequireNetworkRole tests ---

func TestRequireNetworkRole_GlobalAdmin(t *testing.T) {
	t.Parallel()
	c := authz.NewChecker("globaladmin", "")
	nr := newStubNetworkReader()
	nr.addNetwork(1, "", false, map[uint32]authz.Role{42: authz.RoleMember})

	msg := map[string]interface{}{
		"admin_token": "globaladmin",
		"node_id":     float64(99), // not a member
	}
	// Global admin should pass regardless of role.
	if err := c.RequireNetworkRole(msg, 1, nr, authz.RoleOwner); err != nil {
		t.Fatalf("global admin should be authorized: %v", err)
	}
}

func TestRequireNetworkRole_PerNetworkAdminToken(t *testing.T) {
	t.Parallel()
	c := authz.NewChecker("globaladmin", "")
	nr := newStubNetworkReader()
	nr.addNetwork(1, "nettoken", false, nil)

	msg := map[string]interface{}{
		"admin_token": "nettoken",
		"node_id":     float64(99),
	}
	if err := c.RequireNetworkRole(msg, 1, nr, authz.RoleOwner); err != nil {
		t.Fatalf("per-network admin token should be authorized: %v", err)
	}
}

func TestRequireNetworkRole_RBAC_Pass(t *testing.T) {
	t.Parallel()
	c := authz.NewChecker("globaladmin", "")
	nr := newStubNetworkReader()
	nr.addNetwork(2, "", false, map[uint32]authz.Role{7: authz.RoleAdmin})

	msg := map[string]interface{}{
		"admin_token": "wrongtoken",
		"node_id":     float64(7),
	}
	if err := c.RequireNetworkRole(msg, 2, nr, authz.RoleOwner, authz.RoleAdmin); err != nil {
		t.Fatalf("admin role should be authorized: %v", err)
	}
}

func TestRequireNetworkRole_RBAC_Fail_InsufficientRole(t *testing.T) {
	t.Parallel()
	c := authz.NewChecker("globaladmin", "")
	nr := newStubNetworkReader()
	nr.addNetwork(2, "", false, map[uint32]authz.Role{7: authz.RoleMember})

	msg := map[string]interface{}{
		"admin_token": "wrongtoken",
		"node_id":     float64(7),
	}
	err := c.RequireNetworkRole(msg, 2, nr, authz.RoleOwner, authz.RoleAdmin)
	if err == nil {
		t.Fatal("member should not be authorized for owner/admin operations")
	}
}

func TestRequireNetworkRole_NetworkNotFound(t *testing.T) {
	t.Parallel()
	c := authz.NewChecker("", "")
	nr := newStubNetworkReader() // empty — no networks

	msg := map[string]interface{}{"node_id": float64(1)}
	err := c.RequireNetworkRole(msg, 99, nr, authz.RoleOwner)
	if err == nil {
		t.Fatal("expected error for non-existent network")
	}
	if !errors.Is(err, protocol.ErrNetworkNotFound) {
		t.Fatalf("expected ErrNetworkNotFound, got: %v", err)
	}
}

// --- RequireEnterprise tests ---

func TestRequireEnterprise_Pass(t *testing.T) {
	t.Parallel()
	c := authz.NewChecker("", "")
	nr := newStubNetworkReader()
	nr.addNetwork(3, "", true, nil)

	if err := c.RequireEnterprise(3, nr); err != nil {
		t.Fatalf("expected nil for enterprise network: %v", err)
	}
}

func TestRequireEnterprise_Fail_NonEnterprise(t *testing.T) {
	t.Parallel()
	c := authz.NewChecker("", "")
	nr := newStubNetworkReader()
	nr.addNetwork(3, "", false, nil)

	if err := c.RequireEnterprise(3, nr); err == nil {
		t.Fatal("expected error for non-enterprise network")
	}
}

func TestRequireEnterprise_Fail_NetworkNotFound(t *testing.T) {
	t.Parallel()
	c := authz.NewChecker("", "")
	nr := newStubNetworkReader()

	err := c.RequireEnterprise(99, nr)
	if err == nil {
		t.Fatal("expected error for non-existent network")
	}
	if !errors.Is(err, protocol.ErrNetworkNotFound) {
		t.Fatalf("expected ErrNetworkNotFound, got: %v", err)
	}
}

// --- IsEnterpriseNode tests ---

func TestIsEnterpriseNode_True(t *testing.T) {
	t.Parallel()
	c := authz.NewChecker("", "")
	nr := newStubNetworkReader()
	nr.addNetwork(10, "", true, nil)

	nodes := &stubNodeReader{nodes: map[uint32][]uint16{5: {10}}}
	if !c.IsEnterpriseNode(5, nodes, nr) {
		t.Fatal("expected true for node in enterprise network")
	}
}

func TestIsEnterpriseNode_False_NoEnterpriseNetwork(t *testing.T) {
	t.Parallel()
	c := authz.NewChecker("", "")
	nr := newStubNetworkReader()
	nr.addNetwork(10, "", false, nil)

	nodes := &stubNodeReader{nodes: map[uint32][]uint16{5: {10}}}
	if c.IsEnterpriseNode(5, nodes, nr) {
		t.Fatal("expected false for node only in non-enterprise network")
	}
}

func TestIsEnterpriseNode_False_UnknownNode(t *testing.T) {
	t.Parallel()
	c := authz.NewChecker("", "")
	nr := newStubNetworkReader()
	nodes := &stubNodeReader{nodes: map[uint32][]uint16{}}

	if c.IsEnterpriseNode(99, nodes, nr) {
		t.Fatal("expected false for unknown node")
	}
}

// --- VerifyNodeSignature / VerifyHeartbeatSignature tests ---

func TestVerifyNodeSignature_NilPubKey_ValidAdminToken(t *testing.T) {
	t.Parallel()
	msg := map[string]interface{}{"admin_token": "tok"}
	if err := authz.VerifyNodeSignature(nil, "tok", msg, "challenge"); err != nil {
		t.Fatalf("nil pubkey with valid admin token should pass: %v", err)
	}
}

func TestVerifyNodeSignature_NilPubKey_InvalidAdminToken(t *testing.T) {
	t.Parallel()
	msg := map[string]interface{}{"admin_token": "wrong"}
	if err := authz.VerifyNodeSignature(nil, "tok", msg, "challenge"); err == nil {
		t.Fatal("nil pubkey with invalid admin token should fail")
	}
}

func TestVerifyNodeSignature_MissingSignature(t *testing.T) {
	t.Parallel()
	pubKey := []byte{0x01, 0x02} // non-nil but won't be reached for signature check
	msg := map[string]interface{}{}
	err := authz.VerifyNodeSignature(pubKey, "", msg, "challenge")
	if err == nil {
		t.Fatal("missing signature field should fail")
	}
}

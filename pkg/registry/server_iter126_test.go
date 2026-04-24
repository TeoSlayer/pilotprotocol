// SPDX-License-Identifier: AGPL-3.0-or-later

package registry

import (
	"strings"
	"testing"
	"time"
)

// newTestServer returns a Server with admin token pre-set and tears down on cleanup.
// Uses storePath="" so no disk I/O or WAL; saveLoop/statsCollectorLoop still spawn
// but Close() drains them via s.done → saveDone.
func newTestServer(t *testing.T, adminToken string) *Server {
	t.Helper()
	s := New("")
	t.Cleanup(func() { _ = s.Close() })
	if adminToken != "" {
		s.SetAdminToken(adminToken)
	}
	return s
}

// --- checkAdminToken -----------------------------------------------------

func TestCheckAdminTokenDisabledWhenEmpty(t *testing.T) {
	s := newTestServer(t, "")
	err := s.checkAdminToken(map[string]interface{}{"admin_token": "anything"}, "")
	if err == nil || !strings.Contains(err.Error(), "network creation is disabled") {
		t.Fatalf("%v", err)
	}
}

func TestCheckAdminTokenMismatchRejected(t *testing.T) {
	s := newTestServer(t, "")
	err := s.checkAdminToken(map[string]interface{}{"admin_token": "wrong"}, "expected")
	if err == nil || !strings.Contains(err.Error(), "invalid admin token") {
		t.Fatalf("%v", err)
	}
}

func TestCheckAdminTokenMissingFieldRejected(t *testing.T) {
	s := newTestServer(t, "")
	// admin_token absent → token=="" → ConstantTimeCompare ""/expected → mismatch.
	err := s.checkAdminToken(map[string]interface{}{}, "expected")
	if err == nil || !strings.Contains(err.Error(), "invalid admin token") {
		t.Fatalf("%v", err)
	}
}

func TestCheckAdminTokenMatchAllows(t *testing.T) {
	s := newTestServer(t, "")
	if err := s.checkAdminToken(map[string]interface{}{"admin_token": "ok"}, "ok"); err != nil {
		t.Fatalf("%v", err)
	}
}

// --- requireAdminToken + requireAdminTokenLocked ------------------------

func TestRequireAdminTokenUsesServerToken(t *testing.T) {
	s := newTestServer(t, "server-secret")
	if err := s.requireAdminToken(map[string]interface{}{"admin_token": "server-secret"}); err != nil {
		t.Fatalf("good token: %v", err)
	}
	err := s.requireAdminToken(map[string]interface{}{"admin_token": "wrong"})
	if err == nil || !strings.Contains(err.Error(), "invalid admin token") {
		t.Fatalf("bad: %v", err)
	}
}

func TestRequireAdminTokenLockedSkipsRLock(t *testing.T) {
	// Just checks the function dispatches through checkAdminToken with server's token.
	s := newTestServer(t, "tok")
	s.mu.Lock()
	err := s.requireAdminTokenLocked(map[string]interface{}{"admin_token": "tok"})
	s.mu.Unlock()
	if err != nil {
		t.Fatalf("%v", err)
	}
}

// --- requireEnterprise --------------------------------------------------

func TestRequireEnterpriseNetworkNotFound(t *testing.T) {
	s := newTestServer(t, "")
	err := s.requireEnterprise(9999)
	if err == nil || !strings.Contains(err.Error(), "network 9999") {
		t.Fatalf("%v", err)
	}
}

func TestRequireEnterpriseNonEnterpriseRejected(t *testing.T) {
	s := newTestServer(t, "")
	s.mu.Lock()
	s.networks[42] = &NetworkInfo{ID: 42, Name: "plain", Enterprise: false}
	s.mu.Unlock()
	err := s.requireEnterprise(42)
	if err == nil || !strings.Contains(err.Error(), "requires enterprise network") {
		t.Fatalf("%v", err)
	}
}

func TestRequireEnterpriseAllowsEnterpriseNetwork(t *testing.T) {
	s := newTestServer(t, "")
	s.mu.Lock()
	s.networks[7] = &NetworkInfo{ID: 7, Name: "ent", Enterprise: true}
	s.mu.Unlock()
	if err := s.requireEnterprise(7); err != nil {
		t.Fatalf("%v", err)
	}
}

// --- isEnterpriseNode ---------------------------------------------------

func TestIsEnterpriseNodeUnknownNode(t *testing.T) {
	s := newTestServer(t, "")
	if s.isEnterpriseNode(9999) {
		t.Fatal("unknown node should not be enterprise")
	}
}

func TestIsEnterpriseNodeTrueWhenAnyNetworkIsEnterprise(t *testing.T) {
	s := newTestServer(t, "")
	s.mu.Lock()
	s.networks[1] = &NetworkInfo{ID: 1, Enterprise: false}
	s.networks[2] = &NetworkInfo{ID: 2, Enterprise: true}
	s.nodes[100] = &NodeInfo{ID: 100, Networks: []uint16{1, 2}}
	s.mu.Unlock()
	if !s.isEnterpriseNode(100) {
		t.Fatal("node in any enterprise network → true")
	}
}

func TestIsEnterpriseNodeFalseWhenNoEnterpriseNetwork(t *testing.T) {
	s := newTestServer(t, "")
	s.mu.Lock()
	s.networks[1] = &NetworkInfo{ID: 1, Enterprise: false}
	s.networks[2] = &NetworkInfo{ID: 2, Enterprise: false}
	s.nodes[100] = &NodeInfo{ID: 100, Networks: []uint16{1, 2}}
	s.mu.Unlock()
	if s.isEnterpriseNode(100) {
		t.Fatal("node in only non-enterprise networks → false")
	}
}

func TestIsEnterpriseNodeIgnoresMissingNetworks(t *testing.T) {
	s := newTestServer(t, "")
	s.mu.Lock()
	// Node refers to network 5 which does not exist in s.networks.
	s.nodes[100] = &NodeInfo{ID: 100, Networks: []uint16{5}}
	s.mu.Unlock()
	if s.isEnterpriseNode(100) {
		t.Fatal("missing-network reference → false, not panic")
	}
}

// --- appendAudit --------------------------------------------------------

func TestAppendAuditPopulatesEntryAndReturns(t *testing.T) {
	s := newTestServer(t, "")
	entry := s.appendAudit("register", 7, 42, "key", "value", "extra", 99)
	if entry == nil {
		t.Fatal("nil entry returned")
	}
	if entry.Action != "register" || entry.NetworkID != 7 || entry.NodeID != 42 {
		t.Fatalf("core fields: %+v", entry)
	}
	if !strings.Contains(entry.Details, "key=value") || !strings.Contains(entry.Details, "extra=99") {
		t.Fatalf("details: %q", entry.Details)
	}
	if _, err := time.Parse(time.RFC3339, entry.Timestamp); err != nil {
		t.Fatalf("bad timestamp: %q", entry.Timestamp)
	}
	// Appended to the ring buffer.
	s.auditMu.Lock()
	if len(s.auditLog) != 1 {
		t.Fatalf("auditLog len: %d", len(s.auditLog))
	}
	s.auditMu.Unlock()
}

func TestAppendAuditExtractsNodeIDFromAttrs(t *testing.T) {
	s := newTestServer(t, "")
	// Pass zero netID/nodeID explicitly; they should be back-filled from attrs.
	entry := s.appendAudit("act", 0, 0, "node_id", uint32(77), "network_id", uint16(3), "det", "x")
	if entry.NodeID != 77 || entry.NetworkID != 3 {
		t.Fatalf("id extraction: %+v", entry)
	}
	if !strings.Contains(entry.Details, "det=x") || strings.Contains(entry.Details, "node_id=") {
		t.Fatalf("details should exclude node_id/network_id, got %q", entry.Details)
	}
}

func TestAppendAuditTrimsWhenExceedingMax(t *testing.T) {
	s := newTestServer(t, "")
	// Pre-fill the audit log at the cap.
	s.auditMu.Lock()
	for i := 0; i < maxAuditEntries; i++ {
		s.auditLog = append(s.auditLog, AuditEntry{Action: "x"})
	}
	s.auditMu.Unlock()

	s.appendAudit("trigger-trim", 0, 0)

	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if len(s.auditLog) != maxAuditEntries {
		t.Fatalf("len after trim: %d, want %d", len(s.auditLog), maxAuditEntries)
	}
	if s.auditLog[len(s.auditLog)-1].Action != "trigger-trim" {
		t.Fatalf("newest not at tail: %+v", s.auditLog[len(s.auditLog)-1])
	}
	// Oldest should have been dropped — the first N-1 entries are the originals shifted by 1.
	if s.auditLog[0].Action != "x" {
		t.Fatalf("expected original entries to remain at head, got %+v", s.auditLog[0])
	}
}

func TestAppendAuditTypeCoercionFromFloat64AndInt(t *testing.T) {
	s := newTestServer(t, "")
	// JSON numbers arrive as float64 in map[string]interface{}.
	entry := s.appendAudit("a", 0, 0, "node_id", float64(123), "network_id", float64(5))
	if entry.NodeID != 123 || entry.NetworkID != 5 {
		t.Fatalf("float64 coercion: %+v", entry)
	}
	entry = s.appendAudit("a", 0, 0, "node_id", int(200), "network_id", int(9))
	if entry.NodeID != 200 || entry.NetworkID != 9 {
		t.Fatalf("int coercion: %+v", entry)
	}
}

// --- auditEnterprise ----------------------------------------------------

func TestAuditEnterpriseSkipsNonEnterpriseNetworks(t *testing.T) {
	s := newTestServer(t, "")
	s.mu.Lock()
	s.networks[1] = &NetworkInfo{ID: 1, Enterprise: false}
	s.mu.Unlock()

	before := len(s.auditLog)
	s.auditEnterprise(1, "should-not-audit", "k", "v")
	if len(s.auditLog) != before {
		t.Fatalf("auditEnterprise should skip non-enterprise nets; len %d→%d", before, len(s.auditLog))
	}
}

func TestAuditEnterpriseSkipsUnknownNetworks(t *testing.T) {
	s := newTestServer(t, "")
	before := len(s.auditLog)
	s.auditEnterprise(99, "should-not-audit")
	if len(s.auditLog) != before {
		t.Fatalf("unknown-net should skip; len %d→%d", before, len(s.auditLog))
	}
}

func TestAuditEnterpriseLogsForEnterpriseNetwork(t *testing.T) {
	s := newTestServer(t, "")
	s.mu.Lock()
	s.networks[7] = &NetworkInfo{ID: 7, Enterprise: true}
	s.mu.Unlock()

	s.auditEnterprise(7, "provision-done", "count", 3)
	s.auditMu.Lock()
	last := s.auditLog[len(s.auditLog)-1]
	s.auditMu.Unlock()
	if last.Action != "provision-done" || last.NetworkID != 7 {
		t.Fatalf("%+v", last)
	}
	if !strings.Contains(last.Details, "count=3") {
		t.Fatalf("details: %q", last.Details)
	}
}

// --- requireNetworkRole -------------------------------------------------

func TestRequireNetworkRoleGlobalAdminAuthorizes(t *testing.T) {
	s := newTestServer(t, "global")
	s.mu.Lock()
	s.networks[1] = &NetworkInfo{ID: 1, MemberRoles: map[uint32]Role{}}
	s.mu.Unlock()
	err := s.requireNetworkRole(map[string]interface{}{"admin_token": "global"}, 1, RoleAdmin)
	if err != nil {
		t.Fatalf("global admin should authorize: %v", err)
	}
}

func TestRequireNetworkRoleMissingNetwork(t *testing.T) {
	s := newTestServer(t, "global")
	err := s.requireNetworkRole(map[string]interface{}{"admin_token": "wrong"}, 77, RoleAdmin)
	if err == nil || !strings.Contains(err.Error(), "network 77") {
		t.Fatalf("%v", err)
	}
}

func TestRequireNetworkRoleNetworkAdminTokenAuthorizes(t *testing.T) {
	s := newTestServer(t, "global")
	s.mu.Lock()
	s.networks[1] = &NetworkInfo{ID: 1, AdminToken: "per-net", MemberRoles: map[uint32]Role{}}
	s.mu.Unlock()
	err := s.requireNetworkRole(map[string]interface{}{"admin_token": "per-net"}, 1, RoleAdmin)
	if err != nil {
		t.Fatalf("per-net admin token should authorize: %v", err)
	}
}

func TestRequireNetworkRoleRequiresNodeID(t *testing.T) {
	s := newTestServer(t, "global")
	s.mu.Lock()
	s.networks[1] = &NetworkInfo{ID: 1, MemberRoles: map[uint32]Role{}}
	s.mu.Unlock()
	// No admin token, no node_id → "node_id required" error.
	err := s.requireNetworkRole(map[string]interface{}{}, 1, RoleAdmin)
	if err == nil || !strings.Contains(err.Error(), "node_id required") {
		t.Fatalf("%v", err)
	}
}

func TestRequireNetworkRoleNodeWithoutRoleRejected(t *testing.T) {
	s := newTestServer(t, "global")
	s.mu.Lock()
	s.networks[1] = &NetworkInfo{ID: 1, MemberRoles: map[uint32]Role{}}
	s.mu.Unlock()
	err := s.requireNetworkRole(map[string]interface{}{"node_id": float64(42)}, 1, RoleAdmin)
	if err == nil || !strings.Contains(err.Error(), "has no role") {
		t.Fatalf("%v", err)
	}
}

func TestRequireNetworkRoleAllowedRoleGrants(t *testing.T) {
	s := newTestServer(t, "global")
	s.mu.Lock()
	s.networks[1] = &NetworkInfo{
		ID:          1,
		MemberRoles: map[uint32]Role{42: RoleAdmin},
	}
	s.mu.Unlock()
	err := s.requireNetworkRole(map[string]interface{}{"node_id": float64(42)}, 1, RoleAdmin, RoleOwner)
	if err != nil {
		t.Fatalf("admin in allowed list should grant: %v", err)
	}
}

func TestRequireNetworkRoleDisallowedRoleRejects(t *testing.T) {
	s := newTestServer(t, "global")
	s.mu.Lock()
	s.networks[1] = &NetworkInfo{
		ID:          1,
		MemberRoles: map[uint32]Role{42: RoleMember},
	}
	s.mu.Unlock()
	err := s.requireNetworkRole(map[string]interface{}{"node_id": float64(42)}, 1, RoleAdmin, RoleOwner)
	if err == nil || !strings.Contains(err.Error(), "requires one of") {
		t.Fatalf("member should not have admin role: %v", err)
	}
}

// --- GetIdentityProviderConfig / GetAuditExportConfig ------------------

func TestGetIdentityProviderConfigNilWhenUnset(t *testing.T) {
	s := newTestServer(t, "")
	if got := s.GetIdentityProviderConfig(); got != nil {
		t.Fatalf("unset: %+v", got)
	}
}

func TestGetIdentityProviderConfigReturnsStored(t *testing.T) {
	s := newTestServer(t, "")
	idp := &BlueprintIdentityProvider{Type: "oidc", URL: "https://idp"}
	s.storeIdentityProviderConfig(idp)
	got := s.GetIdentityProviderConfig()
	if got != idp {
		t.Fatalf("got %+v, want same pointer %p", got, idp)
	}
}

func TestGetAuditExportConfigNilWhenUnset(t *testing.T) {
	s := newTestServer(t, "")
	if got := s.GetAuditExportConfig(); got != nil {
		t.Fatalf("unset: %+v", got)
	}
}

// --- storeRBACPreAssignments --------------------------------------------

func TestStoreRBACPreAssignmentsInitializesMapAndStores(t *testing.T) {
	s := newTestServer(t, "")
	// Before: rbacPreAssign is nil.
	s.mu.RLock()
	wasNil := s.rbacPreAssign == nil
	s.mu.RUnlock()
	if !wasNil {
		t.Skip("rbacPreAssign pre-initialized by constructor; skipping nil-init check")
	}

	roles := []BlueprintRole{{ExternalID: "u1", Role: "admin"}}
	s.storeRBACPreAssignments(7, roles)

	s.mu.RLock()
	got := s.rbacPreAssign[7]
	s.mu.RUnlock()
	if len(got) != 1 || got[0].ExternalID != "u1" {
		t.Fatalf("%+v", got)
	}
}

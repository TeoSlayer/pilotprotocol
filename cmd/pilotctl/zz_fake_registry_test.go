// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Round-4 coverage push: drive the success paths of every cmd* function
// that talks to the registry (not the daemon). A small in-test TCP fake
// speaks the registry JSON-over-TCP wire protocol (4B big-endian length +
// JSON body) and serves canned responses keyed by the inbound message
// "type" field.
//
// Tests are serialized via a package-local mutex because every cmd* mutates
// the global jsonOutput flag and writes to os.Stdout via captureStdout.

// fakeRegistry is a minimal TCP listener that decodes one request per
// frame and dispatches by msg["type"]. Each handler returns the reply map
// directly (or nil to drop the connection, simulating a crash). Per-type
// handler overrides take precedence over the default.
type fakeRegistry struct {
	t        *testing.T
	ln       net.Listener
	mu       sync.Mutex
	handlers map[string]func(req map[string]interface{}) map[string]interface{}
	requests atomic.Uint32
	// lastByType captures the most recent request for assertion. Last-write-
	// wins is fine since we only assert on one round-trip per test.
	lastByType sync.Map // map[string]map[string]interface{}
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := &fakeRegistry{
		t:        t,
		ln:       ln,
		handlers: map[string]func(map[string]interface{}) map[string]interface{}{},
	}
	go r.accept()
	t.Cleanup(func() { _ = ln.Close() })
	return r
}

func (r *fakeRegistry) addr() string { return r.ln.Addr().String() }

// on registers a handler for a given msg["type"] value.
func (r *fakeRegistry) on(typ string, h func(req map[string]interface{}) map[string]interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[typ] = h
}

// onOK is a convenience for the common case: reply with a fixed JSON map.
// A "type":"ok" key is auto-added if not present.
func (r *fakeRegistry) onOK(typ string, body map[string]interface{}) {
	if body == nil {
		body = map[string]interface{}{}
	}
	if _, ok := body["type"]; !ok {
		body["type"] = "ok"
	}
	r.on(typ, func(_ map[string]interface{}) map[string]interface{} {
		return body
	})
}

// last returns the most recent request map for a given type, or nil if
// no request of that type has been seen.
func (r *fakeRegistry) last(typ string) map[string]interface{} {
	v, ok := r.lastByType.Load(typ)
	if !ok {
		return nil
	}
	return v.(map[string]interface{})
}

func (r *fakeRegistry) accept() {
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			return
		}
		go r.handle(conn)
	}
}

func (r *fakeRegistry) handle(conn net.Conn) {
	defer conn.Close()
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n > 1<<20 {
			return
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		var req map[string]interface{}
		if err := json.Unmarshal(body, &req); err != nil {
			return
		}
		r.requests.Add(1)
		typ, _ := req["type"].(string)
		if typ != "" {
			r.lastByType.Store(typ, req)
		}

		r.mu.Lock()
		h := r.handlers[typ]
		r.mu.Unlock()

		var resp map[string]interface{}
		if h != nil {
			resp = h(req)
		} else {
			// Default: echo a generic ok so unknown calls don't error.
			resp = map[string]interface{}{"type": "ok"}
		}
		if resp == nil {
			return // simulate server-side disconnect
		}
		out, _ := json.Marshal(resp)
		var outLen [4]byte
		binary.BigEndian.PutUint32(outLen[:], uint32(len(out)))
		_, _ = conn.Write(outLen[:])
		_, _ = conn.Write(out)
	}
}

// regSerialize is held across every fake-registry test so that jsonOutput,
// os.Stdout, and the env-var swap don't race. captureStdout + withJSON +
// t.Setenv all mutate process-global state.
var regSerialize sync.Mutex

// useRegistry points the pilotctl client at a fake registry and (by
// default) supplies a placeholder admin token + isolated HOME. The
// returned tmp home path lets the caller seed config files if needed.
func useRegistry(t *testing.T, r *fakeRegistry) string {
	t.Helper()
	regSerialize.Lock()
	t.Cleanup(regSerialize.Unlock)

	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("PILOT_REGISTRY", r.addr())
	t.Setenv("PILOT_SOCKET", "/tmp/nope-"+t.Name()+".sock") // never reached
	t.Setenv("PILOT_ADMIN_TOKEN", "test-token")
	return tmp
}

// --- cmdRegister ----------------------------------------------------------

func TestCmdRegisterSuccessJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("register", map[string]interface{}{
		"node_id": float64(99),
		"address": "0:0000.0000.0063",
	})
	useRegistry(t, r)

	out := captureStdout(t, func() {
		withJSON(func() { cmdRegister([]string{"127.0.0.1:4000"}) })
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	data, _ := env["data"].(map[string]interface{})
	if data["node_id"].(float64) != 99 {
		t.Errorf("node_id = %v", data["node_id"])
	}
	last := r.last("register")
	if last == nil || last["listen_addr"] != "127.0.0.1:4000" {
		t.Errorf("wire listen_addr = %v", last)
	}
}

func TestCmdRegisterNoListenAddr(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("register", map[string]interface{}{"node_id": float64(7)})
	useRegistry(t, r)
	captureStdout(t, func() {
		withJSON(func() { cmdRegister(nil) })
	})
	last := r.last("register")
	if last == nil {
		t.Fatal("no register request seen")
	}
	if v, _ := last["listen_addr"].(string); v != "" {
		t.Errorf("listen_addr should be blank, got %q", v)
	}
}

// --- cmdLookup ------------------------------------------------------------

func TestCmdLookupByNumericID(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("lookup", map[string]interface{}{
		"node_id":  float64(42),
		"hostname": "alice",
		"endpoint": "1.2.3.4:4000", // should be redacted by cmdLookup
	})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() { cmdLookup([]string{"42"}) })
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	data, _ := env["data"].(map[string]interface{})
	if data["hostname"] != "alice" {
		t.Errorf("hostname = %v", data["hostname"])
	}
	if _, ok := data["endpoint"]; ok {
		t.Errorf("endpoint should have been redacted: %v", data)
	}
	last := r.last("lookup")
	if last == nil || uint32(last["node_id"].(float64)) != 42 {
		t.Errorf("wire node_id = %v", last)
	}
}

func TestCmdLookupByAddress(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("lookup", map[string]interface{}{"node_id": float64(0x2A)})
	useRegistry(t, r)
	captureStdout(t, func() {
		withJSON(func() { cmdLookup([]string{"0:0000.0000.002A"}) })
	})
	last := r.last("lookup")
	if last == nil {
		t.Fatal("no lookup")
	}
	if uint32(last["node_id"].(float64)) != 0x2A {
		t.Errorf("decoded address->node_id wrong: %v", last["node_id"])
	}
}

// --- cmdNetworkDelete -----------------------------------------------------

func TestCmdNetworkDeleteJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("delete_network", map[string]interface{}{"deleted": true})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() { cmdNetworkDelete([]string{"5"}) })
	})
	if !strings.Contains(out, `"deleted":true`) {
		t.Errorf("missing deleted=true: %s", out)
	}
	last := r.last("delete_network")
	if last == nil || uint16(last["network_id"].(float64)) != 5 {
		t.Errorf("wire network_id = %v", last)
	}
	if last["admin_token"] != "test-token" {
		t.Errorf("missing admin_token: %v", last)
	}
}

func TestCmdNetworkDeleteText(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("delete_network", map[string]interface{}{"deleted": true})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() { cmdNetworkDelete([]string{"7"}) })
	})
	if !strings.Contains(out, "deleted network 7") {
		t.Errorf("missing text banner: %s", out)
	}
}

// --- cmdNetworkRename -----------------------------------------------------

func TestCmdNetworkRenameJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("rename_network", map[string]interface{}{"renamed": true})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() { cmdNetworkRename([]string{"5", "new-name"}) })
	})
	if !strings.Contains(out, `"renamed":true`) {
		t.Errorf("missing renamed=true: %s", out)
	}
	last := r.last("rename_network")
	if last == nil || last["name"] != "new-name" {
		t.Errorf("wire name = %v", last)
	}
}

func TestCmdNetworkRenameText(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("rename_network", map[string]interface{}{"renamed": true})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() { cmdNetworkRename([]string{"5", "shiny"}) })
	})
	if !strings.Contains(out, "renamed network 5") {
		t.Errorf("missing text banner: %s", out)
	}
}

// --- cmdNetworkPromote / Demote / Kick / Role ----------------------------

func TestCmdNetworkPromoteJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("promote_member", map[string]interface{}{"promoted": true})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() { cmdNetworkPromote([]string{"5", "42"}) })
	})
	if !strings.Contains(out, `"promoted":true`) {
		t.Errorf("%s", out)
	}
	last := r.last("promote_member")
	if last == nil || uint32(last["target_node_id"].(float64)) != 42 {
		t.Errorf("wire target_node_id = %v", last)
	}
}

func TestCmdNetworkPromoteText(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("promote_member", map[string]interface{}{"promoted": true})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() { cmdNetworkPromote([]string{"5", "42"}) })
	})
	if !strings.Contains(out, "promoted node 42") {
		t.Errorf("missing text banner: %s", out)
	}
}

func TestCmdNetworkDemoteJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("demote_member", map[string]interface{}{"demoted": true})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() { cmdNetworkDemote([]string{"5", "42"}) })
	})
	if !strings.Contains(out, `"demoted":true`) {
		t.Errorf("%s", out)
	}
}

func TestCmdNetworkDemoteText(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("demote_member", map[string]interface{}{"demoted": true})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() { cmdNetworkDemote([]string{"5", "42"}) })
	})
	if !strings.Contains(out, "demoted node 42") {
		t.Errorf("missing text banner: %s", out)
	}
}

func TestCmdNetworkKickJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("kick_member", map[string]interface{}{"kicked": true})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() { cmdNetworkKick([]string{"5", "42"}) })
	})
	if !strings.Contains(out, `"kicked":true`) {
		t.Errorf("%s", out)
	}
}

func TestCmdNetworkKickText(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("kick_member", map[string]interface{}{"kicked": true})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() { cmdNetworkKick([]string{"5", "42"}) })
	})
	if !strings.Contains(out, "kicked node 42") {
		t.Errorf("missing text banner: %s", out)
	}
}

func TestCmdNetworkRoleJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("get_member_role", map[string]interface{}{"role": "admin"})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() { cmdNetworkRole([]string{"5", "42"}) })
	})
	if !strings.Contains(out, `"role":"admin"`) {
		t.Errorf("%s", out)
	}
}

func TestCmdNetworkRoleText(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("get_member_role", map[string]interface{}{"role": "member"})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() { cmdNetworkRole([]string{"5", "42"}) })
	})
	if !strings.Contains(out, "role=member") {
		t.Errorf("missing text role: %s", out)
	}
}

// --- cmdNetworkPolicy: get + set ----------------------------------------

func TestCmdNetworkPolicyGet(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("get_network_policy", map[string]interface{}{
		"network_id":  float64(5),
		"max_members": float64(50),
		"description": "the network",
	})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() { cmdNetworkPolicy([]string{"5"}) })
	})
	if !strings.Contains(out, `"description":"the network"`) {
		t.Errorf("%s", out)
	}
}

func TestCmdNetworkPolicySet(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("set_network_policy", map[string]interface{}{"updated": true})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() {
			cmdNetworkPolicy([]string{"5",
				"--max-members", "100",
				"--description", "hello",
				"--allowed-ports", "80,443,8080",
			})
		})
	})
	if !strings.Contains(out, `"updated":true`) {
		t.Errorf("%s", out)
	}
	last := r.last("set_network_policy")
	if last == nil {
		t.Fatal("no set_network_policy request")
	}
	// SetNetworkPolicy flattens the policy map into the top-level request.
	if last["max_members"].(float64) != 100 {
		t.Errorf("max_members = %v", last["max_members"])
	}
	if last["description"] != "hello" {
		t.Errorf("description = %v", last["description"])
	}
	ports, _ := last["allowed_ports"].([]interface{})
	if len(ports) != 3 {
		t.Errorf("allowed_ports = %v", ports)
	}
}

func TestCmdNetworkPolicySetText(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("set_network_policy", map[string]interface{}{"updated": true})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() {
			cmdNetworkPolicy([]string{"5", "--description", "x"})
		})
	})
	if !strings.Contains(out, "updated policy for network 5") {
		t.Errorf("missing text banner: %s", out)
	}
}

// --- cmdAudit -------------------------------------------------------------

func TestCmdAuditJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("get_audit_log", map[string]interface{}{
		"entries": []interface{}{
			map[string]interface{}{
				"timestamp":  "2026-01-01T00:00:00Z",
				"action":     "network.create",
				"node_id":    float64(42),
				"network_id": float64(5),
				"details":    "ok",
			},
		},
	})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() { cmdAudit([]string{"--network", "5"}) })
	})
	if !strings.Contains(out, "network.create") {
		t.Errorf("%s", out)
	}
}

func TestCmdAuditTextEmpty(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("get_audit_log", map[string]interface{}{"entries": []interface{}{}})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() { cmdAudit([]string{}) })
	})
	if !strings.Contains(out, "no audit entries") {
		t.Errorf("missing 'no audit entries' banner: %s", out)
	}
}

func TestCmdAuditTextEntries(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("get_audit_log", map[string]interface{}{
		"entries": []interface{}{
			map[string]interface{}{
				"timestamp":  "2026-01-01T00:00:00Z",
				"action":     "member.kick",
				"node_id":    float64(7),
				"network_id": float64(3),
				"details":    "reason: spam",
			},
			map[string]interface{}{
				"timestamp": "2026-01-02T00:00:00Z",
				"action":    "network.delete",
			},
		},
	})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() { cmdAudit([]string{}) })
	})
	if !strings.Contains(out, "member.kick") || !strings.Contains(out, "node=7") {
		t.Errorf("text audit missing fields: %s", out)
	}
}

// --- cmdProvision ---------------------------------------------------------

func TestCmdProvisionJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("provision_network", map[string]interface{}{
		"network_id": float64(8),
		"name":       "my-net",
		"actions":    []interface{}{"created network", "applied policy"},
	})
	useRegistry(t, r)

	dir := t.TempDir()
	bp := filepath.Join(dir, "blueprint.json")
	body := `{"name":"my-net","join_rule":"invite","admin_token":"x"}`
	if err := os.WriteFile(bp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		withJSON(func() { cmdProvision([]string{bp}) })
	})
	if !strings.Contains(out, `"name":"my-net"`) {
		t.Errorf("%s", out)
	}
	last := r.last("provision_network")
	if last == nil {
		t.Fatal("no provision request")
	}
}

func TestCmdProvisionText(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("provision_network", map[string]interface{}{
		"network_id": float64(8),
		"name":       "my-net",
		"actions":    []interface{}{"created network", "applied policy"},
	})
	useRegistry(t, r)

	dir := t.TempDir()
	bp := filepath.Join(dir, "blueprint.json")
	if err := os.WriteFile(bp, []byte(`{"name":"my-net"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		withText(func() { cmdProvision([]string{bp}) })
	})
	if !strings.Contains(out, "provisioned network 8") {
		t.Errorf("missing provision banner: %s", out)
	}
	if !strings.Contains(out, "applied policy") {
		t.Errorf("missing actions: %s", out)
	}
}

// --- cmdDeprovision -------------------------------------------------------

func TestCmdDeprovisionFound(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("list_networks", map[string]interface{}{
		"networks": []interface{}{
			map[string]interface{}{"id": float64(3), "name": "other"},
			map[string]interface{}{"id": float64(7), "name": "my-net"},
		},
	})
	r.onOK("delete_network", map[string]interface{}{"deleted": true})
	useRegistry(t, r)

	out := captureStdout(t, func() {
		withText(func() { cmdDeprovision([]string{"my-net"}) })
	})
	if !strings.Contains(out, "deprovisioned network") || !strings.Contains(out, "id=7") {
		t.Errorf("missing deprovision banner: %s", out)
	}
	last := r.last("delete_network")
	if last == nil || uint16(last["network_id"].(float64)) != 7 {
		t.Errorf("delete network_id wrong: %v", last)
	}
}

func TestCmdDeprovisionFoundJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("list_networks", map[string]interface{}{
		"networks": []interface{}{
			map[string]interface{}{"id": float64(1), "name": "n1"},
		},
	})
	r.onOK("delete_network", map[string]interface{}{"deleted": true})
	useRegistry(t, r)

	out := captureStdout(t, func() {
		withJSON(func() { cmdDeprovision([]string{"n1"}) })
	})
	if !strings.Contains(out, `"deleted":true`) {
		t.Errorf("%s", out)
	}
}

// --- cmdIDP get + set + disable ------------------------------------------

func TestCmdIDPGetConfigured(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("get_idp_config", map[string]interface{}{
		"configured": true,
		"idp_type":   "oidc",
		"url":        "https://idp.example.com",
		"issuer":     "https://issuer.example.com",
		"tenant_id":  "tnt",
		"client_id":  "cid",
	})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() { cmdIDP([]string{"get"}) })
	})
	if !strings.Contains(out, "IdP: oidc") {
		t.Errorf("missing IdP banner: %s", out)
	}
	if !strings.Contains(out, "issuer:") {
		t.Errorf("missing issuer line: %s", out)
	}
}

func TestCmdIDPGetUnconfigured(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("get_idp_config", map[string]interface{}{"configured": false})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() { cmdIDP([]string{"get"}) })
	})
	if !strings.Contains(out, "no identity provider") {
		t.Errorf("missing 'no identity provider': %s", out)
	}
}

func TestCmdIDPGetJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("get_idp_config", map[string]interface{}{"configured": false})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() { cmdIDP([]string{"get"}) })
	})
	if !strings.Contains(out, `"configured":false`) {
		t.Errorf("%s", out)
	}
}

func TestCmdIDPSetJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("set_idp_config", map[string]interface{}{"status": "ok"})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() {
			cmdIDP([]string{"set", "--type", "oidc", "--url", "https://idp.example.com"})
		})
	})
	if !strings.Contains(out, `"status":"ok"`) {
		t.Errorf("%s", out)
	}
}

func TestCmdIDPSetText(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("set_idp_config", map[string]interface{}{"status": "ok"})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() {
			cmdIDP([]string{"set", "--type", "oidc", "--url", "https://idp.example.com"})
		})
	})
	if !strings.Contains(out, "identity provider configured: oidc") {
		t.Errorf("%s", out)
	}
}

// --- cmdAuditExport get + set + disable ----------------------------------

func TestCmdAuditExportGetEnabled(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("get_audit_export", map[string]interface{}{
		"enabled":  true,
		"format":   "splunk_hec",
		"endpoint": "https://hec.example.com",
		"exported": float64(10),
		"dropped":  float64(0),
	})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() { cmdAuditExport([]string{"get"}) })
	})
	if !strings.Contains(out, "splunk_hec") {
		t.Errorf("%s", out)
	}
	if !strings.Contains(out, "exported:") {
		t.Errorf("missing exported line: %s", out)
	}
}

func TestCmdAuditExportGetDisabled(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("get_audit_export", map[string]interface{}{"enabled": false})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() { cmdAuditExport([]string{"get"}) })
	})
	if !strings.Contains(out, "not configured") {
		t.Errorf("missing 'not configured' banner: %s", out)
	}
}

func TestCmdAuditExportGetJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("get_audit_export", map[string]interface{}{"enabled": true, "format": "json"})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() { cmdAuditExport([]string{"get"}) })
	})
	if !strings.Contains(out, `"format":"json"`) {
		t.Errorf("%s", out)
	}
}

func TestCmdAuditExportSetJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("set_audit_export", map[string]interface{}{"status": "configured"})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() {
			cmdAuditExport([]string{"set",
				"--format", "splunk_hec",
				"--endpoint", "https://hec.example.com",
				"--splunk-token", "T",
				"--index", "idx",
				"--source", "src",
			})
		})
	})
	if !strings.Contains(out, `"status":"configured"`) {
		t.Errorf("%s", out)
	}
}

func TestCmdAuditExportSetText(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("set_audit_export", map[string]interface{}{"status": "ok"})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() {
			cmdAuditExport([]string{"set", "--format", "json", "--endpoint", "https://x"})
		})
	})
	if !strings.Contains(out, "audit export configured: json") {
		t.Errorf("%s", out)
	}
}

func TestCmdAuditExportDisableJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("set_audit_export", map[string]interface{}{"status": "disabled"})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() { cmdAuditExport([]string{"disable"}) })
	})
	if !strings.Contains(out, `"status":"disabled"`) {
		t.Errorf("%s", out)
	}
}

func TestCmdAuditExportDisableText(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("set_audit_export", map[string]interface{}{"status": "disabled"})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() { cmdAuditExport([]string{"disable"}) })
	})
	if !strings.Contains(out, "audit export disabled") {
		t.Errorf("%s", out)
	}
}

// --- cmdProvisionStatus --------------------------------------------------

func TestCmdProvisionStatusJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("get_provision_status", map[string]interface{}{
		"idp_type":        "oidc",
		"audit_export":    "splunk",
		"webhook_enabled": true,
		"networks": []interface{}{
			map[string]interface{}{
				"network_id":           float64(5),
				"name":                 "main",
				"enterprise":           true,
				"members":              float64(10),
				"join_rule":            "invite",
				"rbac_pre_assignments": float64(3),
			},
		},
	})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() { cmdProvisionStatus() })
	})
	if !strings.Contains(out, `"idp_type":"oidc"`) {
		t.Errorf("%s", out)
	}
}

func TestCmdProvisionStatusText(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("get_provision_status", map[string]interface{}{
		"idp_type":        "oidc",
		"audit_export":    "splunk",
		"webhook_enabled": true,
		"networks": []interface{}{
			map[string]interface{}{
				"network_id":           float64(5),
				"name":                 "main",
				"enterprise":           true,
				"members":              float64(10),
				"join_rule":            "invite",
				"rbac_pre_assignments": float64(3),
			},
		},
	})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() { cmdProvisionStatus() })
	})
	if !strings.Contains(out, "identity provider: oidc") {
		t.Errorf("missing idp line: %s", out)
	}
	if !strings.Contains(out, "main") || !strings.Contains(out, "yes") {
		t.Errorf("missing network row: %s", out)
	}
}

func TestCmdProvisionStatusTextEmpty(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("get_provision_status", map[string]interface{}{"networks": []interface{}{}})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() { cmdProvisionStatus() })
	})
	if !strings.Contains(out, "no networks provisioned") {
		t.Errorf("missing empty banner: %s", out)
	}
}

// --- cmdDirectorySync ----------------------------------------------------

func TestCmdDirectorySyncJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("directory_sync", map[string]interface{}{
		"mapped":   float64(2),
		"updated":  float64(1),
		"disabled": float64(0),
		"unmapped": float64(0),
		"actions":  []interface{}{"mapped alice", "updated bob"},
	})
	useRegistry(t, r)
	dir := t.TempDir()
	path := filepath.Join(dir, "dir.json")
	body := `{"network_id":5,"entries":[{"email":"alice@x"},{"email":"bob@x"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		withJSON(func() { cmdDirectorySync([]string{path}) })
	})
	if !strings.Contains(out, `"mapped":2`) {
		t.Errorf("%s", out)
	}
}

func TestCmdDirectorySyncText(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("directory_sync", map[string]interface{}{
		"mapped":   float64(1),
		"updated":  float64(0),
		"disabled": float64(0),
		"unmapped": float64(0),
		"actions":  []interface{}{"mapped alice"},
	})
	useRegistry(t, r)
	dir := t.TempDir()
	path := filepath.Join(dir, "dir.json")
	body := `{"entries":[{"email":"alice@x"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		withText(func() {
			cmdDirectorySync([]string{path, "--network", "5", "--remove-unlisted"})
		})
	})
	if !strings.Contains(out, "directory sync complete") {
		t.Errorf("%s", out)
	}
	if !strings.Contains(out, "mapped alice") {
		t.Errorf("missing actions: %s", out)
	}
}

// --- cmdDirectoryStatus --------------------------------------------------

func TestCmdDirectoryStatusJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("directory_status", map[string]interface{}{
		"network_id":      float64(5),
		"total":           float64(10),
		"mapped":          float64(7),
		"unmapped":        float64(3),
		"pre_assignments": float64(2),
		"last_sync":       "2026-01-01T00:00:00Z",
	})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() { cmdDirectoryStatus([]string{"5"}) })
	})
	if !strings.Contains(out, `"total":10`) {
		t.Errorf("%s", out)
	}
}

func TestCmdDirectoryStatusText(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("directory_status", map[string]interface{}{
		"network_id":      float64(5),
		"total":           float64(10),
		"mapped":          float64(7),
		"unmapped":        float64(3),
		"pre_assignments": float64(2),
		"last_sync":       "2026-01-01T00:00:00Z",
	})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() { cmdDirectoryStatus([]string{"5"}) })
	})
	if !strings.Contains(out, "Network 5 directory status") {
		t.Errorf("%s", out)
	}
	if !strings.Contains(out, "directory mapped: 7") {
		t.Errorf("missing mapped line: %s", out)
	}
	if !strings.Contains(out, "pre-assignments: 2") {
		t.Errorf("missing pre-assignments line: %s", out)
	}
}

// --- error-path coverage: registry replies with an "error" field, which
// triggers the fatalCode("connection_failed", ...) branch via os.Exit.
// Drive these through runCLI so the exit doesn't kill the test process. --

// --- cmdPolicySet (subprocess: validation + registry call hit before
// the daemon-connect fatalHint exits) ----------------------------------

func TestCLIPolicySetRegistryThenDaemonGap(t *testing.T) {
	t.Parallel()
	r := newFakeRegistry(t)
	r.onOK("set_expr_policy", map[string]interface{}{"saved": true})
	defer r.ln.Close()

	dir := t.TempDir()
	pol := filepath.Join(dir, "p.json")
	// Minimal valid expr-policy doc.
	body := `{"version":1,"rules":[{"name":"r1","on":"connect","match":"true","actions":[{"type":"allow"}]}]}`
	if err := os.WriteFile(pol, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := runCLI(t,
		[]string{"policy", "set", "--net", "5", "--file", pol, "--admin-token", "T"},
		map[string]string{
			"PILOT_REGISTRY": r.addr(),
			"PILOT_SOCKET":   "/tmp/nope-" + t.Name() + ".sock",
		})
	// Daemon-not-running fatalHint → non-zero exit.
	if code == 0 {
		t.Error("expected non-zero (daemon absent)")
	}
	if !strings.Contains(stderr, "daemon") && !strings.Contains(stderr, "not_running") {
		t.Errorf("expected daemon hint, got: %s", stderr)
	}
}

func TestCLIPolicySetInlineRegistryError(t *testing.T) {
	t.Parallel()
	r := newFakeRegistry(t)
	r.on("set_expr_policy", func(_ map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"error": "rejected"}
	})
	defer r.ln.Close()

	body := `{"version":1,"rules":[{"name":"r1","on":"connect","match":"true","actions":[{"type":"allow"}]}]}`
	_, stderr, code := runCLI(t,
		[]string{"policy", "set", "--net", "5", "--inline", body, "--admin-token", "T"},
		map[string]string{
			"PILOT_REGISTRY": r.addr(),
			"PILOT_SOCKET":   "/tmp/nope-" + t.Name() + ".sock",
		})
	if code == 0 {
		t.Error("expected non-zero on registry rejection")
	}
	if !strings.Contains(stderr, "rejected") {
		t.Errorf("expected registry error: %s", stderr)
	}
}

func TestCLINetworkDeleteRegistryError(t *testing.T) {
	t.Parallel()
	r := newFakeRegistry(t)
	r.on("delete_network", func(_ map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"error": "boom"}
	})
	defer r.ln.Close()
	_, stderr, code := runCLI(t, []string{"network", "delete", "5"}, map[string]string{
		"PILOT_REGISTRY":    r.addr(),
		"PILOT_SOCKET":      "/tmp/nope-" + t.Name() + ".sock",
		"PILOT_ADMIN_TOKEN": "tok",
	})
	if code == 0 {
		t.Error("expected non-zero exit on registry error")
	}
	if !strings.Contains(stderr, "boom") {
		t.Errorf("expected 'boom' in stderr: %s", stderr)
	}
}

func TestCLILookupRegistryError(t *testing.T) {
	t.Parallel()
	r := newFakeRegistry(t)
	r.on("lookup", func(_ map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"error": "no such node"}
	})
	defer r.ln.Close()
	_, stderr, code := runCLI(t, []string{"lookup", "42"}, map[string]string{
		"PILOT_REGISTRY": r.addr(),
		"PILOT_SOCKET":   "/tmp/nope-" + t.Name() + ".sock",
	})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "no such node") {
		t.Errorf("expected error: %s", stderr)
	}
}

func TestCLIDeprovisionMissingNetwork(t *testing.T) {
	t.Parallel()
	r := newFakeRegistry(t)
	r.onOK("list_networks", map[string]interface{}{
		"networks": []interface{}{
			map[string]interface{}{"id": float64(1), "name": "other"},
		},
	})
	defer r.ln.Close()
	_, stderr, code := runCLI(t, []string{"deprovision", "missing-net"}, map[string]string{
		"PILOT_REGISTRY":    r.addr(),
		"PILOT_SOCKET":      "/tmp/nope-" + t.Name() + ".sock",
		"PILOT_ADMIN_TOKEN": "tok",
	})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "not found") {
		t.Errorf("expected 'not found' hint: %s", stderr)
	}
}

func TestCLIDirectorySyncBadFile(t *testing.T) {
	t.Parallel()
	r := newFakeRegistry(t)
	defer r.ln.Close()
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := runCLI(t, []string{"directory-sync", bad, "--network", "5"},
		map[string]string{
			"PILOT_REGISTRY":    r.addr(),
			"PILOT_SOCKET":      "/tmp/nope-" + t.Name() + ".sock",
			"PILOT_ADMIN_TOKEN": "tok",
		})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "parse") && !strings.Contains(stderr, "invalid") {
		t.Errorf("expected parse error: %s", stderr)
	}
}

func TestCLIDirectorySyncMissingNetID(t *testing.T) {
	t.Parallel()
	r := newFakeRegistry(t)
	defer r.ln.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "d.json")
	if err := os.WriteFile(path, []byte(`{"entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := runCLI(t, []string{"directory-sync", path},
		map[string]string{
			"PILOT_REGISTRY":    r.addr(),
			"PILOT_SOCKET":      "/tmp/nope-" + t.Name() + ".sock",
			"PILOT_ADMIN_TOKEN": "tok",
		})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "network_id") {
		t.Errorf("expected network_id required: %s", stderr)
	}
}

// --- cmdNetworkCreate (3 paths) ------------------------------------------

func TestCmdNetworkCreateBasic(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("create_network", map[string]interface{}{"network_id": float64(7)})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() {
			cmdNetworkCreate([]string{"--name", "my-net", "--join-rule", "open"})
		})
	})
	if !strings.Contains(out, `"network_id":7`) {
		t.Errorf("%s", out)
	}
	last := r.last("create_network")
	if last == nil || last["name"] != "my-net" {
		t.Errorf("wire name = %v", last)
	}
}

func TestCmdNetworkCreateWithNetworkAdminToken(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("create_network", map[string]interface{}{"network_id": float64(8)})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() {
			cmdNetworkCreate([]string{
				"--name", "tok-net",
				"--join-rule", "invite",
				"--enterprise",
				"--network-admin-token", "NAT",
			})
		})
	})
	if !strings.Contains(out, "created network 8") {
		t.Errorf("%s", out)
	}
	last := r.last("create_network")
	if last["network_admin_token"] != "NAT" {
		t.Errorf("missing network_admin_token: %v", last)
	}
}

func TestCmdNetworkCreateManagedWithRules(t *testing.T) {
	r := newFakeRegistry(t)
	// CreateNetwork + CreateManagedNetwork share wire type "create_network";
	// the request carries "rules" only on the managed path.
	r.onOK("create_network", map[string]interface{}{
		"network_id": float64(9),
		"managed":    true,
	})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() {
			cmdNetworkCreate([]string{
				"--name", "managed",
				"--rules", `{"a":1}`,
			})
		})
	})
	if !strings.Contains(out, "managed=true") {
		t.Errorf("%s", out)
	}
	last := r.last("create_network")
	if last == nil || last["rules"] != `{"a":1}` {
		t.Errorf("wire rules = %v", last)
	}
}

func TestCmdNetworkCreateRulesFile(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("create_network", map[string]interface{}{
		"network_id": float64(10),
		"managed":    true,
	})
	useRegistry(t, r)
	dir := t.TempDir()
	rf := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rf, []byte(`{"r":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	captureStdout(t, func() {
		withJSON(func() {
			cmdNetworkCreate([]string{"--name", "rf-net", "--rules-file", rf})
		})
	})
	last := r.last("create_network")
	if last == nil || last["rules"] != `{"r":2}` {
		t.Errorf("wire rules from file = %v", last)
	}
}

// --- cmdNetworkJoin admin path (registry, not daemon) --------------------

func TestCmdNetworkJoinAdminPath(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("join_network", map[string]interface{}{"joined": true})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() {
			cmdNetworkJoin([]string{"5", "--node-id", "42", "--token", "secret"})
		})
	})
	if !strings.Contains(out, `"joined":true`) {
		t.Errorf("%s", out)
	}
	last := r.last("join_network")
	if last == nil || uint32(last["node_id"].(float64)) != 42 {
		t.Errorf("wire node_id = %v", last)
	}
}

func TestCmdNetworkJoinAdminPathText(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("join_network", map[string]interface{}{"joined": true})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() {
			cmdNetworkJoin([]string{"5", "--node-id", "42"})
		})
	})
	if !strings.Contains(out, "joined node 42 to network 5") {
		t.Errorf("%s", out)
	}
}

// --- cmdMemberTagsSet admin path -----------------------------------------

func TestCmdMemberTagsSetAdminPathJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("set_member_tags", map[string]interface{}{"updated": true})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withJSON(func() {
			cmdMemberTagsSet([]string{
				"--net", "5", "--node", "42", "--tags", "ops,prod",
			})
		})
	})
	if !strings.Contains(out, `"updated":true`) {
		t.Errorf("%s", out)
	}
	last := r.last("set_member_tags")
	if last == nil {
		t.Fatal("no set_member_tags req")
	}
	tags, _ := last["tags"].([]interface{})
	if len(tags) != 2 || tags[0] != "ops" || tags[1] != "prod" {
		t.Errorf("wire tags = %v", tags)
	}
}

func TestCmdMemberTagsSetAdminPathText(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("set_member_tags", map[string]interface{}{"updated": true})
	useRegistry(t, r)
	out := captureStdout(t, func() {
		withText(func() {
			cmdMemberTagsSet([]string{
				"--net", "5", "--node", "42", "--tags", "ops",
			})
		})
	})
	if !strings.Contains(out, "Member tags set for node 42") {
		t.Errorf("%s", out)
	}
}

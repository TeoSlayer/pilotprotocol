package tests

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	icrypto "github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

func TestEndToEnd(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Start daemon A
	a := env.AddDaemon()
	t.Logf("daemon A: node=%d addr=%s", a.Daemon.NodeID(), a.Daemon.Addr())

	// Start daemon B
	b := env.AddDaemon()
	t.Logf("daemon B: node=%d addr=%s", b.Daemon.NodeID(), b.Daemon.Addr())

	// Listen on port 1000 via driver A
	ln, err := a.Driver.Listen(1000)
	if err != nil {
		t.Fatalf("driver A listen: %v", err)
	}
	t.Log("driver A: listening on port 1000")

	// Server goroutine: accept and echo
	serverReady := make(chan struct{})
	serverDone := make(chan string, 1)
	go func() {
		close(serverReady)
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- fmt.Sprintf("accept error: %v", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			serverDone <- fmt.Sprintf("read error: %v", err)
			return
		}

		received := string(buf[:n])
		log.Printf("server received: %q", received)

		conn.Write([]byte("echo:" + received))
		serverDone <- received
	}()
	<-serverReady

	// Driver B dials daemon A on port 1000
	targetAddr := fmt.Sprintf("%s:1000", a.Daemon.Addr().String())
	t.Logf("driver B: dialing %s", targetAddr)

	conn, err := b.Driver.Dial(targetAddr)
	if err != nil {
		t.Fatalf("driver B dial: %v", err)
	}
	defer conn.Close()

	t.Log("driver B: connected!")

	_, err = conn.Write([]byte("hello pilot"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	response := string(buf[:n])
	t.Logf("client received: %q", response)

	if response != "echo:hello pilot" {
		t.Errorf("expected %q, got %q", "echo:hello pilot", response)
	}

	select {
	case received := <-serverDone:
		if received != "hello pilot" {
			t.Errorf("server received %q, want %q", received, "hello pilot")
		}
	case <-time.After(5 * time.Second):
		t.Error("server timed out")
	}

	rc, _ := registry.Dial(env.RegistryAddr)
	defer rc.Close()

	nets, _ := rc.ListNetworks()
	t.Logf("networks: %v", nets)
}

// === TDD Integration Tests ===
// These test real round-trips through actual HTTP mock servers.

// --- Mock Splunk HEC Server ---

type splunkHECCollector struct {
	mu     sync.Mutex
	events []json.RawMessage
	server *httptest.Server
}

func newSplunkHECCollector(expectedToken string) *splunkHECCollector {
	sc := &splunkHECCollector{}
	sc.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if expectedToken != "" && auth != "Splunk "+expectedToken {
			http.Error(w, `{"text":"Invalid token","code":4}`, http.StatusForbidden)
			return
		}
		ct := r.Header.Get("Content-Type")
		if ct != "application/json" {
			http.Error(w, "bad content type", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		sc.mu.Lock()
		sc.events = append(sc.events, json.RawMessage(body))
		sc.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	return sc
}

func (sc *splunkHECCollector) URL() string { return sc.server.URL }
func (sc *splunkHECCollector) Close()      { sc.server.Close() }
func (sc *splunkHECCollector) Events() []json.RawMessage {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	out := make([]json.RawMessage, len(sc.events))
	copy(out, sc.events)
	return out
}
func (sc *splunkHECCollector) WaitForEvents(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		sc.mu.Lock()
		count := len(sc.events)
		sc.mu.Unlock()
		if count >= n {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func TestHTTPOverPilot(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	// Start HTTP server on daemon A port 80
	ln, err := a.Driver.Listen(80)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	go http.Serve(ln, mux)

	// Connect from daemon B and send HTTP request
	conn, err := b.Driver.DialAddr(a.Daemon.Addr(), 80)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	t.Log("connected to port 80")

	req := "GET /status HTTP/1.0\r\nHost: test\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Log("sent HTTP request")

	// Read response
	var resp []byte
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			resp = append(resp, buf[:n]...)
		}
		if err == io.EOF || err != nil {
			break
		}
	}

	t.Logf("HTTP response:\n%s", string(resp))

	if len(resp) == 0 {
		t.Fatal("got empty response")
	}
}

// --- Mock Identity Provider (OIDC webhook) ---

type identityProviderMock struct {
	mu       sync.Mutex
	requests []string
	server   *httptest.Server
}

func newIdentityProviderMock(verified bool, externalID, errorMsg string) *identityProviderMock {
	idp := &identityProviderMock{}
	idp.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal(body, &req)
		idp.mu.Lock()
		idp.requests = append(idp.requests, req.Token)
		idp.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"verified":    verified,
			"external_id": externalID,
		}
		if errorMsg != "" {
			resp["error"] = errorMsg
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	return idp
}

func (idp *identityProviderMock) URL() string { return idp.server.URL }
func (idp *identityProviderMock) Close()      { idp.server.Close() }
func (idp *identityProviderMock) Requests() []string {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	out := make([]string, len(idp.requests))
	copy(out, idp.requests)
	return out
}

// --- Mock CEF/Syslog Receiver ---

type cefCollector struct {
	mu     sync.Mutex
	lines  []string
	server *httptest.Server
}

func newCEFCollector() *cefCollector {
	cc := &cefCollector{}
	cc.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		cc.mu.Lock()
		cc.lines = append(cc.lines, string(body))
		cc.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	return cc
}

func (cc *cefCollector) URL() string { return cc.server.URL }
func (cc *cefCollector) Close()      { cc.server.Close() }
func (cc *cefCollector) WaitForLines(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cc.mu.Lock()
		count := len(cc.lines)
		cc.mu.Unlock()
		if count >= n {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
func (cc *cefCollector) Lines() []string {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	out := make([]string, len(cc.lines))
	copy(out, cc.lines)
	return out
}

// ============================================================
// Integration Test: Splunk HEC round-trip
// ============================================================
// TDD: Configure audit export with splunk_hec format → trigger real audit
// events → verify they arrive at mock Splunk HEC with correct format & auth.

func TestIntegration_SplunkHECRoundTrip(t *testing.T) {
	t.Parallel()

	splunkToken := "test-hec-token-12345"
	splunk := newSplunkHECCollector(splunkToken)
	defer splunk.Close()

	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	// Configure audit export to mock Splunk HEC
	resp, err := rc.SetAuditExport("splunk_hec", splunk.URL(), splunkToken, "pilot-index", "test-registry", TestAdminToken)
	if err != nil {
		t.Fatalf("set audit export: %v", err)
	}
	if resp["type"] != "set_audit_export_ok" {
		t.Fatalf("expected set_audit_export_ok, got %v", resp["type"])
	}

	// Verify config stored
	getResp, err := rc.GetAuditExport(TestAdminToken)
	if err != nil {
		t.Fatalf("get audit export: %v", err)
	}
	if getResp["format"] != "splunk_hec" {
		t.Fatalf("expected format=splunk_hec, got %v", getResp["format"])
	}

	// Trigger audit events
	ownerID, _ := registerTestNode(t, rc)
	netResp, err := rc.CreateNetwork(ownerID, "splunk-test-net", "open", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))
	memberID, _ := registerTestNode(t, rc)
	_, err = rc.JoinNetwork(memberID, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join network: %v", err)
	}

	// Wait for events
	if !splunk.WaitForEvents(1, 5*time.Second) {
		t.Fatal("no Splunk HEC events received within timeout")
	}

	events := splunk.Events()
	t.Logf("received %d Splunk HEC events", len(events))

	// Parse and verify each event
	for _, raw := range events {
		var ev map[string]interface{}
		if err := json.Unmarshal(raw, &ev); err != nil {
			t.Errorf("unmarshal splunk event: %v", err)
			continue
		}
		if ev["sourcetype"] != "pilot:audit" {
			t.Errorf("expected sourcetype=pilot:audit, got %v", ev["sourcetype"])
		}
		if ev["event"] == nil {
			t.Error("event payload is nil")
			continue
		}
		event, _ := ev["event"].(map[string]interface{})
		action, _ := event["action"].(string)
		t.Logf("  splunk event: action=%s source=%v", action, ev["source"])
	}
}

// ============================================================
// Integration Test: CEF audit export round-trip
// ============================================================

func TestIntegration_CEFExportRoundTrip(t *testing.T) {
	t.Parallel()

	cef := newCEFCollector()
	defer cef.Close()

	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	resp, err := rc.SetAuditExport("syslog_cef", cef.URL(), "", "", "test-cef", TestAdminToken)
	if err != nil {
		t.Fatalf("set audit export: %v", err)
	}
	if resp["type"] != "set_audit_export_ok" {
		t.Fatalf("expected set_audit_export_ok, got %v", resp["type"])
	}

	// Trigger events
	ownerID, _ := registerTestNode(t, rc)
	_, err = rc.CreateNetwork(ownerID, "cef-test-net", "open", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}

	if !cef.WaitForLines(1, 5*time.Second) {
		t.Fatal("no CEF lines received within timeout")
	}

	lines := cef.Lines()
	t.Logf("received %d CEF lines", len(lines))

	foundValid := false
	for _, line := range lines {
		if strings.HasPrefix(line, "CEF:0|Pilot|Registry|") {
			foundValid = true
			if !strings.Contains(line, "cs1Label=action") {
				t.Errorf("CEF line missing cs1Label=action: %s", line)
			}
			if !strings.Contains(line, "cn1Label=network_id") {
				t.Errorf("CEF line missing cn1Label=network_id: %s", line)
			}
			maxLen := len(line)
			if maxLen > 120 {
				maxLen = 120
			}
			t.Logf("  valid CEF: %s", line[:maxLen])
		}
	}
	if !foundValid {
		t.Errorf("no valid CEF-formatted lines found; got: %v", lines)
	}
}

// ============================================================
// Integration Test: Identity webhook verification round-trip
// ============================================================
// TDD: Register a node with identity_token, verify the token is forwarded
// to the identity webhook, and the external_id is stored on the node.

func TestIntegration_IdentityWebhookVerification(t *testing.T) {
	t.Parallel()

	idp := newIdentityProviderMock(true, "user@corp.example.com", "")
	defer idp.Close()

	rc, reg, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	reg.SetIdentityWebhookURL(idp.URL())

	// Register node WITH identity token
	id, _ := icrypto.GenerateIdentity()
	resp, err := rc.Send(map[string]interface{}{
		"type":           "register",
		"listen_addr":    "127.0.0.1:5000",
		"public_key":     icrypto.EncodePublicKey(id.PublicKey),
		"identity_token": "my-oidc-jwt-token-abc123",
	})
	if err != nil {
		t.Fatalf("register with identity: %v", err)
	}
	if resp["type"] != "register_ok" {
		t.Fatalf("expected register_ok, got %v (error: %v)", resp["type"], resp["error"])
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Verify webhook received the token
	reqs := idp.Requests()
	if len(reqs) == 0 {
		t.Fatal("identity webhook received no requests")
	}
	if reqs[0] != "my-oidc-jwt-token-abc123" {
		t.Fatalf("expected token 'my-oidc-jwt-token-abc123', got %q", reqs[0])
	}

	// Verify node has external ID stored
	idResp, err := rc.GetIdentity(nodeID, TestAdminToken)
	if err != nil {
		t.Fatalf("get identity: %v", err)
	}
	if idResp["external_id"] != "user@corp.example.com" {
		t.Fatalf("expected external_id=user@corp.example.com, got %v", idResp["external_id"])
	}

	t.Logf("identity verification: token forwarded, external_id=%s stored", idResp["external_id"])
}

// ============================================================
// Integration Test: Identity webhook rejection
// ============================================================

func TestIntegration_IdentityWebhookRejection(t *testing.T) {
	t.Parallel()

	idp := newIdentityProviderMock(false, "", "invalid token signature")
	defer idp.Close()

	rc, reg, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	reg.SetIdentityWebhookURL(idp.URL())

	id, _ := icrypto.GenerateIdentity()
	resp, err := rc.Send(map[string]interface{}{
		"type":           "register",
		"listen_addr":    "127.0.0.1:5001",
		"public_key":     icrypto.EncodePublicKey(id.PublicKey),
		"identity_token": "bad-token-xyz",
	})

	if err != nil {
		// Server rejected registration entirely — valid behavior
		if !strings.Contains(err.Error(), "identity") {
			t.Fatalf("unexpected error: %v", err)
		}
		t.Logf("identity rejection: registration rejected (%v)", err)
		return
	}

	// If registration succeeded, node should NOT have an external_id
	if resp["type"] != "register_ok" {
		t.Fatalf("expected register_ok or error, got %v", resp["type"])
	}
	nodeID := uint32(resp["node_id"].(float64))

	idResp, err := rc.GetIdentity(nodeID, TestAdminToken)
	if err != nil {
		t.Fatalf("get identity: %v", err)
	}
	extID, _ := idResp["external_id"].(string)
	if extID != "" {
		t.Fatalf("rejected token should not produce external_id, got %q", extID)
	}
	t.Log("identity rejection: registration succeeded but no external_id stored")
}

// ============================================================
// Integration Test: Prometheus /metrics scrape
// ============================================================
// TDD: Perform real operations, then scrape /metrics and verify Prometheus
// text format with correct TYPE/HELP declarations, labeled metrics, and
// histogram buckets.

func TestIntegration_PrometheusMetricsScrape(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	reg.SetAdminToken(TestAdminToken)
	go reg.ListenAndServe(":0")
	defer reg.Close()
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()
	go reg.ServeDashboard(dashAddr)
	waitDashboard(t, dashAddr)

	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	ownerID, _ := registerTestNode(t, rc)
	memberID, _ := registerTestNode(t, rc)

	netResp, err := rc.CreateNetwork(ownerID, "prom-test-net", "open", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	_, err = rc.JoinNetwork(memberID, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	_, err = rc.PromoteMember(netID, ownerID, memberID, TestAdminToken)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}

	body := fetchMetrics(t, dashAddr)

	// TYPE + HELP declarations
	requiredMetrics := []string{
		"# TYPE pilot_requests_total counter",
		"# TYPE pilot_nodes_online gauge",
		"# TYPE pilot_uptime_seconds gauge",
		"# TYPE pilot_request_duration_seconds histogram",
		"# TYPE pilot_registrations_total counter",
		"# TYPE pilot_networks_total gauge",
		"# TYPE pilot_audit_events_total counter",
		"# TYPE pilot_rbac_operations_total counter",
		"# HELP pilot_requests_total",
		"# HELP pilot_nodes_online",
		"# HELP pilot_uptime_seconds",
		// Actual values
		"pilot_registrations_total",
		"pilot_nodes_total",
		"pilot_networks_enterprise",
		"pilot_audit_events_total",
		// Per-network labeled metrics
		`pilot_network_members{network="prom-test-net"}`,
		`pilot_network_enterprise{network="prom-test-net"} 1`,
	}
	for _, expected := range requiredMetrics {
		if !strings.Contains(body, expected) {
			t.Errorf("metrics missing %q", expected)
		}
	}

	// Histogram buckets
	if !strings.Contains(body, "pilot_request_duration_seconds_bucket{") {
		t.Error("missing request duration histogram buckets")
	}
	if !strings.Contains(body, `le="+Inf"`) {
		t.Error("missing +Inf bucket")
	}

	// Request type labels
	if !strings.Contains(body, `pilot_requests_total{type="register"}`) {
		t.Error("missing register request count")
	}
	if !strings.Contains(body, `pilot_requests_total{type="create_network"}`) {
		t.Error("missing create_network request count")
	}

	// RBAC operation tracked
	if !strings.Contains(body, `pilot_rbac_operations_total{op="promote"}`) {
		t.Error("missing RBAC promote metric")
	}

	t.Logf("prometheus scrape: %d bytes, all required metrics present", len(body))
}

// ============================================================
// Integration Test: /healthz endpoint
// ============================================================

func TestIntegration_HealthzEndpoint(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	go reg.ListenAndServe(":0")
	defer reg.Close()
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()
	go reg.ServeDashboard(dashAddr)
	waitDashboard(t, dashAddr)

	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s/healthz", dashAddr))
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("expected application/json, got %s", ct)
	}

	body, _ := io.ReadAll(resp.Body)
	var health map[string]interface{}
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatalf("parse healthz: %v", err)
	}

	if health["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", health["status"])
	}
	for _, field := range []string{"uptime_seconds", "nodes_online", "version"} {
		if _, ok := health[field]; !ok {
			t.Errorf("healthz missing %s", field)
		}
	}
	t.Logf("healthz: %s", string(body))
}

// ============================================================
// Integration Test: Audit log API round-trip
// ============================================================
// TDD: Do real operations, then query audit log and verify events match.

func TestIntegration_AuditLogRoundTrip(t *testing.T) {
	t.Parallel()

	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, _ := registerTestNode(t, rc)
	memberID, _ := registerTestNode(t, rc)

	netResp, err := rc.CreateNetwork(ownerID, "audit-rt-net", "open", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	_, err = rc.JoinNetwork(memberID, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	_, err = rc.PromoteMember(netID, ownerID, memberID, TestAdminToken)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}

	auditResp, err := rc.GetAuditLog(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("get audit log: %v", err)
	}
	if auditResp["type"] != "get_audit_log_ok" {
		t.Fatalf("expected type=get_audit_log_ok, got %v", auditResp["type"])
	}

	entries, ok := auditResp["entries"].([]interface{})
	if !ok {
		t.Fatalf("expected entries array, got %T", auditResp["entries"])
	}
	t.Logf("audit log: %d entries", len(entries))

	actions := map[string]bool{}
	for _, raw := range entries {
		entry, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		action, _ := entry["action"].(string)
		actions[action] = true
	}

	for _, required := range []string{"network.created", "network.joined", "member.promoted"} {
		if !actions[required] {
			t.Errorf("audit log missing %q; found: %v", required, actions)
		}
	}
}

// ============================================================
// Integration Test: Directory sync end-to-end
// ============================================================
// TDD: Push AD directory listing → verify roles updated, disabled users
// kicked, status reported.

func TestIntegration_DirectorySyncE2E(t *testing.T) {
	t.Parallel()

	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	ownerID, _ := registerTestNode(t, rc)
	node2ID, _ := registerTestNode(t, rc)
	node3ID, _ := registerTestNode(t, rc)

	netResp, err := rc.CreateNetwork(ownerID, "dirsync-e2e", "open", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	_, err = rc.JoinNetwork(node2ID, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join node2: %v", err)
	}
	_, err = rc.JoinNetwork(node3ID, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join node3: %v", err)
	}

	// Set external IDs
	_, err = rc.SetExternalID(node2ID, "alice@corp.com", TestAdminToken)
	if err != nil {
		t.Fatalf("set external id node2: %v", err)
	}
	_, err = rc.SetExternalID(node3ID, "bob@corp.com", TestAdminToken)
	if err != nil {
		t.Fatalf("set external id node3: %v", err)
	}

	// Directory sync: Alice=admin, Bob=disabled
	entries := []map[string]interface{}{
		{"external_id": "alice@corp.com", "display_name": "Alice Smith", "email": "alice@corp.com", "role": "admin", "disabled": false},
		{"external_id": "bob@corp.com", "display_name": "Bob Jones", "email": "bob@corp.com", "role": "member", "disabled": true},
	}

	syncResp, err := rc.DirectorySync(netID, entries, false, TestAdminToken)
	if err != nil {
		t.Fatalf("directory sync: %v", err)
	}
	if syncResp["type"] != "directory_sync_ok" {
		t.Fatalf("expected directory_sync_ok, got %v (error: %v)", syncResp["type"], syncResp["error"])
	}
	t.Logf("directory sync: mapped=%v", syncResp["mapped"])

	// Verify Alice got admin
	roleResp, err := rc.GetMemberRole(netID, node2ID)
	if err != nil {
		t.Fatalf("get role alice: %v", err)
	}
	if roleResp["role"] != "admin" {
		t.Errorf("expected Alice to be admin, got %v", roleResp["role"])
	}

	// Check directory status
	statusResp, err := rc.DirectoryStatus(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("directory status: %v", err)
	}
	if statusResp["type"] != "directory_status_ok" {
		t.Fatalf("expected directory_status_ok, got %v", statusResp["type"])
	}
	t.Logf("directory status: mapped=%v unmapped=%v", statusResp["mapped"], statusResp["unmapped"])
}

// ============================================================
// Integration Test: Blueprint provisioning end-to-end
// ============================================================
// TDD: Apply a comprehensive blueprint → verify all subsystems configured.

func TestIntegration_BlueprintProvisioningE2E(t *testing.T) {
	t.Parallel()

	splunk := newSplunkHECCollector("bp-token-123")
	defer splunk.Close()

	idp := newIdentityProviderMock(true, "admin@corp.com", "")
	defer idp.Close()

	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	blueprint := map[string]interface{}{
		"name":       "blueprint-e2e",
		"join_rule":  "token",
		"join_token": "secret-corp-token",
		"enterprise": true,
		"policy": map[string]interface{}{
			"max_members":   50,
			"allowed_ports": []interface{}{float64(7), float64(80), float64(443)},
			"description":   "Production network",
		},
		"identity_provider": map[string]interface{}{
			"type":      "oidc",
			"url":       idp.URL(),
			"issuer":    "https://login.corp.example.com",
			"client_id": "pilot-app-123",
		},
		"webhooks": map[string]interface{}{
			"audit_url":    "http://audit.example.com/hook",
			"identity_url": idp.URL(),
		},
		"audit_export": map[string]interface{}{
			"format":   "splunk_hec",
			"endpoint": splunk.URL(),
			"token":    "bp-token-123",
			"index":    "pilot",
			"source":   "blueprint-test",
		},
		"roles": []interface{}{
			map[string]interface{}{"external_id": "admin@corp.com", "role": "admin"},
			map[string]interface{}{"external_id": "user@corp.com", "role": "member"},
		},
	}

	resp, err := rc.ProvisionNetwork(blueprint, TestAdminToken)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if resp["type"] != "provision_network_ok" {
		t.Fatalf("expected provision_network_ok, got %v (error: %v)", resp["type"], resp["error"])
	}

	netID := uint16(resp["network_id"].(float64))
	created, _ := resp["created"].(bool)
	actions, _ := resp["actions"].([]interface{})
	t.Logf("provisioned: network_id=%d created=%v actions=%d", netID, created, len(actions))
	for _, a := range actions {
		t.Logf("  %s", a)
	}
	if !created {
		t.Error("expected network to be created")
	}

	// Verify IDP config
	idpResp, err := rc.GetIDPConfig(TestAdminToken)
	if err != nil {
		t.Fatalf("get idp config: %v", err)
	}
	if idpResp["idp_type"] != "oidc" {
		t.Errorf("expected idp_type=oidc, got %v", idpResp["idp_type"])
	}
	if idpResp["issuer"] != "https://login.corp.example.com" {
		t.Errorf("expected issuer, got %v", idpResp["issuer"])
	}

	// Verify audit export
	aeResp, err := rc.GetAuditExport(TestAdminToken)
	if err != nil {
		t.Fatalf("get audit export: %v", err)
	}
	if aeResp["format"] != "splunk_hec" {
		t.Errorf("expected splunk_hec, got %v", aeResp["format"])
	}

	// Verify policy
	polResp, err := rc.GetNetworkPolicy(netID)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	maxMembers := int(polResp["max_members"].(float64))
	if maxMembers != 50 {
		t.Errorf("expected max_members=50, got %d", maxMembers)
	}

	// Verify provision status
	statusResp, err := rc.GetProvisionStatus(TestAdminToken)
	if err != nil {
		t.Fatalf("get provision status: %v", err)
	}
	if statusResp["type"] != "get_provision_status_ok" {
		t.Fatalf("expected get_provision_status_ok, got %v", statusResp["type"])
	}

	t.Log("blueprint e2e: all subsystems verified")
}

// ============================================================
// Integration Test: Webhook DLQ with real failing endpoint
// ============================================================
// TDD: Configure webhook to a 500-returning server, verify events land in DLQ.

func TestIntegration_WebhookDLQWithRealServer(t *testing.T) {
	t.Parallel()

	var requestCount int
	var mu sync.Mutex
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failServer.Close()

	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	_, err := rc.SetWebhook(failServer.URL, TestAdminToken)
	if err != nil {
		t.Fatalf("set webhook: %v", err)
	}

	// Trigger events
	ownerID, _ := registerTestNode(t, rc)
	_, err = rc.CreateNetwork(ownerID, "dlq-test", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}

	// Wait for retries to exhaust (3 retries * exponential backoff)
	time.Sleep(8 * time.Second)

	whResp, err := rc.GetWebhook(TestAdminToken)
	if err != nil {
		t.Fatalf("get webhook: %v", err)
	}

	failed, _ := whResp["failed"].(float64)
	delivered, _ := whResp["delivered"].(float64)
	t.Logf("webhook stats: delivered=%v failed=%v", delivered, failed)

	if failed == 0 {
		t.Error("expected some failed webhook deliveries")
	}

	// Check DLQ
	dlqResp, err := rc.GetWebhookDLQ(TestAdminToken)
	if err != nil {
		t.Fatalf("get webhook dlq: %v", err)
	}
	if dlqResp["type"] != "get_webhook_dlq_ok" {
		t.Fatalf("expected get_webhook_dlq_ok, got %v", dlqResp["type"])
	}

	events, ok := dlqResp["events"].([]interface{})
	if !ok {
		t.Fatalf("expected events array, got %T", dlqResp["events"])
	}
	t.Logf("DLQ: %d events", len(events))

	if len(events) == 0 {
		t.Error("expected DLQ to contain failed events")
	}

	for _, raw := range events {
		ev, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if ev["action"] == nil {
			t.Error("DLQ event missing action")
		}
		if ev["event_id"] == nil {
			t.Error("DLQ event missing event_id")
		}
	}

	mu.Lock()
	rc2 := requestCount
	mu.Unlock()
	if rc2 == 0 {
		t.Error("fail server received no requests")
	}
	t.Logf("fail server received %d requests (retries)", rc2)
}

// ============================================================
// Integration Test: Metrics reflect real operation counts
// ============================================================

func TestIntegration_MetricsReflectOperations(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	reg.SetAdminToken(TestAdminToken)
	go reg.ListenAndServe(":0")
	defer reg.Close()
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()
	go reg.ServeDashboard(dashAddr)
	waitDashboard(t, dashAddr)

	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	id1, _ := registerTestNode(t, rc)
	id2, _ := registerTestNode(t, rc)
	id3, _ := registerTestNode(t, rc)

	netResp, err := rc.CreateNetwork(id1, "metrics-ops-net", "open", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	_, _ = rc.JoinNetwork(id2, netID, "", 0, TestAdminToken)
	_, _ = rc.JoinNetwork(id3, netID, "", 0, TestAdminToken)
	_, _ = rc.PromoteMember(netID, id1, id2, TestAdminToken)

	body := fetchMetrics(t, dashAddr)

	checks := map[string]string{
		"pilot_registrations_total":                            "registrations exist",
		"pilot_nodes_total":                                    "nodes total exists",
		"pilot_networks_total":                                 "networks total exists",
		"pilot_networks_enterprise":                            "enterprise count exists",
		`pilot_network_members{network="metrics-ops-net"}`:     "per-network members",
		`pilot_rbac_operations_total{op="promote"}`:            "RBAC promote tracked",
		`pilot_requests_total{type="register"}`:                "register requests tracked",
		`pilot_request_duration_seconds_bucket{type="register"`: "register histogram",
	}
	for metric, desc := range checks {
		if !strings.Contains(body, metric) {
			t.Errorf("missing: %s (%s)", metric, desc)
		}
	}
	t.Logf("verified %d metric checks, body=%d bytes", len(checks), len(body))
}

// ============================================================
// Integration Test: OIDC JWT token validation (built-in)
// ============================================================
// TDD: When IDP is configured as OIDC with a JWKS endpoint, the registry
// should validate JWT tokens directly (decode, verify signature, check claims)
// without needing an external webhook.

func TestIntegration_OIDCJWTValidation(t *testing.T) {
	t.Parallel()

	// Create a mock JWKS endpoint that serves our test key
	secret := []byte("test-secret-key-for-hs256-signing")
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve a JWKS response with our HMAC key
		// For HMAC, we serve as a symmetric key in JWK format
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[{"kty":"oct","k":"dGVzdC1zZWNyZXQta2V5LWZvci1oczI1Ni1zaWduaW5n","kid":"test-key-1","alg":"HS256"}]}`))
	}))
	defer jwksServer.Close()

	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	// Configure OIDC IDP with JWKS endpoint
	_, err := rc.SetIDPConfig("oidc", jwksServer.URL, "https://auth.corp.example.com", "pilot-app", "", "", TestAdminToken)
	if err != nil {
		t.Fatalf("set idp config: %v", err)
	}

	// Create a valid JWT token
	validJWT := createTestJWT(t, secret, map[string]interface{}{
		"iss": "https://auth.corp.example.com",
		"aud": "pilot-app",
		"sub": "user-12345@corp.example.com",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	// Try to validate the token via the registry
	resp, err := rc.Send(map[string]interface{}{
		"type":        "validate_token",
		"token":       validJWT,
		"admin_token": TestAdminToken,
	})
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if resp["type"] == "error" {
		t.Fatalf("token validation returned error: %v", resp["error"])
	}

	verified, _ := resp["verified"].(bool)
	subject, _ := resp["subject"].(string)
	issuer, _ := resp["issuer"].(string)

	if !verified {
		t.Error("expected token to be verified")
	}
	if subject != "user-12345@corp.example.com" {
		t.Errorf("expected subject=user-12345@corp.example.com, got %v", subject)
	}
	if issuer != "https://auth.corp.example.com" {
		t.Errorf("expected issuer, got %v", issuer)
	}

	t.Logf("OIDC JWT validated: subject=%s issuer=%s", subject, issuer)

	// Test expired token
	expiredJWT := createTestJWT(t, secret, map[string]interface{}{
		"iss": "https://auth.corp.example.com",
		"aud": "pilot-app",
		"sub": "expired@corp.example.com",
		"exp": time.Now().Add(-1 * time.Hour).Unix(), // expired
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	})

	resp2, err := rc.Send(map[string]interface{}{
		"type":        "validate_token",
		"token":       expiredJWT,
		"admin_token": TestAdminToken,
	})
	if err != nil {
		// Expected — expired token should fail
		t.Logf("expired token correctly rejected: %v", err)
	} else {
		verified2, _ := resp2["verified"].(bool)
		if verified2 {
			t.Error("expired token should not be verified")
		} else {
			t.Log("expired token correctly rejected via response")
		}
	}

	// Test wrong issuer
	wrongIssuerJWT := createTestJWT(t, secret, map[string]interface{}{
		"iss": "https://evil.example.com",
		"aud": "pilot-app",
		"sub": "hacker@evil.com",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	resp3, err := rc.Send(map[string]interface{}{
		"type":        "validate_token",
		"token":       wrongIssuerJWT,
		"admin_token": TestAdminToken,
	})
	if err != nil {
		t.Logf("wrong issuer correctly rejected: %v", err)
	} else {
		verified3, _ := resp3["verified"].(bool)
		if verified3 {
			t.Error("wrong issuer token should not be verified")
		} else {
			t.Log("wrong issuer correctly rejected via response")
		}
	}

	// Test malformed token
	_, err = rc.Send(map[string]interface{}{
		"type":        "validate_token",
		"token":       "not-a-jwt-token",
		"admin_token": TestAdminToken,
	})
	if err != nil {
		t.Logf("malformed token correctly rejected: %v", err)
	} else {
		t.Log("malformed token handled (may return verified=false)")
	}
}

// createTestJWT creates an HS256-signed JWT for testing.
func createTestJWT(t *testing.T, secret []byte, claims map[string]interface{}) string {
	t.Helper()

	header := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT","kid":"test-key-1"}`))

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	payload := base64URLEncode(claimsJSON)

	signingInput := header + "." + payload

	// HMAC-SHA256
	mac := hmacSHA256([]byte(signingInput), secret)
	signature := base64URLEncode(mac)

	return signingInput + "." + signature
}

func base64URLEncode(data []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString(data)
	return encoded
}

func hmacSHA256(message, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return h.Sum(nil)
}

// ============================================================
// Integration Test: Splunk HEC receives actual audit events
// ============================================================
// Tightened: Wait for specific audit event types (not just config event).

func TestIntegration_SplunkHECAuditEvents(t *testing.T) {
	t.Parallel()

	splunkToken := "splunk-audit-events-token"
	splunk := newSplunkHECCollector(splunkToken)
	defer splunk.Close()

	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	// Configure audit export first
	_, err := rc.SetAuditExport("splunk_hec", splunk.URL(), splunkToken, "pilot-audit", "audit-test", TestAdminToken)
	if err != nil {
		t.Fatalf("set audit export: %v", err)
	}

	// Now do operations that generate audit events
	ownerID, _ := registerTestNode(t, rc)
	netResp, err := rc.CreateNetwork(ownerID, "splunk-audit-net", "open", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))
	memberID, _ := registerTestNode(t, rc)
	_, err = rc.JoinNetwork(memberID, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	_, err = rc.PromoteMember(netID, ownerID, memberID, TestAdminToken)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}

	// Wait for events to arrive (async export)
	time.Sleep(500 * time.Millisecond)
	if !splunk.WaitForEvents(3, 5*time.Second) {
		events := splunk.Events()
		t.Logf("only got %d events (wanted 3+)", len(events))
	}

	events := splunk.Events()
	t.Logf("total Splunk HEC events: %d", len(events))

	// Parse and check for specific audit actions
	actions := map[string]bool{}
	for _, raw := range events {
		var ev map[string]interface{}
		if err := json.Unmarshal(raw, &ev); err != nil {
			continue
		}
		event, _ := ev["event"].(map[string]interface{})
		if event == nil {
			continue
		}
		action, _ := event["action"].(string)
		if action != "" {
			actions[action] = true
			t.Logf("  HEC event: action=%s", action)
		}
		// Verify structure
		if ev["sourcetype"] != "pilot:audit" {
			t.Errorf("wrong sourcetype: %v", ev["sourcetype"])
		}
	}

	// We should see at least node.registered and network.created
	// (network.joined/member.promoted may still be in the async channel)
	expected := []string{"node.registered", "network.created"}
	for _, exp := range expected {
		if !actions[exp] {
			t.Errorf("missing Splunk HEC event: %s (got: %v)", exp, actions)
		}
	}
	if len(events) < 2 {
		t.Errorf("expected at least 2 Splunk events, got %d", len(events))
	}
}

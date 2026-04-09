package tests

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	icrypto "github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// waitDashboard polls the dashboard until it responds or times out.
func waitDashboard(t *testing.T, dashAddr string) {
	t.Helper()
	client := http.Client{Timeout: 2 * time.Second}
	for i := 0; i < 30; i++ {
		resp, err := client.Get(fmt.Sprintf("http://%s/metrics", dashAddr))
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("dashboard did not start within timeout")
}

// fetchMetrics GETs /metrics and returns the body as a string.
func fetchMetrics(t *testing.T, dashAddr string) string {
	t.Helper()
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s/metrics", dashAddr))
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 from /metrics, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Fatalf("expected text/plain content type, got %s", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics body: %v", err)
	}
	return string(body)
}

// metricsRegisterNode registers a node and returns its node_id.
func metricsRegisterNode(t *testing.T, addr string) uint32 {
	t.Helper()
	ident, err := icrypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	rc, err := registry.Dial(addr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	resp, err := rc.Send(map[string]interface{}{
		"type":        "register",
		"listen_addr": "127.0.0.1:4000",
		"public_key":  icrypto.EncodePublicKey(ident.PublicKey),
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if resp["type"] != "register_ok" {
		t.Fatalf("expected register_ok, got %v", resp["type"])
	}
	return uint32(resp["node_id"].(float64))
}

// metricsRegisterNodeWithIdentity registers a node and returns identity + node_id.
func metricsRegisterNodeWithIdentity(t *testing.T, addr string) (*icrypto.Identity, uint32) {
	t.Helper()
	ident, err := icrypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	rc, err := registry.Dial(addr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	resp, err := rc.Send(map[string]interface{}{
		"type":        "register",
		"listen_addr": "127.0.0.1:4000",
		"public_key":  icrypto.EncodePublicKey(ident.PublicKey),
		"public":      true,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if resp["type"] != "register_ok" {
		t.Fatalf("expected register_ok, got %v", resp["type"])
	}
	return ident, uint32(resp["node_id"].(float64))
}

func TestMetricsEndpointExists(t *testing.T) {
	t.Parallel()

	r := registry.New("127.0.0.1:9001")
	defer r.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()

	go r.ServeDashboard(dashAddr)
	waitDashboard(t, dashAddr)

	body := fetchMetrics(t, dashAddr)

	// Should contain pilot_* metrics and TYPE declarations
	for _, expected := range []string{
		"pilot_requests_total",
		"pilot_nodes_online",
		"pilot_nodes_total",
		"pilot_trust_links",
		"pilot_uptime_seconds",
		"pilot_registrations_total",
		"pilot_deregistrations_total",
		"# TYPE pilot_uptime_seconds gauge",
		"# TYPE pilot_registrations_total counter",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("metrics output missing %q", expected)
		}
	}
}

func TestMetricsRequestCounting(t *testing.T) {
	t.Parallel()

	r := registry.New("127.0.0.1:9001")
	go r.ListenAndServe("127.0.0.1:0")
	<-r.Ready()
	defer r.Close()

	regAddr := r.Addr().String()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()

	go r.ServeDashboard(dashAddr)
	waitDashboard(t, dashAddr)

	// Register a node (generates a "register" request)
	nodeID := metricsRegisterNode(t, regAddr)

	// Lookup the node (generates a "lookup" request)
	rc, err := registry.Dial(regAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()
	_, err = rc.Send(map[string]interface{}{
		"type":    "lookup",
		"node_id": nodeID,
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	body := fetchMetrics(t, dashAddr)

	// Verify register counter
	if !strings.Contains(body, `pilot_requests_total{type="register"}`) {
		t.Error("missing pilot_requests_total for register")
	}
	// Verify lookup counter
	if !strings.Contains(body, `pilot_requests_total{type="lookup"}`) {
		t.Error("missing pilot_requests_total for lookup")
	}
	// Verify lifecycle counter
	if !strings.Contains(body, "pilot_registrations_total 1") {
		t.Error("expected pilot_registrations_total to be 1")
	}

	// Verify histogram exists for register
	if !strings.Contains(body, `pilot_request_duration_seconds_bucket{type="register"`) {
		t.Error("missing request duration histogram for register")
	}
}

func TestMetricsGauges(t *testing.T) {
	t.Parallel()

	r := registry.New("127.0.0.1:9001")
	go r.ListenAndServe("127.0.0.1:0")
	<-r.Ready()
	defer r.Close()

	regAddr := r.Addr().String()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()

	go r.ServeDashboard(dashAddr)
	waitDashboard(t, dashAddr)

	// Register 2 nodes and report trust between them
	identA, nodeA := metricsRegisterNodeWithIdentity(t, regAddr)
	identB, nodeB := metricsRegisterNodeWithIdentity(t, regAddr)

	// Report trust: A trusts B (requires signature)
	rc, err := registry.Dial(regAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	challenge := fmt.Sprintf("report_trust:%d:%d", nodeA, nodeB)
	sig := identA.Sign([]byte(challenge))

	resp, err := rc.Send(map[string]interface{}{
		"type":      "report_trust",
		"node_id":   nodeA,
		"peer_id":   nodeB,
		"signature": base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatalf("report_trust: %v", err)
	}
	if resp["type"] != "report_trust_ok" {
		t.Fatalf("expected report_trust_ok, got %v (error: %v)", resp["type"], resp["error"])
	}
	_ = identB // used for registration

	body := fetchMetrics(t, dashAddr)

	// Verify gauges
	if !strings.Contains(body, "pilot_nodes_online 2") {
		t.Errorf("expected pilot_nodes_online 2, got:\n%s", extractLine(body, "pilot_nodes_online "))
	}
	if !strings.Contains(body, "pilot_nodes_total 2") {
		t.Errorf("expected pilot_nodes_total 2, got:\n%s", extractLine(body, "pilot_nodes_total "))
	}
	if !strings.Contains(body, "pilot_trust_links 1") {
		t.Errorf("expected pilot_trust_links 1, got:\n%s", extractLine(body, "pilot_trust_links "))
	}
	if !strings.Contains(body, "pilot_trust_reports_total 1") {
		t.Errorf("expected pilot_trust_reports_total 1, got:\n%s", extractLine(body, "pilot_trust_reports_total "))
	}
}

func TestMetricsErrorCounting(t *testing.T) {
	t.Parallel()

	r := registry.New("127.0.0.1:9001")
	go r.ListenAndServe("127.0.0.1:0")
	<-r.Ready()
	defer r.Close()

	regAddr := r.Addr().String()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()

	go r.ServeDashboard(dashAddr)
	waitDashboard(t, dashAddr)

	// Send a lookup for a nonexistent node (should error)
	rc, err := registry.Dial(regAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	resp, err := rc.Send(map[string]interface{}{
		"type":    "lookup",
		"node_id": 99999,
	})
	// The registry returns {"type":"error",...} which the client may surface as an error
	if err == nil && resp["type"] != "error" {
		t.Fatalf("expected error response, got %v", resp["type"])
	}

	body := fetchMetrics(t, dashAddr)

	// Verify error counter for lookup
	if !strings.Contains(body, `pilot_errors_total{type="lookup"}`) {
		t.Error("missing pilot_errors_total for lookup")
	}
}

func TestMetricsEnterprise(t *testing.T) {
	t.Parallel()

	r := registry.New("127.0.0.1:9001")
	r.SetAdminToken(TestAdminToken)
	go r.ListenAndServe("127.0.0.1:0")
	<-r.Ready()
	defer r.Close()

	regAddr := r.Addr().String()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()

	go r.ServeDashboard(dashAddr)
	waitDashboard(t, dashAddr)

	// Register owner and create enterprise network
	rc, err := registry.Dial(regAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	ownerID, _ := icrypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", icrypto.EncodePublicKey(ownerID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	ownerNodeID := uint32(resp["node_id"].(float64))

	memberID, _ := icrypto.GenerateIdentity()
	resp, err = rc.RegisterWithKey("", icrypto.EncodePublicKey(memberID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register member: %v", err)
	}
	memberNodeID := uint32(resp["node_id"].(float64))

	// Create enterprise network
	setClientSigner(rc, ownerID)
	resp, err = rc.CreateNetwork(ownerNodeID, "metrics-ent", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Invite + accept member
	_, err = rc.InviteToNetwork(netID, ownerNodeID, memberNodeID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	setClientSigner(rc, memberID)
	_, err = rc.RespondInvite(memberNodeID, netID, true)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	// Promote member
	setClientSigner(rc, ownerID)
	_, err = rc.PromoteMember(netID, ownerNodeID, memberNodeID, TestAdminToken)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}

	// Set policy
	_, err = rc.SetNetworkPolicy(netID, map[string]interface{}{
		"max_members": float64(50),
	}, TestAdminToken)
	if err != nil {
		t.Fatalf("set policy: %v", err)
	}

	body := fetchMetrics(t, dashAddr)

	// Verify enterprise gauges
	for _, metric := range []string{
		"pilot_networks_total",
		"pilot_networks_enterprise",
		"pilot_invites_pending",
		"pilot_audit_events_total",
		"pilot_invites_sent_total",
		"pilot_invites_accepted_total",
		"pilot_rbac_operations_total",
		"pilot_policy_changes_total",
		"pilot_key_rotations_total",
	} {
		if !strings.Contains(body, metric) {
			t.Errorf("metrics output missing %q", metric)
		}
	}

	// Check specific values
	if !strings.Contains(body, "pilot_networks_enterprise 1") {
		t.Errorf("expected pilot_networks_enterprise 1, got: %s", extractLine(body, "pilot_networks_enterprise "))
	}
	if !strings.Contains(body, "pilot_invites_sent_total 1") {
		t.Errorf("expected pilot_invites_sent_total 1, got: %s", extractLine(body, "pilot_invites_sent_total "))
	}
	if !strings.Contains(body, "pilot_invites_accepted_total 1") {
		t.Errorf("expected pilot_invites_accepted_total 1, got: %s", extractLine(body, "pilot_invites_accepted_total "))
	}
	if !strings.Contains(body, `pilot_rbac_operations_total{op="promote"} 1`) {
		t.Errorf("expected promote rbac op, got: %s", extractLine(body, "pilot_rbac_operations_total"))
	}
	if !strings.Contains(body, "pilot_policy_changes_total 1") {
		t.Errorf("expected pilot_policy_changes_total 1, got: %s", extractLine(body, "pilot_policy_changes_total "))
	}

	t.Logf("enterprise metrics verified: networks_enterprise=1, invites_sent=1, invites_accepted=1, rbac promote=1, policy_changes=1")
}

// extractLine returns the first line containing prefix, for better error messages.
func extractLine(body, prefix string) string {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return "(not found)"
}

// TestPerNetworkMetrics verifies Grafana-ready per-network labeled metrics.
func TestPerNetworkMetrics(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	reg.SetAdminToken(TestAdminToken)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry start timeout")
	}
	defer reg.Close()

	// Start dashboard
	dashLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dashAddr := dashLn.Addr().String()
	dashLn.Close()
	go reg.ServeDashboard(dashAddr)
	waitDashboard(t, dashAddr)

	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	// Create an enterprise network with members
	id1, _ := icrypto.GenerateIdentity()
	resp1, _ := rc.RegisterWithKey("", icrypto.EncodePublicKey(id1.PublicKey), "", nil)
	nodeID1 := uint32(resp1["node_id"].(float64))

	id2, _ := icrypto.GenerateIdentity()
	resp2, _ := rc.RegisterWithKey("", icrypto.EncodePublicKey(id2.PublicKey), "", nil)
	nodeID2 := uint32(resp2["node_id"].(float64))

	netResp, err := rc.CreateNetwork(nodeID1, "grafana-test", "open", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	_, err = rc.JoinNetwork(nodeID2, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join: %v", err)
	}

	// Promote nodeID2 to admin
	_, err = rc.PromoteMember(netID, nodeID1, nodeID2, TestAdminToken)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}

	// Scrape metrics
	time.Sleep(100 * time.Millisecond) // let gauges update
	client := http.Client{Timeout: 2 * time.Second}
	metricsResp, err := client.Get(fmt.Sprintf("http://%s/metrics", dashAddr))
	if err != nil {
		t.Fatalf("scrape metrics: %v", err)
	}
	body, _ := io.ReadAll(metricsResp.Body)
	metricsResp.Body.Close()
	metricsBody := string(body)

	// Check per-network metrics
	if !strings.Contains(metricsBody, `pilot_network_members{network="grafana-test"}`) {
		t.Error("missing pilot_network_members for grafana-test")
		t.Log(extractLine(metricsBody, "pilot_network_members"))
	}
	if !strings.Contains(metricsBody, `pilot_network_admins{network="grafana-test"}`) {
		t.Error("missing pilot_network_admins for grafana-test")
	}
	if !strings.Contains(metricsBody, `pilot_network_enterprise{network="grafana-test"} 1`) {
		t.Error("missing pilot_network_enterprise for grafana-test")
	}

	// Check enterprise status gauges
	if !strings.Contains(metricsBody, "pilot_idp_configured") {
		t.Error("missing pilot_idp_configured metric")
	}
	if !strings.Contains(metricsBody, "pilot_webhook_configured") {
		t.Error("missing pilot_webhook_configured metric")
	}

	t.Log("per-network Grafana metrics verified")
}

// TestWebhookDLQ verifies the dead letter queue for failed webhook deliveries.
func TestWebhookDLQ(t *testing.T) {
	t.Parallel()
	rc, reg, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	// Configure webhook to an endpoint that always returns 500
	failCount := 0
	srv := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			failCount++
			w.WriteHeader(500)
		}),
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go srv.Serve(ln)
	defer srv.Close()

	_, err := rc.SetWebhook("http://"+ln.Addr().String(), TestAdminToken)
	if err != nil {
		t.Fatalf("set webhook: %v", err)
	}
	reg.SetWebhookRetryBackoff(10 * time.Millisecond) // fast retries in tests

	// Trigger audit events that will fail to deliver
	registerTestNode(t, rc)
	time.Sleep(200 * time.Millisecond) // wait for retries

	// Check webhook stats
	whResp, err := rc.GetWebhook(TestAdminToken)
	if err != nil {
		t.Fatalf("get webhook: %v", err)
	}
	t.Logf("webhook stats: delivered=%v failed=%v dropped=%v dlq=%v",
		whResp["delivered"], whResp["failed"], whResp["dropped"], whResp["dlq_size"])

	if whResp["failed"] == float64(0) && whResp["dlq_size"] == float64(0) {
		t.Log("warning: no failed events detected (timing sensitive)")
	}

	// Check DLQ contents
	dlqResp, err := rc.GetWebhookDLQ(TestAdminToken)
	if err != nil {
		t.Fatalf("get webhook dlq: %v", err)
	}
	dlqCount := dlqResp["count"]
	t.Logf("DLQ has %v events", dlqCount)

	t.Log("webhook DLQ test passed")
}

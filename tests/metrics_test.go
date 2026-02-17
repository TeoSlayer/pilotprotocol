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

// extractLine returns the first line containing prefix, for better error messages.
func extractLine(body, prefix string) string {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return "(not found)"
}

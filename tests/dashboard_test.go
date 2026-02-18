package tests

import (
	"encoding/json"
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

// dashRegisterNode registers a test node with the given hostname via the registry client.
func dashRegisterNode(t *testing.T, addr, hostname string) {
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

	msg := map[string]interface{}{
		"type":        "register",
		"listen_addr": "127.0.0.1:4000",
		"public_key":  icrypto.EncodePublicKey(ident.PublicKey),
	}
	if hostname != "" {
		msg["hostname"] = hostname
	}

	resp, err := rc.Send(msg)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if resp["type"] != "register_ok" {
		t.Fatalf("expected register_ok, got %v", resp["type"])
	}
}

func TestDashboardStatsEmpty(t *testing.T) {
	t.Parallel()

	r := registry.New("127.0.0.1:9001")
	defer r.Close()

	stats := r.GetDashboardStats()

	if stats.TotalNodes != 0 {
		t.Fatalf("expected 0 total nodes, got %d", stats.TotalNodes)
	}
	if stats.ActiveNodes != 0 {
		t.Fatalf("expected 0 active nodes, got %d", stats.ActiveNodes)
	}
	if stats.TotalRequests != 0 {
		t.Fatalf("expected 0 total requests, got %d", stats.TotalRequests)
	}
	if stats.UptimeSecs < 0 {
		t.Fatal("uptime should not be negative")
	}
	// Should have at least the backbone network
	if len(stats.Networks) < 1 {
		t.Fatal("expected at least 1 network (backbone)")
	}
	found := false
	for _, n := range stats.Networks {
		if n.Name == "backbone" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected backbone network in stats")
	}
}

func TestDashboardStatsWithNodes(t *testing.T) {
	t.Parallel()

	r := registry.New("127.0.0.1:9001")
	go r.ListenAndServe("127.0.0.1:0")
	<-r.Ready()
	defer r.Close()

	addr := r.Addr().String()

	// Register two nodes with hostnames
	dashRegisterNode(t, addr, "alpha")
	dashRegisterNode(t, addr, "beta")

	stats := r.GetDashboardStats()

	if stats.TotalNodes != 2 {
		t.Fatalf("expected 2 total nodes, got %d", stats.TotalNodes)
	}
	if stats.ActiveNodes != 2 {
		t.Fatalf("expected 2 active nodes, got %d", stats.ActiveNodes)
	}
	// Each register call is a request via handleMessage
	if stats.TotalRequests < 2 {
		t.Fatalf("expected at least 2 requests, got %d", stats.TotalRequests)
	}
	if len(stats.Nodes) != 2 {
		t.Fatalf("expected 2 nodes in list, got %d", len(stats.Nodes))
	}

	// Verify no IPs leak in addresses
	for _, node := range stats.Nodes {
		if strings.Contains(node.Address, "127.0.0.1") {
			t.Fatalf("node address should be a pilot address, not an IP: %s", node.Address)
		}
	}

	// Verify node addresses are pilot addresses (not IPs)
	for _, node := range stats.Nodes {
		if strings.Contains(node.Address, "127.0.0.1") {
			t.Fatalf("node address should be a pilot address, not IP: %s", node.Address)
		}
	}
}

func TestDashboardHTTPEndpoints(t *testing.T) {
	t.Parallel()

	r := registry.New("127.0.0.1:9001")
	defer r.Close()

	// Find a free port for the dashboard
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()

	go r.ServeDashboard(dashAddr)

	// Wait for dashboard to start
	var client http.Client
	client.Timeout = 2 * time.Second
	var resp *http.Response
	for i := 0; i < 20; i++ {
		resp, err = client.Get(fmt.Sprintf("http://%s/api/stats", dashAddr))
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dashboard did not start: %v", err)
	}
	defer resp.Body.Close()

	// Test /api/stats
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("expected JSON content type, got %s", ct)
	}

	var stats registry.DashboardStats
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &stats); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if stats.UptimeSecs < 0 {
		t.Fatal("uptime should not be negative")
	}

	// Test / serves HTML
	htmlResp, err := client.Get(fmt.Sprintf("http://%s/", dashAddr))
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer htmlResp.Body.Close()

	if htmlResp.StatusCode != 200 {
		t.Fatalf("expected 200 for /, got %d", htmlResp.StatusCode)
	}
	htmlCt := htmlResp.Header.Get("Content-Type")
	if !strings.Contains(htmlCt, "text/html") {
		t.Fatalf("expected text/html content type, got %s", htmlCt)
	}
	htmlBody, _ := io.ReadAll(htmlResp.Body)
	if !strings.Contains(string(htmlBody), "Pilot Protocol") {
		t.Fatal("HTML page should contain 'Pilot Protocol'")
	}

	// Test 404 for unknown paths
	notFoundResp, err := client.Get(fmt.Sprintf("http://%s/nonexistent", dashAddr))
	if err != nil {
		t.Fatalf("GET /nonexistent: %v", err)
	}
	defer notFoundResp.Body.Close()
	if notFoundResp.StatusCode != 404 {
		t.Fatalf("expected 404 for /nonexistent, got %d", notFoundResp.StatusCode)
	}
}

func TestDashboardNoIPLeak(t *testing.T) {
	t.Parallel()

	r := registry.New("127.0.0.1:9001")
	go r.ListenAndServe("127.0.0.1:0")
	<-r.Ready()
	defer r.Close()

	addr := r.Addr().String()
	dashRegisterNode(t, addr, "leak-test")

	// Find a free port for the dashboard
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()

	go r.ServeDashboard(dashAddr)

	var client http.Client
	client.Timeout = 2 * time.Second
	var resp *http.Response
	for i := 0; i < 20; i++ {
		resp, err = client.Get(fmt.Sprintf("http://%s/api/stats", dashAddr))
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dashboard did not start: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// The JSON response should not contain any real IP addresses
	if strings.Contains(bodyStr, "127.0.0.1") {
		t.Fatal("API response leaks 127.0.0.1")
	}
	if strings.Contains(bodyStr, "real_addr") {
		t.Fatal("API response contains real_addr field")
	}
	if strings.Contains(bodyStr, "public_key") {
		t.Fatal("API response contains public_key field")
	}
}

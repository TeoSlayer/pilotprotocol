// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build nightly

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

	registry "github.com/pilot-protocol/rendezvous"
)

// dashRegisterNode lives in zz_dashboard_helper_test.go (default-tag).

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
	// Nodes registered without a version should appear as "<1.7.0"
	if stats.Versions == nil {
		t.Fatal("expected non-nil Versions map")
	}
	if stats.Versions["<1.7.0"] != 2 {
		t.Fatalf("expected 2 nodes with version <1.7.0, got %d", stats.Versions["<1.7.0"])
	}
}

func TestDashboardHTTPEndpoints(t *testing.T) {
	requireRealNetwork(t)
	t.Parallel()

	r := registry.New("127.0.0.1:9001")
	defer r.Close()
	// /api/stats is admin-gated (rich payload moved behind requireAdminToken;
	// anonymous callers use /api/public-stats). Authenticate as an operator.
	const adminToken = "dash-http-admin-token"
	r.SetAdminToken(adminToken)

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
	statsURL := fmt.Sprintf("http://%s/api/stats?admin_token=%s", dashAddr, adminToken)
	for i := 0; i < 20; i++ {
		resp, err = client.Get(statsURL)
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
	// /api/stats is admin-gated; authenticate as an operator.
	const adminToken = "dash-leak-admin-token"
	r.SetAdminToken(adminToken)

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
	statsURL := fmt.Sprintf("http://%s/api/stats?admin_token=%s", dashAddr, adminToken)
	for i := 0; i < 20; i++ {
		resp, err = client.Get(statsURL)
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

// TestDashboardAPIShape pins the public /api/stats schema: only fields the
// dashboard UI actually renders are exposed. Internal time-series, version
// distribution, relay counters, and per-network history rings must not leak.
func TestDashboardAPIShape(t *testing.T) {
	t.Parallel()

	r := registry.New("127.0.0.1:9001")
	go r.ListenAndServe("127.0.0.1:0")
	<-r.Ready()
	defer r.Close()

	r.SetDashboardToken("shape-test-token")
	// /api/stats is admin-gated; operators reach it with the admin token.
	// The dashboard `token` param still toggles per-network (authenticated)
	// fields on top of the admin gate.
	const adminToken = "shape-admin-token"
	r.SetAdminToken(adminToken)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()

	go r.ServeDashboard(dashAddr)

	var client http.Client
	client.Timeout = 2 * time.Second

	fetch := func(token string) map[string]interface{} {
		t.Helper()
		url := fmt.Sprintf("http://%s/api/stats?admin_token=%s", dashAddr, adminToken)
		if token != "" {
			url += "&token=" + token
		}
		var resp *http.Response
		for i := 0; i < 20; i++ {
			resp, err = client.Get(url)
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
		var m map[string]interface{}
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("decode JSON: %v", err)
		}
		return m
	}

	// Fields that must NEVER appear (redundant — UI does not render them).
	forbidden := []string{
		"versions",
		"relay_forwarded",
		"relay_dropped",
		"relay_not_found",
		"req_per_day",
		"downtime_intervals", // top-level; per-probe ones live under probes[*]
		"total_trust_links",
		"trust_links",
	}

	for _, mode := range []struct {
		name  string
		token string
	}{
		{"public", ""},
		{"authenticated", "shape-test-token"},
	} {
		stats := fetch(mode.token)
		for _, f := range forbidden {
			if _, ok := stats[f]; ok {
				t.Errorf("[%s] forbidden field %q present in response", mode.name, f)
			}
		}
		// Required core counters always render.
		for _, f := range []string{"total_requests", "total_nodes", "active_nodes", "uptime_secs"} {
			if _, ok := stats[f]; !ok {
				t.Errorf("[%s] required field %q missing from response", mode.name, f)
			}
		}
	}
}

// TestDashboardBannerEndpoint exercises the admin-only `/api/banner`
// endpoint: 401 without token, GET round-trips PUT, both methods rejected
// without auth, and the new banner surfaces in /api/stats for the public
// dashboard renderer. Pinning the lockdown so a future regression that
// re-opens the GET path fails this test.
func TestDashboardBannerEndpoint(t *testing.T) {
	requireRealNetwork(t)
	t.Parallel()

	const adminToken = "banner-test-admin-token"
	r := registry.New("127.0.0.1:9001")
	defer r.Close()
	r.SetAdminToken(adminToken)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()
	go r.ServeDashboard(dashAddr)

	client := http.Client{Timeout: 2 * time.Second}
	base := fmt.Sprintf("http://%s/api/banner", dashAddr)

	// Wait for server to start.
	for i := 0; i < 20; i++ {
		if resp, err := client.Get(base); err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 1. GET without token → 401.
	resp, err := client.Get(base)
	if err != nil {
		t.Fatalf("GET no-token: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET no-token: status=%d, want 401", resp.StatusCode)
	}

	// 2. PUT without token → 401.
	req, _ := http.NewRequest(http.MethodPut, base, strings.NewReader("attack"))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("PUT no-token: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("PUT no-token: status=%d, want 401", resp.StatusCode)
	}

	// 3. GET with bad token → 401.
	reqBad, _ := http.NewRequest(http.MethodGet, base, nil)
	reqBad.Header.Set("X-Admin-Token", "wrong")
	resp, err = client.Do(reqBad)
	if err != nil {
		t.Fatalf("GET bad-token: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET bad-token: status=%d, want 401", resp.StatusCode)
	}

	// 4. PUT with valid token sets the banner.
	const newBanner = "Pre-1.7.0 no longer supported. Please update to 1.9.0."
	putReq, _ := http.NewRequest(http.MethodPut, base, strings.NewReader(newBanner))
	putReq.Header.Set("X-Admin-Token", adminToken)
	resp, err = client.Do(putReq)
	if err != nil {
		t.Fatalf("PUT good-token: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT good-token: status=%d body=%s", resp.StatusCode, string(body))
	}
	var putResp struct {
		OK     bool   `json:"ok"`
		Banner string `json:"banner"`
	}
	if err := json.Unmarshal(body, &putResp); err != nil {
		t.Fatalf("PUT body decode: %v (body=%s)", err, string(body))
	}
	if !putResp.OK || putResp.Banner != newBanner {
		t.Fatalf("PUT response = %+v, want ok=true banner=%q", putResp, newBanner)
	}

	// 5. GET with valid token round-trips the new value.
	getReq, _ := http.NewRequest(http.MethodGet, base, nil)
	getReq.Header.Set("X-Admin-Token", adminToken)
	resp, err = client.Do(getReq)
	if err != nil {
		t.Fatalf("GET good-token: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET good-token: status=%d", resp.StatusCode)
	}
	var getResp struct {
		Banner string `json:"banner"`
	}
	if err := json.Unmarshal(body, &getResp); err != nil {
		t.Fatalf("GET body decode: %v", err)
	}
	if getResp.Banner != newBanner {
		t.Fatalf("GET banner = %q, want %q", getResp.Banner, newBanner)
	}

	// 6. The new banner must surface in the /api/stats payload so the
	//    dashboard HTML renders it (admin-gated; authenticate as operator).
	statsResp, err := client.Get(fmt.Sprintf("http://%s/api/stats?admin_token=%s", dashAddr, adminToken))
	if err != nil {
		t.Fatalf("GET stats: %v", err)
	}
	statsBody, _ := io.ReadAll(statsResp.Body)
	statsResp.Body.Close()
	var stats map[string]interface{}
	if err := json.Unmarshal(statsBody, &stats); err != nil {
		t.Fatalf("stats decode: %v", err)
	}
	if got, _ := stats["maintenance_banner"].(string); got != newBanner {
		t.Fatalf("/api/stats maintenance_banner = %q, want %q", got, newBanner)
	}

	// 7. PUT empty body clears the banner.
	clearReq, _ := http.NewRequest(http.MethodPut, base, strings.NewReader(""))
	clearReq.Header.Set("X-Admin-Token", adminToken)
	resp, err = client.Do(clearReq)
	if err != nil {
		t.Fatalf("PUT clear: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT clear: status=%d", resp.StatusCode)
	}
	if r.MaintenanceBanner() != "" {
		t.Fatalf("after empty-body PUT, banner = %q, want empty", r.MaintenanceBanner())
	}

	// 8. DELETE is not in the allowed methods → 405.
	delReq, _ := http.NewRequest(http.MethodDelete, base, nil)
	delReq.Header.Set("X-Admin-Token", adminToken)
	resp, err = client.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE: status=%d, want 405", resp.StatusCode)
	}
}

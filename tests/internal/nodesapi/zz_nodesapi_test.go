// SPDX-License-Identifier: AGPL-3.0-or-later

package nodesapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/nodesapi"
)

func newFakeServer(t *testing.T, token string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"service":"pilot-geo-exporter"}`))
	})
	check := func(w http.ResponseWriter, r *http.Request) bool {
		if token == "" {
			return true
		}
		if r.URL.Query().Get("token") == token || r.Header.Get("X-Token") == token {
			return true
		}
		http.Error(w, `{"error":"unauthorized"}`, 401)
		return false
	}
	resp := nodesapi.Response{
		UpdatedAt:              float64(time.Now().Unix()),
		OnlineThresholdSeconds: 600,
		InfraIPsExcluded:       []string{"34.70.116.35"},
		MetricCap:              5000,
		MetricTruncated:        false,
		Count:                  3,
		Nodes: []nodesapi.Node{
			{NodeID: 14213, IP: "147.185.40.93", Country: "US", Hostname: "arxiv", Public: true, RealAddr: "147.185.40.93:60302", LastSeen: "2026-05-01T23:33:10Z", LastSeenUnix: 1746138430},
			{NodeID: 14341, IP: "147.185.40.93", Country: "US", Hostname: "arxiv-search", Public: true, RealAddr: "147.185.40.93:39812", LastSeen: "2026-05-01T23:33:11Z", LastSeenUnix: 1746138431},
			{NodeID: 113868, IP: "113.89.9.69", Country: "CN", Hostname: "", Public: false, RealAddr: "113.89.9.69:28728", LastSeen: "2026-05-01T23:33:00Z", LastSeenUnix: 1746138420},
		},
	}
	mux.HandleFunc("/nodes", func(w http.ResponseWriter, r *http.Request) {
		if !check(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/nodes/by_ip", func(w http.ResponseWriter, r *http.Request) {
		if !check(w, r) {
			return
		}
		ip := r.URL.Query().Get("ip")
		filtered := resp
		filtered.Nodes = nil
		for _, n := range resp.Nodes {
			if n.IP == ip {
				filtered.Nodes = append(filtered.Nodes, n)
			}
		}
		filtered.Count = len(filtered.Nodes)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(filtered)
	})
	return httptest.NewServer(mux)
}

func TestHealthz(t *testing.T) {
	t.Parallel()
	srv := newFakeServer(t, "")
	defer srv.Close()
	c := nodesapi.New(srv.URL, "")
	if err := c.Healthz(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestListUnauthorized(t *testing.T) {
	t.Parallel()
	srv := newFakeServer(t, "secret")
	defer srv.Close()
	c := nodesapi.New(srv.URL, "") // no token
	_, err := c.List(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestListWithToken(t *testing.T) {
	t.Parallel()
	srv := newFakeServer(t, "secret")
	defer srv.Close()
	c := nodesapi.New(srv.URL, "secret")
	r, err := c.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Count != 3 || len(r.Nodes) != 3 {
		t.Fatalf("count=%d nodes=%d, want 3 each", r.Count, len(r.Nodes))
	}
	if r.InfraIPsExcluded[0] != "34.70.116.35" {
		t.Fatalf("infra excluded = %v", r.InfraIPsExcluded)
	}
}

func TestByIP(t *testing.T) {
	t.Parallel()
	srv := newFakeServer(t, "secret")
	defer srv.Close()
	c := nodesapi.New(srv.URL, "secret")
	r, err := c.ByIP(context.Background(), "147.185.40.93")
	if err != nil {
		t.Fatal(err)
	}
	if r.Count != 2 {
		t.Fatalf("count=%d, want 2", r.Count)
	}
	for _, n := range r.Nodes {
		if n.IP != "147.185.40.93" {
			t.Fatalf("got node with wrong IP: %s", n.IP)
		}
	}
}

func TestByIPRequiresIP(t *testing.T) {
	t.Parallel()
	c := nodesapi.New("http://127.0.0.1:0", "")
	_, err := c.ByIP(context.Background(), "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestIDs(t *testing.T) {
	t.Parallel()
	r := &nodesapi.Response{Nodes: []nodesapi.Node{{NodeID: 3}, {NodeID: 1}, {NodeID: 2}}}
	ids := r.IDs()
	if len(ids) != 3 {
		t.Fatalf("ids len = %d, want 3", len(ids))
	}
	want := []uint32{3, 1, 2}
	for i, id := range ids {
		if id != want[i] {
			t.Fatalf("ids[%d] = %d, want %d", i, id, want[i])
		}
	}
}

func TestFilters(t *testing.T) {
	t.Parallel()
	r := &nodesapi.Response{Nodes: []nodesapi.Node{
		{NodeID: 1, Country: "US", Hostname: "a", Public: true},
		{NodeID: 2, Country: "us", Hostname: "", Public: false},
		{NodeID: 3, Country: "FR", Hostname: "c", Public: true},
	}}
	if got := r.FilterCountry("US"); len(got) != 2 {
		t.Fatalf("FilterCountry US = %d, want 2 (case-insensitive)", len(got))
	}
	if got := r.FilterHostnamed(); len(got) != 2 {
		t.Fatalf("FilterHostnamed = %d, want 2", len(got))
	}
	if got := r.FilterPublic(); len(got) != 2 {
		t.Fatalf("FilterPublic = %d, want 2", len(got))
	}
}

func TestNilResponseSafe(t *testing.T) {
	t.Parallel()
	var r *nodesapi.Response
	if r.IDs() != nil || r.FilterCountry("US") != nil || r.FilterHostnamed() != nil || r.FilterPublic() != nil {
		t.Fatal("nil-Response methods should return nil, not panic")
	}
}

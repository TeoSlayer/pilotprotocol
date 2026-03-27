package tests

import (
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// TestRegistryHealthEndpoint verifies that the registry /healthz endpoint returns
// valid JSON with status "ok", version, uptime_seconds, and nodes_online.
func TestRegistryHealthEndpoint(t *testing.T) {
	t.Parallel()

	// Start a registry server
	reg := registry.New("127.0.0.1:9001")
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	// Register a node so we can verify nodes_online
	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	id, _ := crypto.GenerateIdentity()
	_, err = rc.RegisterWithKey("127.0.0.1:4000", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node: %v", err)
	}

	// Start the dashboard (which serves /healthz)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()

	go reg.ServeDashboard(dashAddr)

	// Wait for dashboard to be ready
	var client http.Client
	client.Timeout = 2 * time.Second
	var resp *http.Response
	for i := 0; i < 20; i++ {
		resp, err = client.Get("http://" + dashAddr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	// Verify HTTP status
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Verify Content-Type
	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}

	// Parse JSON response
	var health map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	// Verify required fields
	status, ok := health["status"].(string)
	if !ok || status != "ok" {
		t.Fatalf("expected status 'ok', got %v", health["status"])
	}

	version, ok := health["version"].(string)
	if !ok || version != "1.0" {
		t.Fatalf("expected version '1.0', got %v", health["version"])
	}

	uptimeVal, ok := health["uptime_seconds"].(float64)
	if !ok {
		t.Fatalf("missing uptime_seconds in response")
	}
	if uptimeVal < 0 {
		t.Fatalf("uptime_seconds should be >= 0, got %v", uptimeVal)
	}

	nodesOnline, ok := health["nodes_online"].(float64)
	if !ok {
		t.Fatalf("missing nodes_online in response")
	}
	if int(nodesOnline) < 1 {
		t.Fatalf("expected at least 1 node online, got %v", nodesOnline)
	}
}

// TestRegistryHealthEndpointNoNodes verifies that /healthz works with zero nodes.
func TestRegistryHealthEndpointNoNodes(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()

	go reg.ServeDashboard(dashAddr)

	var client http.Client
	client.Timeout = 2 * time.Second
	var resp *http.Response
	for i := 0; i < 20; i++ {
		resp, err = client.Get("http://" + dashAddr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var health map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if health["status"] != "ok" {
		t.Fatalf("expected status 'ok', got %v", health["status"])
	}
	if int(health["nodes_online"].(float64)) != 0 {
		t.Fatalf("expected 0 nodes online, got %v", health["nodes_online"])
	}
}

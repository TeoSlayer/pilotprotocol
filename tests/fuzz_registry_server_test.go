package tests

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func startTestServer(t *testing.T) *registry.Server {
	t.Helper()
	s := registry.New("")
	go s.ListenAndServe("127.0.0.1:0")
	select {
	case <-s.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("registry server did not start in time")
	}
	return s
}

func startTestServerWithStore(t *testing.T) (*registry.Server, string) {
	t.Helper()
	dir := t.TempDir()
	storePath := filepath.Join(dir, "registry.json")
	s := registry.NewWithStore("", storePath)
	go s.ListenAndServe("127.0.0.1:0")
	select {
	case <-s.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("registry server did not start in time")
	}
	return s, storePath
}

// regTestNodeWithKey registers a node using a fresh identity and sets the
// client signer so subsequent authenticated operations succeed.
func regTestNodeWithKey(t *testing.T, c *registry.Client, listenAddr string) uint32 {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	resp, err := c.RegisterWithKey(listenAddr, crypto.EncodePublicKey(id.PublicKey), "")
	if err != nil {
		t.Fatalf("RegisterWithKey: %v", err)
	}
	setClientSigner(c, id)
	return uint32(resp["node_id"].(float64))
}

// ---------------------------------------------------------------------------
// Server creation
// ---------------------------------------------------------------------------

func TestRegistryServerNew(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	if s.Addr() == nil {
		t.Fatal("expected bound address")
	}
}

func TestRegistryServerNewWithStore(t *testing.T) {
	s, storePath := startTestServerWithStore(t)
	defer s.Close()

	if err := s.TriggerSnapshot(); err != nil {
		t.Fatalf("TriggerSnapshot: %v", err)
	}
	if _, err := os.Stat(storePath); err != nil {
		t.Fatalf("store file should exist after snapshot: %v", err)
	}
}

func TestRegistryServerNewWithStoreNonExistentDir(t *testing.T) {
	s := registry.NewWithStore("", "/tmp/pilot-test-noexist-"+fmt.Sprintf("%d", time.Now().UnixNano())+"/registry.json")
	go s.ListenAndServe("127.0.0.1:0")
	select {
	case <-s.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("server did not start")
	}
	defer s.Close()
}

// ---------------------------------------------------------------------------
// Admin token
// ---------------------------------------------------------------------------

func TestRegistryServerSetAdminToken(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()
	s.SetAdminToken("test-token-123")
}

func TestRegistryServerSetAdminTokenEmpty(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()
	s.SetAdminToken("")
}

// ---------------------------------------------------------------------------
// Replication token
// ---------------------------------------------------------------------------

func TestRegistryServerSetReplicationToken(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()
	s.SetReplicationToken("repl-secret")
}

func TestRegistryServerSetReplicationTokenEmpty(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()
	s.SetReplicationToken("")
}

// ---------------------------------------------------------------------------
// Standby mode
// ---------------------------------------------------------------------------

func TestRegistryServerIsStandbyDefault(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	if s.IsStandby() {
		t.Fatal("should not be standby by default")
	}
}

// ---------------------------------------------------------------------------
// Dashboard stats
// ---------------------------------------------------------------------------

func TestRegistryServerDashboardStatsEmpty(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	stats := s.GetDashboardStats()
	if stats.TotalNodes != 0 {
		t.Fatalf("expected 0 total nodes, got %d", stats.TotalNodes)
	}
	if stats.ActiveNodes != 0 {
		t.Fatalf("expected 0 active nodes, got %d", stats.ActiveNodes)
	}
	if stats.TotalTrustLinks != 0 {
		t.Fatalf("expected 0 trust links, got %d", stats.TotalTrustLinks)
	}
	if stats.TotalRequests != 0 {
		t.Fatalf("expected 0 requests, got %d", stats.TotalRequests)
	}
	if stats.UniqueTags != 0 {
		t.Fatalf("expected 0 unique tags, got %d", stats.UniqueTags)
	}
	if stats.TaskExecutors != 0 {
		t.Fatalf("expected 0 task executors, got %d", stats.TaskExecutors)
	}
	if stats.UptimeSecs < 0 {
		t.Fatalf("uptime should be non-negative, got %d", stats.UptimeSecs)
	}
}

func TestRegistryServerDashboardStatsAfterRegister(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	addr := s.Addr().(*net.TCPAddr)
	c, err := registry.Dial(addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	regTestNodeWithKey(t, c, "127.0.0.1:4000")

	stats := s.GetDashboardStats()
	if stats.TotalNodes != 1 {
		t.Fatalf("expected 1 total node, got %d", stats.TotalNodes)
	}
}

func TestRegistryServerDashboardStatsJSON(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	stats := s.GetDashboardStats()
	data, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("marshal DashboardStats: %v", err)
	}
	var decoded registry.DashboardStats
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal DashboardStats: %v", err)
	}
	if decoded.TotalNodes != stats.TotalNodes {
		t.Fatal("round-trip mismatch")
	}
}

func TestRegistryServerDashboardStatsNetworks(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	stats := s.GetDashboardStats()
	if len(stats.Networks) < 1 {
		t.Fatal("expected at least backbone network")
	}
	found := false
	for _, n := range stats.Networks {
		if n.Name == "backbone" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("backbone network not found in dashboard stats")
	}
}

// ---------------------------------------------------------------------------
// Dashboard HTTP
// ---------------------------------------------------------------------------

func TestRegistryServerDashboardHTTP(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()

	go s.ServeDashboard(dashAddr)
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://" + dashAddr + "/api/stats")
	if err != nil {
		t.Fatalf("GET /api/stats: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var stats registry.DashboardStats
	if err := json.Unmarshal(body, &stats); err != nil {
		t.Fatalf("unmarshal /api/stats: %v", err)
	}
}

func TestRegistryServerDashboardBadges(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()

	go s.ServeDashboard(dashAddr)
	time.Sleep(100 * time.Millisecond)

	badges := []string{"nodes", "trust", "requests", "tags", "task-executors"}
	for _, badge := range badges {
		resp, err := http.Get("http://" + dashAddr + "/api/badge/" + badge)
		if err != nil {
			t.Fatalf("GET /api/badge/%s: %v", badge, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("/api/badge/%s: expected 200, got %d", badge, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "image/svg+xml" {
			t.Fatalf("/api/badge/%s: expected SVG, got %s", badge, ct)
		}
	}
}

func TestRegistryServerDashboardRoot(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()

	go s.ServeDashboard(dashAddr)
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://" + dashAddr + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("expected HTML, got %s", ct)
	}
}

func TestRegistryServerDashboard404(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()

	go s.ServeDashboard(dashAddr)
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://" + dashAddr + "/nonexistent")
	if err != nil {
		t.Fatalf("GET /nonexistent: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestRegistryServerDashboardSnapshotMethodNotAllowed(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()

	go s.ServeDashboard(dashAddr)
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://" + dashAddr + "/api/snapshot")
	if err != nil {
		t.Fatalf("GET /api/snapshot: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestRegistryServerDashboardSnapshotPOST(t *testing.T) {
	s, _ := startTestServerWithStore(t)
	defer s.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()

	go s.ServeDashboard(dashAddr)
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Post("http://"+dashAddr+"/api/snapshot", "", nil)
	if err != nil {
		t.Fatalf("POST /api/snapshot: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

func TestRegistryServerPersistenceRoundTrip(t *testing.T) {
	s, storePath := startTestServerWithStore(t)

	addr := s.Addr().(*net.TCPAddr)
	c, err := registry.Dial(addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	regTestNodeWithKey(t, c, "127.0.0.1:4000")
	c.Close()

	if err := s.TriggerSnapshot(); err != nil {
		t.Fatalf("TriggerSnapshot: %v", err)
	}
	s.Close()

	data, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var snapshot map[string]interface{}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatalf("snapshot is not valid JSON: %v", err)
	}
}

func TestRegistryServerTriggerSnapshotNoStore(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	err := s.TriggerSnapshot()
	if err != nil {
		t.Fatalf("TriggerSnapshot should not error without store: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Close idempotent
// ---------------------------------------------------------------------------

func TestRegistryServerCloseIdempotent(t *testing.T) {
	s := startTestServer(t)
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	s.Close()
}

// ---------------------------------------------------------------------------
// Client register + lookup
// ---------------------------------------------------------------------------

func TestRegistryClientRegisterLookup(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	addr := s.Addr().(*net.TCPAddr)
	c, err := registry.Dial(addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	nodeID := regTestNodeWithKey(t, c, "127.0.0.1:4000")

	lookupResp, err := c.Lookup(nodeID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if uint32(lookupResp["node_id"].(float64)) != nodeID {
		t.Fatal("Lookup returned wrong node ID")
	}
}

func TestRegistryClientRegisterWithKey(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	addr := s.Addr().(*net.TCPAddr)
	c, err := registry.Dial(addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	resp, err := c.RegisterWithKey("127.0.0.1:4000", crypto.EncodePublicKey(id.PublicKey), "testowner@example.com")
	if err != nil {
		t.Fatalf("RegisterWithKey: %v", err)
	}
	if resp["node_id"] == nil {
		t.Fatal("expected node_id in response")
	}
}

func TestRegistryClientLookupNonExistent(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	addr := s.Addr().(*net.TCPAddr)
	c, err := registry.Dial(addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	_, err = c.Lookup(99999)
	if err == nil {
		t.Fatal("expected error for non-existent node")
	}
}

// ---------------------------------------------------------------------------
// Client heartbeat + deregister
// ---------------------------------------------------------------------------

func TestRegistryClientHeartbeat(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	addr := s.Addr().(*net.TCPAddr)
	c, err := registry.Dial(addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	nodeID := regTestNodeWithKey(t, c, "127.0.0.1:4000")

	hbResp, err := c.Heartbeat(nodeID)
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if hbResp["type"] != "heartbeat_ok" {
		t.Fatalf("expected heartbeat_ok, got %v", hbResp["type"])
	}
}

func TestRegistryClientDeregister(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	addr := s.Addr().(*net.TCPAddr)
	c, err := registry.Dial(addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	nodeID := regTestNodeWithKey(t, c, "127.0.0.1:4000")

	deregResp, err := c.Deregister(nodeID)
	if err != nil {
		t.Fatalf("Deregister: %v", err)
	}
	if deregResp["type"] != "deregister_ok" {
		t.Fatalf("expected deregister_ok, got %v", deregResp["type"])
	}

	// Lookup should fail now
	_, err = c.Lookup(nodeID)
	if err == nil {
		t.Fatal("expected error after deregister")
	}
}

// ---------------------------------------------------------------------------
// Client set visibility + tags + hostname
// ---------------------------------------------------------------------------

func TestRegistryClientSetVisibility(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	addr := s.Addr().(*net.TCPAddr)
	c, err := registry.Dial(addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	nodeID := regTestNodeWithKey(t, c, "127.0.0.1:4000")

	visResp, err := c.SetVisibility(nodeID, true)
	if err != nil {
		t.Fatalf("SetVisibility: %v", err)
	}
	if visResp["type"] != "set_visibility_ok" {
		t.Fatalf("expected set_visibility_ok, got %v", visResp["type"])
	}
}

func TestRegistryClientSetTags(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	addr := s.Addr().(*net.TCPAddr)
	c, err := registry.Dial(addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	nodeID := regTestNodeWithKey(t, c, "127.0.0.1:4000")

	tagResp, err := c.SetTags(nodeID, []string{"ml", "compute"})
	if err != nil {
		t.Fatalf("SetTags: %v", err)
	}
	if tagResp["type"] != "set_tags_ok" {
		t.Fatalf("expected set_tags_ok, got %v", tagResp["type"])
	}

	stats := s.GetDashboardStats()
	if stats.UniqueTags < 1 {
		t.Fatal("expected at least 1 unique tag")
	}
}

func TestRegistryClientSetHostname(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	addr := s.Addr().(*net.TCPAddr)
	c, err := registry.Dial(addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	nodeID := regTestNodeWithKey(t, c, "127.0.0.1:4000")

	hnResp, err := c.SetHostname(nodeID, "myagent")
	if err != nil {
		t.Fatalf("SetHostname: %v", err)
	}
	if hnResp["type"] != "set_hostname_ok" {
		t.Fatalf("expected set_hostname_ok, got %v", hnResp["type"])
	}

	resolveResp, err := c.ResolveHostnameAs(nodeID, "myagent")
	if err != nil {
		t.Fatalf("ResolveHostname: %v", err)
	}
	if uint32(resolveResp["node_id"].(float64)) != nodeID {
		t.Fatal("hostname resolved to wrong node")
	}
}

func TestRegistryClientSetHostnameReserved(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	addr := s.Addr().(*net.TCPAddr)
	c, err := registry.Dial(addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	nodeID := regTestNodeWithKey(t, c, "127.0.0.1:4000")

	_, err = c.SetHostname(nodeID, "localhost")
	if err == nil {
		t.Fatal("expected error for reserved hostname 'localhost'")
	}
}

func TestRegistryClientSetHostnameDuplicate(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	sAddr := s.Addr().(*net.TCPAddr).String()

	// Two separate clients so each can have its own signer
	c1, err := registry.Dial(sAddr)
	if err != nil {
		t.Fatalf("Dial c1: %v", err)
	}
	defer c1.Close()

	c2, err := registry.Dial(sAddr)
	if err != nil {
		t.Fatalf("Dial c2: %v", err)
	}
	defer c2.Close()

	nodeID1 := regTestNodeWithKey(t, c1, "127.0.0.1:4001")
	nodeID2 := regTestNodeWithKey(t, c2, "127.0.0.1:4002")

	if _, err := c1.SetHostname(nodeID1, "unique-host"); err != nil {
		t.Fatalf("SetHostname first: %v", err)
	}

	_, err = c2.SetHostname(nodeID2, "unique-host")
	if err == nil {
		t.Fatal("expected error for duplicate hostname")
	}
}

// ---------------------------------------------------------------------------
// Client network operations
// ---------------------------------------------------------------------------

func TestRegistryClientNetworkCreateNoToken(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	addr := s.Addr().(*net.TCPAddr)
	c, err := registry.Dial(addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	nodeID := regTestNodeWithKey(t, c, "127.0.0.1:4000")

	_, err = c.CreateNetwork(nodeID, "testnet", "open", "", "")
	if err == nil {
		t.Fatal("expected error when no admin token configured")
	}
}

func TestRegistryClientNetworkCreateWithToken(t *testing.T) {
	s := startTestServer(t)
	s.SetAdminToken(TestAdminToken)
	defer s.Close()

	addr := s.Addr().(*net.TCPAddr)
	c, err := registry.Dial(addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	nodeID := regTestNodeWithKey(t, c, "127.0.0.1:4000")

	resp, err := c.CreateNetwork(nodeID, "tokennet", "open", "", TestAdminToken)
	if err != nil {
		t.Fatalf("CreateNetwork with token: %v", err)
	}
	netID, ok := resp["network_id"].(float64)
	if !ok || netID < 1 {
		t.Fatalf("expected valid network_id, got %v", resp["network_id"])
	}
	t.Logf("created network %d", int(netID))
}

func TestRegistryClientNetworkJoinLeave(t *testing.T) {
	s := startTestServer(t)
	s.SetAdminToken(TestAdminToken)
	defer s.Close()

	addr := s.Addr().(*net.TCPAddr)
	c1, err := registry.Dial(addr.String())
	if err != nil {
		t.Fatalf("Dial c1: %v", err)
	}
	defer c1.Close()
	c2, err := registry.Dial(addr.String())
	if err != nil {
		t.Fatalf("Dial c2: %v", err)
	}
	defer c2.Close()

	nodeID1 := regTestNodeWithKey(t, c1, "127.0.0.1:4001")
	nodeID2 := regTestNodeWithKey(t, c2, "127.0.0.1:4002")

	// Create network with node1
	resp, err := c1.CreateNetwork(nodeID1, "joinleave", "open", "", TestAdminToken)
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Node2 joins
	_, err = c2.JoinNetwork(nodeID2, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("JoinNetwork: %v", err)
	}

	// Node2 leaves
	_, err = c2.LeaveNetwork(nodeID2, netID, TestAdminToken)
	if err != nil {
		t.Fatalf("LeaveNetwork: %v", err)
	}
	t.Logf("node %d joined and left network %d", nodeID2, netID)
}

func TestRegistryClientListNetworks(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	addr := s.Addr().(*net.TCPAddr)
	c, err := registry.Dial(addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	resp, err := c.ListNetworks()
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	nets, ok := resp["networks"].([]interface{})
	if !ok {
		t.Fatal("expected networks array")
	}
	if len(nets) < 1 {
		t.Fatal("expected at least backbone network")
	}
}

func TestRegistryClientListNodesBackboneBlocked(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	addr := s.Addr().(*net.TCPAddr)
	c, err := registry.Dial(addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	_ = regTestNodeWithKey(t, c, "127.0.0.1:4000")

	// Listing backbone nodes is blocked for privacy
	_, err = c.ListNodes(0)
	if err == nil {
		t.Fatal("expected error listing backbone nodes")
	}
}

// ---------------------------------------------------------------------------
// Client trust operations
// ---------------------------------------------------------------------------

func TestRegistryClientTrustReportRevoke(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	sAddr := s.Addr().(*net.TCPAddr).String()

	c1, err := registry.Dial(sAddr)
	if err != nil {
		t.Fatalf("Dial c1: %v", err)
	}
	defer c1.Close()

	c2, err := registry.Dial(sAddr)
	if err != nil {
		t.Fatalf("Dial c2: %v", err)
	}
	defer c2.Close()

	nodeID1 := regTestNodeWithKey(t, c1, "127.0.0.1:4001")
	nodeID2 := regTestNodeWithKey(t, c2, "127.0.0.1:4002")

	trustResp, err := c1.ReportTrust(nodeID1, nodeID2)
	if err != nil {
		t.Fatalf("ReportTrust: %v", err)
	}
	if trustResp["type"] != "report_trust_ok" {
		t.Fatalf("expected report_trust_ok, got %v", trustResp["type"])
	}

	revokeResp, err := c1.RevokeTrust(nodeID1, nodeID2)
	if err != nil {
		t.Fatalf("RevokeTrust: %v", err)
	}
	if revokeResp["type"] != "revoke_trust_ok" {
		t.Fatalf("expected revoke_trust_ok, got %v", revokeResp["type"])
	}
}

// ---------------------------------------------------------------------------
// Client POLO score
// ---------------------------------------------------------------------------

func TestRegistryClientPoloScore(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	addr := s.Addr().(*net.TCPAddr)
	c, err := registry.Dial(addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	nodeID := regTestNodeWithKey(t, c, "127.0.0.1:4000")

	_, err = c.SetPoloScore(nodeID, 42)
	if err != nil {
		t.Fatalf("SetPoloScore: %v", err)
	}

	score, err := c.GetPoloScore(nodeID)
	if err != nil {
		t.Fatalf("GetPoloScore: %v", err)
	}
	if score != 42 {
		t.Fatalf("expected 42, got %d", score)
	}

	_, err = c.UpdatePoloScore(nodeID, 10)
	if err != nil {
		t.Fatalf("UpdatePoloScore: %v", err)
	}
	score2, _ := c.GetPoloScore(nodeID)
	if score2 != 52 {
		t.Fatalf("expected 52 after +10, got %d", score2)
	}
}

// ---------------------------------------------------------------------------
// Client task exec
// ---------------------------------------------------------------------------

func TestRegistryClientSetTaskExec(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()

	addr := s.Addr().(*net.TCPAddr)
	c, err := registry.Dial(addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	nodeID := regTestNodeWithKey(t, c, "127.0.0.1:4000")

	execResp, err := c.SetTaskExec(nodeID, true)
	if err != nil {
		t.Fatalf("SetTaskExec: %v", err)
	}
	if execResp["type"] != "set_task_exec_ok" {
		t.Fatalf("expected set_task_exec_ok, got %v", execResp["type"])
	}

	stats := s.GetDashboardStats()
	if stats.TaskExecutors != 1 {
		t.Fatalf("expected 1 task executor, got %d", stats.TaskExecutors)
	}
}

// ---------------------------------------------------------------------------
// Type structs
// ---------------------------------------------------------------------------

func TestRegistryDashboardNodeJSON(t *testing.T) {
	node := registry.DashboardNode{
		Address:    "0:0001.0000.002A",
		Tags:       []string{"ml", "gpu"},
		Online:     true,
		TrustLinks: 3,
		TaskExec:   true,
		PoloScore:  50,
	}
	data, err := json.Marshal(node)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded registry.DashboardNode
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Address != node.Address {
		t.Fatal("address mismatch")
	}
	if len(decoded.Tags) != 2 {
		t.Fatal("tags mismatch")
	}
	if decoded.PoloScore != 50 {
		t.Fatal("polo score mismatch")
	}
}

func TestRegistryDashboardEdgeJSON(t *testing.T) {
	edge := registry.DashboardEdge{
		Source: "0:0001.0000.0001",
		Target: "0:0001.0000.0002",
	}
	data, _ := json.Marshal(edge)
	var decoded registry.DashboardEdge
	json.Unmarshal(data, &decoded)
	if decoded.Source != edge.Source || decoded.Target != edge.Target {
		t.Fatal("edge JSON round-trip failed")
	}
}

func TestRegistryDashboardNetworkJSON(t *testing.T) {
	n := registry.DashboardNetwork{
		ID:            1,
		Name:          "testnet",
		Members:       5,
		OnlineMembers: 3,
	}
	data, _ := json.Marshal(n)
	var decoded registry.DashboardNetwork
	json.Unmarshal(data, &decoded)
	if decoded.ID != 1 || decoded.Name != "testnet" || decoded.Members != 5 || decoded.OnlineMembers != 3 {
		t.Fatal("network JSON round-trip failed")
	}
}

func TestRegistryHandshakeRelayMsgJSON(t *testing.T) {
	msg := registry.HandshakeRelayMsg{
		FromNodeID:    42,
		Justification: "need access to compute cluster",
		Timestamp:     time.Now(),
	}
	data, _ := json.Marshal(msg)
	var decoded registry.HandshakeRelayMsg
	json.Unmarshal(data, &decoded)
	if decoded.FromNodeID != 42 || decoded.Justification != "need access to compute cluster" {
		t.Fatal("HandshakeRelayMsg JSON round-trip failed")
	}
}

func TestRegistryHandshakeResponseMsgJSON(t *testing.T) {
	msg := registry.HandshakeResponseMsg{
		FromNodeID: 99,
		Accept:     true,
		Timestamp:  time.Now(),
	}
	data, _ := json.Marshal(msg)
	var decoded registry.HandshakeResponseMsg
	json.Unmarshal(data, &decoded)
	if decoded.FromNodeID != 99 || !decoded.Accept {
		t.Fatal("HandshakeResponseMsg JSON round-trip failed")
	}
}

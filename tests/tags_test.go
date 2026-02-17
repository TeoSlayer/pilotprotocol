package tests

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	icrypto "github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

func TestSetTagsBasic(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	nodeID, id := registerTestNode(t, rc)
	setClientSigner(rc, id)

	// Set tags
	resp, err := rc.SetTags(nodeID, []string{"webserver", "assistant"})
	if err != nil {
		t.Fatalf("set tags: %v", err)
	}
	if resp["type"] != "set_tags_ok" {
		t.Fatalf("expected set_tags_ok, got %v", resp["type"])
	}

	// Verify via lookup
	lookup, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	tags, ok := lookup["tags"].([]interface{})
	if !ok || len(tags) != 2 {
		t.Fatalf("expected 2 tags in lookup, got %v", lookup["tags"])
	}
	if tags[0] != "webserver" || tags[1] != "assistant" {
		t.Fatalf("expected [webserver assistant], got %v", tags)
	}
}

func TestSetTagsValidation(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	nodeID, id := registerTestNode(t, rc)
	setClientSigner(rc, id)

	// Too many tags (>10)
	tooMany := make([]string, 11)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("tag%d", i)
	}
	_, err := rc.SetTags(nodeID, tooMany)
	if err == nil {
		t.Fatal("expected error for >10 tags")
	}

	// Tag too long (>32 chars)
	_, err = rc.SetTags(nodeID, []string{"a-very-long-tag-that-exceeds-the-limit"})
	if err == nil {
		t.Fatal("expected error for tag >32 chars")
	}

	// Invalid chars (uppercase)
	_, err = rc.SetTags(nodeID, []string{"WebServer"})
	if err == nil {
		t.Fatal("expected error for uppercase tag")
	}

	// Invalid chars (spaces)
	_, err = rc.SetTags(nodeID, []string{"web server"})
	if err == nil {
		t.Fatal("expected error for tag with spaces")
	}
}

func TestSetTagsSignatureRequired(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	nodeID, _ := registerTestNode(t, rc)

	// Do not set signer — should fail
	_, err := rc.SetTags(nodeID, []string{"test"})
	if err == nil {
		t.Fatal("expected error without signature")
	}
	// The server returns "signature required for authenticated node" but the
	// handleMessage wrapper may convert it to "request failed". Either indicates
	// the unsigned request was rejected.
	errStr := err.Error()
	if !strings.Contains(errStr, "signature") && !strings.Contains(errStr, "request failed") {
		t.Fatalf("expected signature/auth error, got: %v", err)
	}
}

func TestSetTagsNormalization(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	nodeID, id := registerTestNode(t, rc)
	setClientSigner(rc, id)

	// Set tags with leading '#'
	resp, err := rc.SetTags(nodeID, []string{"#webserver", "#marketing"})
	if err != nil {
		t.Fatalf("set tags: %v", err)
	}

	// Tags should be normalized (no '#')
	tags, ok := resp["tags"].([]interface{})
	if !ok || len(tags) != 2 {
		t.Fatalf("expected 2 tags, got %v", resp["tags"])
	}
	if tags[0] != "webserver" || tags[1] != "marketing" {
		t.Fatalf("expected normalized tags, got %v", tags)
	}
}

func TestSetTagsClearTags(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	nodeID, id := registerTestNode(t, rc)
	setClientSigner(rc, id)

	// Set then clear
	_, err := rc.SetTags(nodeID, []string{"webserver"})
	if err != nil {
		t.Fatalf("set tags: %v", err)
	}

	_, err = rc.SetTags(nodeID, []string{})
	if err != nil {
		t.Fatalf("clear tags: %v", err)
	}

	// Verify cleared
	lookup, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if tags, ok := lookup["tags"]; ok {
		if arr, ok := tags.([]interface{}); ok && len(arr) > 0 {
			t.Fatalf("expected empty tags after clear, got %v", tags)
		}
	}
}

func TestSetTagsPersistence(t *testing.T) {
	t.Parallel()

	// Create a temporary file for persistence
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "registry.json")

	// Start registry with persistence
	reg := registry.NewWithStore("127.0.0.1:9001", storePath)
	go reg.ListenAndServe("127.0.0.1:0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	addr := reg.Addr().String()

	// Register and set tags
	ident, _ := icrypto.GenerateIdentity()
	rc, err := registry.Dial(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	resp, err := rc.RegisterWithKey("127.0.0.1:4000", icrypto.EncodePublicKey(ident.PublicKey), "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))
	setClientSigner(rc, ident)

	_, err = rc.SetTags(nodeID, []string{"persistent", "data"})
	if err != nil {
		t.Fatalf("set tags: %v", err)
	}
	rc.Close()
	reg.Close()

	// Verify snapshot file exists
	if _, err := os.Stat(storePath); os.IsNotExist(err) {
		t.Fatal("snapshot file not created")
	}

	// Restart registry from snapshot
	reg2 := registry.NewWithStore("127.0.0.1:9001", storePath)
	go reg2.ListenAndServe("127.0.0.1:0")
	select {
	case <-reg2.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry2 failed to start")
	}
	defer reg2.Close()

	rc2, err := registry.Dial(reg2.Addr().String())
	if err != nil {
		t.Fatalf("dial2: %v", err)
	}
	defer rc2.Close()

	lookup, err := rc2.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup after restart: %v", err)
	}
	tags, ok := lookup["tags"].([]interface{})
	if !ok || len(tags) != 2 {
		t.Fatalf("expected 2 tags after restart, got %v", lookup["tags"])
	}
	if tags[0] != "persistent" || tags[1] != "data" {
		t.Fatalf("expected [persistent data], got %v", tags)
	}
}

func TestSetTagsDashboardAPI(t *testing.T) {
	t.Parallel()

	r := registry.New("127.0.0.1:9001")
	go r.ListenAndServe("127.0.0.1:0")
	<-r.Ready()
	defer r.Close()

	regAddr := r.Addr().String()

	// Register a node and set tags
	ident, _ := icrypto.GenerateIdentity()
	rc, err := registry.Dial(regAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	resp, err := rc.RegisterWithKey("127.0.0.1:4000", icrypto.EncodePublicKey(ident.PublicKey), "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))
	setClientSigner(rc, ident)
	_, err = rc.SetTags(nodeID, []string{"webserver", "api"})
	if err != nil {
		t.Fatalf("set tags: %v", err)
	}

	// Start dashboard
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()
	go r.ServeDashboard(dashAddr)

	var client http.Client
	client.Timeout = 2 * time.Second
	var httpResp *http.Response
	for i := 0; i < 20; i++ {
		httpResp, err = client.Get(fmt.Sprintf("http://%s/api/stats", dashAddr))
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dashboard did not start: %v", err)
	}
	defer httpResp.Body.Close()

	var stats registry.DashboardStats
	body, _ := io.ReadAll(httpResp.Body)
	if err := json.Unmarshal(body, &stats); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if len(stats.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(stats.Nodes))
	}
	if len(stats.Nodes[0].Tags) != 2 {
		t.Fatalf("expected 2 tags, got %d: %v", len(stats.Nodes[0].Tags), stats.Nodes[0].Tags)
	}
	if stats.UniqueTags != 2 {
		t.Fatalf("expected 2 unique tags, got %d", stats.UniqueTags)
	}
}

func TestSetTagsDashboardNoHostname(t *testing.T) {
	t.Parallel()

	r := registry.New("127.0.0.1:9001")
	go r.ListenAndServe("127.0.0.1:0")
	<-r.Ready()
	defer r.Close()

	regAddr := r.Addr().String()
	dashRegisterNode(t, regAddr, "test-host")

	// Get dashboard stats via API
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()
	go r.ServeDashboard(dashAddr)

	var client http.Client
	client.Timeout = 2 * time.Second
	var httpResp *http.Response
	for i := 0; i < 20; i++ {
		httpResp, err = client.Get(fmt.Sprintf("http://%s/api/stats", dashAddr))
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dashboard did not start: %v", err)
	}
	defer httpResp.Body.Close()

	body, _ := io.ReadAll(httpResp.Body)
	bodyStr := string(body)

	// Dashboard JSON should NOT contain hostname field
	if strings.Contains(bodyStr, "\"hostname\"") {
		t.Fatal("dashboard JSON should not contain hostname field")
	}
}

func TestSetTagsDashboardNoIPLeak(t *testing.T) {
	t.Parallel()

	r := registry.New("127.0.0.1:9001")
	go r.ListenAndServe("127.0.0.1:0")
	<-r.Ready()
	defer r.Close()

	regAddr := r.Addr().String()
	dashRegisterNode(t, regAddr, "")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	dashAddr := ln.Addr().String()
	ln.Close()
	go r.ServeDashboard(dashAddr)

	var client http.Client
	client.Timeout = 2 * time.Second
	var httpResp *http.Response
	for i := 0; i < 20; i++ {
		httpResp, err = client.Get(fmt.Sprintf("http://%s/api/stats", dashAddr))
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dashboard did not start: %v", err)
	}
	defer httpResp.Body.Close()

	body, _ := io.ReadAll(httpResp.Body)
	bodyStr := string(body)

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

func TestSetTagsOverwrite(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	nodeID, id := registerTestNode(t, rc)
	setClientSigner(rc, id)

	// Set initial tags
	_, err := rc.SetTags(nodeID, []string{"alpha", "beta"})
	if err != nil {
		t.Fatalf("set tags 1: %v", err)
	}

	// Overwrite with different tags
	_, err = rc.SetTags(nodeID, []string{"gamma"})
	if err != nil {
		t.Fatalf("set tags 2: %v", err)
	}

	// Verify overwrite (not append)
	lookup, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	tags, ok := lookup["tags"].([]interface{})
	if !ok || len(tags) != 1 {
		t.Fatalf("expected 1 tag after overwrite, got %v", lookup["tags"])
	}
	if tags[0] != "gamma" {
		t.Fatalf("expected gamma, got %v", tags[0])
	}
}

func TestSetTagsViaIPC(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	di := env.AddDaemon()

	result, err := di.Driver.SetTags([]string{"ipc-test", "agent"})
	if err != nil {
		t.Fatalf("set tags via IPC: %v", err)
	}
	if result["type"] != "set_tags_ok" {
		t.Fatalf("expected set_tags_ok, got %v", result["type"])
	}
	tags, ok := result["tags"].([]interface{})
	if !ok || len(tags) != 2 {
		t.Fatalf("expected 2 tags, got %v", result["tags"])
	}
}

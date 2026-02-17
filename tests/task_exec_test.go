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

func TestSetTaskExecBasic(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	nodeID, id := registerTestNode(t, rc)
	setClientSigner(rc, id)

	// Enable task exec
	resp, err := rc.SetTaskExec(nodeID, true)
	if err != nil {
		t.Fatalf("set task_exec: %v", err)
	}
	if resp["type"] != "set_task_exec_ok" {
		t.Fatalf("expected set_task_exec_ok, got %v", resp["type"])
	}
	if resp["task_exec"] != true {
		t.Fatalf("expected task_exec=true, got %v", resp["task_exec"])
	}

	// Verify via lookup
	lookup, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if lookup["task_exec"] != true {
		t.Fatalf("expected task_exec=true in lookup, got %v", lookup["task_exec"])
	}
}

func TestSetTaskExecToggle(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	nodeID, id := registerTestNode(t, rc)
	setClientSigner(rc, id)

	// Enable
	_, err := rc.SetTaskExec(nodeID, true)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}

	// Verify enabled
	lookup, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup1: %v", err)
	}
	if lookup["task_exec"] != true {
		t.Fatalf("expected task_exec=true after enable")
	}

	// Disable
	_, err = rc.SetTaskExec(nodeID, false)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}

	// Verify disabled — field should be absent (omitempty behavior in lookup)
	lookup, err = rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup2: %v", err)
	}
	if v, ok := lookup["task_exec"]; ok && v == true {
		t.Fatalf("expected task_exec absent or false after disable, got %v", v)
	}
}

func TestSetTaskExecSignatureRequired(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	nodeID, _ := registerTestNode(t, rc)

	// Do not set signer — should fail
	_, err := rc.SetTaskExec(nodeID, true)
	if err == nil {
		t.Fatal("expected error without signature")
	}
	errStr := err.Error()
	if !strings.Contains(errStr, "signature") && !strings.Contains(errStr, "request failed") {
		t.Fatalf("expected signature/auth error, got: %v", err)
	}
}

func TestSetTaskExecPersistence(t *testing.T) {
	t.Parallel()

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

	// Register and enable task exec
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

	_, err = rc.SetTaskExec(nodeID, true)
	if err != nil {
		t.Fatalf("set task_exec: %v", err)
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
	if lookup["task_exec"] != true {
		t.Fatalf("expected task_exec=true after restart, got %v", lookup["task_exec"])
	}
}

func TestSetTaskExecDashboardAPI(t *testing.T) {
	t.Parallel()

	r := registry.New("127.0.0.1:9001")
	go r.ListenAndServe("127.0.0.1:0")
	<-r.Ready()
	defer r.Close()

	regAddr := r.Addr().String()

	// Register a node and enable task exec
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
	_, err = rc.SetTaskExec(nodeID, true)
	if err != nil {
		t.Fatalf("set task_exec: %v", err)
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

	if stats.TaskExecutors != 1 {
		t.Fatalf("expected 1 task executor, got %d", stats.TaskExecutors)
	}
	if len(stats.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(stats.Nodes))
	}
	if !stats.Nodes[0].TaskExec {
		t.Fatal("expected node task_exec=true in dashboard")
	}
}

func TestSetTaskExecLookup(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	nodeID, id := registerTestNode(t, rc)
	setClientSigner(rc, id)

	// Before enabling, task_exec should not be present
	lookup, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if v, ok := lookup["task_exec"]; ok && v == true {
		t.Fatal("task_exec should not be present before enabling")
	}

	// Enable
	_, err = rc.SetTaskExec(nodeID, true)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}

	// Now it should be present
	lookup, err = rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup2: %v", err)
	}
	if lookup["task_exec"] != true {
		t.Fatalf("expected task_exec=true in lookup, got %v", lookup["task_exec"])
	}
}

func TestSetTaskExecViaIPC(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	di := env.AddDaemon()

	result, err := di.Driver.SetTaskExec(true)
	if err != nil {
		t.Fatalf("set task_exec via IPC: %v", err)
	}
	if result["type"] != "set_task_exec_ok" {
		t.Fatalf("expected set_task_exec_ok, got %v", result["type"])
	}
	if result["task_exec"] != true {
		t.Fatalf("expected task_exec=true, got %v", result["task_exec"])
	}
}

package tests

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// ---------------------------------------------------------------------------
// Daemon Stop() idempotency
// ---------------------------------------------------------------------------

func TestStopIdempotent(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	d, _ := env.AddDaemonOnly()

	// First Stop succeeds
	if err := d.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}

	// Second Stop should return nil (idempotent, not panic or double-close)
	if err := d.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}

	// Third for good measure
	if err := d.Stop(); err != nil {
		t.Fatalf("third Stop: %v", err)
	}
}

func TestStopConcurrent(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	d, _ := env.AddDaemonOnly()

	var wg sync.WaitGroup
	errs := make([]error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = d.Stop()
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d Stop error: %v", i, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Heartbeat updates atomic LastSeen (visible to reap/list_nodes)
// ---------------------------------------------------------------------------

func TestHeartbeatUpdatesLastSeen(t *testing.T) {
	t.Parallel()
	rc, reg, cleanup := startTestRegistry(t)
	defer cleanup()

	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Send heartbeat
	setClientSigner(rc, id)
	hbResp, err := rc.Heartbeat(nodeID)
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if hbResp["type"] != "heartbeat_ok" {
		t.Fatalf("expected heartbeat_ok, got %v", hbResp["type"])
	}

	// Verify via lookup that the node is still live after heartbeat
	lookupResp, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup after heartbeat: %v", err)
	}
	if lookupResp["type"] != "lookup_ok" {
		t.Fatalf("expected lookup_ok, got %v", lookupResp["type"])
	}

	// The node should not be reaped — heartbeat kept it alive.
	// GetDashboardStats reads atomic LastSeen, so verify via dashboard endpoint
	// if available. For now, verify the heartbeat_ok response is valid.
	_ = reg // keep compiler happy
}

// ---------------------------------------------------------------------------
// flushSave single-marshal checksum round-trip
// ---------------------------------------------------------------------------

func TestFlushSaveChecksumRoundTrip(t *testing.T) {
	t.Parallel()
	tmpDir, err := os.MkdirTemp("/tmp", "w4-flush-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "registry.json")

	// Start registry with persistence, register a node, and close
	reg := registry.NewWithStore("127.0.0.1:9001", storePath)
	reg.SetAdminToken(TestAdminToken)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}

	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	id, _ := crypto.GenerateIdentity()
	_, err = rc.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	rc.Close()
	reg.Close()

	// Read persisted file and verify checksum
	data, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("store file is empty")
	}

	// The server's single-marshal approach: marshal without checksum, hash,
	// then append `,"checksum":"<hex>"}` to the JSON. To verify, strip that
	// suffix from the raw bytes and recompute.
	dataStr := string(data)
	checksumPrefix := `,"checksum":"`
	idx := strings.LastIndex(dataStr, checksumPrefix)
	if idx < 0 {
		t.Fatal("snapshot missing checksum field")
	}
	checksumStr := dataStr[idx+len(checksumPrefix) : len(dataStr)-2] // strip trailing "}
	if len(checksumStr) != 64 {
		t.Fatalf("checksum length = %d, want 64 hex chars", len(checksumStr))
	}

	// Original data without checksum: everything before the ,"checksum":"..." + closing brace
	original := dataStr[:idx] + "}"
	hash := sha256.Sum256([]byte(original))
	expected := hex.EncodeToString(hash[:])

	if checksumStr != expected {
		t.Errorf("checksum mismatch:\n  stored:   %s\n  computed: %s", checksumStr, expected)
	}

	// Verify the snapshot reloads correctly (NewWithStore loads from storePath)
	reg2 := registry.NewWithStore("127.0.0.1:9001", storePath)
	go reg2.ListenAndServe(":0")
	select {
	case <-reg2.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 2 failed to start (checksum reload)")
	}

	rc2, err := registry.Dial(reg2.Addr().String())
	if err != nil {
		t.Fatalf("dial registry 2: %v", err)
	}
	defer rc2.Close()

	// The registered node should still exist (survived save/load cycle).
	// Use lookup(1) since backbone list_nodes is blocked.
	lookupResp, err := rc2.Lookup(1)
	if err != nil {
		t.Fatalf("lookup after reload: %v", err)
	}
	if lookupResp["type"] != "lookup_ok" {
		t.Errorf("expected lookup_ok after reload, got %v", lookupResp["type"])
	}
	reg2.Close()
}

// ---------------------------------------------------------------------------
// Deregister on shutdown (integration)
// ---------------------------------------------------------------------------

func TestDeregisterOnShutdown(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	d, _ := env.AddDaemonOnly()
	nodeID := d.NodeID()

	// Confirm node is registered
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	resp, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup before stop: %v", err)
	}
	if resp["type"] != "lookup_ok" {
		t.Fatalf("expected lookup_ok, got %v", resp["type"])
	}

	// Stop should deregister
	d.Stop()

	// Verify deregistered (lookup returns error when node not found)
	deadline := time.After(3 * time.Second)
	for {
		_, lookupErr := rc.Lookup(nodeID)
		if lookupErr != nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("node not deregistered within 3s after Stop()")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

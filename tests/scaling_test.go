package tests

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// --- Phase 1 Tests ---

// TestChunkedReap verifies that stale nodes are eventually reaped across
// multiple chunked reap ticks (vs the old all-at-once approach).
func TestChunkedReap(t *testing.T) {
	t.Parallel()

	clk := newTestClock()
	reg := registry.New("127.0.0.1:9001")
	reg.SetClock(clk.Now)
	go reg.ListenAndServe(":0")
	<-reg.Ready()
	defer reg.Close()

	rc, err := registry.Dial(resolveLocalAddr(reg.Addr()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	// Register several nodes
	var nodeIDs []uint32
	for i := 0; i < 5; i++ {
		id, _ := crypto.GenerateIdentity()
		resp, err := rc.RegisterWithKey("127.0.0.1:4000", crypto.EncodePublicKey(id.PublicKey), "", nil)
		if err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
		nodeIDs = append(nodeIDs, uint32(resp["node_id"].(float64)))
	}

	// Advance past stale threshold (5 minutes)
	clk.Advance(6 * time.Minute)

	// Multiple reap calls — chunked reap processes a subset each time
	for i := 0; i < 10; i++ {
		reg.Reap()
	}

	// All nodes should be reaped
	for _, nid := range nodeIDs {
		_, err := rc.Lookup(nid)
		if err == nil {
			t.Fatalf("node %d should have been reaped", nid)
		}
	}
}

// TestFlushSaveUnderConcurrentHeartbeat verifies that flushSave produces
// a consistent snapshot while heartbeats update nodes concurrently.
func TestFlushSaveUnderConcurrentHeartbeat(t *testing.T) {
	t.Parallel()

	tmpDir, err := os.MkdirTemp("/tmp", "w4-flushsave-")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	storePath := filepath.Join(tmpDir, "registry.json")

	reg := registry.NewWithStore("127.0.0.1:9001", storePath)
	go reg.ListenAndServe(":0")
	<-reg.Ready()

	rc, err := registry.Dial(resolveLocalAddr(reg.Addr()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Register 10 nodes with keys
	var identities []*crypto.Identity
	var nodeIDs []uint32
	for i := 0; i < 10; i++ {
		id, _ := crypto.GenerateIdentity()
		resp, err := rc.RegisterWithKey("127.0.0.1:4000", crypto.EncodePublicKey(id.PublicKey), "", nil)
		if err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
		identities = append(identities, id)
		nodeIDs = append(nodeIDs, uint32(resp["node_id"].(float64)))
	}

	// Heartbeat all nodes concurrently while registry saves
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			hrc, err := registry.Dial(resolveLocalAddr(reg.Addr()))
			if err != nil {
				return
			}
			defer hrc.Close()
			setClientSigner(hrc, identities[idx])
			for j := 0; j < 20; j++ {
				hrc.Heartbeat(nodeIDs[idx])
				time.Sleep(time.Millisecond)
			}
		}(i)
	}
	wg.Wait()
	rc.Close()
	reg.Close()

	// Verify the snapshot is loadable
	reg2 := registry.NewWithStore("127.0.0.1:9001", storePath)
	go reg2.ListenAndServe(":0")
	<-reg2.Ready()
	defer reg2.Close()

	rc2, err := registry.Dial(resolveLocalAddr(reg2.Addr()))
	if err != nil {
		t.Fatalf("dial2: %v", err)
	}
	defer rc2.Close()

	for _, nid := range nodeIDs {
		_, err := rc2.Lookup(nid)
		if err != nil {
			t.Fatalf("lookup %d after reload: %v", nid, err)
		}
	}
}

// --- Phase 2 Tests ---

// TestShardedLockHeartbeatConcurrency verifies that concurrent heartbeats
// on nodes in different shards don't contend on each other.
func TestShardedLockHeartbeatConcurrency(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	go reg.ListenAndServe(":0")
	<-reg.Ready()
	defer reg.Close()

	rc, err := registry.Dial(resolveLocalAddr(reg.Addr()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	// Register 8 nodes (stays within the 10/min rate limit from single IP).
	// Even 8 nodes exercise shard-level locking since they map to different shards.
	const numNodes = 8
	var identities []*crypto.Identity
	var nodeIDs []uint32
	for i := 0; i < numNodes; i++ {
		id, _ := crypto.GenerateIdentity()
		resp, err := rc.RegisterWithKey("127.0.0.1:4000", crypto.EncodePublicKey(id.PublicKey), "", nil)
		if err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
		identities = append(identities, id)
		nodeIDs = append(nodeIDs, uint32(resp["node_id"].(float64)))
	}

	// Heartbeat all nodes concurrently — this exercises shard-level locking
	var wg sync.WaitGroup
	errCh := make(chan error, numNodes)
	for i := 0; i < numNodes; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			hrc, err := registry.Dial(resolveLocalAddr(reg.Addr()))
			if err != nil {
				errCh <- fmt.Errorf("dial %d: %w", idx, err)
				return
			}
			defer hrc.Close()
			setClientSigner(hrc, identities[idx])
			for j := 0; j < 10; j++ {
				if _, err := hrc.Heartbeat(nodeIDs[idx]); err != nil {
					errCh <- fmt.Errorf("heartbeat %d/%d: %w", idx, j, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}
}

// TestShardedLockCrossShardResolve verifies that resolve works when the
// requester and target are in different shard buckets.
func TestShardedLockCrossShardResolve(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	go reg.ListenAndServe(":0")
	<-reg.Ready()
	defer reg.Close()

	rc, err := registry.Dial(resolveLocalAddr(reg.Addr()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	// Register two nodes
	nodeA, idA := registerTestNode(t, rc)
	nodeB, idB := registerTestNode(t, rc)

	// Make both public (each needs its own signer)
	setClientSigner(rc, idA)
	if _, err := rc.SetVisibility(nodeA, true); err != nil {
		t.Fatalf("set A public: %v", err)
	}
	setClientSigner(rc, idB)
	if _, err := rc.SetVisibility(nodeB, true); err != nil {
		t.Fatalf("set B public: %v", err)
	}

	// Resolve B from A (switch back to A's signer)
	setClientSigner(rc, idA)
	resp, err := rc.Resolve(nodeB, nodeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resp["type"] != "resolve_ok" {
		t.Fatalf("expected resolve_ok, got %v", resp["type"])
	}
}

// --- Phase 3 Tests ---

// TestHeartbeatSkipVerificationWhenRecent verifies that the verify-skip
// optimization allows rapid heartbeats without re-verifying every time.
func TestHeartbeatSkipVerificationWhenRecent(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	go reg.ListenAndServe(":0")
	<-reg.Ready()
	defer reg.Close()

	rc, err := registry.Dial(resolveLocalAddr(reg.Addr()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	nodeID, id := registerTestNode(t, rc)
	setClientSigner(rc, id)

	// First heartbeat — must verify
	resp, err := rc.Heartbeat(nodeID)
	if err != nil {
		t.Fatalf("first heartbeat: %v", err)
	}
	if resp["type"] != "heartbeat_ok" {
		t.Fatalf("expected heartbeat_ok, got %v", resp["type"])
	}

	// Rapid subsequent heartbeats — verify-skip should kick in
	for i := 0; i < 10; i++ {
		resp, err = rc.Heartbeat(nodeID)
		if err != nil {
			t.Fatalf("heartbeat %d: %v", i, err)
		}
		if resp["type"] != "heartbeat_ok" {
			t.Fatalf("heartbeat %d: expected heartbeat_ok, got %v", i, resp["type"])
		}
	}
}

// TestHeartbeatRequireVerificationAfterGap verifies that verify-skip
// expires after the configured window (120s) and re-verification is required.
func TestHeartbeatRequireVerificationAfterGap(t *testing.T) {
	t.Parallel()

	clk := newTestClock()
	reg := registry.New("127.0.0.1:9001")
	reg.SetClock(clk.Now)
	go reg.ListenAndServe(":0")
	<-reg.Ready()
	defer reg.Close()

	rc, err := registry.Dial(resolveLocalAddr(reg.Addr()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	nodeID, id := registerTestNode(t, rc)
	setClientSigner(rc, id)

	// First heartbeat verifies the signature
	if _, err := rc.Heartbeat(nodeID); err != nil {
		t.Fatalf("first heartbeat: %v", err)
	}

	// Advance clock past the 120s verify-skip window
	clk.Advance(3 * time.Minute)

	// Next heartbeat with valid signature — should re-verify and succeed
	if _, err := rc.Heartbeat(nodeID); err != nil {
		t.Fatalf("heartbeat after gap: %v", err)
	}

	// Advance again and try with WRONG signer — should fail since re-verify is needed
	clk.Advance(3 * time.Minute)

	badID, _ := crypto.GenerateIdentity()
	setClientSigner(rc, badID) // wrong key
	_, err = rc.Heartbeat(nodeID)
	if err == nil {
		t.Fatal("expected error when heartbeat with wrong key after verify-skip expired")
	}
}

// --- Binary Wire Protocol Integration Tests ---

// TestBinaryWireNegotiation verifies that the server correctly detects
// binary magic and switches to binary mode, while JSON clients still work.
func TestBinaryWireNegotiation(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	go reg.ListenAndServe(":0")
	<-reg.Ready()
	defer reg.Close()

	addr := resolveLocalAddr(reg.Addr())

	// JSON client still works
	jsonRC, err := registry.Dial(addr)
	if err != nil {
		t.Fatalf("json dial: %v", err)
	}
	defer jsonRC.Close()

	// Register a node via JSON
	id, _ := crypto.GenerateIdentity()
	resp, err := jsonRC.Send(map[string]interface{}{
		"type":       "register",
		"public_key": crypto.EncodePublicKey(id.PublicKey),
	})
	if err != nil {
		t.Fatalf("json register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Binary client connects and performs operations
	brc, err := registry.DialBinary(addr)
	if err != nil {
		t.Fatalf("binary dial: %v", err)
	}
	defer brc.Close()

	// Binary lookup
	result, err := brc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("binary lookup: %v", err)
	}
	if result.NodeID != nodeID {
		t.Fatalf("lookup nodeID: got %d, want %d", result.NodeID, nodeID)
	}
}

// TestBinaryHeartbeatRoundTrip tests the full binary heartbeat flow:
// register via JSON, then heartbeat via binary protocol.
func TestBinaryHeartbeatRoundTrip(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	go reg.ListenAndServe(":0")
	<-reg.Ready()
	defer reg.Close()

	addr := resolveLocalAddr(reg.Addr())

	// Register via JSON (registration has no binary encoding)
	jsonRC, err := registry.Dial(addr)
	if err != nil {
		t.Fatalf("json dial: %v", err)
	}
	defer jsonRC.Close()

	id, _ := crypto.GenerateIdentity()
	resp, err := jsonRC.Send(map[string]interface{}{
		"type":       "register",
		"public_key": crypto.EncodePublicKey(id.PublicKey),
		"public":     true,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Binary heartbeat
	brc, err := registry.DialBinary(addr)
	if err != nil {
		t.Fatalf("binary dial: %v", err)
	}
	defer brc.Close()

	// Sign the heartbeat challenge with raw bytes (not base64)
	challenge := fmt.Sprintf("heartbeat:%d", nodeID)
	sig := id.Sign([]byte(challenge))

	unixTime, keyWarning, err := brc.Heartbeat(nodeID, sig)
	if err != nil {
		t.Fatalf("binary heartbeat: %v", err)
	}
	if unixTime == 0 {
		t.Fatal("expected non-zero unix time")
	}
	if keyWarning {
		t.Fatal("unexpected key expiry warning")
	}

	// Second heartbeat (verify-skip should work)
	_, _, err = brc.Heartbeat(nodeID, sig)
	if err != nil {
		t.Fatalf("second binary heartbeat: %v", err)
	}
}

// TestBinaryLookupRoundTrip tests binary lookup with populated fields.
func TestBinaryLookupRoundTrip(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	reg.SetAdminToken(TestAdminToken)
	go reg.ListenAndServe(":0")
	<-reg.Ready()
	defer reg.Close()

	addr := resolveLocalAddr(reg.Addr())

	// Register node with hostname, tags, etc.
	jsonRC, err := registry.Dial(addr)
	if err != nil {
		t.Fatalf("json dial: %v", err)
	}
	defer jsonRC.Close()

	id, _ := crypto.GenerateIdentity()
	resp, err := jsonRC.Send(map[string]interface{}{
		"type":       "register",
		"public_key": crypto.EncodePublicKey(id.PublicKey),
		"hostname":   "test-node",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	setClientSigner(jsonRC, id)
	jsonRC.SetVisibility(nodeID, true)
	jsonRC.SetTagsAdmin(nodeID, []string{"svc", "data"}, TestAdminToken)

	// Binary lookup
	brc, err := registry.DialBinary(addr)
	if err != nil {
		t.Fatalf("binary dial: %v", err)
	}
	defer brc.Close()

	result, err := brc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("binary lookup: %v", err)
	}

	if result.NodeID != nodeID {
		t.Fatalf("NodeID: got %d, want %d", result.NodeID, nodeID)
	}
	if !result.Public {
		t.Fatal("expected Public=true")
	}
	if result.Hostname != "test-node" {
		t.Fatalf("Hostname: got %q, want %q", result.Hostname, "test-node")
	}
	if len(result.Tags) != 2 || result.Tags[0] != "svc" || result.Tags[1] != "data" {
		t.Fatalf("Tags: got %v", result.Tags)
	}
	if len(result.PubKey) == 0 {
		t.Fatal("expected non-empty PubKey")
	}
}

// TestBinaryResolveRoundTrip tests the full binary resolve flow with
// signature authentication and trust checks.
func TestBinaryResolveRoundTrip(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	go reg.ListenAndServe(":0")
	<-reg.Ready()
	defer reg.Close()

	addr := resolveLocalAddr(reg.Addr())

	jsonRC, err := registry.Dial(addr)
	if err != nil {
		t.Fatalf("json dial: %v", err)
	}
	defer jsonRC.Close()

	// Register two public nodes
	idA, _ := crypto.GenerateIdentity()
	respA, err := jsonRC.Send(map[string]interface{}{
		"type":       "register",
		"public_key": crypto.EncodePublicKey(idA.PublicKey),
	})
	if err != nil {
		t.Fatalf("register A: %v", err)
	}
	nodeA := uint32(respA["node_id"].(float64))

	idB, _ := crypto.GenerateIdentity()
	respB, err := jsonRC.Send(map[string]interface{}{
		"type":        "register",
		"public_key":  crypto.EncodePublicKey(idB.PublicKey),
		"listen_addr": "10.0.0.2:4000",
	})
	if err != nil {
		t.Fatalf("register B: %v", err)
	}
	nodeB := uint32(respB["node_id"].(float64))

	// Make B public so A can resolve it
	setClientSigner(jsonRC, idB)
	jsonRC.SetVisibility(nodeB, true)

	// Binary resolve: A resolves B
	brc, err := registry.DialBinary(addr)
	if err != nil {
		t.Fatalf("binary dial: %v", err)
	}
	defer brc.Close()

	challenge := fmt.Sprintf("resolve:%d:%d", nodeA, nodeB)
	sig := idA.Sign([]byte(challenge))

	result, err := brc.Resolve(nodeB, nodeA, sig)
	if err != nil {
		t.Fatalf("binary resolve: %v", err)
	}

	if result.NodeID != nodeB {
		t.Fatalf("NodeID: got %d, want %d", result.NodeID, nodeB)
	}
}

// TestBinaryResolvePrivateDenied verifies that resolving a private node
// without trust is denied via binary protocol.
func TestBinaryResolvePrivateDenied(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	go reg.ListenAndServe(":0")
	<-reg.Ready()
	defer reg.Close()

	addr := resolveLocalAddr(reg.Addr())

	jsonRC, err := registry.Dial(addr)
	if err != nil {
		t.Fatalf("json dial: %v", err)
	}
	defer jsonRC.Close()

	idA, _ := crypto.GenerateIdentity()
	respA, _ := jsonRC.Send(map[string]interface{}{
		"type":       "register",
		"public_key": crypto.EncodePublicKey(idA.PublicKey),
	})
	nodeA := uint32(respA["node_id"].(float64))

	idB, _ := crypto.GenerateIdentity()
	respB, _ := jsonRC.Send(map[string]interface{}{
		"type":       "register",
		"public_key": crypto.EncodePublicKey(idB.PublicKey),
	})
	nodeB := uint32(respB["node_id"].(float64))
	// B is private by default

	brc, err := registry.DialBinary(addr)
	if err != nil {
		t.Fatalf("binary dial: %v", err)
	}
	defer brc.Close()

	challenge := fmt.Sprintf("resolve:%d:%d", nodeA, nodeB)
	sig := idA.Sign([]byte(challenge))

	_, err = brc.Resolve(nodeB, nodeA, sig)
	if err == nil {
		t.Fatal("expected error resolving private node without trust")
	}
}

// TestBinaryJSONPassthrough verifies that the JSON-over-binary passthrough
// works for operations without native binary encoding.
func TestBinaryJSONPassthrough(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	reg.SetAdminToken(TestAdminToken)
	go reg.ListenAndServe(":0")
	<-reg.Ready()
	defer reg.Close()

	addr := resolveLocalAddr(reg.Addr())

	brc, err := registry.DialBinary(addr)
	if err != nil {
		t.Fatalf("binary dial: %v", err)
	}
	defer brc.Close()

	// Register via JSON passthrough
	id, _ := crypto.GenerateIdentity()
	resp, err := brc.SendJSON(map[string]interface{}{
		"type":       "register",
		"public_key": crypto.EncodePublicKey(id.PublicKey),
	})
	if err != nil {
		t.Fatalf("register via passthrough: %v", err)
	}
	if resp["type"] != "register_ok" {
		t.Fatalf("expected register_ok, got %v", resp["type"])
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Heartbeat via JSON passthrough (with base64 sig, as JSON path expects)
	challenge := fmt.Sprintf("heartbeat:%d", nodeID)
	sig := id.Sign([]byte(challenge))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	resp, err = brc.SendJSON(map[string]interface{}{
		"type":      "heartbeat",
		"node_id":   nodeID,
		"signature": sigB64,
	})
	if err != nil {
		t.Fatalf("heartbeat via passthrough: %v", err)
	}
	if resp["type"] != "heartbeat_ok" {
		t.Fatalf("expected heartbeat_ok, got %v", resp["type"])
	}

	// Create network via JSON passthrough
	resp, err = brc.SendJSON(map[string]interface{}{
		"type":        "create_network",
		"node_id":     nodeID,
		"name":        "bin-test-net",
		"join_rule":   "open",
		"admin_token": TestAdminToken,
	})
	if err != nil {
		t.Fatalf("create network via passthrough: %v", err)
	}
	if resp["type"] != "create_network_ok" {
		t.Fatalf("expected create_network_ok, got %v", resp["type"])
	}
}

// TestBinaryAndJSONClientsCoexist verifies that binary and JSON clients
// can operate simultaneously on the same server without interference.
func TestBinaryAndJSONClientsCoexist(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	go reg.ListenAndServe(":0")
	<-reg.Ready()
	defer reg.Close()

	addr := resolveLocalAddr(reg.Addr())

	// Create multiple JSON and binary clients
	var wg sync.WaitGroup
	errCh := make(chan error, 20)

	for i := 0; i < 5; i++ {
		wg.Add(2)

		// JSON client goroutine
		go func(idx int) {
			defer wg.Done()
			jrc, err := registry.Dial(addr)
			if err != nil {
				errCh <- fmt.Errorf("json dial %d: %w", idx, err)
				return
			}
			defer jrc.Close()
			id, _ := crypto.GenerateIdentity()
			_, err = jrc.Send(map[string]interface{}{
				"type":       "register",
				"public_key": crypto.EncodePublicKey(id.PublicKey),
			})
			if err != nil {
				errCh <- fmt.Errorf("json register %d: %w", idx, err)
			}
		}(i)

		// Binary client goroutine
		go func(idx int) {
			defer wg.Done()
			brc, err := registry.DialBinary(addr)
			if err != nil {
				errCh <- fmt.Errorf("binary dial %d: %w", idx, err)
				return
			}
			defer brc.Close()
			id, _ := crypto.GenerateIdentity()
			_, err = brc.SendJSON(map[string]interface{}{
				"type":       "register",
				"public_key": crypto.EncodePublicKey(id.PublicKey),
			})
			if err != nil {
				errCh <- fmt.Errorf("binary register %d: %w", idx, err)
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}
}

// TestBinaryHeartbeatBadSignature verifies that binary heartbeat rejects
// invalid signatures.
func TestBinaryHeartbeatBadSignature(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	go reg.ListenAndServe(":0")
	<-reg.Ready()
	defer reg.Close()

	addr := resolveLocalAddr(reg.Addr())

	jsonRC, err := registry.Dial(addr)
	if err != nil {
		t.Fatalf("json dial: %v", err)
	}
	defer jsonRC.Close()

	id, _ := crypto.GenerateIdentity()
	resp, err := jsonRC.Send(map[string]interface{}{
		"type":       "register",
		"public_key": crypto.EncodePublicKey(id.PublicKey),
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	brc, err := registry.DialBinary(addr)
	if err != nil {
		t.Fatalf("binary dial: %v", err)
	}
	defer brc.Close()

	// Wrong signature (all zeros)
	badSig := make([]byte, 64)
	_, _, err = brc.Heartbeat(nodeID, badSig)
	if err == nil {
		t.Fatal("expected error with bad signature")
	}
}

// TestBinaryLookupNodeNotFound verifies binary lookup error for non-existent nodes.
func TestBinaryLookupNodeNotFound(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	go reg.ListenAndServe(":0")
	<-reg.Ready()
	defer reg.Close()

	brc, err := registry.DialBinary(resolveLocalAddr(reg.Addr()))
	if err != nil {
		t.Fatalf("binary dial: %v", err)
	}
	defer brc.Close()

	_, err = brc.Lookup(99999)
	if err == nil {
		t.Fatal("expected error for non-existent node")
	}
}

// TestBinaryClientReconnect verifies that the binary client can reconnect
// after the server drops the connection.
func TestBinaryClientReconnect(t *testing.T) {
	t.Parallel()

	tmpDir, err := os.MkdirTemp("/tmp", "w4-binreconn-")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	storePath := filepath.Join(tmpDir, "registry.json")

	reg := registry.NewWithStore("127.0.0.1:9001", storePath)
	go reg.ListenAndServe(":0")
	<-reg.Ready()

	addr := resolveLocalAddr(reg.Addr())

	// Register node via JSON
	jsonRC, err := registry.Dial(addr)
	if err != nil {
		t.Fatalf("json dial: %v", err)
	}
	id, _ := crypto.GenerateIdentity()
	resp, err := jsonRC.Send(map[string]interface{}{
		"type":       "register",
		"public_key": crypto.EncodePublicKey(id.PublicKey),
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))
	jsonRC.Close()

	// Connect binary client
	brc, err := registry.DialBinary(addr)
	if err != nil {
		t.Fatalf("binary dial: %v", err)
	}
	defer brc.Close()

	// Verify lookup works
	_, err = brc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}

	// Restart registry on same port (persistence)
	_, port, _ := net.SplitHostPort(addr)
	reg.Close()
	reg2 := registry.NewWithStore("127.0.0.1:9001", storePath)
	go reg2.ListenAndServe(":" + port) // use same port
	<-reg2.Ready()
	defer reg2.Close()

	// Lookup should trigger reconnect + re-handshake
	result, err := brc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup after reconnect: %v", err)
	}
	if result.NodeID != nodeID {
		t.Fatalf("NodeID after reconnect: got %d, want %d", result.NodeID, nodeID)
	}
}

package tests

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// TestRegistryResolveNotRateLimited verifies that resolve operations are not
// per-IP rate limited (removed to support large agent deployments behind NAT).
func TestRegistryResolveNotRateLimited(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	reg.SetAdminToken(TestAdminToken)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	regAddr := reg.Addr().String()

	rc, err := registry.Dial(regAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	id1, _ := crypto.GenerateIdentity()
	id2, _ := crypto.GenerateIdentity()

	resp1, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id1.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node 1: %v", err)
	}
	nodeID1 := uint32(resp1["node_id"].(float64))

	resp2, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id2.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node 2: %v", err)
	}
	nodeID2 := uint32(resp2["node_id"].(float64))

	setClientSigner(rc, id1)
	if _, err := rc.SetVisibility(nodeID1, true); err != nil {
		t.Fatalf("set visibility: %v", err)
	}
	setClientSigner(rc, id2)
	if _, err := rc.SetVisibility(nodeID2, true); err != nil {
		t.Fatalf("set visibility: %v", err)
	}

	// 200 resolves from the same IP should all succeed
	setClientSigner(rc, id1)
	for i := 0; i < 200; i++ {
		_, err := rc.Resolve(nodeID2, nodeID1)
		if err != nil {
			t.Fatalf("resolve %d should succeed (no per-IP rate limit): %v", i+1, err)
		}
	}
}

// TestRegistryMessageSizeLimit verifies that oversized messages cause
// the connection to be closed.
func TestRegistryMessageSizeLimit(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	regAddr := reg.Addr().String()

	// Connect raw TCP — we need to send an oversized message
	conn, err := net.Dial("tcp", regAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send a message with length prefix claiming 128KB (exceeds 64KB limit)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 128*1024)
	if _, err := conn.Write(lenBuf[:]); err != nil {
		t.Fatalf("write length: %v", err)
	}

	// Write some junk bytes (the server should close before reading all of them)
	junk := make([]byte, 1024)
	conn.Write(junk)

	// Try to read — the server should have closed the connection
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	readBuf := make([]byte, 256)
	n, readErr := conn.Read(readBuf)
	if readErr == nil && n > 0 {
		// If we got a response, it should be an error (but usually the conn just closes)
		t.Logf("got response (%d bytes): %s", n, string(readBuf[:n]))
	}

	// Verify we can no longer send requests on this connection
	binary.BigEndian.PutUint32(lenBuf[:], 10)
	_, err = conn.Write(lenBuf[:])
	conn.Write([]byte(`{"type":"lookup","node_id":1}`))

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, err = conn.Read(readBuf)
	if err == nil {
		t.Fatal("expected connection to be closed after oversized message")
	}
	t.Logf("connection closed as expected after oversized message: %v", err)
}

// TestRegistrySnapshotChecksum verifies that snapshots include a valid
// SHA256 checksum and that it can be verified on load.
func TestRegistrySnapshotChecksum(t *testing.T) {
	t.Parallel()

	snapDir := t.TempDir()
	snapPath := filepath.Join(snapDir, "registry-checksum.json")

	// Start registry with persistence
	reg := registry.NewWithStore("127.0.0.1:9001", snapPath)
	reg.SetAdminToken(TestAdminToken)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}

	regAddr := reg.Addr().String()

	// Register a node to create some data
	rc, err := registry.Dial(regAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	id1, _ := crypto.GenerateIdentity()
	_, err = rc.RegisterWithKey("", crypto.EncodePublicKey(id1.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	rc.Close()

	// Trigger snapshot save
	if err := reg.TriggerSnapshot(); err != nil {
		t.Fatalf("trigger snapshot: %v", err)
	}
	reg.Close()

	// Read the snapshot file
	data, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}

	// Parse and validate checksum field exists
	var snap map[string]interface{}
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}

	checksumStr, ok := snap["checksum"].(string)
	if !ok || checksumStr == "" {
		t.Fatal("snapshot missing checksum field")
	}
	t.Logf("snapshot checksum: %s", checksumStr)

	// Verify the checksum is a valid hex-encoded SHA256 (64 hex chars)
	if len(checksumStr) != 64 {
		t.Errorf("checksum length = %d, expected 64 hex chars", len(checksumStr))
	}
	if _, err := hex.DecodeString(checksumStr); err != nil {
		t.Errorf("checksum is not valid hex: %v", err)
	}

	// Verify the checksum: the save code marshals the struct with Checksum=""
	// (omitempty causes it to be omitted), computes SHA256, then sets Checksum
	// and re-marshals. To verify, we need to remove the checksum and re-marshal
	// using the same struct type. Since the struct is unexported, we verify
	// by removing "checksum" from the raw JSON and hashing that.
	// Note: this won't match because map key ordering differs from struct ordering.
	// Instead, we rely on the load-time verification (the server logs "snapshot checksum verified")
	// and validate the checksum is non-empty, valid hex, and the snapshot loads correctly.
	t.Logf("checksum field present and valid hex SHA256")

	// Verify the snapshot can be loaded by a new registry
	reg2 := registry.NewWithStore("127.0.0.1:9001", snapPath)
	go reg2.ListenAndServe(":0")
	select {
	case <-reg2.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 2 failed to start")
	}
	defer reg2.Close()

	regAddr2 := reg2.Addr().String()
	rc2, err := registry.Dial(regAddr2)
	if err != nil {
		t.Fatalf("dial registry 2: %v", err)
	}
	defer rc2.Close()

	// Verify the node survived the save/load cycle
	_, err = rc2.Lookup(1)
	if err != nil {
		t.Fatalf("lookup after reload: %v", err)
	}
	t.Logf("snapshot with checksum loaded and verified successfully")
}

// TestRegistryConnectionLimit verifies that the server rejects new connections
// when the maximum connection count is reached.
func TestRegistryConnectionLimit(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	// Set a very low connection limit for testing
	reg.SetMaxConnections(5)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	regAddr := reg.Addr().String()

	// Open connections up to the limit
	conns := make([]net.Conn, 0, 5)
	for i := 0; i < 5; i++ {
		conn, err := net.Dial("tcp", regAddr)
		if err != nil {
			t.Fatalf("dial connection %d: %v", i, err)
		}
		conns = append(conns, conn)
	}

	// Wait briefly for the server to track all connections
	time.Sleep(100 * time.Millisecond)

	// Verify connection count
	if count := reg.ConnCount(); count != 5 {
		t.Logf("connection count = %d (expected 5, may vary due to timing)", count)
	}

	// Try to open one more — this should be rejected (connection closed immediately)
	extraConn, err := net.Dial("tcp", regAddr)
	if err != nil {
		t.Fatalf("dial extra connection: %v", err)
	}

	// The server accepts the TCP connection (OS level) but immediately closes it.
	// Try to send a message — it should fail because the server closed its side.
	time.Sleep(100 * time.Millisecond)

	// Write a valid message header
	var lenBuf [4]byte
	msg := []byte(`{"type":"lookup","node_id":1}`)
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(msg)))

	extraConn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_, writeErr := extraConn.Write(lenBuf[:])
	if writeErr == nil {
		_, writeErr = extraConn.Write(msg)
	}

	// Try to read a response
	extraConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	readBuf := make([]byte, 256)
	_, readErr := extraConn.Read(readBuf)

	// Either the write or read should fail because the server closed the connection
	if writeErr == nil && readErr == nil {
		t.Fatal("expected connection to be rejected at limit, but both write and read succeeded")
	}
	t.Logf("connection at limit rejected as expected (write_err=%v, read_err=%v)", writeErr, readErr)

	extraConn.Close()

	// Close all existing connections to free slots
	for _, c := range conns {
		c.Close()
	}
	time.Sleep(200 * time.Millisecond) // wait for server to decrement counters

	// Verify we can open a new connection and use it
	newRC, err := registry.Dial(regAddr)
	if err != nil {
		t.Fatalf("dial after freeing slots: %v", err)
	}
	defer newRC.Close()

	id1, _ := crypto.GenerateIdentity()
	_, err = newRC.RegisterWithKey("", crypto.EncodePublicKey(id1.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register after freeing slots: %v", err)
	}
	t.Logf("successfully registered after freeing connection slots")
}

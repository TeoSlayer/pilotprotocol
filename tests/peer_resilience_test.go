package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/beacon"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// TestEndpointCacheFallback verifies that when a peer's endpoint has been
// resolved, it is cached so that future ensureTunnel calls can use it
// as a fallback when the registry is unreachable.
func TestEndpointCacheFallback(t *testing.T) {
	t.Parallel()

	tmpDir, err := os.MkdirTemp("/tmp", "w4-cache-fb-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Start beacon + registry
	bsrv := beacon.New()
	go bsrv.ListenAndServe(":0")
	select {
	case <-bsrv.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to start")
	}
	defer bsrv.Close()
	beaconAddr := resolveLocalAddr(bsrv.Addr())

	reg := registry.New(beaconAddr)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()
	regAddr := resolveLocalAddr(reg.Addr())

	// Start two daemons
	dA := daemon.New(daemon.Config{
		RegistryAddr:      regAddr,
		BeaconAddr:        beaconAddr,
		ListenAddr:        ":0",
		SocketPath:        filepath.Join(tmpDir, "a.sock"),
		IdentityPath:      filepath.Join(tmpDir, "id-a.json"),
		Email:             "a@pilot.local",
		Public:            true,
		KeepaliveInterval: 30 * time.Second,
	})
	if err := dA.Start(); err != nil {
		t.Fatalf("daemon A start: %v", err)
	}
	defer dA.Stop()

	dB := daemon.New(daemon.Config{
		RegistryAddr:      regAddr,
		BeaconAddr:        beaconAddr,
		ListenAddr:        ":0",
		SocketPath:        filepath.Join(tmpDir, "b.sock"),
		IdentityPath:      filepath.Join(tmpDir, "id-b.json"),
		Email:             "b@pilot.local",
		Public:            true,
		KeepaliveInterval: 30 * time.Second,
	})
	if err := dB.Start(); err != nil {
		t.Fatalf("daemon B start: %v", err)
	}
	defer dB.Stop()

	t.Logf("daemon A: node=%d, daemon B: node=%d", dA.NodeID(), dB.NodeID())

	// Before dial, B should NOT have A's endpoint cached
	_, ok := dB.CachedEndpoint(dA.NodeID())
	if ok {
		t.Fatal("expected no cache entry before dial")
	}

	// B dials A on echo port (7) — this triggers ensureTunnel which resolves A's endpoint
	conn, err := dB.DialConnection(dA.Addr(), 7)
	if err != nil {
		t.Fatalf("dial B->A: %v", err)
	}
	dB.CloseConnection(conn)
	time.Sleep(100 * time.Millisecond)

	// Verify the endpoint cache was populated for node A
	cached, ok := dB.CachedEndpoint(dA.NodeID())
	if !ok {
		t.Fatal("expected endpoint cache to be populated after dial")
	}
	if cached == "" {
		t.Fatal("cached endpoint is empty")
	}
	t.Logf("cache populated: node %d -> %s", dA.NodeID(), cached)
}

// TestRegistryReconnect verifies that the registry client automatically
// reconnects when the TCP connection drops, and subsequent operations succeed.
func TestRegistryReconnect(t *testing.T) {
	t.Parallel()

	tmpDir, err := os.MkdirTemp("/tmp", "w4-reconnect-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "registry.json")

	// Start a beacon
	b := beacon.New()
	go b.ListenAndServe(":0")
	select {
	case <-b.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to start")
	}
	defer b.Close()
	beaconAddr := resolveLocalAddr(b.Addr())

	// Start registry
	reg := registry.NewWithStore(beaconAddr, storePath)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	regAddr := resolveLocalAddr(reg.Addr())
	t.Logf("registry on %s", regAddr)

	// Register a node with identity and signer (required for H3 authenticated ops)
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	pubKeyB64 := crypto.EncodePublicKey(id.PublicKey)

	rc, err := registry.Dial(regAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Set up signer for authenticated operations (H3 fix)
	setClientSigner(rc, id)

	resp, err := rc.RegisterWithKey("127.0.0.1:4000", pubKeyB64, "test@pilot.local", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))
	t.Logf("registered node %d", nodeID)

	// Verify heartbeat works before restart
	_, err = rc.Heartbeat(nodeID)
	if err != nil {
		t.Fatalf("heartbeat before restart: %v", err)
	}
	t.Log("heartbeat succeeded before restart")

	// Stop the registry (simulates connection drop)
	reg.Close()
	t.Log("registry stopped")

	// Start a NEW registry on the SAME address from the store
	reg2 := registry.NewWithStore(beaconAddr, storePath)
	go reg2.ListenAndServe(regAddr)
	select {
	case <-reg2.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 2 failed to start")
	}
	defer reg2.Close()
	t.Log("registry 2 started on same address")

	// The client should auto-reconnect when we attempt an operation.
	var lookupResp map[string]interface{}
	var lookupErr error

	for attempt := 0; attempt < 5; attempt++ {
		lookupResp, lookupErr = rc.Lookup(nodeID)
		if lookupErr == nil {
			break
		}
		t.Logf("attempt %d: lookup failed (reconnecting): %v", attempt+1, lookupErr)
		time.Sleep(500 * time.Millisecond)
	}

	if lookupErr != nil {
		t.Fatalf("lookup failed after reconnect attempts: %v", lookupErr)
	}

	gotNodeID := uint32(lookupResp["node_id"].(float64))
	if gotNodeID != nodeID {
		t.Fatalf("node_id mismatch: got %d, want %d", gotNodeID, nodeID)
	}
	t.Logf("lookup succeeded after reconnect: node_id=%d", gotNodeID)
}

// TestDaemonSurvivesRegistryRestart verifies that the daemon continues to
// function after the registry goes down and comes back up:
// 1. Start registry + daemon, verify heartbeat works
// 2. Stop registry
// 3. Start new registry (from same store)
// 4. Wait for daemon to re-register via heartbeat loop
// 5. Verify daemon is functional (lookup returns its node)
func TestDaemonSurvivesRegistryRestart(t *testing.T) {
	t.Parallel()

	tmpDir, err := os.MkdirTemp("/tmp", "w4-survive-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "registry.json")
	sockPath := filepath.Join(tmpDir, "daemon.sock")
	identityPath := filepath.Join(tmpDir, "identity.json")

	// Start beacon
	bsrv := beacon.New()
	go bsrv.ListenAndServe(":0")
	select {
	case <-bsrv.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to start")
	}
	defer bsrv.Close()
	beaconAddr := resolveLocalAddr(bsrv.Addr())

	// Start registry 1
	reg1 := registry.NewWithStore(beaconAddr, storePath)
	go reg1.ListenAndServe(":0")
	select {
	case <-reg1.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 1 failed to start")
	}
	regAddr := resolveLocalAddr(reg1.Addr())
	t.Logf("registry 1 on %s", regAddr)

	// Start daemon with a fast heartbeat so re-registration happens quickly
	d := daemon.New(daemon.Config{
		RegistryAddr:      regAddr,
		BeaconAddr:        beaconAddr,
		ListenAddr:        ":0",
		SocketPath:        sockPath,
		IdentityPath:      identityPath,
		Email:             "survive@pilot.local",
		Public:            true,
		KeepaliveInterval: 1 * time.Second, // fast heartbeat for test speed
	})
	if err := d.Start(); err != nil {
		t.Fatalf("daemon start: %v", err)
	}
	defer d.Stop()

	originalNodeID := d.NodeID()
	t.Logf("daemon started: node_id=%d", originalNodeID)

	// Verify the daemon is registered
	rc1, err := registry.Dial(regAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	resp, err := rc1.Lookup(originalNodeID)
	if err != nil {
		t.Fatalf("lookup before restart: %v", err)
	}
	t.Logf("daemon found on registry 1: node_id=%v", resp["node_id"])
	rc1.Close()

	// Stop registry 1
	reg1.Close()
	t.Log("registry 1 stopped — daemon is now disconnected")

	// Wait for the daemon to notice the registry is gone
	time.Sleep(2 * time.Second)

	// Start registry 2 on the SAME address
	reg2 := registry.NewWithStore(beaconAddr, storePath)
	go reg2.ListenAndServe(regAddr)
	select {
	case <-reg2.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 2 failed to start")
	}
	defer reg2.Close()
	t.Logf("registry 2 started on %s", regAddr)

	// Wait for the daemon to re-register via the heartbeat loop
	var lookupResp map[string]interface{}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		rc2, dialErr := registry.Dial(regAddr)
		if dialErr != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		lookupResp, err = rc2.Lookup(originalNodeID)
		rc2.Close()
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if lookupResp == nil {
		t.Fatal("daemon did not re-register after registry restart within 15s")
	}

	gotNodeID := uint32(lookupResp["node_id"].(float64))
	if gotNodeID != originalNodeID {
		t.Fatalf("node_id mismatch after re-registration: got %d, want %d", gotNodeID, originalNodeID)
	}
	t.Logf("daemon successfully re-registered after registry restart: node_id=%d", gotNodeID)

	// Verify daemon is still functional
	info := d.Info()
	if info.NodeID != originalNodeID {
		t.Fatalf("daemon info node_id = %d, want %d", info.NodeID, originalNodeID)
	}
	t.Logf("daemon info confirmed: node_id=%d, uptime=%s", info.NodeID, info.Uptime)
}

// TestEndpointCachePopulated verifies that after a successful ensureTunnel
// (triggered by DialConnection), the daemon's endpoint cache contains
// the resolved peer address.
func TestEndpointCachePopulated(t *testing.T) {
	t.Parallel()

	tmpDir, err := os.MkdirTemp("/tmp", "w4-ep-pop-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Start beacon + registry
	bsrv := beacon.New()
	go bsrv.ListenAndServe(":0")
	select {
	case <-bsrv.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to start")
	}
	defer bsrv.Close()
	beaconAddr := resolveLocalAddr(bsrv.Addr())

	reg := registry.New(beaconAddr)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()
	regAddr := resolveLocalAddr(reg.Addr())

	// Start two daemons
	dA := daemon.New(daemon.Config{
		RegistryAddr:      regAddr,
		BeaconAddr:        beaconAddr,
		ListenAddr:        ":0",
		SocketPath:        filepath.Join(tmpDir, "a.sock"),
		IdentityPath:      filepath.Join(tmpDir, "id-a.json"),
		Email:             "a@pilot.local",
		Public:            true,
		KeepaliveInterval: 30 * time.Second,
	})
	if err := dA.Start(); err != nil {
		t.Fatalf("daemon A start: %v", err)
	}
	defer dA.Stop()

	dB := daemon.New(daemon.Config{
		RegistryAddr:      regAddr,
		BeaconAddr:        beaconAddr,
		ListenAddr:        ":0",
		SocketPath:        filepath.Join(tmpDir, "b.sock"),
		IdentityPath:      filepath.Join(tmpDir, "id-b.json"),
		Email:             "b@pilot.local",
		Public:            true,
		KeepaliveInterval: 30 * time.Second,
	})
	if err := dB.Start(); err != nil {
		t.Fatalf("daemon B start: %v", err)
	}
	defer dB.Stop()

	t.Logf("daemon A: node=%d, daemon B: node=%d", dA.NodeID(), dB.NodeID())

	// Before dial, no cache entry should exist
	_, ok := dA.CachedEndpoint(dB.NodeID())
	if ok {
		t.Fatal("expected no cache entry before dial")
	}

	// A dials B on echo port — triggers ensureTunnel → Resolve → cache
	conn, err := dA.DialConnection(dB.Addr(), 7)
	if err != nil {
		t.Fatalf("dial A->B: %v", err)
	}
	dA.CloseConnection(conn)

	// Cache should now have B's endpoint
	cached, ok := dA.CachedEndpoint(dB.NodeID())
	if !ok {
		t.Fatal("expected cache entry after dial, got none")
	}
	if cached == "" {
		t.Fatal("cached endpoint is empty")
	}
	t.Logf("endpoint cache populated for node %d: %s", dB.NodeID(), cached)
}

// TestRegistryClientReconnectOnBrokenConn verifies that the registry client
// recovers from a broken connection and successfully sends a message
// after the registry restarts.
func TestRegistryClientReconnectOnBrokenConn(t *testing.T) {
	t.Parallel()

	tmpDir, err := os.MkdirTemp("/tmp", "w4-rc-reconn-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	storePath := filepath.Join(tmpDir, "registry.json")

	// Start beacon
	bsrv := beacon.New()
	go bsrv.ListenAndServe(":0")
	select {
	case <-bsrv.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to start")
	}
	defer bsrv.Close()
	beaconAddr := resolveLocalAddr(bsrv.Addr())

	// Start registry
	reg := registry.NewWithStore(beaconAddr, storePath)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	regAddr := resolveLocalAddr(reg.Addr())

	// Register with identity and signer (H3 fix requires signatures)
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	rc, err := registry.Dial(regAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	setClientSigner(rc, id)

	resp, err := rc.RegisterWithKey("127.0.0.1:4000", crypto.EncodePublicKey(id.PublicKey), "rc-test@pilot.local", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Heartbeat should work
	_, err = rc.Heartbeat(nodeID)
	if err != nil {
		t.Fatalf("heartbeat before restart: %v", err)
	}
	t.Log("heartbeat succeeded before restart")

	// Restart registry (stop + start on same addr from store)
	reg.Close()
	t.Log("registry stopped")

	reg2 := registry.NewWithStore(beaconAddr, storePath)
	go reg2.ListenAndServe(regAddr)
	select {
	case <-reg2.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 2 failed to start")
	}
	defer reg2.Close()
	t.Log("registry 2 started")

	// After reconnect, heartbeat should succeed again
	var hbErr error
	for attempt := 0; attempt < 5; attempt++ {
		_, hbErr = rc.Heartbeat(nodeID)
		if hbErr == nil {
			t.Logf("heartbeat succeeded after reconnect (attempt %d)", attempt+1)
			break
		}
		t.Logf("heartbeat attempt %d failed: %v", attempt+1, hbErr)
		time.Sleep(500 * time.Millisecond)
	}
	if hbErr != nil {
		t.Fatalf("heartbeat failed after registry restart: %v", hbErr)
	}

	// Verify the node is accessible via lookup
	lookup, err := rc.Lookup(nodeID)
	if err != nil {
		// Node may not exist on new registry yet; re-register
		_, err = rc.RegisterWithKey("127.0.0.1:4000", crypto.EncodePublicKey(id.PublicKey), "rc-test@pilot.local", nil)
		if err != nil {
			t.Fatalf("re-register: %v", err)
		}
		lookup, err = rc.Lookup(nodeID)
		if err != nil {
			t.Fatalf("lookup after re-register: %v", err)
		}
	}
	gotID := uint32(lookup["node_id"].(float64))
	if gotID != nodeID {
		t.Fatalf("node_id = %d, want %d", gotID, nodeID)
	}
	t.Logf("node %d verified after reconnect", gotID)
}

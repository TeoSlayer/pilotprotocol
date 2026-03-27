package tests

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// TestBeaconRegisterAndList verifies beacon registration and listing via the registry.
func TestBeaconRegisterAndList(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	// Register a beacon
	resp, err := rc.Send(map[string]interface{}{
		"type":      "beacon_register",
		"beacon_id": float64(42),
		"addr":      "10.0.0.1:9001",
	})
	if err != nil {
		t.Fatalf("beacon_register: %v", err)
	}
	if resp["type"] != "beacon_register_ok" {
		t.Fatalf("expected beacon_register_ok, got %v", resp["type"])
	}

	// Register a second beacon
	_, err = rc.Send(map[string]interface{}{
		"type":      "beacon_register",
		"beacon_id": float64(99),
		"addr":      "10.0.0.2:9001",
	})
	if err != nil {
		t.Fatalf("beacon_register second: %v", err)
	}

	// List beacons
	resp, err = rc.Send(map[string]interface{}{"type": "beacon_list"})
	if err != nil {
		t.Fatalf("beacon_list: %v", err)
	}
	if resp["type"] != "beacon_list_ok" {
		t.Fatalf("expected beacon_list_ok, got %v", resp["type"])
	}

	beacons, ok := resp["beacons"].([]interface{})
	if !ok || len(beacons) != 2 {
		t.Fatalf("expected 2 beacons, got %v", resp["beacons"])
	}
	t.Logf("beacons: %v", beacons)
}

// TestBeaconRegisterValidation verifies that beacon_register rejects missing fields.
func TestBeaconRegisterValidation(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	// Missing beacon_id
	_, err := rc.Send(map[string]interface{}{
		"type": "beacon_register",
		"addr": "10.0.0.1:9001",
	})
	if err == nil {
		t.Fatal("expected error for missing beacon_id")
	}

	// Missing addr
	_, err = rc.Send(map[string]interface{}{
		"type":      "beacon_register",
		"beacon_id": float64(1),
	})
	if err == nil {
		t.Fatal("expected error for missing addr")
	}
}

// TestBeaconListFiltersExpired verifies that expired beacons are excluded from list.
func TestBeaconListFiltersExpired(t *testing.T) {
	t.Parallel()

	clk := newTestClock()
	reg := registry.New("127.0.0.1:9001")
	reg.SetClock(clk.Now)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	// Register beacon at current clock time
	_, err = rc.Send(map[string]interface{}{
		"type":      "beacon_register",
		"beacon_id": float64(1),
		"addr":      "10.0.0.1:9001",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// List — should see 1 beacon
	resp, err := rc.Send(map[string]interface{}{"type": "beacon_list"})
	if err != nil {
		t.Fatalf("list before expire: %v", err)
	}
	beacons := resp["beacons"].([]interface{})
	if len(beacons) != 1 {
		t.Fatalf("expected 1 beacon before expiry, got %d", len(beacons))
	}

	// Advance clock past beacon TTL (60s)
	clk.Advance(90 * time.Second)

	// List — beacon should be filtered out
	resp, err = rc.Send(map[string]interface{}{"type": "beacon_list"})
	if err != nil {
		t.Fatalf("list after expire: %v", err)
	}
	beacons = resp["beacons"].([]interface{})
	if len(beacons) != 0 {
		t.Fatalf("expected 0 beacons after expiry, got %d", len(beacons))
	}
}

// TestReapStaleNodes verifies that nodes without heartbeats are reaped.
func TestReapStaleNodes(t *testing.T) {
	t.Parallel()

	clk := newTestClock()
	reg := registry.New("127.0.0.1:9001")
	reg.SetClock(clk.Now)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	// Register a node
	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("127.0.0.1:4000", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Verify node exists
	_, err = rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup before reap: %v", err)
	}

	// Advance clock past stale threshold (3 minutes)
	clk.Advance(4 * time.Minute)

	// Trigger reap
	reg.Reap()

	// Node should be gone
	_, err = rc.Lookup(nodeID)
	if err == nil {
		t.Fatal("expected lookup to fail after reap, node still exists")
	}
	t.Logf("correctly reaped: %v", err)
}

// TestReapStaleBeacons verifies that stale beacons are removed by reap.
func TestReapStaleBeacons(t *testing.T) {
	t.Parallel()

	clk := newTestClock()
	reg := registry.New("127.0.0.1:9001")
	reg.SetClock(clk.Now)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	// Register beacon
	_, err = rc.Send(map[string]interface{}{
		"type":      "beacon_register",
		"beacon_id": float64(1),
		"addr":      "10.0.0.1:9001",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Advance clock past beacon TTL
	clk.Advance(90 * time.Second)

	// Trigger reap
	reg.Reap()

	// Beacon list should be empty (both reap cleanup and list filter agree)
	resp, err := rc.Send(map[string]interface{}{"type": "beacon_list"})
	if err != nil {
		t.Fatalf("list after reap: %v", err)
	}
	beacons := resp["beacons"].([]interface{})
	if len(beacons) != 0 {
		t.Fatalf("expected 0 beacons after reap, got %d", len(beacons))
	}
}

// TestRegistryPunch verifies the punch message handler.
func TestRegistryPunch(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	// Register two nodes with endpoints
	nodeA, idA := registerTestNode(t, rc)
	nodeB, _ := registerTestNode(t, rc)

	// Punch requires signature from requester
	setClientSigner(rc, idA)
	resp, err := rc.Punch(nodeA, nodeA, nodeB)
	if err != nil {
		t.Fatalf("punch: %v", err)
	}
	if resp["type"] != "punch_ok" {
		t.Fatalf("expected punch_ok, got %v", resp["type"])
	}
	if resp["node_a_addr"] == nil || resp["node_b_addr"] == nil {
		t.Fatal("expected both node addresses in punch response")
	}
	t.Logf("punch: A=%v B=%v", resp["node_a_addr"], resp["node_b_addr"])
}


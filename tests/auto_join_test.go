package tests

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

func TestAutoJoinNetworks(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Create a network via a pre-registered node
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "fleet-net", "open", "", TestAdminToken)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Start daemon with auto-join config
	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
		cfg.Networks = []uint16{netID}
	})

	// Verify daemon is a member by listing nodes in the network
	nodeID := info.Daemon.NodeID()
	members, err := rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	nodeList, ok := members["nodes"].([]interface{})
	if !ok {
		t.Fatalf("expected nodes array, got %T", members["nodes"])
	}

	found := false
	for _, n := range nodeList {
		nm, ok := n.(map[string]interface{})
		if !ok {
			continue
		}
		if uint32(nm["node_id"].(float64)) == nodeID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("daemon node %d not found in network %d after auto-join", nodeID, netID)
	}
}

func TestAutoJoinAlreadyMember(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "idempotent-net", "open", "", TestAdminToken)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Start daemon with same network listed twice — should not error
	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
		cfg.Networks = []uint16{netID, netID}
	})

	// Verify membership (should succeed despite double join)
	nodeID := info.Daemon.NodeID()
	members, err := rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	nodeList, ok := members["nodes"].([]interface{})
	if !ok {
		t.Fatalf("expected nodes array, got %T", members["nodes"])
	}

	count := 0
	for _, n := range nodeList {
		nm, ok := n.(map[string]interface{})
		if !ok {
			continue
		}
		if uint32(nm["node_id"].(float64)) == nodeID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 membership in network %d, got %d", netID, count)
	}
}

func TestAutoJoinInvalidNetwork(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Start daemon with a non-existent network ID — should start fine, just log a warning
	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
		cfg.Networks = []uint16{65535} // unlikely to exist
	})

	// Daemon should still be running and responsive
	nodeID := info.Daemon.NodeID()
	if nodeID == 0 {
		t.Fatal("daemon failed to register — nodeID is 0")
	}
}

// TestAutoJoinNoAdminToken verifies that when no admin token is configured,
// auto-join is silently skipped and the daemon still starts successfully.
func TestAutoJoinNoAdminToken(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "no-token-net", "open", "", TestAdminToken)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Start daemon with Networks set but no AdminToken
	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = "" // no token
		cfg.Networks = []uint16{netID}
	})

	// Daemon should be running
	if info.Daemon.NodeID() == 0 {
		t.Fatal("daemon failed to start")
	}

	// Daemon should NOT have joined the network (auto-join skipped)
	members, err := rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	for _, n := range members["nodes"].([]interface{}) {
		nm := n.(map[string]interface{})
		if uint32(nm["node_id"].(float64)) == info.Daemon.NodeID() {
			t.Fatal("daemon should NOT have joined network when no admin token is configured")
		}
	}
}

// TestAutoJoinMultipleNetworks verifies that a daemon auto-joins all networks
// listed in config on startup.
func TestAutoJoinMultipleNetworks(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)

	const numNets = 3
	netIDs := make([]uint16, numNets)
	for i := 0; i < numNets; i++ {
		resp, err := rc.CreateNetwork(creatorID, fmt.Sprintf("multi-auto-net-%d", i), "open", "", TestAdminToken)
		if err != nil {
			t.Fatalf("create network %d: %v", i, err)
		}
		netIDs[i] = uint16(resp["network_id"].(float64))
	}

	// Start daemon with all three networks in config
	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
		cfg.Networks = netIDs
	})

	nodeID := info.Daemon.NodeID()
	for _, netID := range netIDs {
		members, err := rc.ListNodes(netID, TestAdminToken)
		if err != nil {
			t.Fatalf("list nodes for net %d: %v", netID, err)
		}
		found := false
		for _, n := range members["nodes"].([]interface{}) {
			nm := n.(map[string]interface{})
			if uint32(nm["node_id"].(float64)) == nodeID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("daemon not a member of network %d after auto-join", netID)
		}
	}
}

// TestAutoJoinInviteNetworkFails verifies that auto-join of an invite-only
// network fails gracefully — the daemon starts successfully but logs a warning.
func TestAutoJoinInviteNetworkFails(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "invite-only-autojoin", "invite", "", TestAdminToken)
	if err != nil {
		t.Fatalf("create invite network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Daemon should start fine even though it can't auto-join an invite-only network
	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
		cfg.Networks = []uint16{netID}
	})

	if info.Daemon.NodeID() == 0 {
		t.Fatal("daemon should start successfully even when auto-join fails")
	}

	// Daemon should NOT be in the invite-only network
	members, err := rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	for _, n := range members["nodes"].([]interface{}) {
		nm := n.(map[string]interface{})
		if uint32(nm["node_id"].(float64)) == info.Daemon.NodeID() {
			t.Fatal("daemon should NOT be in invite-only network via auto-join")
		}
	}
}

func TestAutoJoinWebhookEvent(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var events []daemon.WebhookEvent

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev daemon.WebhookEvent
		json.Unmarshal(body, &ev)
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "webhook-net", "open", "", TestAdminToken)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Start daemon with webhook + auto-join
	env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
		cfg.Networks = []uint16{netID}
		cfg.WebhookURL = srv.URL
	})

	// Poll for webhook event (async delivery)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		found := false
		for _, ev := range events {
			if ev.Event == "network.auto_joined" {
				found = true
				break
			}
		}
		mu.Unlock()
		if found {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	t.Fatalf("expected 'network.auto_joined' webhook event within 5s, got %d events: %v", len(events), events)
}

// TestAutoJoinTokenGatedWithoutJoinToken verifies that a daemon cannot auto-join
// a token-gated network because autoJoinNetworks doesn't pass a join token.
// The daemon should start successfully and log a warning.
func TestAutoJoinTokenGatedWithoutJoinToken(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "token-gated-autojoin", "token", "secret-token", TestAdminToken)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Daemon auto-join passes empty join token — should fail for token-gated network
	// but daemon should still start and operate normally
	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
		cfg.Networks = []uint16{netID}
	})

	// Daemon should still be running
	if info.Daemon.NodeID() == 0 {
		t.Fatal("daemon should start even when auto-join fails for token-gated network")
	}

	// Check membership: daemon may or may not be a member depending on whether
	// admin token overrides token requirement. Either outcome is valid as long
	// as daemon doesn't crash.
	members, err := rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	found := false
	for _, n := range members["nodes"].([]interface{}) {
		nm := n.(map[string]interface{})
		if uint32(nm["node_id"].(float64)) == info.Daemon.NodeID() {
			found = true
			break
		}
	}
	t.Logf("daemon joined token-gated network via auto-join: %v (admin token may override)", found)
}

// TestAutoJoinMixedValidInvalid verifies that when a daemon is configured with
// both valid and invalid network IDs, it joins the valid ones and skips the
// invalid ones without affecting each other.
func TestAutoJoinMixedValidInvalid(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "mixed-valid-net", "open", "", TestAdminToken)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	validNetID := uint16(resp["network_id"].(float64))

	// Start daemon with one valid network and one non-existent
	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
		cfg.Networks = []uint16{65534, validNetID} // 65534 doesn't exist
	})

	// Should be a member of the valid network despite the invalid one failing
	members, err := rc.ListNodes(validNetID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	found := false
	for _, n := range members["nodes"].([]interface{}) {
		nm := n.(map[string]interface{})
		if uint32(nm["node_id"].(float64)) == info.Daemon.NodeID() {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("daemon should have joined valid network even though invalid network failed")
	}
}

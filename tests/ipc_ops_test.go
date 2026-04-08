package tests

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// TestSetHostnameViaIPC verifies the driver → IPC → daemon → registry round-trip
// for SetHostname.
func TestSetHostnameViaIPC(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	di := env.AddDaemon()

	// Set hostname via driver IPC
	result, err := di.Driver.SetHostname("my-agent")
	if err != nil {
		t.Fatalf("set hostname: %v", err)
	}
	if result["hostname"] != "my-agent" {
		t.Fatalf("expected hostname 'my-agent' in response, got %v", result["hostname"])
	}

	// Verify daemon Info() reflects the change
	info, err := di.Driver.Info()
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	if info["hostname"] != "my-agent" {
		t.Fatalf("expected hostname 'my-agent' in info, got %v", info["hostname"])
	}

	// Verify registry lookup shows hostname
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	lookup, err := rc.Lookup(di.Daemon.NodeID())
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if lookup["hostname"] != "my-agent" {
		t.Fatalf("expected hostname 'my-agent' in lookup, got %v", lookup["hostname"])
	}

	// Clear hostname
	result, err = di.Driver.SetHostname("")
	if err != nil {
		t.Fatalf("clear hostname: %v", err)
	}
	if result["hostname"] != "" {
		t.Fatalf("expected empty hostname, got %v", result["hostname"])
	}
}

// TestSetVisibilityViaIPC verifies the driver → IPC → daemon → registry round-trip
// for SetVisibility.
func TestSetVisibilityViaIPC(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	di := env.AddDaemon() // default: Public=true
	nodeID := di.Daemon.NodeID()

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Verify initially public
	lookup, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("initial lookup: %v", err)
	}
	if lookup["public"] != true {
		t.Fatalf("expected initially public, got %v", lookup["public"])
	}

	// Set to private
	result, err := di.Driver.SetVisibility(false)
	if err != nil {
		t.Fatalf("set visibility private: %v", err)
	}
	if result["type"] != "set_visibility_ok" {
		t.Fatalf("expected set_visibility_ok, got %v", result["type"])
	}

	// Verify registry reflects private
	lookup, err = rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup after private: %v", err)
	}
	if lookup["public"] != false {
		t.Fatalf("expected public=false in registry, got %v", lookup["public"])
	}

	// Set back to public
	result, err = di.Driver.SetVisibility(true)
	if err != nil {
		t.Fatalf("set visibility public: %v", err)
	}

	lookup, err = rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup after public: %v", err)
	}
	if lookup["public"] != true {
		t.Fatalf("expected public=true in registry, got %v", lookup["public"])
	}
}

// TestDeregisterViaIPC verifies the driver → IPC → daemon → registry round-trip
// for Deregister.
func TestDeregisterViaIPC(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	di := env.AddDaemon()
	nodeID := di.Daemon.NodeID()

	// Verify node exists
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	_, err = rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup before deregister: %v", err)
	}

	// Deregister via driver IPC
	result, err := di.Driver.Deregister()
	if err != nil {
		t.Fatalf("deregister: %v", err)
	}
	if result["type"] != "deregister_ok" {
		t.Fatalf("expected deregister_ok, got %v", result["type"])
	}

	// Verify lookup now fails
	_, err = rc.Lookup(nodeID)
	if err == nil {
		t.Fatal("expected lookup to fail after deregister, got nil")
	}
}

// TestSetWebhookViaIPC verifies the driver → IPC → daemon round-trip for SetWebhook.
// This is a local-only operation (does not call registry).
func TestSetWebhookViaIPC(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	di := env.AddDaemon()

	// Set webhook
	result, err := di.Driver.SetWebhook("http://localhost:9999/hooks")
	if err != nil {
		t.Fatalf("set webhook: %v", err)
	}
	if result["webhook"] != "http://localhost:9999/hooks" {
		t.Fatalf("expected webhook URL, got %v", result["webhook"])
	}

	// Clear webhook
	result, err = di.Driver.SetWebhook("")
	if err != nil {
		t.Fatalf("clear webhook: %v", err)
	}
	if result["webhook"] != "" {
		t.Fatalf("expected empty webhook, got %v", result["webhook"])
	}
}

// TestResolveHostnameViaIPC verifies the driver → IPC → daemon → registry round-trip
// for ResolveHostname.
func TestResolveHostnameViaIPC(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	di := env.AddDaemon()

	// Set a hostname first
	_, err := di.Driver.SetHostname("resolve-test-agent")
	if err != nil {
		t.Fatalf("set hostname: %v", err)
	}

	// Resolve it via driver IPC
	result, err := di.Driver.ResolveHostname("resolve-test-agent")
	if err != nil {
		t.Fatalf("resolve hostname: %v", err)
	}
	if result["address"] == nil {
		t.Fatal("expected address in resolve result")
	}
	t.Logf("resolved: %v", result)

	// Resolve non-existent hostname — should fail
	_, err = di.Driver.ResolveHostname("nonexistent-host")
	if err == nil {
		t.Fatal("expected error for non-existent hostname")
	}
}

// TestDisconnectViaIPC verifies the driver → IPC round-trip for Disconnect.
// Disconnect always returns OK (even for non-existent IDs), so we verify
// the round-trip completes without error.
func TestDisconnectViaIPC(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	di := env.AddDaemon()

	// Disconnect a non-existent connection — should still return OK
	err := di.Driver.Disconnect(999)
	if err != nil {
		t.Fatalf("disconnect: %v", err)
	}
}

// TestSetTagsTooManyViaIPC verifies the daemon rejects >3 tags.
func TestSetTagsTooManyViaIPC(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	di := env.AddDaemon()

	// Attempt to set 4 tags — should fail
	_, err := di.Driver.SetTags([]string{"a", "b", "c", "d"})
	if err == nil {
		t.Fatal("expected error for >3 tags, got nil")
	}

	// Verify 3 tags works
	result, err := di.Driver.SetTags([]string{"x", "y", "z"})
	if err != nil {
		t.Fatalf("set 3 tags: %v", err)
	}
	if result["type"] != "set_tags_ok" {
		t.Fatalf("expected set_tags_ok, got %v", result["type"])
	}

	// Clear tags
	result, err = di.Driver.SetTags([]string{})
	if err != nil {
		t.Fatalf("clear tags: %v", err)
	}
	if result["type"] != "set_tags_ok" {
		t.Fatalf("expected set_tags_ok, got %v", result["type"])
	}
}

// TestRegistryClientBeaconAndNetwork tests registry client operations
// to cover beacon_list, list_networks, and beacon_register handlers.
func TestRegistryClientBeaconAndNetwork(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	_ = env.AddDaemon()

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// List networks
	result, err := rc.ListNetworks()
	if err != nil {
		t.Fatalf("list networks: %v", err)
	}
	if result["type"] != "list_networks_ok" {
		t.Fatalf("expected list_networks_ok, got %v", result["type"])
	}

	// Beacon register
	result, err = rc.Send(map[string]interface{}{
		"type":      "beacon_register",
		"beacon_id": uint32(42),
		"addr":      "127.0.0.1:9001",
	})
	if err != nil {
		t.Fatalf("beacon register: %v", err)
	}
	if result["type"] != "beacon_register_ok" {
		t.Fatalf("expected beacon_register_ok, got %v", result["type"])
	}

	// Beacon list
	result, err = rc.Send(map[string]interface{}{"type": "beacon_list"})
	if err != nil {
		t.Fatalf("beacon list: %v", err)
	}
	if result["type"] != "beacon_list_ok" {
		t.Fatalf("expected beacon_list_ok, got %v", result["type"])
	}
	beacons, ok := result["beacons"].([]interface{})
	if !ok || len(beacons) < 1 {
		t.Fatalf("expected at least 1 beacon, got %v", result["beacons"])
	}
}

// TestDaemonCustomConfig creates a daemon with custom config values to
// exercise the "config set" branches in config helper methods.
func TestDaemonCustomConfig(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	di := env.AddDaemon(func(c *daemon.Config) {
		c.KeepaliveInterval = 60 * time.Second
		c.IdleTimeout = 180 * time.Second
		c.SYNRateLimit = 50
		c.MaxConnectionsPerPort = 512
		c.MaxTotalConnections = 2048
		c.TimeWaitDuration = 5 * time.Second
		c.DisableEcho = true
	})

	// Verify daemon runs with custom config
	info, err := di.Driver.Info()
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	if info["address"] == nil {
		t.Fatal("expected address in info")
	}

	// Echo should be disabled — connect to port 7 should fail or timeout
	// We just verify the daemon is running with the custom config
	t.Logf("daemon with custom config: addr=%v", info["address"])
}

// TestIPCOpsAfterDeregister verifies IPC commands return errors after deregistration.
func TestIPCOpsAfterDeregister(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	di := env.AddDaemon()

	// Deregister first
	_, err := di.Driver.Deregister()
	if err != nil {
		t.Fatalf("deregister: %v", err)
	}

	// SetHostname should fail (node no longer registered)
	_, err = di.Driver.SetHostname("should-fail")
	if err == nil {
		t.Fatal("expected error for SetHostname after deregister")
	}

	// SetVisibility should fail
	_, err = di.Driver.SetVisibility(false)
	if err == nil {
		t.Fatal("expected error for SetVisibility after deregister")
	}

	// SetTags should fail
	_, err = di.Driver.SetTags([]string{"fail"})
	if err == nil {
		t.Fatal("expected error for SetTags after deregister")
	}

	// SetTaskExec should fail
	_, err = di.Driver.SetTaskExec(true)
	if err == nil {
		t.Fatal("expected error for SetTaskExec after deregister")
	}
}

// TestPolicySetGetViaIPC verifies the full driver → IPC → daemon round-trip
// for PolicySet and PolicyGet.
func TestPolicySetGetViaIPC(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	di := env.AddDaemon()

	// Create a network for the daemon to join
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	nodeID := di.Daemon.NodeID()
	resp, err := rc.CreateNetwork(nodeID, "ipc-policy-net", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Creator auto-joins, so no need to join explicitly.

	// Set policy on registry first (admin gated)
	policyJSON := []byte(`{"version":1,"rules":[{"name":"allow-80","on":"connect","match":"port == 80","actions":[{"type":"allow"}]},{"name":"deny-all","on":"connect","match":"true","actions":[{"type":"deny"}]}]}`)
	_, err = rc.SetExprPolicy(netID, policyJSON, TestAdminToken)
	if err != nil {
		t.Fatalf("SetExprPolicy on registry: %v", err)
	}

	// Apply policy to daemon via IPC
	setResult, err := di.Driver.PolicySet(netID, policyJSON)
	if err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	if setResult["applied"] != true {
		t.Fatalf("expected applied=true, got %v", setResult["applied"])
	}

	// Get policy status via IPC
	getResult, err := di.Driver.PolicyGet(netID)
	if err != nil {
		t.Fatalf("PolicyGet: %v", err)
	}
	if getResult["engine"] != "policy" {
		t.Fatalf("expected engine=policy, got %v", getResult["engine"])
	}
	if getResult["expr_policy"] == nil {
		t.Fatal("expected expr_policy in response")
	}
}

// TestPolicyGetNoRunnerViaIPC verifies PolicyGet returns engine=none when
// no policy runner exists for the given network.
func TestPolicyGetNoRunnerViaIPC(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	di := env.AddDaemon()

	// Get policy for a network with no runner — returns engine=none
	result, err := di.Driver.PolicyGet(9999)
	if err != nil {
		t.Fatalf("PolicyGet: %v", err)
	}
	if result["engine"] != "none" {
		t.Fatalf("expected engine=none, got %v", result["engine"])
	}
}

// TestManagedOpsViaIPCWithPolicyRunner verifies that existing managed commands
// (score, status, rankings, cycle) work through the PolicyRunner when no
// ManagedEngine exists.
func TestManagedOpsViaIPCWithPolicyRunner(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	di := env.AddDaemon()

	// Create a network
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	nodeID := di.Daemon.NodeID()
	resp, err := rc.CreateNetwork(nodeID, "managed-compat", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Creator auto-joins, so no need to join explicitly.

	// Set policy with cycle/score rules
	policyJSON := []byte(`{"version":1,"config":{"cycle":"1h","max_peers":50},"rules":[{"name":"score-data","on":"datagram","match":"size > 0","actions":[{"type":"score","params":{"delta":1,"topic":"activity"}}]},{"name":"cycle","on":"cycle","match":"true","actions":[{"type":"prune","params":{"count":2,"by":"score"}}]}]}`)
	_, err = di.Driver.PolicySet(netID, policyJSON)
	if err != nil {
		t.Fatalf("PolicySet: %v", err)
	}

	// ManagedStatus should work via PolicyRunner
	status, err := di.Driver.ManagedStatus(netID)
	if err != nil {
		t.Fatalf("ManagedStatus: %v", err)
	}
	if status["engine"] != "policy" {
		t.Fatalf("expected engine=policy, got %v", status["engine"])
	}

	// ManagedRankings should work
	rankings, err := di.Driver.ManagedRankings(netID)
	if err != nil {
		t.Fatalf("ManagedRankings: %v", err)
	}
	_ = rankings

	// ManagedForceCycle should work
	cycleResp, err := di.Driver.ManagedForceCycle(netID)
	if err != nil {
		t.Fatalf("ManagedForceCycle: %v", err)
	}
	_ = cycleResp
}

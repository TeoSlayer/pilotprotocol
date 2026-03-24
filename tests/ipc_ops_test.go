package tests

import (
	"testing"

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

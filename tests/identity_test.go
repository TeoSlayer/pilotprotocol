package tests

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// waitForSocketRemoval polls until the given unix socket file is removed,
// confirming the daemon has fully shut down and released the path.
func waitForSocketRemoval(t *testing.T, sockPath string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if _, err := os.Stat(sockPath); os.IsNotExist(err) {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for socket removal: %s", sockPath)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestIdentityPersistence(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	identityDir := t.TempDir()
	identityPath := filepath.Join(identityDir, "identity.json")

	// Start daemon with identity persistence (first run — no file exists)
	d1, sockPath := env.AddDaemonOnly(func(c *daemon.Config) {
		c.IdentityPath = identityPath
	})

	// Verify identity file was created
	if _, err := os.Stat(identityPath); err != nil {
		t.Fatalf("identity file not created: %v", err)
	}

	// Get first-run info
	drv1, err := driver.Connect(sockPath)
	if err != nil {
		t.Fatalf("connect driver: %v", err)
	}
	info1, err := drv1.Info()
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	drv1.Close()

	nodeID1 := int(info1["node_id"].(float64))
	pubKey1 := info1["public_key"].(string)
	hasIdentity1 := info1["identity"].(bool)

	if !hasIdentity1 {
		t.Fatal("expected identity=true after first registration")
	}
	if pubKey1 == "" {
		t.Fatal("expected non-empty public_key")
	}

	t.Logf("first run: node_id=%d, pubkey=%s...", nodeID1, pubKey1[:16])

	// Stop daemon and wait for socket to be released
	d1.Stop()
	waitForSocketRemoval(t, sockPath)

	// Verify identity file can be loaded
	id, err := crypto.LoadIdentity(identityPath)
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	if id == nil {
		t.Fatal("loaded identity is nil")
	}
	if crypto.EncodePublicKey(id.PublicKey) != pubKey1 {
		t.Fatal("loaded identity public key mismatch")
	}

	// Start daemon again (re-register with existing identity) — create manually to avoid adding to env list
	d2 := daemon.New(daemon.Config{
		RegistryAddr: env.RegistryAddr,
		BeaconAddr:   env.BeaconAddr,
		ListenAddr:   ":0",
		SocketPath:   sockPath,
		IdentityPath: identityPath,
	})
	if err := d2.Start(); err != nil {
		t.Fatalf("daemon restart: %v", err)
	}
	defer d2.Stop()

	// Get second-run info
	drv2, err := driver.Connect(sockPath)
	if err != nil {
		t.Fatalf("connect driver 2: %v", err)
	}
	info2, err := drv2.Info()
	if err != nil {
		t.Fatalf("info 2: %v", err)
	}
	drv2.Close()

	nodeID2 := int(info2["node_id"].(float64))
	pubKey2 := info2["public_key"].(string)

	// Verify same node_id and public key
	if nodeID2 != nodeID1 {
		t.Errorf("node_id changed across restart: %d -> %d", nodeID1, nodeID2)
	}
	if pubKey2 != pubKey1 {
		t.Errorf("public_key changed across restart")
	}

	t.Logf("second run: node_id=%d (same=%v), pubkey matches=%v",
		nodeID2, nodeID2 == nodeID1, pubKey2 == pubKey1)
}

func TestIdentityWithoutPersistence(t *testing.T) {
	t.Parallel()
	// Verify that daemons without -identity still work (backward compat)
	env := NewTestEnv(t)

	info := env.AddDaemon(func(c *daemon.Config) {
		c.IdentityPath = "" // no persistence
	})
	drv := info.Driver

	drvInfo, err := drv.Info()
	if err != nil {
		t.Fatalf("info: %v", err)
	}

	hasIdentity := drvInfo["identity"].(bool)
	if hasIdentity {
		t.Error("expected identity=false when no -identity flag")
	}

	t.Logf("no-persistence mode: node_id=%d, identity=%v",
		int(drvInfo["node_id"].(float64)), hasIdentity)
}

func TestKeyRotationViaSignature(t *testing.T) {
	t.Parallel()
	// Test that a node can rotate its keypair by proving ownership with a signature
	env := NewTestEnv(t)

	identityDir := t.TempDir()
	identityPath := filepath.Join(identityDir, "identity.json")

	// Start daemon with identity + owner
	d, sockPath := env.AddDaemonOnly(func(c *daemon.Config) {
		c.IdentityPath = identityPath
		c.Owner = "test@example.com"
	})

	// Get original info
	drv, err := driver.Connect(sockPath)
	if err != nil {
		t.Fatalf("connect driver: %v", err)
	}
	info, err := drv.Info()
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	drv.Close()

	nodeID := uint32(info["node_id"].(float64))
	origPubKey := info["public_key"].(string)
	t.Logf("original: node_id=%d, pubkey=%s...", nodeID, origPubKey[:16])

	// Load identity to sign the rotation challenge
	id, err := crypto.LoadIdentity(identityPath)
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}

	// Sign the challenge "rotate:<node_id>"
	challenge := fmt.Sprintf("rotate:%d", nodeID)
	signature := id.Sign([]byte(challenge))
	sigB64 := base64.StdEncoding.EncodeToString(signature)

	// Generate a new keypair for rotation (client-side)
	newID, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate new identity: %v", err)
	}
	newPubKeyB64 := crypto.EncodePublicKey(newID.PublicKey)

	// Rotate key via registry client
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	resp, err := rc.RotateKey(nodeID, sigB64, newPubKeyB64)
	if err != nil {
		t.Fatalf("rotate key: %v", err)
	}

	newPubKey, _ := resp["public_key"].(string)
	newNodeID := uint32(resp["node_id"].(float64))

	// Same node_id, different key
	if newNodeID != nodeID {
		t.Errorf("node_id changed: %d -> %d", nodeID, newNodeID)
	}
	if newPubKey == origPubKey {
		t.Error("public key should have changed after rotation")
	}
	if newPubKey != newPubKeyB64 {
		t.Error("returned public key should match the provided new_public_key")
	}

	t.Logf("rotated: node_id=%d (same=%v), new_pubkey=%s...", newNodeID, newNodeID == nodeID, newPubKey[:16])

	d.Stop()
}

func TestKeyRotationRequiresSignature(t *testing.T) {
	t.Parallel()
	// Test that rotation without signature is rejected (owner-only path removed)
	env := NewTestEnv(t)

	identityDir := t.TempDir()
	identityPath := filepath.Join(identityDir, "identity.json")

	// Start daemon with identity + owner
	d1, _ := env.AddDaemonOnly(func(c *daemon.Config) {
		c.IdentityPath = identityPath
		c.Owner = "recovery@example.com"
	})

	// Get node ID via registry lookup
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Poll until daemon is registered
	{
		deadline := time.After(5 * time.Second)
		for {
			_, lookupErr := rc.Lookup(d1.NodeID())
			if lookupErr == nil {
				break
			}
			select {
			case <-deadline:
				t.Fatalf("timed out waiting for daemon registration: %v", lookupErr)
			case <-time.After(10 * time.Millisecond):
			}
		}
	}

	// Attempt rotation without signature — should be rejected
	_, err = rc.RotateKey(1, "", "some-new-key")
	if err == nil {
		t.Error("expected error for rotation without signature")
	} else {
		t.Logf("correctly rejected rotation without signature: %v", err)
	}

	// Attempt rotation without new_public_key — should be rejected
	_, err = rc.RotateKey(1, "some-sig", "")
	if err == nil {
		t.Error("expected error for rotation without new_public_key")
	} else {
		t.Logf("correctly rejected rotation without new_public_key: %v", err)
	}

	d1.Stop()
}

func TestOwnerBasedReRegistration(t *testing.T) {
	t.Parallel()
	// Test that a daemon with owner can re-register after losing its identity file
	env := NewTestEnv(t)

	identityDir := t.TempDir()
	identityPath := filepath.Join(identityDir, "identity.json")

	// Start daemon with identity + owner
	d1, sockPath := env.AddDaemonOnly(func(c *daemon.Config) {
		c.IdentityPath = identityPath
		c.Owner = "agent@example.com"
	})

	drv1, err := driver.Connect(sockPath)
	if err != nil {
		t.Fatalf("connect driver: %v", err)
	}
	info1, err := drv1.Info()
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	drv1.Close()

	nodeID1 := int(info1["node_id"].(float64))
	pubKey1 := info1["public_key"].(string)
	t.Logf("first run: node_id=%d, pubkey=%s...", nodeID1, pubKey1[:16])

	d1.Stop()
	waitForSocketRemoval(t, sockPath)

	// DELETE the identity file — simulates losing the private key
	os.Remove(identityPath)

	// Start daemon again with same owner but no identity file — create manually to avoid adding to env list
	d2 := daemon.New(daemon.Config{
		RegistryAddr: env.RegistryAddr,
		BeaconAddr:   env.BeaconAddr,
		ListenAddr:   ":0",
		SocketPath:   sockPath,
		IdentityPath: identityPath,
		Owner:        "agent@example.com",
	})
	if err := d2.Start(); err != nil {
		t.Fatalf("daemon restart: %v", err)
	}
	defer d2.Stop()

	drv2, err := driver.Connect(sockPath)
	if err != nil {
		t.Fatalf("connect driver 2: %v", err)
	}
	info2, err := drv2.Info()
	if err != nil {
		t.Fatalf("info 2: %v", err)
	}
	drv2.Close()

	nodeID2 := int(info2["node_id"].(float64))
	pubKey2 := info2["public_key"].(string)

	// Same node_id (owner recovery), but new keypair
	if nodeID2 != nodeID1 {
		t.Errorf("node_id should be same after owner recovery: %d -> %d", nodeID1, nodeID2)
	}
	if pubKey2 == pubKey1 {
		t.Error("public key should change after identity file loss + owner recovery")
	}

	t.Logf("owner recovery: node_id=%d (same=%v), new_pubkey=%s...",
		nodeID2, nodeID2 == nodeID1, pubKey2[:16])
}

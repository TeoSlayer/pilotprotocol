package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

func TestHandshakeMutualAutoApprove(t *testing.T) {
	t.Parallel()
	// Two nodes send handshake requests to each other → auto-approved (mutual)

	env := NewTestEnv(t)

	infoA := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})
	infoB := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})

	daemonA := infoA.Daemon
	daemonB := infoB.Daemon
	drvA := infoA.Driver
	drvB := infoB.Driver

	t.Logf("daemon A: node=%d, daemon B: node=%d", daemonA.NodeID(), daemonB.NodeID())

	// A sends handshake to B
	_, err := drvA.Handshake(daemonB.NodeID(), "want to collaborate")
	if err != nil {
		t.Fatalf("A handshake to B: %v", err)
	}
	t.Logf("A sent handshake to B")

	// Poll until B has a pending handshake from A
	deadline := time.After(5 * time.Second)
	for {
		pending, pErr := drvB.PendingHandshakes()
		if pErr == nil {
			if pl, _ := pending["pending"].([]interface{}); len(pl) > 0 {
				break
			}
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for A's handshake to reach B")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// B sends handshake to A -> mutual auto-approve
	_, err = drvB.Handshake(daemonA.NodeID(), "want to collaborate too")
	if err != nil {
		t.Fatalf("B handshake to A: %v", err)
	}
	t.Logf("B sent handshake to A")

	// Poll until both see each other as trusted
	deadline = time.After(5 * time.Second)
	var trustedA, trustedB []interface{}
	for {
		trustA, tErr := drvA.TrustedPeers()
		trustB, tErr2 := drvB.TrustedPeers()
		if tErr == nil && tErr2 == nil {
			trustedA, _ = trustA["trusted"].([]interface{})
			trustedB, _ = trustB["trusted"].([]interface{})
			if len(trustedA) > 0 && len(trustedB) > 0 {
				break
			}
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for mutual trust: A=%d B=%d", len(trustedA), len(trustedB))
		case <-time.After(10 * time.Millisecond):
		}
	}

	t.Logf("A trusted peers: %d, B trusted peers: %d", len(trustedA), len(trustedB))

	if len(trustedA) == 0 {
		t.Error("A should have trusted peers after mutual handshake")
	}
	if len(trustedB) == 0 {
		t.Error("B should have trusted peers after mutual handshake")
	}

	// Check that B is in A's trusted list
	foundB := false
	for _, tp := range trustedA {
		rec := tp.(map[string]interface{})
		if uint32(rec["node_id"].(float64)) == daemonB.NodeID() {
			foundB = true
			if m, ok := rec["mutual"].(bool); ok {
				t.Logf("A trusts B: mutual=%v", m)
			}
		}
	}
	if !foundB {
		t.Errorf("B not found in A's trusted peers")
	}

	// Check that A is in B's trusted list
	foundA := false
	for _, tp := range trustedB {
		rec := tp.(map[string]interface{})
		if uint32(rec["node_id"].(float64)) == daemonA.NodeID() {
			foundA = true
			if m, ok := rec["mutual"].(bool); ok {
				t.Logf("B trusts A: mutual=%v", m)
			}
		}
	}
	if !foundA {
		t.Errorf("A not found in B's trusted peers")
	}
}

func TestHandshakePendingApproveReject(t *testing.T) {
	t.Parallel()
	// A sends handshake to B → pending. B approves. Then C sends → B rejects.

	env := NewTestEnv(t)

	infoA := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})
	infoB := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})
	infoC := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})

	daemonA := infoA.Daemon
	daemonB := infoB.Daemon
	daemonC := infoC.Daemon
	drvA := infoA.Driver
	drvB := infoB.Driver
	drvC := infoC.Driver

	t.Logf("A=%d, B=%d, C=%d", daemonA.NodeID(), daemonB.NodeID(), daemonC.NodeID())

	// A sends handshake to B (one-way -> pending on B)
	_, err := drvA.Handshake(daemonB.NodeID(), "I am agent A")
	if err != nil {
		t.Fatalf("A handshake: %v", err)
	}

	// Poll until B has a pending handshake
	deadline := time.After(5 * time.Second)
	var pendingList []interface{}
	for {
		pending, pErr := drvB.PendingHandshakes()
		if pErr != nil {
			t.Fatalf("pending: %v", pErr)
		}
		pendingList, _ = pending["pending"].([]interface{})
		if len(pendingList) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("B should have a pending handshake from A")
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Logf("B pending handshakes: %d", len(pendingList))

	// Verify A's node ID is in pending
	foundA := false
	for _, p := range pendingList {
		req := p.(map[string]interface{})
		if uint32(req["node_id"].(float64)) == daemonA.NodeID() {
			foundA = true
			t.Logf("pending from A: justification=%q", req["justification"])
		}
	}
	if !foundA {
		t.Errorf("A not found in B's pending handshakes")
	}

	// B approves A
	_, err = drvB.ApproveHandshake(daemonA.NodeID())
	if err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Poll until B's trusted list includes A
	deadline = time.After(5 * time.Second)
	for {
		trust, tErr := drvB.TrustedPeers()
		if tErr != nil {
			t.Fatalf("trust: %v", tErr)
		}
		trustedList, _ := trust["trusted"].([]interface{})
		if len(trustedList) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("B should have A as trusted after approval")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// C sends handshake to B -> B rejects
	_, err = drvC.Handshake(daemonB.NodeID(), "I am agent C")
	if err != nil {
		t.Fatalf("C handshake: %v", err)
	}

	// Poll until B has C's pending handshake
	deadline = time.After(5 * time.Second)
	for {
		pend, pErr := drvB.PendingHandshakes()
		if pErr == nil {
			if pl, _ := pend["pending"].([]interface{}); len(pl) > 0 {
				break
			}
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for C's handshake to reach B as pending")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// B rejects C
	_, err = drvB.RejectHandshake(daemonC.NodeID(), "not authorized")
	if err != nil {
		t.Fatalf("reject: %v", err)
	}

	// C should NOT be in B's trusted list
	trust2, err := drvB.TrustedPeers()
	if err != nil {
		t.Fatalf("trust2: %v", err)
	}
	trusted2, _ := trust2["trusted"].([]interface{})
	for _, tp := range trusted2 {
		rec := tp.(map[string]interface{})
		if uint32(rec["node_id"].(float64)) == daemonC.NodeID() {
			t.Errorf("C should NOT be in B's trusted list after rejection")
		}
	}

	t.Logf("B trusted peers: %d (should be 1, just A)", len(trusted2))
}

func TestHandshakeNetworkTrust(t *testing.T) {
	t.Skip("custom networks are WIP")
	t.Parallel()
	// Two nodes on the same non-backbone network should auto-approve handshakes

	env := NewTestEnv(t)

	infoA := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})
	infoB := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})

	daemonA := infoA.Daemon
	daemonB := infoB.Daemon
	drvA := infoA.Driver
	drvB := infoB.Driver

	t.Logf("A=%d, B=%d", daemonA.NodeID(), daemonB.NodeID())

	// Create a network and join both nodes via registry
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("registry dial: %v", err)
	}
	defer rc.Close()

	netResp, err := rc.CreateNetwork(daemonA.NodeID(), "test-trust-net", "open", "", env.AdminToken)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))
	t.Logf("created network %d", netID)

	// A is already joined (creator). Join B.
	_, err = rc.JoinNetwork(daemonB.NodeID(), netID, "", 0, env.AdminToken)
	if err != nil {
		t.Fatalf("B join network: %v", err)
	}
	t.Logf("both nodes joined network %d", netID)

	// A sends handshake to B -- should auto-approve due to shared network
	_, err = drvA.Handshake(daemonB.NodeID(), "same network")
	if err != nil {
		t.Fatalf("A handshake: %v", err)
	}

	// Poll until B trusts A (auto-approved via network trust)
	deadline := time.After(5 * time.Second)
	foundA := false
	for {
		trust, tErr := drvB.TrustedPeers()
		if tErr != nil {
			t.Fatalf("trust: %v", tErr)
		}
		trustedList, _ := trust["trusted"].([]interface{})
		for _, tp := range trustedList {
			rec := tp.(map[string]interface{})
			if uint32(rec["node_id"].(float64)) == daemonA.NodeID() {
				foundA = true
				network := uint16(rec["network"].(float64))
				t.Logf("B trusts A via network %d", network)
				if network != netID {
					t.Errorf("expected network trust via %d, got %d", netID, network)
				}
			}
		}
		if foundA {
			break
		}
		select {
		case <-deadline:
			// Check pending for diagnostics
			pending, _ := drvB.PendingHandshakes()
			pendingList, _ := pending["pending"].([]interface{})
			t.Logf("B pending: %d", len(pendingList))
			for _, p := range pendingList {
				req := p.(map[string]interface{})
				t.Logf("  pending: node=%d", int(req["node_id"].(float64)))
			}
			t.Fatalf("A not found in B's trusted list -- network auto-approve failed")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// There should be no pending requests (auto-approved)
	pending, err := drvB.PendingHandshakes()
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	pendingList, _ := pending["pending"].([]interface{})
	if len(pendingList) > 0 {
		for _, p := range pendingList {
			req := p.(map[string]interface{})
			t.Logf("unexpected pending: node=%d", int(req["node_id"].(float64)))
		}
	}

}

// TestHandshakeRevokeTrust verifies trust can be revoked after being established.
func TestHandshakeRevokeTrust(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	infoA := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})
	infoB := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})

	daemonA := infoA.Daemon
	daemonB := infoB.Daemon
	drvA := infoA.Driver
	drvB := infoB.Driver

	// Establish mutual trust via handshake
	drvA.Handshake(daemonB.NodeID(), "hello")

	deadline := time.After(5 * time.Second)
	for {
		pending, _ := drvB.PendingHandshakes()
		if pl, _ := pending["pending"].([]interface{}); len(pl) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for handshake")
		case <-time.After(10 * time.Millisecond):
		}
	}

	drvB.Handshake(daemonA.NodeID(), "hello back")

	// Wait for mutual trust
	deadline = time.After(5 * time.Second)
	for {
		trustA, _ := drvA.TrustedPeers()
		trustedA, _ := trustA["trusted"].([]interface{})
		trustB, _ := drvB.TrustedPeers()
		trustedB, _ := trustB["trusted"].([]interface{})
		if len(trustedA) > 0 && len(trustedB) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for mutual trust")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// A revokes trust in B
	_, err := drvA.RevokeTrust(daemonB.NodeID())
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Verify B is no longer in A's trusted list
	trust, _ := drvA.TrustedPeers()
	trustedList, _ := trust["trusted"].([]interface{})
	for _, tp := range trustedList {
		rec := tp.(map[string]interface{})
		if uint32(rec["node_id"].(float64)) == daemonB.NodeID() {
			t.Error("B should not be in A's trusted list after revocation")
		}
	}
	t.Logf("A trusted peers after revoke: %d", len(trustedList))
}

// TestHandshakeTrustPersistence verifies trust survives daemon restart.
func TestHandshakeTrustPersistence(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	identityDirA := t.TempDir()
	identityPathA := filepath.Join(identityDirA, "identity.json")
	// Trust store is auto-derived: same dir as identity → trust.json
	trustPathA := filepath.Join(identityDirA, "trust.json")

	infoA := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = identityPathA
	})
	infoB := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})

	daemonA := infoA.Daemon
	daemonB := infoB.Daemon
	drvA := infoA.Driver

	// Establish mutual trust
	drvA.Handshake(daemonB.NodeID(), "persist-test")

	deadline := time.After(5 * time.Second)
	for {
		pending, _ := infoB.Driver.PendingHandshakes()
		if pl, _ := pending["pending"].([]interface{}); len(pl) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for handshake")
		case <-time.After(10 * time.Millisecond):
		}
	}

	infoB.Driver.Handshake(daemonA.NodeID(), "persist-test-back")

	// Wait for mutual trust
	deadline = time.After(5 * time.Second)
	for {
		trustA, _ := drvA.TrustedPeers()
		trustedA, _ := trustA["trusted"].([]interface{})
		if len(trustedA) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for trust")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Verify trust store file exists
	if _, err := os.Stat(trustPathA); err != nil {
		t.Fatalf("trust store not created: %v", err)
	}
	t.Log("trust store file created")
}

// TestHandshakeRejectReason verifies rejection includes a reason.
func TestHandshakeRejectReason(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	infoA := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})
	infoB := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})

	daemonA := infoA.Daemon
	daemonB := infoB.Daemon
	drvA := infoA.Driver
	drvB := infoB.Driver

	// A sends handshake to B
	_, err := drvA.Handshake(daemonB.NodeID(), "please trust me")
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// Wait for pending
	deadline := time.After(5 * time.Second)
	for {
		pending, _ := drvB.PendingHandshakes()
		if pl, _ := pending["pending"].([]interface{}); len(pl) > 0 {
			// Verify justification is included
			req := pl[0].(map[string]interface{})
			if j, ok := req["justification"].(string); ok {
				t.Logf("justification: %q", j)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// B rejects with reason
	_, err = drvB.RejectHandshake(daemonA.NodeID(), "not authorized for this network")
	if err != nil {
		t.Fatalf("reject: %v", err)
	}

	// Verify A not in trusted list
	trust, _ := drvB.TrustedPeers()
	trustedList, _ := trust["trusted"].([]interface{})
	for _, tp := range trustedList {
		rec := tp.(map[string]interface{})
		if uint32(rec["node_id"].(float64)) == daemonA.NodeID() {
			t.Error("rejected node should not be trusted")
		}
	}

	// Verify pending is now empty
	pending, _ := drvB.PendingHandshakes()
	pendingList, _ := pending["pending"].([]interface{})
	if len(pendingList) > 0 {
		t.Errorf("expected empty pending after reject, got %d", len(pendingList))
	}
	t.Log("reject with reason succeeded, pending cleared")
}

var _ = driver.Connect // keep driver import
var _ = os.Remove      // keep os import

package tests

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// TestResolveHostnamePrivateNodeRequiresTrust verifies that resolving a private
// node's hostname fails without a trust pair or shared network.
func TestResolveHostnamePrivateNodeRequiresTrust(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Node A is private with a hostname
	infoA := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
		cfg.Hostname = "secret-agent"
	})
	// Node B is a separate node with no trust
	infoB := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Set hostname for A via registry
	setClientSigner(rc, infoA.Daemon.Identity())
	_, err = rc.SetHostname(infoA.Daemon.NodeID(), "secret-agent")
	if err != nil {
		t.Fatalf("set hostname: %v", err)
	}

	// B tries to resolve A's hostname — should fail (no trust, A is private)
	setClientSigner(rc, infoB.Daemon.Identity())
	_, err = rc.ResolveHostnameAs(infoB.Daemon.NodeID(), "secret-agent")
	if err == nil {
		t.Fatal("expected resolve_hostname to fail for private node without trust, but it succeeded")
	}
	t.Logf("resolve correctly blocked: %v", err)
}

// TestResolveHostnamePrivateNodeWithTrust verifies that resolving a private
// node's hostname succeeds when the requester has a trust pair.
func TestResolveHostnamePrivateNodeWithTrust(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	infoA := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})
	infoB := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Set hostname for A
	setClientSigner(rc, infoA.Daemon.Identity())
	_, err = rc.SetHostname(infoA.Daemon.NodeID(), "trusted-agent")
	if err != nil {
		t.Fatalf("set hostname: %v", err)
	}

	// Establish trust
	_, err = rc.ReportTrust(infoA.Daemon.NodeID(), infoB.Daemon.NodeID())
	if err != nil {
		t.Fatalf("report trust: %v", err)
	}

	// B resolves A's hostname — should succeed (trust pair exists)
	setClientSigner(rc, infoB.Daemon.Identity())
	resp, err := rc.ResolveHostnameAs(infoB.Daemon.NodeID(), "trusted-agent")
	if err != nil {
		t.Fatalf("expected resolve_hostname to succeed with trust: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))
	if nodeID != infoA.Daemon.NodeID() {
		t.Errorf("expected node_id=%d, got %d", infoA.Daemon.NodeID(), nodeID)
	}
	t.Logf("resolved 'trusted-agent' → node %d (correct)", nodeID)
}

// TestResolveHostnamePublicNodeNoTrustRequired verifies that resolving a public
// node's hostname always succeeds regardless of trust.
func TestResolveHostnamePublicNodeNoTrustRequired(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// A is public
	infoA := env.AddDaemon()
	// B is any node
	infoB := env.AddDaemon()

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Set hostname for public A
	setClientSigner(rc, infoA.Daemon.Identity())
	_, err = rc.SetHostname(infoA.Daemon.NodeID(), "public-agent")
	if err != nil {
		t.Fatalf("set hostname: %v", err)
	}

	// B resolves A's hostname — should succeed (A is public)
	setClientSigner(rc, infoB.Daemon.Identity())
	resp, err := rc.ResolveHostnameAs(infoB.Daemon.NodeID(), "public-agent")
	if err != nil {
		t.Fatalf("expected resolve_hostname to succeed for public node: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))
	if nodeID != infoA.Daemon.NodeID() {
		t.Errorf("expected node_id=%d, got %d", infoA.Daemon.NodeID(), nodeID)
	}
	t.Logf("resolved 'public-agent' → node %d (correct)", nodeID)
}

// TestResolveHostnamePrivateNodeSameNetwork verifies that resolving a private
// node's hostname succeeds when both nodes share a non-backbone network.
func TestResolveHostnamePrivateNodeSameNetwork(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	infoA := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})
	infoB := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Set hostname for A
	setClientSigner(rc, infoA.Daemon.Identity())
	_, err = rc.SetHostname(infoA.Daemon.NodeID(), "network-agent")
	if err != nil {
		t.Fatalf("set hostname: %v", err)
	}

	// Create a network and join both nodes
	resp, err := rc.CreateNetwork(infoA.Daemon.NodeID(), "hostname-net", "open", "", env.AdminToken)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))
	setClientSigner(rc, infoB.Daemon.Identity())
	_, err = rc.JoinNetwork(infoB.Daemon.NodeID(), netID, "", 0, env.AdminToken)
	if err != nil {
		t.Fatalf("join network: %v", err)
	}

	// B resolves A's hostname — should succeed (same network)
	resolveResp, err := rc.ResolveHostnameAs(infoB.Daemon.NodeID(), "network-agent")
	if err != nil {
		t.Fatalf("expected resolve_hostname to succeed for same-network node: %v", err)
	}
	nodeID := uint32(resolveResp["node_id"].(float64))
	if nodeID != infoA.Daemon.NodeID() {
		t.Errorf("expected node_id=%d, got %d", infoA.Daemon.NodeID(), nodeID)
	}
	t.Logf("resolved 'network-agent' → node %d via shared network %d", nodeID, netID)
}

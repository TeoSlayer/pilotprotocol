package tests

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// TestPrivateNodeResolveBlocked verifies that a private node cannot be resolved
// by another node without mutual trust or a shared non-backbone network.
func TestPrivateNodeResolveBlocked(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Create two private nodes (override the test default of public)
	infoA := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})
	infoB := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})

	nodeA := infoA.Daemon.NodeID()
	nodeB := infoB.Daemon.NodeID()

	// Try to resolve A from B — should fail (both private, no trust)
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	setClientSigner(rc, infoB.Daemon.Identity())
	_, err = rc.Resolve(nodeA, nodeB)
	if err == nil {
		t.Fatal("expected resolve to fail for private node, but it succeeded")
	}
	t.Logf("resolve correctly blocked: %v", err)
}

// TestPublicNodeResolveAllowed verifies that a public node can be resolved
// by any registered node.
func TestPublicNodeResolveAllowed(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Node A is public (test default)
	infoA := env.AddDaemon()
	// Node B is private
	infoB := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})

	nodeA := infoA.Daemon.NodeID()
	nodeB := infoB.Daemon.NodeID()

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Resolve public A from private B — should succeed
	setClientSigner(rc, infoB.Daemon.Identity())
	resp, err := rc.Resolve(nodeA, nodeB)
	if err != nil {
		t.Fatalf("resolve public node failed: %v", err)
	}
	realAddr, _ := resp["real_addr"].(string)
	if realAddr == "" {
		t.Fatal("expected real_addr in resolve response for public node")
	}
	t.Logf("public node resolved: real_addr=%s", realAddr)

	// Resolve private B from A — should fail (no trust)
	setClientSigner(rc, infoA.Daemon.Identity())
	_, err = rc.Resolve(nodeB, nodeA)
	if err == nil {
		t.Fatal("expected resolve to fail for private node B, but it succeeded")
	}
	t.Logf("private node correctly blocked: %v", err)
}

// TestTrustPairEnablesResolve verifies that after establishing mutual trust,
// a private node can be resolved.
func TestTrustPairEnablesResolve(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Both nodes private
	infoA := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})
	infoB := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})

	nodeA := infoA.Daemon.NodeID()
	nodeB := infoB.Daemon.NodeID()

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Before trust: resolve should fail
	setClientSigner(rc, infoB.Daemon.Identity())
	_, err = rc.Resolve(nodeA, nodeB)
	if err == nil {
		t.Fatal("expected resolve to fail before trust")
	}

	// Report mutual trust
	setClientSigner(rc, infoA.Daemon.Identity())
	_, err = rc.ReportTrust(nodeA, nodeB)
	if err != nil {
		t.Fatalf("report trust: %v", err)
	}

	// After trust: resolve should succeed both ways
	setClientSigner(rc, infoB.Daemon.Identity())
	resp, err := rc.Resolve(nodeA, nodeB)
	if err != nil {
		t.Fatalf("resolve A from B after trust: %v", err)
	}
	if resp["real_addr"] == nil {
		t.Fatal("expected real_addr after trust")
	}
	t.Logf("A resolved by B after trust: %s", resp["real_addr"])

	setClientSigner(rc, infoA.Daemon.Identity())
	resp, err = rc.Resolve(nodeB, nodeA)
	if err != nil {
		t.Fatalf("resolve B from A after trust: %v", err)
	}
	t.Logf("B resolved by A after trust: %s", resp["real_addr"])
}

// TestRevokeTrustBlocksResolve verifies that after revoking trust,
// a private node can no longer be resolved.
func TestRevokeTrustBlocksResolve(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Both nodes private
	infoA := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})
	infoB := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})

	nodeA := infoA.Daemon.NodeID()
	nodeB := infoB.Daemon.NodeID()

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Establish trust
	setClientSigner(rc, infoA.Daemon.Identity())
	_, err = rc.ReportTrust(nodeA, nodeB)
	if err != nil {
		t.Fatalf("report trust: %v", err)
	}

	// Resolve should work
	setClientSigner(rc, infoB.Daemon.Identity())
	_, err = rc.Resolve(nodeA, nodeB)
	if err != nil {
		t.Fatalf("resolve after trust: %v", err)
	}
	t.Log("resolve succeeds with trust (correct)")

	// Revoke trust (A revokes B)
	setClientSigner(rc, infoA.Daemon.Identity())
	_, err = rc.RevokeTrust(nodeA, nodeB)
	if err != nil {
		t.Fatalf("revoke trust: %v", err)
	}
	t.Log("trust revoked")

	// Resolve should now fail both ways
	setClientSigner(rc, infoB.Daemon.Identity())
	_, err = rc.Resolve(nodeA, nodeB)
	if err == nil {
		t.Fatal("expected resolve A from B to fail after revocation, but it succeeded")
	}
	t.Logf("resolve A from B correctly blocked: %v", err)

	setClientSigner(rc, infoA.Daemon.Identity())
	_, err = rc.Resolve(nodeB, nodeA)
	if err == nil {
		t.Fatal("expected resolve B from A to fail after revocation, but it succeeded")
	}
	t.Logf("resolve B from A correctly blocked: %v", err)
}

// TestHandshakeRelayForPrivateNode verifies that handshake requests can be
// relayed through the registry for private nodes.
func TestHandshakeRelayForPrivateNode(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Both nodes private
	infoA := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})
	infoB := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})

	nodeA := infoA.Daemon.NodeID()
	nodeB := infoB.Daemon.NodeID()

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Relay a handshake request from A to B (M12: signed)
	challenge := fmt.Sprintf("handshake:%d:%d", nodeA, nodeB)
	sigA := base64.StdEncoding.EncodeToString(infoA.Daemon.Identity().Sign([]byte(challenge)))
	_, err = rc.RequestHandshake(nodeA, nodeB, "I want to collaborate", sigA)
	if err != nil {
		t.Fatalf("relay handshake: %v", err)
	}

	// Poll B's inbox — sign as node B (H3 auth required)
	rc.SetSigner(func(challenge string) string {
		return base64.StdEncoding.EncodeToString(infoB.Daemon.Identity().Sign([]byte(challenge)))
	})
	resp, err := rc.PollHandshakes(nodeB)
	if err != nil {
		t.Fatalf("poll handshakes: %v", err)
	}

	requests, ok := resp["requests"].([]interface{})
	if !ok || len(requests) == 0 {
		t.Fatal("expected pending handshake request")
	}

	req := requests[0].(map[string]interface{})
	fromID := uint32(req["from_node_id"].(float64))
	justification, _ := req["justification"].(string)
	if fromID != nodeA {
		t.Errorf("from_node_id: got %d, want %d", fromID, nodeA)
	}
	if justification != "I want to collaborate" {
		t.Errorf("justification: got %q, want %q", justification, "I want to collaborate")
	}
	t.Logf("relayed handshake received: from=%d justification=%q", fromID, justification)

	// B approves via registry (M12: signed)
	respondChallenge := fmt.Sprintf("respond:%d:%d", nodeB, nodeA)
	sigB := base64.StdEncoding.EncodeToString(infoB.Daemon.Identity().Sign([]byte(respondChallenge)))
	_, err = rc.RespondHandshake(nodeB, nodeA, true, sigB)
	if err != nil {
		t.Fatalf("respond handshake: %v", err)
	}

	// Now resolve should work both ways
	setClientSigner(rc, infoB.Daemon.Identity())
	_, err = rc.Resolve(nodeA, nodeB)
	if err != nil {
		t.Fatalf("resolve A from B after approval: %v", err)
	}
	setClientSigner(rc, infoA.Daemon.Identity())
	_, err = rc.Resolve(nodeB, nodeA)
	if err != nil {
		t.Fatalf("resolve B from A after approval: %v", err)
	}
	t.Log("both nodes resolvable after handshake approval")
}

// TestBackboneListNodesBlocked verifies that listing backbone (network 0) nodes
// is rejected to prevent node enumeration.
func TestBackboneListNodesBlocked(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	env.AddDaemon() // at least one node

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	_, err = rc.ListNodes(0)
	if err == nil {
		t.Fatal("expected backbone list_nodes to be rejected, but it succeeded")
	}
	t.Logf("backbone listing correctly blocked: %v", err)
}

// TestLookupHidesRealAddr verifies that lookup does not expose real_addr for private nodes.
func TestLookupHidesRealAddr(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Private node
	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})
	nodeID := info.Daemon.NodeID()

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	resp, err := rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	if _, hasRealAddr := resp["real_addr"]; hasRealAddr {
		t.Fatal("lookup should NOT include real_addr for private node")
	}
	t.Logf("private node lookup: no real_addr exposed (correct)")

	if pub, ok := resp["public"].(bool); ok && pub {
		t.Fatal("expected public=false")
	}
}

// TestHTTPPublicToPublic verifies that HTTP-over-Pilot works between two public nodes.
func TestHTTPPublicToPublic(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	server := env.AddDaemon() // public (default)
	client := env.AddDaemon() // public (default)

	httpOverPilotHelper(t, server, client, "public→public")
}

// TestHTTPPublicToPrivate verifies that a private client can reach a public server over HTTP.
func TestHTTPPublicToPrivate(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	server := env.AddDaemon() // public
	client := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})

	httpOverPilotHelper(t, server, client, "public-server→private-client")
}

// TestHTTPPrivateWithTrust verifies HTTP between two private nodes after trust is established.
func TestHTTPPrivateWithTrust(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	server := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})
	client := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})

	// Establish trust via registry
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()
	setClientSigner(rc, server.Daemon.Identity())

	_, err = rc.ReportTrust(server.Daemon.NodeID(), client.Daemon.NodeID())
	if err != nil {
		t.Fatalf("report trust: %v", err)
	}
	t.Log("trust established between private nodes")

	httpOverPilotHelper(t, server, client, "private+trust")
}

// TestHTTPPrivateWithoutTrustFails verifies that a private server cannot be
// reached over HTTP without trust.
func TestHTTPPrivateWithoutTrustFails(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	server := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})
	client := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})

	// Start HTTP server on the private node
	ln, err := server.Driver.Listen(80)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "should not reach")
	})
	go http.Serve(ln, mux)

	// Client dial should fail because no tunnel can be established (resolve blocked)
	_, err = client.Driver.DialAddr(server.Daemon.Addr(), 80)
	if err == nil {
		t.Fatal("expected dial to fail between untrusted private nodes, but it succeeded")
	}
	t.Logf("dial correctly failed: %v", err)
}

// TestHTTPAfterTrustRevoke verifies that HTTP stops working after trust is revoked.
func TestHTTPAfterTrustRevoke(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	server := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})
	client := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()
	setClientSigner(rc, server.Daemon.Identity())

	// Step 1: Establish trust and verify HTTP works
	_, err = rc.ReportTrust(server.Daemon.NodeID(), client.Daemon.NodeID())
	if err != nil {
		t.Fatalf("report trust: %v", err)
	}

	httpOverPilotHelper(t, server, client, "before-revoke")

	// Step 2: Revoke trust
	_, err = rc.RevokeTrust(server.Daemon.NodeID(), client.Daemon.NodeID())
	if err != nil {
		t.Fatalf("revoke trust: %v", err)
	}
	t.Log("trust revoked")

	// Step 3: Verify resolve is now blocked
	setClientSigner(rc, client.Daemon.Identity())
	_, err = rc.Resolve(server.Daemon.NodeID(), client.Daemon.NodeID())
	if err == nil {
		t.Fatal("expected resolve to fail after revocation")
	}
	t.Logf("resolve correctly blocked after revoke: %v", err)
}

// TestTrustRevokeAndReestablish verifies the full lifecycle:
// establish trust → use → revoke → verify blocked → re-establish → use again.
func TestTrustRevokeAndReestablish(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})
	b := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})

	nodeA := a.Daemon.NodeID()
	nodeB := b.Daemon.NodeID()

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()
	setClientSigner(rc, a.Daemon.Identity())

	// Phase 1: Establish trust
	_, err = rc.ReportTrust(nodeA, nodeB)
	if err != nil {
		t.Fatalf("report trust: %v", err)
	}
	setClientSigner(rc, b.Daemon.Identity())
	_, err = rc.Resolve(nodeA, nodeB)
	if err != nil {
		t.Fatalf("resolve after trust: %v", err)
	}
	t.Log("phase 1: trust established, resolve works")

	// Phase 2: Revoke
	setClientSigner(rc, a.Daemon.Identity())
	_, err = rc.RevokeTrust(nodeA, nodeB)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	setClientSigner(rc, b.Daemon.Identity())
	_, err = rc.Resolve(nodeA, nodeB)
	if err == nil {
		t.Fatal("phase 2: expected resolve to fail after revoke")
	}
	t.Log("phase 2: trust revoked, resolve blocked")

	// Phase 3: Re-establish trust
	setClientSigner(rc, a.Daemon.Identity())
	_, err = rc.ReportTrust(nodeA, nodeB)
	if err != nil {
		t.Fatalf("re-report trust: %v", err)
	}
	setClientSigner(rc, b.Daemon.Identity())
	_, err = rc.Resolve(nodeA, nodeB)
	if err != nil {
		t.Fatalf("resolve after re-trust: %v", err)
	}
	setClientSigner(rc, a.Daemon.Identity())
	_, err = rc.Resolve(nodeB, nodeA)
	if err != nil {
		t.Fatalf("resolve B→A after re-trust: %v", err)
	}
	t.Log("phase 3: trust re-established, resolve works both ways")
}

// httpOverPilotHelper is a helper that starts an HTTP server on the server daemon,
// connects from the client daemon, makes an HTTP request, and verifies the response.
func httpOverPilotHelper(t *testing.T, server, client *DaemonInfo, label string) {
	t.Helper()

	ln, err := server.Driver.Listen(80)
	if err != nil {
		t.Fatalf("[%s] listen: %v", label, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "hello from %s", label)
	})
	go http.Serve(ln, mux)

	conn, err := client.Driver.DialAddr(server.Daemon.Addr(), 80)
	if err != nil {
		t.Fatalf("[%s] dial: %v", label, err)
	}
	defer conn.Close()

	req := "GET /test HTTP/1.0\r\nHost: test\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("[%s] write: %v", label, err)
	}

	var resp []byte
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			resp = append(resp, buf[:n]...)
		}
		if err == io.EOF || err != nil {
			break
		}
	}

	body := string(resp)
	expected := fmt.Sprintf("hello from %s", label)
	if len(resp) == 0 {
		t.Fatalf("[%s] got empty HTTP response", label)
	}
	if !contains(body, expected) {
		t.Fatalf("[%s] HTTP response missing expected body %q:\n%s", label, expected, body)
	}
	t.Logf("[%s] HTTP response OK (%d bytes)", label, len(resp))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

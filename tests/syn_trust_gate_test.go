package tests

import (
	"net"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// localUDPAddr converts a daemon's tunnel address to a localhost UDPAddr
// (wildcard addresses like [::] need to be resolved to 127.0.0.1 for local testing).
func localUDPAddr(d *daemon.Daemon) *net.UDPAddr {
	addr := d.TunnelAddr().(*net.UDPAddr)
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: addr.Port}
}

// TestSYNFromUntrustedNodeRejected verifies that two daemons without trust
// cannot establish a connection — the SYN should be rejected by the trust gate.
func TestSYNFromUntrustedNodeRejected(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Both nodes private, no trust established
	server := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})
	client := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})

	// Pre-populate client's tunnel with server's address to bypass resolve.
	// This simulates the scenario where an attacker already knows the endpoint
	// (e.g., from a cached previous session). The trust gate is defense-in-depth.
	client.Daemon.AddTunnelPeer(server.Daemon.NodeID(), localUDPAddr(server.Daemon))

	// Server listens on port 7 (echo) by default, so dial should fail via trust gate.
	// Use short timeout — we expect rejection, not a 30s dial timeout.
	_, err := client.Driver.DialAddrTimeout(server.Daemon.Addr(), 7, 2*time.Second)
	if err == nil {
		t.Fatal("expected dial to fail between untrusted nodes, but it succeeded")
	}
	t.Logf("dial correctly rejected: %v", err)
}

// TestSYNFromTrustedNodeAccepted verifies that after establishing mutual trust
// via handshake, two daemons can connect.
func TestSYNFromTrustedNodeAccepted(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	server := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
		cfg.Encrypt = true

		cfg.KeepaliveInterval = 500 * time.Millisecond // fast relay polling
	})
	client := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
		cfg.Encrypt = true

		cfg.KeepaliveInterval = 500 * time.Millisecond // fast relay polling
	})

	// Establish mutual trust via handshake (relayed via registry for private nodes)
	_, err := client.Driver.Handshake(server.Daemon.NodeID(), "trust me")
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	// Wait for pending (relayed handshakes need heartbeat poll)
	deadline := time.After(10 * time.Second)
	for {
		pending, _ := server.Driver.PendingHandshakes()
		if pl, _ := pending["pending"].([]interface{}); len(pl) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for handshake")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Server reciprocates → mutual auto-approve
	_, err = server.Driver.Handshake(client.Daemon.NodeID(), "trust back")
	if err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	// Wait for mutual trust
	deadline = time.After(10 * time.Second)
	for {
		trustA, _ := client.Driver.TrustedPeers()
		trustedA, _ := trustA["trusted"].([]interface{})
		trustB, _ := server.Driver.TrustedPeers()
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

	// Pre-populate tunnel peers so dial bypasses resolve
	client.Daemon.AddTunnelPeer(server.Daemon.NodeID(), localUDPAddr(server.Daemon))
	server.Daemon.AddTunnelPeer(client.Daemon.NodeID(), localUDPAddr(client.Daemon))

	// Now dial should succeed — trust gate allows trusted peers
	conn, err := client.Driver.DialAddr(server.Daemon.Addr(), 7)
	if err != nil {
		t.Fatalf("expected dial to succeed between trusted nodes: %v", err)
	}
	conn.Close()
	t.Log("dial succeeded between trusted nodes")
}

// TestSYNFromSameNetworkAccepted verifies that two daemons in the same
// non-backbone network can connect without explicit trust pairs.
func TestSYNFromSameNetworkAccepted(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	server := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})
	client := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})

	// Join both to the same custom network via registry
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	resp, err := rc.CreateNetwork(server.Daemon.NodeID(), "syn-net-test", "open", "", env.AdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	_, err = rc.JoinNetwork(client.Daemon.NodeID(), netID, "", 0, env.AdminToken)
	if err != nil {
		t.Fatalf("join network: %v", err)
	}
	t.Logf("both nodes joined network %d", netID)

	// Pre-populate tunnel peers so dial bypasses resolve
	client.Daemon.AddTunnelPeer(server.Daemon.NodeID(), localUDPAddr(server.Daemon))
	server.Daemon.AddTunnelPeer(client.Daemon.NodeID(), localUDPAddr(client.Daemon))

	// Dial should succeed — same network allows SYN
	conn, err := client.Driver.DialAddr(server.Daemon.Addr(), 7)
	if err != nil {
		t.Fatalf("expected dial to succeed for same-network nodes: %v", err)
	}
	conn.Close()
	t.Log("dial succeeded between same-network nodes")
}

// TestSYNRejectionWebhook verifies that a syn.rejected webhook event is emitted
// when an untrusted node attempts to connect.
func TestSYNRejectionWebhook(t *testing.T) {
	t.Parallel()
	collector := newWebhookCollector()
	defer collector.Close()

	env := NewTestEnv(t)

	server := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
		cfg.WebhookURL = collector.URL()
	})
	client := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})

	// Pre-populate client's tunnel with server's address to bypass resolve
	client.Daemon.AddTunnelPeer(server.Daemon.NodeID(), localUDPAddr(server.Daemon))

	// Attempt connection — should be rejected by trust gate.
	// Use short timeout — we expect rejection, not a 30s dial timeout.
	_, _ = client.Driver.DialAddrTimeout(server.Daemon.Addr(), 7, 2*time.Second)

	// Wait for syn.rejected webhook event
	ev, ok := collector.WaitFor("syn.rejected", 3*time.Second)
	if !ok {
		t.Fatal("expected syn.rejected webhook event, but none received")
	}
	data, _ := ev.Data.(map[string]interface{})
	t.Logf("syn.rejected: src_node=%v", data["src_node_id"])
}

// TestPublicNodeAcceptsUntrustedSYN verifies that public nodes skip the trust
// gate entirely — any node can connect without trust or shared network.
func TestPublicNodeAcceptsUntrustedSYN(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	server := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = true // public node — trust gate should be skipped
	})
	client := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false // private, no trust, no shared network
	})

	client.Daemon.AddTunnelPeer(server.Daemon.NodeID(), localUDPAddr(server.Daemon))
	server.Daemon.AddTunnelPeer(client.Daemon.NodeID(), localUDPAddr(client.Daemon))

	conn, err := client.Driver.DialAddr(server.Daemon.Addr(), 7)
	if err != nil {
		t.Fatalf("expected dial to public node to succeed without trust: %v", err)
	}
	conn.Close()
	t.Log("dial to public node succeeded without trust")
}

// TestDatagramRejectedFromUntrustedNode verifies that private nodes drop
// datagrams from untrusted sources (same trust gate as SYN).
func TestDatagramRejectedFromUntrustedNode(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	server := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})
	client := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})

	// Pre-populate tunnel peers
	client.Daemon.AddTunnelPeer(server.Daemon.NodeID(), localUDPAddr(server.Daemon))
	server.Daemon.AddTunnelPeer(client.Daemon.NodeID(), localUDPAddr(client.Daemon))

	// Start listening for datagrams on server
	received := make(chan struct{}, 1)
	go func() {
		dg, err := server.Driver.RecvFrom()
		if err == nil && dg != nil {
			received <- struct{}{}
		}
	}()

	// Send datagram from untrusted client — should be silently dropped
	_ = client.Driver.SendTo(server.Daemon.Addr(), 5000, []byte("untrusted datagram"))

	select {
	case <-received:
		t.Fatal("datagram from untrusted node should have been dropped, but was delivered")
	case <-time.After(500 * time.Millisecond):
		t.Log("correctly: datagram from untrusted node was dropped")
	}
}

// TestDatagramAllowedFromSameNetwork verifies that datagrams from same-network
// peers are delivered normally (trust via shared network membership).
func TestDatagramAllowedFromSameNetwork(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	server := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})
	client := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})

	// Join both to the same custom network via registry
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	resp, err := rc.CreateNetwork(server.Daemon.NodeID(), "dg-trust-net", "open", "", env.AdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	if _, err := rc.JoinNetwork(client.Daemon.NodeID(), netID, "", 0, env.AdminToken); err != nil {
		t.Fatalf("join network: %v", err)
	}

	// Pre-populate tunnel peers
	client.Daemon.AddTunnelPeer(server.Daemon.NodeID(), localUDPAddr(server.Daemon))
	server.Daemon.AddTunnelPeer(client.Daemon.NodeID(), localUDPAddr(client.Daemon))

	// Start listening for datagrams on server
	received := make(chan string, 1)
	go func() {
		dg, err := server.Driver.RecvFrom()
		if err == nil && dg != nil {
			received <- string(dg.Data)
		}
	}()

	// Send datagram from trusted client — should be delivered
	if err := client.Driver.SendTo(server.Daemon.Addr(), 5000, []byte("trusted datagram")); err != nil {
		t.Fatalf("sendto: %v", err)
	}

	select {
	case msg := <-received:
		if msg != "trusted datagram" {
			t.Errorf("expected %q, got %q", "trusted datagram", msg)
		}
		t.Log("datagram from same-network node delivered correctly")
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for datagram from same-network node")
	}
}

// TestDatagramRejectionWebhook verifies that a datagram.rejected webhook event
// is emitted when an untrusted node sends a datagram to a private node.
func TestDatagramRejectionWebhook(t *testing.T) {
	t.Parallel()
	collector := newWebhookCollector()
	defer collector.Close()

	env := NewTestEnv(t)

	server := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
		cfg.WebhookURL = collector.URL()
	})
	client := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Public = false
	})

	client.Daemon.AddTunnelPeer(server.Daemon.NodeID(), localUDPAddr(server.Daemon))

	// Send datagram — should be rejected
	_ = client.Driver.SendTo(server.Daemon.Addr(), 5000, []byte("should be rejected"))

	ev, ok := collector.WaitFor("datagram.rejected", 3*time.Second)
	if !ok {
		t.Fatal("expected datagram.rejected webhook event, but none received")
	}
	data, _ := ev.Data.(map[string]interface{})
	t.Logf("datagram.rejected: src_node=%v", data["src_node_id"])
}

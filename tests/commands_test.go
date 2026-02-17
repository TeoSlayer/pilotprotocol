package tests

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	icrypto "github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// ======================
// INFO / PEERS / CONNECTIONS / DISCONNECT
// ======================

func TestCmdInfo(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()

	info, err := a.Driver.Info()
	if err != nil {
		t.Fatalf("info: %v", err)
	}

	// Verify essential fields are present
	for _, key := range []string{"node_id", "address", "uptime_secs", "encrypt", "bytes_sent", "bytes_recv", "pkts_sent", "pkts_recv"} {
		if _, ok := info[key]; !ok {
			t.Errorf("missing field: %s", key)
		}
	}

	nodeID := uint32(info["node_id"].(float64))
	if nodeID == 0 {
		t.Error("node_id should be nonzero")
	}

	addr, ok := info["address"].(string)
	if !ok || addr == "" {
		t.Error("address should be a non-empty string")
	}

	t.Logf("info: node_id=%d address=%s", nodeID, addr)
}

func TestCmdPeers(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	// Exchange traffic to establish peer relationship
	ln, err := b.Driver.Listen(8100)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	conn, err := a.Driver.DialAddr(b.Daemon.Addr(), 8100)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Write([]byte("hello"))
	conn.Close()

	// Poll until peer appears in peer_list
	deadline := time.After(5 * time.Second)
	for {
		info, err := a.Driver.Info()
		if err != nil {
			t.Fatalf("info: %v", err)
		}
		peers, _ := info["peer_list"].([]interface{})
		for _, p := range peers {
			pm, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			if uint32(pm["node_id"].(float64)) == b.Daemon.NodeID() {
				t.Logf("peer %d found in peer_list", b.Daemon.NodeID())
				return
			}
		}
		select {
		case <-deadline:
			t.Fatalf("peer %d not found in peer_list", b.Daemon.NodeID())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func TestCmdConnectionsDisconnect(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	ln, err := b.Driver.Listen(8101)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Accept connections in background (read and discard)
	go func() {
		for {
			sc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer sc.Close()
				buf := make([]byte, 256)
				for {
					if _, err := sc.Read(buf); err != nil {
						return
					}
				}
			}()
		}
	}()

	conn, err := a.Driver.DialAddr(b.Daemon.Addr(), 8101)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	conn.Write([]byte("data"))

	// Poll until connection appears in conn_list
	deadline := time.After(5 * time.Second)
	for {
		info, err := a.Driver.Info()
		if err != nil {
			t.Fatalf("info: %v", err)
		}
		connList, _ := info["conn_list"].([]interface{})
		if len(connList) > 0 {
			firstConn := connList[0].(map[string]interface{})
			connID := uint32(firstConn["id"].(float64))
			t.Logf("connection %d appeared in conn_list", connID)
			conn.Close()
			return
		}
		select {
		case <-deadline:
			t.Fatal("timeout waiting for connection to appear in conn_list")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// ======================
// REGISTRY: LOOKUP / SET-PUBLIC / SET-PRIVATE / SET-HOSTNAME
// ======================

func TestCmdLookup(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	resp, err := rc.Lookup(a.Daemon.NodeID())
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	if resp["type"] != "lookup_ok" {
		t.Errorf("expected type lookup_ok, got %v", resp["type"])
	}

	nodeID := uint32(resp["node_id"].(float64))
	if nodeID != a.Daemon.NodeID() {
		t.Errorf("node_id mismatch: got %d want %d", nodeID, a.Daemon.NodeID())
	}

	t.Logf("lookup: node_id=%d address=%v", nodeID, resp["address"])
}

func TestCmdLookupNotFound(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	_, err = rc.Lookup(99999)
	if err == nil {
		t.Fatal("expected error for nonexistent node")
	}
}

func TestCmdSetVisibility(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()
	setClientSigner(rc, a.Daemon.Identity())

	// Set private
	resp, err := rc.SetVisibility(a.Daemon.NodeID(), false)
	if err != nil {
		t.Fatalf("set-private: %v", err)
	}
	if resp["visibility"] != "private" {
		t.Errorf("expected private, got %v", resp["visibility"])
	}

	// Set public
	resp, err = rc.SetVisibility(a.Daemon.NodeID(), true)
	if err != nil {
		t.Fatalf("set-public: %v", err)
	}
	if resp["visibility"] != "public" {
		t.Errorf("expected public, got %v", resp["visibility"])
	}
}

func TestCmdSetHostname(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()
	setClientSigner(rc, a.Daemon.Identity())

	resp, err := rc.SetHostname(a.Daemon.NodeID(), "test-agent")
	if err != nil {
		t.Fatalf("set-hostname: %v", err)
	}
	if resp["type"] != "set_hostname_ok" {
		t.Errorf("expected set_hostname_ok, got %v", resp["type"])
	}

	// Verify via find (driver API)
	result, err := a.Driver.ResolveHostname("test-agent")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	resolvedNodeID := uint32(result["node_id"].(float64))
	if resolvedNodeID != a.Daemon.NodeID() {
		t.Errorf("resolved node_id: got %d want %d", resolvedNodeID, a.Daemon.NodeID())
	}
}

func TestCmdSetHostnameInvalid(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()
	setClientSigner(rc, a.Daemon.Identity())

	_, err = rc.SetHostname(a.Daemon.NodeID(), "INVALID HOSTNAME!")
	if err == nil {
		t.Fatal("expected error for invalid hostname")
	}
}

func TestCmdRotateKey(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	nodeID := a.Daemon.NodeID()
	identity := a.Daemon.Identity()
	if identity == nil {
		t.Fatal("daemon should have an identity")
	}

	// Sign rotation challenge with current key
	challenge := fmt.Sprintf("rotate:%d", nodeID)
	sig := identity.Sign([]byte(challenge))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// Generate new keypair for the test
	newIdentity, err := newTestIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	newPubKeyB64 := icrypto.EncodePublicKey(newIdentity.PublicKey)

	resp, err := rc.RotateKey(nodeID, sigB64, newPubKeyB64)
	if err != nil {
		t.Fatalf("rotate-key: %v", err)
	}
	if resp["type"] != "rotate_key_ok" {
		t.Errorf("expected rotate_key_ok, got %v", resp["type"])
	}
	if resp["public_key"] != newPubKeyB64 {
		t.Error("public_key not updated")
	}
	t.Logf("key rotated for node %d", nodeID)
}

func TestCmdRotateKeyBadSignature(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	newIdentity, err := newTestIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	newPubKeyB64 := icrypto.EncodePublicKey(newIdentity.PublicKey)

	_, err = rc.RotateKey(a.Daemon.NodeID(), "badsignature", newPubKeyB64)
	if err == nil {
		t.Fatal("expected error for bad signature")
	}
}

// ======================
// DISCOVERY: FIND / RESOLVE HOSTNAME
// ======================

func TestCmdFindNotFound(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()

	_, err := a.Driver.ResolveHostname("nonexistent-host")
	if err == nil {
		t.Fatal("expected error for nonexistent hostname")
	}
}

func TestCmdFindRegisteredHostname(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Register daemon with hostname
	a := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Hostname = "agent-alpha"
	})

	result, err := a.Driver.ResolveHostname("agent-alpha")
	if err != nil {
		t.Fatalf("find: %v", err)
	}

	resolvedNodeID := uint32(result["node_id"].(float64))
	if resolvedNodeID != a.Daemon.NodeID() {
		t.Errorf("resolved node_id: got %d want %d", resolvedNodeID, a.Daemon.NodeID())
	}
}

// ======================
// COMMUNICATION: CONNECT / SEND / RECV
// ======================

func TestCmdConnectSendRecv(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	// B listens
	ln, err := b.Driver.Listen(8200)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Server goroutine echoes back
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		conn.Write(buf[:n])
	}()

	// A connects and sends
	conn, err := a.Driver.DialAddr(b.Daemon.Addr(), 8200)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello from A")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf[:n]) != "hello from A" {
		t.Errorf("echo mismatch: got %q", string(buf[:n]))
	}
}

// ======================
// PING / ECHO
// ======================

func TestCmdPing(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	// Disable built-in echo so test can bind port 7 via driver
	disableEcho := func(cfg *daemon.Config) { cfg.DisableEcho = true }
	a := env.AddDaemon(disableEcho)
	b := env.AddDaemon(disableEcho)

	// Start echo service on B (port 7)
	ln, err := b.Driver.Listen(protocol.PortEcho)
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 65536)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					conn.Write(buf[:n])
				}
			}()
		}
	}()

	// Ping from A to B
	conn, err := a.Driver.DialAddr(b.Daemon.Addr(), protocol.PortEcho)
	if err != nil {
		t.Fatalf("dial echo: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	_, err = conn.Write([]byte("ping"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	rtt := time.Since(start)

	if string(buf[:n]) != "ping" {
		t.Errorf("echo mismatch: got %q", string(buf[:n]))
	}
	t.Logf("ping RTT: %v", rtt)
}

// ======================
// TRUST: HANDSHAKE / APPROVE / REJECT / PENDING / TRUST / UNTRUST
// ======================

func TestCmdHandshakePendingApproveReject(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Encrypt = true
		cfg.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})
	b := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Encrypt = true
		cfg.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})
	c := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Encrypt = true
		cfg.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})

	// B sends handshake to A
	_, err := b.Driver.Handshake(a.Daemon.NodeID(), "I am agent B")
	if err != nil {
		t.Fatalf("handshake B→A: %v", err)
	}

	// A should see pending
	deadline := time.After(5 * time.Second)
	for {
		pending, err := a.Driver.PendingHandshakes()
		if err != nil {
			t.Fatalf("pending: %v", err)
		}
		list, _ := pending["pending"].([]interface{})
		if len(list) > 0 {
			p := list[0].(map[string]interface{})
			peerID := uint32(p["node_id"].(float64))
			if peerID == b.Daemon.NodeID() {
				t.Logf("pending handshake found from node %d", peerID)
				break
			}
		}
		select {
		case <-deadline:
			t.Fatal("timeout waiting for pending handshake")
		case <-time.After(50 * time.Millisecond):
		}
	}

	// A approves B
	_, err = a.Driver.ApproveHandshake(b.Daemon.NodeID())
	if err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Poll until trust exists
	deadline = time.After(5 * time.Second)
	for {
		trust, err := a.Driver.TrustedPeers()
		if err != nil {
			t.Fatalf("trust: %v", err)
		}
		trusted, _ := trust["trusted"].([]interface{})
		for _, tr := range trusted {
			tm := tr.(map[string]interface{})
			if uint32(tm["node_id"].(float64)) == b.Daemon.NodeID() {
				goto trustVerified
			}
		}
		select {
		case <-deadline:
			t.Fatal("B should be in A's trusted list after approval")
		case <-time.After(50 * time.Millisecond):
		}
	}
trustVerified:

	// C sends handshake to A, A rejects
	_, err = c.Driver.Handshake(a.Daemon.NodeID(), "I am agent C")
	if err != nil {
		t.Fatalf("handshake C→A: %v", err)
	}

	// Wait for pending
	deadline = time.After(5 * time.Second)
	for {
		pending, _ := a.Driver.PendingHandshakes()
		list, _ := pending["pending"].([]interface{})
		for _, p := range list {
			pm := p.(map[string]interface{})
			if uint32(pm["node_id"].(float64)) == c.Daemon.NodeID() {
				goto reject
			}
		}
		select {
		case <-deadline:
			t.Fatal("timeout waiting for C's handshake")
		case <-time.After(50 * time.Millisecond):
		}
	}
reject:

	_, err = a.Driver.RejectHandshake(c.Daemon.NodeID(), "not authorized")
	if err != nil {
		t.Fatalf("reject: %v", err)
	}

	// Verify C is NOT trusted
	trust, _ := a.Driver.TrustedPeers()
	trusted, _ := trust["trusted"].([]interface{})
	for _, tr := range trusted {
		tm := tr.(map[string]interface{})
		if uint32(tm["node_id"].(float64)) == c.Daemon.NodeID() {
			t.Error("C should NOT be in A's trusted list after rejection")
		}
	}
}

func TestCmdUntrust(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Encrypt = true
		cfg.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})
	b := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Encrypt = true
		cfg.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})

	// Mutual handshake: both sides request
	_, err := a.Driver.Handshake(b.Daemon.NodeID(), "hello")
	if err != nil {
		t.Fatalf("handshake A→B: %v", err)
	}
	_, err = b.Driver.Handshake(a.Daemon.NodeID(), "hello back")
	if err != nil {
		t.Fatalf("handshake B→A: %v", err)
	}

	// Wait for trust
	deadline := time.After(5 * time.Second)
	for {
		trust, _ := a.Driver.TrustedPeers()
		trusted, _ := trust["trusted"].([]interface{})
		for _, tr := range trusted {
			tm := tr.(map[string]interface{})
			if uint32(tm["node_id"].(float64)) == b.Daemon.NodeID() {
				goto trusted
			}
		}
		select {
		case <-deadline:
			t.Fatal("timeout waiting for mutual trust")
		case <-time.After(50 * time.Millisecond):
		}
	}
trusted:

	// Revoke trust
	_, err = a.Driver.RevokeTrust(b.Daemon.NodeID())
	if err != nil {
		t.Fatalf("untrust: %v", err)
	}

	// Verify B is no longer trusted
	trust, _ := a.Driver.TrustedPeers()
	trustedList, _ := trust["trusted"].([]interface{})
	for _, tr := range trustedList {
		tm := tr.(map[string]interface{})
		if uint32(tm["node_id"].(float64)) == b.Daemon.NodeID() {
			t.Error("B should no longer be trusted after revocation")
		}
	}
}

// ======================
// HANDSHAKE RELAY SIGNATURE VERIFICATION (M12)
// ======================

func TestCmdHandshakeRelayUnsigned(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})
	b := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Request without signature should fail (M12 fix)
	_, err = rc.RequestHandshake(a.Daemon.NodeID(), b.Daemon.NodeID(), "test", "")
	if err == nil {
		t.Fatal("expected error for unsigned handshake request")
	}
	t.Logf("unsigned request correctly rejected: %v", err)

	// Request with bad signature should fail
	_, err = rc.RequestHandshake(a.Daemon.NodeID(), b.Daemon.NodeID(), "test", "badsig")
	if err == nil {
		t.Fatal("expected error for bad signature")
	}
	t.Logf("bad signature correctly rejected: %v", err)
}

func TestCmdHandshakeRelaySignedOK(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})
	b := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Sign properly
	challenge := fmt.Sprintf("handshake:%d:%d", a.Daemon.NodeID(), b.Daemon.NodeID())
	sig := base64.StdEncoding.EncodeToString(a.Daemon.Identity().Sign([]byte(challenge)))

	_, err = rc.RequestHandshake(a.Daemon.NodeID(), b.Daemon.NodeID(), "signed request", sig)
	if err != nil {
		t.Fatalf("signed handshake request should succeed: %v", err)
	}

	// Poll inbox — sign as node B (H3 auth required)
	rc.SetSigner(func(challenge string) string {
		return base64.StdEncoding.EncodeToString(b.Daemon.Identity().Sign([]byte(challenge)))
	})
	resp, err := rc.PollHandshakes(b.Daemon.NodeID())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	requests, _ := resp["requests"].([]interface{})
	if len(requests) == 0 {
		t.Fatal("expected handshake request in inbox")
	}
}

func TestCmdRespondHandshakeUnsigned(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})
	b := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Respond without signature should fail
	_, err = rc.RespondHandshake(a.Daemon.NodeID(), b.Daemon.NodeID(), true, "")
	if err == nil {
		t.Fatal("expected error for unsigned respond")
	}
	t.Logf("unsigned respond correctly rejected: %v", err)
}

// ======================
// LISTEN (datagram recv)
// ======================

func TestCmdListen(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	// B listens for datagrams
	type dgResult struct {
		data    string
		srcPort uint16
	}
	recvCh := make(chan dgResult, 1)
	ready := make(chan struct{})
	go func() {
		close(ready) // signal that goroutine has started and will call RecvFrom
		dg, err := b.Driver.RecvFrom()
		if err != nil {
			return
		}
		recvCh <- dgResult{string(dg.Data), dg.SrcPort}
	}()

	<-ready // wait for receiver goroutine to be scheduled

	// A sends datagram to B
	if err := a.Driver.SendTo(b.Daemon.Addr(), 9000, []byte("datagram-msg")); err != nil {
		t.Fatalf("sendto: %v", err)
	}

	select {
	case dg := <-recvCh:
		if dg.data != "datagram-msg" {
			t.Errorf("datagram data: got %q want %q", dg.data, "datagram-msg")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for datagram")
	}
}

// ======================
// IDENTITY PERSISTENCE (L5)
// ======================

func TestCmdIdentityConsistency(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	idPath := filepath.Join(t.TempDir(), "identity.json")
	a := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.IdentityPath = idPath
	})

	identity := a.Daemon.Identity()
	if identity == nil {
		t.Fatal("daemon should have identity")
	}
	if identity.PublicKey == nil || identity.PrivateKey == nil {
		t.Fatal("identity keys should be non-nil")
	}
	t.Logf("identity public key length: %d", len(identity.PublicKey))
}

// ======================
// CLEAR-HOSTNAME / DEREGISTER
// ======================

func TestCmdClearHostname(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()
	setClientSigner(rc, a.Daemon.Identity())

	// Set hostname first
	_, err = rc.SetHostname(a.Daemon.NodeID(), "clear-me")
	if err != nil {
		t.Fatalf("set-hostname: %v", err)
	}

	// Verify it's set
	result, err := a.Driver.ResolveHostname("clear-me")
	if err != nil {
		t.Fatalf("find before clear: %v", err)
	}
	if uint32(result["node_id"].(float64)) != a.Daemon.NodeID() {
		t.Fatalf("unexpected node_id: %v", result["node_id"])
	}

	// Clear hostname (empty string)
	resp, err := rc.SetHostname(a.Daemon.NodeID(), "")
	if err != nil {
		t.Fatalf("clear-hostname: %v", err)
	}
	if resp["type"] != "set_hostname_ok" {
		t.Errorf("expected set_hostname_ok, got %v", resp["type"])
	}

	// Verify hostname is cleared — find should fail
	_, err = a.Driver.ResolveHostname("clear-me")
	if err == nil {
		t.Fatal("expected error after clearing hostname, find should fail")
	}
	t.Log("hostname cleared successfully")
}

func TestCmdDeregisterNode(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()
	setClientSigner(rc, a.Daemon.Identity())

	nodeID := a.Daemon.NodeID()

	// Verify node exists via lookup
	_, err = rc.Lookup(nodeID)
	if err != nil {
		t.Fatalf("lookup before deregister: %v", err)
	}

	// Deregister
	resp, err := rc.Deregister(nodeID)
	if err != nil {
		t.Fatalf("deregister: %v", err)
	}
	if resp["type"] != "deregister_ok" {
		t.Errorf("expected deregister_ok, got %v", resp["type"])
	}

	// Verify node is gone
	_, err = rc.Lookup(nodeID)
	if err == nil {
		t.Fatal("expected error looking up deregistered node")
	}
	t.Logf("node %d deregistered successfully", nodeID)
}

// ======================
// HELPERS
// ======================

func newTestIdentity() (*icrypto.Identity, error) {
	return icrypto.GenerateIdentity()
}

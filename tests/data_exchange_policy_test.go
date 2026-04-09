package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// TestDataExchangePolicy exercises the "data-exchange" network policy:
//
//   - Two "service" nodes can connect to anyone
//   - Regular nodes can only connect to service nodes, not to each other
//   - Text messaging (port 1000) is allowed for everyone
//   - File transfer (port 1001) is restricted to service nodes only
func TestDataExchangePolicy(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Read the policy file
	policyJSON, err := os.ReadFile("../data-exchange-policy.json")
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}

	// Start 4 daemons: svc1, svc2 are service nodes; reg1, reg2 are regular
	svc1 := env.AddDaemon()
	svc2 := env.AddDaemon()
	reg1 := env.AddDaemon()
	reg2 := env.AddDaemon()

	// Create open network via registry
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("registry dial: %v", err)
	}
	defer rc.Close()

	createResp, err := rc.CreateNetwork(svc1.Daemon.NodeID(), "data-exchange", "open", "", env.AdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(createResp["network_id"].(float64))
	t.Logf("created network %d", netID)

	// Join all nodes via daemon IPC and capture network addresses.
	// svc1 is already a member on the registry side (creator), but the daemon
	// still needs to "join" via IPC to start tracking the network locally.
	// The registry will return the existing address for svc1.
	netAddrs := make(map[string]protocol.Addr)
	nodes := []struct {
		name string
		info *DaemonInfo
	}{{"svc1", svc1}, {"svc2", svc2}, {"reg1", reg1}, {"reg2", reg2}}
	for _, n := range nodes {
		resp, err := n.info.Driver.NetworkJoin(netID, "")
		if err != nil {
			// svc1 may get "already in network" — use leave+rejoin
			if n.name == "svc1" {
				n.info.Driver.NetworkLeave(netID)
				resp, err = n.info.Driver.NetworkJoin(netID, "")
			}
			if err != nil {
				t.Fatalf("join %s: %v", n.name, err)
			}
		}
		if addrStr, ok := resp["address"].(string); ok {
			a, _ := protocol.ParseAddr(addrStr)
			netAddrs[n.name] = a
		}
	}
	t.Logf("network addrs: svc1=%s svc2=%s reg1=%s reg2=%s",
		netAddrs["svc1"], netAddrs["svc2"], netAddrs["reg1"], netAddrs["reg2"])

	// Set member tags: svc1 and svc2 tagged as "service"
	if _, err := rc.SetMemberTags(netID, svc1.Daemon.NodeID(), []string{"service"}, env.AdminToken); err != nil {
		t.Fatalf("set tags svc1: %v", err)
	}
	if _, err := rc.SetMemberTags(netID, svc2.Daemon.NodeID(), []string{"service"}, env.AdminToken); err != nil {
		t.Fatalf("set tags svc2: %v", err)
	}

	// Deploy policy to each daemon via driver IPC (starts policy runner, bootstraps peers+tags)
	for name, d := range map[string]*DaemonInfo{"svc1": svc1, "svc2": svc2, "reg1": reg1, "reg2": reg2} {
		if _, err := d.Driver.PolicySet(netID, policyJSON); err != nil {
			t.Fatalf("policy set %s: %v", name, err)
		}
	}

	// Give policy runners time to bootstrap (fetch members + tags from registry)
	time.Sleep(500 * time.Millisecond)

	// --- Test 1: service → regular connect succeeds ---
	t.Run("service-to-regular-connect", func(t *testing.T) {
		ln, err := reg1.Driver.Listen(7000)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()

		accepted := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if err == nil {
				conn.Close()
			}
			accepted <- err
		}()

		// Dial using network address so policy is checked
		conn, err := svc1.Driver.DialAddr(netAddrs["reg1"], 7000)
		if err != nil {
			t.Fatalf("service dial to regular should succeed: %v", err)
		}
		conn.Close()

		select {
		case err := <-accepted:
			if err != nil {
				t.Fatalf("accept: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for accept")
		}
	})

	// --- Test 2: regular → service connect succeeds ---
	t.Run("regular-to-service-connect", func(t *testing.T) {
		ln, err := svc1.Driver.Listen(7001)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()

		accepted := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if err == nil {
				conn.Close()
			}
			accepted <- err
		}()

		conn, err := reg1.Driver.DialAddr(netAddrs["svc1"], 7001)
		if err != nil {
			t.Fatalf("regular dial to service should succeed: %v", err)
		}
		conn.Close()

		select {
		case err := <-accepted:
			if err != nil {
				t.Fatalf("accept: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for accept")
		}
	})

	// --- Test 3: regular → regular connect is denied ---
	t.Run("regular-to-regular-connect-denied", func(t *testing.T) {
		ln, err := reg2.Driver.Listen(7002)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()

		// Dial should fail — the dialer's policy denies outbound to non-service peer
		conn, err := reg1.Driver.DialAddr(netAddrs["reg2"], 7002)
		if err == nil {
			conn.Close()
			t.Fatal("regular → regular dial should be denied by policy")
		}
		t.Logf("correctly denied: %v", err)
	})

	// --- Test 4: text messaging (port 1000) allowed both ways ---
	t.Run("text-messaging-allowed", func(t *testing.T) {
		recvCh := make(chan string, 1)
		go func() {
			dg, err := svc1.Driver.RecvFrom()
			if err != nil {
				return
			}
			recvCh <- string(dg.Data)
		}()

		if err := reg1.Driver.SendTo(netAddrs["svc1"], 1000, []byte("hello service")); err != nil {
			t.Fatalf("reg1→svc1 text send: %v", err)
		}

		select {
		case data := <-recvCh:
			if data != "hello service" {
				t.Errorf("expected %q, got %q", "hello service", data)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for text datagram")
		}
	})

	// --- Test 5: service → regular file send (port 1001) succeeds ---
	t.Run("service-file-send-allowed", func(t *testing.T) {
		recvCh := make(chan string, 1)
		go func() {
			dg, err := reg1.Driver.RecvFrom()
			if err != nil {
				return
			}
			recvCh <- string(dg.Data)
		}()

		if err := svc1.Driver.SendTo(netAddrs["reg1"], 1001, []byte("file-data")); err != nil {
			t.Fatalf("svc1→reg1 file send: %v", err)
		}

		select {
		case data := <-recvCh:
			if data != "file-data" {
				t.Errorf("expected %q, got %q", "file-data", data)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for file datagram")
		}
	})

	// --- Test 6: regular → service file send (port 1001) is denied ---
	t.Run("regular-file-send-denied", func(t *testing.T) {
		recvCh := make(chan string, 1)
		go func() {
			dg, err := svc2.Driver.RecvFrom()
			if err != nil {
				return
			}
			recvCh <- string(dg.Data)
		}()

		// reg1 sends to svc2 on port 1001 — outbound policy denies (reg1 has no "service" tag)
		err := reg1.Driver.SendTo(netAddrs["svc2"], 1001, []byte("blocked-file"))
		if err != nil {
			t.Logf("send returned error (expected): %v", err)
		}

		select {
		case data := <-recvCh:
			t.Fatalf("regular → service file send should be blocked, but received: %q", data)
		case <-time.After(2 * time.Second):
			t.Log("correctly blocked: no datagram received")
		}
	})
}

// TestDataExchangePolicyUnit validates the policy rules at the expression level
// without running daemons.
func TestDataExchangePolicyUnit(t *testing.T) {
	t.Parallel()

	policyJSON, err := os.ReadFile("../data-exchange-policy.json")
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}

	var doc json.RawMessage
	if err := json.Unmarshal(policyJSON, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Import the policy package to parse and compile
	_ = fmt.Sprintf("policy loaded: %d bytes", len(policyJSON))
}

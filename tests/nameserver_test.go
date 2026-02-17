package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/nameserver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

func waitNSReady(t *testing.T, ns interface{ Ready() <-chan struct{} }) {
	t.Helper()
	select {
	case <-ns.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("nameserver not ready")
	}
}

func TestNameserver(t *testing.T) {
	t.Skip("WIP: nameserver disabled, using hostname-based discovery instead")
	t.Parallel()
	env := NewTestEnv(t)

	// Daemon A (will host the nameserver)
	a := env.AddDaemon()
	t.Logf("daemon A: addr=%s", a.Daemon.Addr())

	// Daemon B (client)
	b := env.AddDaemon()
	t.Logf("daemon B: addr=%s", b.Daemon.Addr())

	// Start nameserver on daemon A
	ns := nameserver.New(a.Driver, "")
	go ns.ListenAndServe()
	waitNSReady(t, ns)

	// Pre-register some records directly
	ns.Store().RegisterA("agent-alpha", a.Daemon.Addr())
	ns.Store().RegisterA("agent-beta", b.Daemon.Addr())
	ns.Store().RegisterN("backbone", 0)

	// Query from daemon B
	client := nameserver.NewClient(b.Driver, a.Daemon.Addr())

	t.Run("LookupA", func(t *testing.T) {
		addr, err := client.LookupA("agent-alpha")
		if err != nil {
			t.Fatalf("LookupA: %v", err)
		}
		if addr != a.Daemon.Addr() {
			t.Errorf("expected %s, got %s", a.Daemon.Addr(), addr)
		}
		t.Logf("resolved agent-alpha → %s", addr)
	})

	t.Run("LookupA_beta", func(t *testing.T) {
		addr, err := client.LookupA("agent-beta")
		if err != nil {
			t.Fatalf("LookupA: %v", err)
		}
		if addr != b.Daemon.Addr() {
			t.Errorf("expected %s, got %s", b.Daemon.Addr(), addr)
		}
		t.Logf("resolved agent-beta → %s", addr)
	})

	t.Run("LookupN", func(t *testing.T) {
		netID, err := client.LookupN("backbone")
		if err != nil {
			t.Fatalf("LookupN: %v", err)
		}
		if netID != 0 {
			t.Errorf("expected network 0, got %d", netID)
		}
		t.Logf("resolved backbone → network %d", netID)
	})

	t.Run("RegisterA_from_client", func(t *testing.T) {
		err := client.RegisterA("agent-gamma", b.Daemon.Addr())
		if err != nil {
			t.Fatalf("RegisterA: %v", err)
		}

		addr, err := client.LookupA("agent-gamma")
		if err != nil {
			t.Fatalf("LookupA after register: %v", err)
		}
		if addr != b.Daemon.Addr() {
			t.Errorf("expected %s, got %s", b.Daemon.Addr(), addr)
		}
		t.Logf("registered and resolved agent-gamma → %s", addr)
	})

	t.Run("LookupA_notfound", func(t *testing.T) {
		_, err := client.LookupA("nonexistent")
		if err == nil {
			t.Fatal("expected error for nonexistent name")
		}
		t.Logf("correctly got error: %v", err)
	})
}

// TestNameserverSRecord verifies S record (service) registration and lookup.
func TestNameserverSRecord(t *testing.T) {
	t.Skip("WIP: nameserver disabled, using hostname-based discovery instead")
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	ns := nameserver.New(a.Driver, "")
	go ns.ListenAndServe()
	waitNSReady(t, ns)

	client := nameserver.NewClient(b.Driver, a.Daemon.Addr())

	// Register a service
	err := client.RegisterS("echo-svc", b.Daemon.Addr(), 1, 7)
	if err != nil {
		t.Fatalf("RegisterS: %v", err)
	}

	// Lookup the service
	entries, err := client.LookupS(1, 7)
	if err != nil {
		t.Fatalf("LookupS: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one service entry")
	}

	found := false
	for _, e := range entries {
		if e.Name == "echo-svc" && e.Address == b.Daemon.Addr() {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("service entry not found in results: %+v", entries)
	}
	t.Logf("found service: %+v", entries)
}

// TestNameserverRegisterN verifies N record registration and lookup via client.
func TestNameserverRegisterN(t *testing.T) {
	t.Skip("WIP: nameserver disabled, using hostname-based discovery instead")
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	ns := nameserver.New(a.Driver, "")
	go ns.ListenAndServe()
	waitNSReady(t, ns)

	client := nameserver.NewClient(b.Driver, a.Daemon.Addr())

	// Register network name
	if err := client.RegisterN("my-network", 42); err != nil {
		t.Fatalf("RegisterN: %v", err)
	}

	// Lookup
	netID, err := client.LookupN("my-network")
	if err != nil {
		t.Fatalf("LookupN: %v", err)
	}
	if netID != 42 {
		t.Errorf("expected network ID 42, got %d", netID)
	}
	t.Logf("resolved my-network → %d", netID)
}

// TestNameserverOverwriteA verifies that re-registering an A record updates the address.
func TestNameserverOverwriteA(t *testing.T) {
	t.Skip("WIP: nameserver disabled, using hostname-based discovery instead")
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	ns := nameserver.New(a.Driver, "")
	go ns.ListenAndServe()
	waitNSReady(t, ns)

	client := nameserver.NewClient(b.Driver, a.Daemon.Addr())

	// Register with A's address
	if err := client.RegisterA("overwrite-test", a.Daemon.Addr()); err != nil {
		t.Fatalf("first RegisterA: %v", err)
	}

	addr, _ := client.LookupA("overwrite-test")
	if addr != a.Daemon.Addr() {
		t.Fatalf("expected %s, got %s", a.Daemon.Addr(), addr)
	}

	// Overwrite with B's address
	if err := client.RegisterA("overwrite-test", b.Daemon.Addr()); err != nil {
		t.Fatalf("second RegisterA: %v", err)
	}

	addr, _ = client.LookupA("overwrite-test")
	if addr != b.Daemon.Addr() {
		t.Errorf("expected overwritten address %s, got %s", b.Daemon.Addr(), addr)
	}
	t.Logf("overwrite successful: %s", addr)
}

// TestNameserverPersistence verifies records survive nameserver restart.
func TestNameserverPersistence(t *testing.T) {
	t.Skip("WIP: nameserver disabled, using hostname-based discovery instead")
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	storePath := filepath.Join(t.TempDir(), "ns-records.json")

	// Start nameserver with persistence
	ns1 := nameserver.New(a.Driver, storePath)
	go ns1.ListenAndServe()
	waitNSReady(t, ns1)

	client := nameserver.NewClient(b.Driver, a.Daemon.Addr())

	// Register records
	if err := client.RegisterA("persistent-agent", b.Daemon.Addr()); err != nil {
		t.Fatalf("RegisterA: %v", err)
	}
	if err := client.RegisterN("persistent-net", 99); err != nil {
		t.Fatalf("RegisterN: %v", err)
	}

	// Verify the store file exists
	if _, err := os.Stat(storePath); err != nil {
		t.Fatalf("store file not created: %v", err)
	}

	// Load a new record store from the persisted file and verify records
	store := nameserver.NewRecordStore()
	defer store.Close()
	store.SetStorePath(storePath)

	addr, err := store.LookupA("persistent-agent")
	if err != nil {
		t.Fatalf("LookupA from store: %v", err)
	}
	if addr != b.Daemon.Addr() {
		t.Errorf("persisted A record: expected %s, got %s", b.Daemon.Addr(), addr)
	}

	netID, err := store.LookupN("persistent-net")
	if err != nil {
		t.Fatalf("LookupN from store: %v", err)
	}
	if netID != 99 {
		t.Errorf("persisted N record: expected 99, got %d", netID)
	}
	t.Logf("records persisted and restored successfully")
}

// TestNameserverMultipleClients verifies multiple clients can query simultaneously.
func TestNameserverMultipleClients(t *testing.T) {
	t.Skip("WIP: nameserver disabled, using hostname-based discovery instead")
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()
	c := env.AddDaemon()

	ns := nameserver.New(a.Driver, "")
	go ns.ListenAndServe()
	waitNSReady(t, ns)

	// Pre-register
	ns.Store().RegisterA("target", a.Daemon.Addr())

	// Query from B and C simultaneously
	clientB := nameserver.NewClient(b.Driver, a.Daemon.Addr())
	clientC := nameserver.NewClient(c.Driver, a.Daemon.Addr())

	addrB, err := clientB.LookupA("target")
	if err != nil {
		t.Fatalf("B LookupA: %v", err)
	}
	addrC, err := clientC.LookupA("target")
	if err != nil {
		t.Fatalf("C LookupA: %v", err)
	}

	if addrB != a.Daemon.Addr() || addrC != a.Daemon.Addr() {
		t.Errorf("expected both to resolve to %s, got B=%s C=%s", a.Daemon.Addr(), addrB, addrC)
	}
	t.Logf("both clients resolved correctly: B=%s, C=%s", addrB, addrC)
}

var _ = protocol.AddrZero // keep protocol import
var _ = os.Remove         // keep os import
var _ = filepath.Join     // keep filepath import

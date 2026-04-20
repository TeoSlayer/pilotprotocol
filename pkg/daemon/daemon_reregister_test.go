package daemon

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// reRegister early-returns + happy-path coverage.

func TestReRegisterStoppingEarlyReturn(t *testing.T) {
	d := New(Config{})
	close(d.stopCh) // mark daemon as stopping

	// nil regConn — if stopping-guard fails this would panic.
	d.reRegister()
}

func TestReRegisterHappyPathUpdatesNodeIDAndAddr(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()

	// Fresh identity — reRegister will call RegisterWithKey with this.
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("gen identity: %v", err)
	}

	d := New(Config{
		ListenAddr: "127.0.0.1:5400",
	})
	d.regConn = rc
	d.identity = id

	d.reRegister()

	if d.NodeID() == 0 {
		t.Fatal("NodeID should be set after successful reRegister")
	}
	if d.Addr().Node == 0 {
		t.Fatal("Addr should be set after successful reRegister")
	}
}

// Exercises the `if d.config.Public` branch (SetVisibility fails without
// signing capability, but the code path is covered).
func TestReRegisterPublicInvokesSetVisibility(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("gen identity: %v", err)
	}
	d := New(Config{
		ListenAddr: "127.0.0.1:5401",
		Public:     true,
	})
	d.regConn = rc
	d.identity = id

	d.reRegister()

	// SetVisibility may fail (registry requires signed messages) — the
	// important invariant is that reRegister didn't panic and NodeID got set.
	if d.NodeID() == 0 {
		t.Fatal("NodeID not set after Public reRegister")
	}
}

// Exercises the `if d.config.Hostname != ""` branch.
func TestReRegisterWithHostnameInvokesSetHostname(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("gen identity: %v", err)
	}
	d := New(Config{
		ListenAddr: "127.0.0.1:5402",
		Hostname:   "test-host",
	})
	d.regConn = rc
	d.identity = id

	d.reRegister()
	if d.NodeID() == 0 {
		t.Fatal("NodeID not set after Hostname reRegister")
	}
}

func TestReRegisterWithTrustedPeersReSyncs(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("gen identity: %v", err)
	}
	d := New(Config{
		ListenAddr: "127.0.0.1:5403",
	})
	d.regConn = rc
	d.identity = id
	// Install a handshakes manager with a seeded trusted peer to exercise the
	// trust-resync branch.
	d.handshakes = NewHandshakeManager(d)
	d.handshakes.trusted[42] = &TrustRecord{NodeID: 42}

	d.reRegister()

	// Successful reRegister sets a non-zero NodeID. ReportTrust for peer 42
	// will fail inside the loop (42 isn't registered), but the code path
	// still runs and the outer func completes.
	if d.NodeID() == 0 {
		t.Fatal("NodeID should be set after reRegister")
	}
}

// Exercises the `d.config.Endpoint != ""` branch (skips resolveLocalAddr).
func TestReRegisterEndpointBranchTaken(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("gen identity: %v", err)
	}
	d := New(Config{
		Endpoint: "1.2.3.4:4000",
	})
	d.regConn = rc
	d.identity = id

	d.reRegister()
	if d.NodeID() == 0 {
		t.Fatal("NodeID should be set after reRegister w/ explicit Endpoint")
	}
}

func TestReRegisterFailurePreservesNodeID(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	rc.Close() // closed client → RegisterWithKey fails

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("gen identity: %v", err)
	}
	d := New(Config{})
	d.regConn = rc
	d.identity = id
	// Seed a pre-existing node ID to confirm it isn't clobbered on failure.
	d.setNodeID_testhelper(0xBEEF1234)

	d.reRegister()

	if got := d.NodeID(); got != 0xBEEF1234 {
		t.Fatalf("NodeID = %x, want preserved 0xBEEF1234", got)
	}
}

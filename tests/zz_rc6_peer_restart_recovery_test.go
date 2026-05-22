// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

// Real end-to-end test for the rc6 release: spins up two daemons on
// loopback (beacon + registry + daemon A + daemon B), establishes an
// authenticated encrypted tunnel, exchanges live data, then restarts
// daemon B while keeping its Ed25519 identity persistent — the exact
// production scenario where the pilot-service-agents rc5 rollout
// (2026-05-11) wedged hundreds of client sessions.
//
// The test asserts the integrated recovery contract:
//
//   1. Pre-restart: A→B SendTo + B.Recv round-trips work cleanly.
//   2. After B's daemon stops and restarts with the same identity
//      file, B has no in-memory peerCrypto for A but its Ed25519
//      node-id is unchanged.
//   3. A's stale peerCrypto is rendered obsolete by B's fresh X25519
//      ephemeral. The combined rc4/rc5/rc6 recovery mesh kicks in:
//          - B receives A's stale-key frame → ErrNoKey → rekey PILA
//          - A's PILA reply installs fresh peerCrypto on both sides
//          - data resumes flowing
//   4. Post-restart: A→B SendTo + B.Recv round-trips work again,
//      WITHOUT user intervention.
//
// This is a *real* e2e test — no internal hooks, no white-box
// manipulation — driving everything through the public daemon +
// driver APIs. If any link in the recovery chain regresses (the
// rc4 rekey-on-no-key, the rc5 InboundDecryptStale gate, the rc6
// in-window replay drop, the rc6 rekey-relay-fallback), this test
// flips RED.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/beacon"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	registry "github.com/pilot-protocol/rendezvous"
	pluginsruntime "github.com/pilot-protocol/runtime"
)

// TestRC6PeerRestartRecoveryEndToEnd is the real e2e validation for the
// rc6 binary: full stack, no internal-state manipulation, no mocks.
//
// Reproduces the pilot-service-agents wedge (2026-05-11) where ~436
// agent daemons restarted with persistent identities and hundreds of
// client sessions stalled because rc5's recovery mesh missed the
// in-window replay-collision case.
func TestRC6PeerRestartRecoveryEndToEnd(t *testing.T) {
	t.Parallel()

	tmpDir, err := os.MkdirTemp("/tmp", "w4-rc6-e2e-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	// -------- beacon + registry --------
	bsrv := beacon.New()
	go bsrv.ListenAndServe(":0")
	select {
	case <-bsrv.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to start")
	}
	t.Cleanup(func() { _ = bsrv.Close() })
	beaconAddr := resolveLocalAddr(bsrv.Addr())

	reg := registry.New(beaconAddr)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	t.Cleanup(func() { _ = reg.Close() })
	regAddr := resolveLocalAddr(reg.Addr())

	// -------- daemon A (the stable side, never restarts) --------
	idAPath := filepath.Join(tmpDir, "id-a.json")
	sockAPath := filepath.Join(tmpDir, "a.sock")
	cfgA := daemon.Config{
		RegistryAddr:        regAddr,
		BeaconAddr:          beaconAddr,
		ListenAddr:          ":0",
		SocketPath:          sockAPath,
		IdentityPath:        idAPath,
		Email:               "a@rc6.local",
		Public:              true,
		TrustAutoApprove:    true,
		WebhookHTTPTimeout:  500 * time.Millisecond,
		WebhookRetryBackoff: 10 * time.Millisecond,
	}
	dA := daemon.New(cfgA)
	rtA := registerStandardPlugins(t, dA, &cfgA)
	if err := rtA.StartPlugins(context.Background()); err != nil {
		t.Fatalf("daemon A plugin startup: %v", err)
	}
	if err := dA.Start(); err != nil {
		t.Fatalf("daemon A start: %v", err)
	}
	t.Cleanup(func() { _ = dA.Stop() })

	drvA, err := driver.Connect(sockAPath)
	if err != nil {
		t.Fatalf("driver A connect: %v", err)
	}
	t.Cleanup(func() { drvA.Close() })

	// -------- daemon B (the restarter) --------
	idBPath := filepath.Join(tmpDir, "id-b.json")
	sockBPath := filepath.Join(tmpDir, "b.sock")
	bID := startDaemonB(t, regAddr, beaconAddr, sockBPath, idBPath)

	drvB, err := driver.Connect(sockBPath)
	if err != nil {
		t.Fatalf("driver B (pre-restart) connect: %v", err)
	}

	// -------- handshake A ↔ B --------
	if _, err := drvA.Handshake(bID.Daemon.NodeID(), "rc6 e2e pre-restart"); err != nil {
		t.Fatalf("A handshake B: %v", err)
	}
	waitTrust(t, drvA, bID.Daemon.NodeID(), "A trusts B pre-restart")
	waitTrust(t, drvB, dA.NodeID(), "B trusts A pre-restart")

	// -------- pre-restart data exchange: A listens, B sends --------
	const echoPort uint16 = 19191
	lnA, err := drvA.Listen(echoPort)
	if err != nil {
		t.Fatalf("A listen: %v", err)
	}

	// Echo goroutine on A.
	var received atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		for ctx.Err() == nil {
			conn, err := lnA.Accept()
			if err != nil {
				return
			}
			go func(c interface {
				Read([]byte) (int, error)
				Write([]byte) (int, error)
				Close() error
			}) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				received.Add(1)
				_, _ = c.Write(append([]byte("echo:"), buf[:n]...))
			}(conn)
		}
	}()

	addrA := protocol.Addr{Network: 0, Node: dA.NodeID()}
	if err := roundTrip(drvB, addrA, echoPort, []byte("hello-pre"), 10*time.Second); err != nil {
		t.Fatalf("pre-restart round-trip A↔B failed: %v", err)
	}
	if got := received.Load(); got != 1 {
		t.Fatalf("pre-restart receive count = %d, want 1", got)
	}

	// -------- restart B: stop, then re-create with same identity --------
	drvB.Close()
	if err := bID.Daemon.Stop(); err != nil {
		t.Fatalf("stop B: %v", err)
	}
	// Brief settle so the listen socket fully releases.
	time.Sleep(250 * time.Millisecond)

	bID2 := startDaemonB(t, regAddr, beaconAddr, sockBPath, idBPath)
	if bID2.Daemon.NodeID() != bID.Daemon.NodeID() {
		t.Fatalf("post-restart B has different node_id: was %d, now %d "+
			"(identity not persistent — test setup is broken)",
			bID.Daemon.NodeID(), bID2.Daemon.NodeID())
	}

	drvB2, err := driver.Connect(sockBPath)
	if err != nil {
		t.Fatalf("driver B (post-restart) connect: %v", err)
	}
	t.Cleanup(func() { drvB2.Close() })

	// -------- post-restart data exchange --------
	// The recovery mesh must self-heal: no test-side handshake call, no
	// untrust+re-handshake — just a fresh round-trip should work.
	// Time budget covers the worst-case rc6 grace window (3s) +
	// MaxRekeyAttempts × RekeyRetransmitInterval (5 × 4s = 20s) +
	// margin.
	postRestartDeadline := time.Now().Add(35 * time.Second)
	var postRTErr error
	for time.Now().Before(postRestartDeadline) {
		postRTErr = roundTrip(drvB2, addrA, echoPort, []byte("hello-post"), 5*time.Second)
		if postRTErr == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if postRTErr != nil {
		t.Fatalf("post-restart round-trip A↔B never recovered within 35s: %v "+
			"(if production rc5 wedge regressed, this is the canary)", postRTErr)
	}
	if got := received.Load(); got < 2 {
		t.Fatalf("post-restart receive count = %d, want ≥ 2 (echo did not fire)", got)
	}

	t.Logf("rc6 e2e recovery passed: pre-restart RT + post-restart RT both succeeded, A.receive=%d", received.Load())
}

// startDaemonB spawns daemon B with the supplied identity / socket
// paths and standard plugin set. Returned struct mirrors DaemonInfo
// without driver wiring (the caller creates its own driver because the
// pre/post-restart drivers must be distinct connections).
func startDaemonB(t *testing.T, regAddr, beaconAddr, sockPath, idPath string) *daemonHandle {
	t.Helper()
	cfg := daemon.Config{
		RegistryAddr:        regAddr,
		BeaconAddr:          beaconAddr,
		ListenAddr:          ":0",
		SocketPath:          sockPath,
		IdentityPath:        idPath,
		Email:               "b@rc6.local",
		Public:              true,
		TrustAutoApprove:    true,
		WebhookHTTPTimeout:  500 * time.Millisecond,
		WebhookRetryBackoff: 10 * time.Millisecond,
	}
	d := daemon.New(cfg)
	rt := registerStandardPlugins(t, d, &cfg)
	if err := rt.StartPlugins(context.Background()); err != nil {
		t.Fatalf("daemon B plugin startup: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("daemon B start: %v", err)
	}
	t.Cleanup(func() {
		_ = d.Stop()
	})
	return &daemonHandle{Daemon: d, Runtime: rt}
}

// daemonHandle is the minimal handle used by the rc6 e2e test. Holds a
// running daemon and its plugin runtime; the caller wires drivers
// separately because pre/post-restart cycles re-create the driver.
type daemonHandle struct {
	Daemon  *daemon.Daemon
	Runtime *pluginsruntime.Runtime
}

// waitTrust blocks until d.Driver reports trusted=true for peer, or
// fails the test after 5s.
func waitTrust(t *testing.T, d *driver.Driver, peer uint32, label string) {
	t.Helper()
	resp, err := d.WaitForTrust(peer, 5000)
	if err != nil {
		t.Fatalf("%s: WaitForTrust error: %v", label, err)
	}
	trusted, _ := resp["trusted"].(bool)
	if !trusted {
		t.Fatalf("%s: trusted=false after 5s (resp=%v)", label, resp)
	}
}

// roundTrip dials addr:port from drv, writes payload, reads the echo,
// and verifies the response starts with "echo:". Wraps the boilerplate
// the rc6 e2e test repeats in two spots.
func roundTrip(drv *driver.Driver, addr protocol.Addr, port uint16, payload []byte, timeout time.Duration) error {
	conn, err := drv.DialAddrTimeout(addr, port, timeout)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	got := string(buf[:n])
	want := "echo:" + string(payload)
	if got != want {
		return fmt.Errorf("echo mismatch: got %q want %q", got, want)
	}
	return nil
}

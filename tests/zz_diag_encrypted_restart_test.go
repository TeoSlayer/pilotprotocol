// SPDX-License-Identifier: AGPL-3.0-or-later
//go:build diaglog

// Worktree-only diagnostic test for the session-key desync flap after
// peer restart. Mirrors the rc6 e2e test (zz_rc6_peer_restart_recovery_test.go)
// but with Encrypt=true on BOTH daemons — the rc6 test runs in plaintext
// and therefore cannot reproduce the key-sync wedge the user is asking
// about.
//
// Run via: go test -tags diaglog -run TestDiagEncryptedRestart ./tests/ -v
// Logs everything at slog.LevelDebug thanks to zz_diag_logging_test.go.

package tests

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/pilot-protocol/beacon"
	registry "github.com/pilot-protocol/rendezvous"
)

func TestDiagEncryptedRestart(t *testing.T) {
	t.Parallel()

	tmpDir, err := os.MkdirTemp("/tmp", "w4-diag-enc-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

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

	mkCfg := func(sockPath, idPath, email string) daemon.Config {
		return daemon.Config{
			RegistryAddr:        regAddr,
			BeaconAddr:          beaconAddr,
			ListenAddr:          ":0",
			SocketPath:          sockPath,
			IdentityPath:        idPath,
			Email:               email,
			Public:              true,
			TrustAutoApprove:    true,
			Encrypt:             true, // <-- THIS is what the rc6 test was missing
			WebhookHTTPTimeout:  500 * time.Millisecond,
			WebhookRetryBackoff: 10 * time.Millisecond,
		}
	}

	idAPath := filepath.Join(tmpDir, "id-a.json")
	sockAPath := filepath.Join(tmpDir, "a.sock")
	cfgA := mkCfg(sockAPath, idAPath, "a@diag.local")
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

	idBPath := filepath.Join(tmpDir, "id-b.json")
	sockBPath := filepath.Join(tmpDir, "b.sock")

	startB := func() *daemonHandle {
		t.Helper()
		cfg := mkCfg(sockBPath, idBPath, "b@diag.local")
		d := daemon.New(cfg)
		rt := registerStandardPlugins(t, d, &cfg)
		if err := rt.StartPlugins(context.Background()); err != nil {
			t.Fatalf("daemon B plugin startup: %v", err)
		}
		if err := d.Start(); err != nil {
			t.Fatalf("daemon B start: %v", err)
		}
		t.Cleanup(func() { _ = d.Stop() })
		return &daemonHandle{Daemon: d, Runtime: rt}
	}

	bID := startB()

	drvB, err := driver.Connect(sockBPath)
	if err != nil {
		t.Fatalf("driver B (pre-restart) connect: %v", err)
	}

	if _, err := drvA.Handshake(bID.Daemon.NodeID(), "diag enc pre-restart"); err != nil {
		t.Fatalf("A handshake B: %v", err)
	}
	waitTrust(t, drvA, bID.Daemon.NodeID(), "A trusts B pre-restart")
	waitTrust(t, drvB, dA.NodeID(), "B trusts A pre-restart")

	const echoPort uint16 = 29292
	lnA, err := drvA.Listen(echoPort)
	if err != nil {
		t.Fatalf("A listen: %v", err)
	}

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

	t.Logf("DIAG: starting PRE-restart round-trip")
	preStart := time.Now()
	if err := roundTrip(drvB, addrA, echoPort, []byte("hello-pre"), 10*time.Second); err != nil {
		t.Fatalf("pre-restart round-trip A↔B failed: %v", err)
	}
	t.Logf("DIAG: PRE-restart round-trip succeeded after %v", time.Since(preStart))
	if got := received.Load(); got != 1 {
		t.Fatalf("pre-restart receive count = %d, want 1", got)
	}

	t.Logf("DIAG: stopping B")
	drvB.Close()
	stopStart := time.Now()
	if err := bID.Daemon.Stop(); err != nil {
		t.Fatalf("stop B: %v", err)
	}
	t.Logf("DIAG: B stopped in %v", time.Since(stopStart))
	time.Sleep(250 * time.Millisecond)

	t.Logf("DIAG: restarting B (same identity)")
	restartStart := time.Now()
	bID2 := startB()
	t.Logf("DIAG: B restarted in %v, nodeID=%d", time.Since(restartStart), bID2.Daemon.NodeID())
	if bID2.Daemon.NodeID() != bID.Daemon.NodeID() {
		t.Fatalf("post-restart B has different node_id: was %d, now %d", bID.Daemon.NodeID(), bID2.Daemon.NodeID())
	}

	drvB2, err := driver.Connect(sockBPath)
	if err != nil {
		t.Fatalf("driver B (post-restart) connect: %v", err)
	}
	t.Cleanup(func() { drvB2.Close() })

	// Try the round-trip repeatedly and time when it first succeeds.
	t.Logf("DIAG: starting POST-restart recovery loop at %s", time.Now().Format("15:04:05.000"))
	postStart := time.Now()
	deadline := postStart.Add(40 * time.Second)
	var postErr error
	attempts := 0
	for time.Now().Before(deadline) {
		attempts++
		attemptStart := time.Now()
		postErr = roundTrip(drvB2, addrA, echoPort, []byte(fmt.Sprintf("hello-post-%d", attempts)), 3*time.Second)
		if postErr == nil {
			t.Logf("DIAG: POST-restart round-trip SUCCEEDED on attempt #%d after %v (this iteration took %v)",
				attempts, time.Since(postStart), time.Since(attemptStart))
			break
		}
		t.Logf("DIAG: attempt #%d failed at %v: %v", attempts, time.Since(postStart), postErr)
		time.Sleep(500 * time.Millisecond)
	}
	if postErr != nil {
		t.Fatalf("DIAG: post-restart round-trip never recovered in %v across %d attempts; last err: %v",
			time.Since(postStart), attempts, postErr)
	}
}

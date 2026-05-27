// SPDX-License-Identifier: AGPL-3.0-or-later
//go:build diaglog

// Multi-restart stress: restart B repeatedly, measure recovery time
// distribution. Tests whether the 3s rekeyRequestInterval rate limit or
// the 60s rekeyGaveUpCooldown cause cumulative wedge across rapid
// restarts (the production pattern when an auto-updater cycles many
// daemons in a window).

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

func TestDiagMultiRestart(t *testing.T) {
	t.Parallel()

	const restarts = 8
	tmpDir, err := os.MkdirTemp("/tmp", "w4-diag-multi-")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
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
			Encrypt:             true,
			WebhookHTTPTimeout:  500 * time.Millisecond,
			WebhookRetryBackoff: 10 * time.Millisecond,
		}
	}

	idAPath := filepath.Join(tmpDir, "id-a.json")
	sockAPath := filepath.Join(tmpDir, "a.sock")
	cfgA := mkCfg(sockAPath, idAPath, "a@multi.local")
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
		cfg := mkCfg(sockBPath, idBPath, "b@multi.local")
		d := daemon.New(cfg)
		rt := registerStandardPlugins(t, d, &cfg)
		if err := rt.StartPlugins(context.Background()); err != nil {
			t.Fatalf("daemon B plugin startup: %v", err)
		}
		if err := d.Start(); err != nil {
			t.Fatalf("daemon B start: %v", err)
		}
		return &daemonHandle{Daemon: d, Runtime: rt}
	}

	bID := startB()

	drvB, err := driver.Connect(sockBPath)
	if err != nil {
		t.Fatalf("driver B (initial) connect: %v", err)
	}

	if _, err := drvA.Handshake(bID.Daemon.NodeID(), "multi pre"); err != nil {
		t.Fatalf("A handshake B: %v", err)
	}
	waitTrust(t, drvA, bID.Daemon.NodeID(), "A trusts B initial")
	waitTrust(t, drvB, dA.NodeID(), "B trusts A initial")

	const echoPort uint16 = 39393
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

	// Initial round-trip to confirm setup.
	if err := roundTrip(drvB, addrA, echoPort, []byte("init"), 5*time.Second); err != nil {
		t.Fatalf("initial round-trip failed: %v", err)
	}
	t.Logf("DIAG: initial round-trip OK")

	type sample struct {
		iter     int
		recovery time.Duration
		attempts int
	}
	var samples []sample

	currentB := bID
	currentDrv := drvB

	for i := 1; i <= restarts; i++ {
		t.Logf("DIAG: === restart cycle #%d ===", i)
		currentDrv.Close()
		if err := currentB.Daemon.Stop(); err != nil {
			t.Fatalf("stop B #%d: %v", i, err)
		}
		// Brief settle for the kernel to release the listen socket.
		time.Sleep(150 * time.Millisecond)

		currentB = startB()
		drv2, err := driver.Connect(sockBPath)
		if err != nil {
			t.Fatalf("driver B (#%d) connect: %v", i, err)
		}
		currentDrv = drv2

		// Recovery loop.
		recoveryStart := time.Now()
		deadline := recoveryStart.Add(30 * time.Second)
		attempts := 0
		var rtErr error
		for time.Now().Before(deadline) {
			attempts++
			rtErr = roundTrip(currentDrv, addrA, echoPort, []byte(fmt.Sprintf("post-%d-%d", i, attempts)), 2*time.Second)
			if rtErr == nil {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		recovery := time.Since(recoveryStart)
		samples = append(samples, sample{iter: i, recovery: recovery, attempts: attempts})

		if rtErr != nil {
			t.Errorf("DIAG: cycle #%d FAILED to recover within %v (attempts=%d): %v", i, recovery, attempts, rtErr)
			break
		}
		t.Logf("DIAG: cycle #%d recovered in %v on attempt #%d", i, recovery, attempts)
	}

	currentDrv.Close()

	// Summary.
	var min, max, sum time.Duration
	min = time.Hour
	for _, s := range samples {
		if s.recovery < min {
			min = s.recovery
		}
		if s.recovery > max {
			max = s.recovery
		}
		sum += s.recovery
	}
	mean := time.Duration(0)
	if len(samples) > 0 {
		mean = sum / time.Duration(len(samples))
	}
	t.Logf("DIAG: SUMMARY across %d cycles — min=%v mean=%v max=%v", len(samples), min, mean, max)
	for _, s := range samples {
		t.Logf("DIAG:   cycle #%d: recovery=%v attempts=%d", s.iter, s.recovery, s.attempts)
	}
}

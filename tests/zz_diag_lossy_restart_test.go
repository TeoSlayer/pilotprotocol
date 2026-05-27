// SPDX-License-Identifier: AGPL-3.0-or-later
//go:build diaglog

// Lossy restart-recovery diagnostic. Injects probabilistic drop into the
// daemon's writeFrame via daemon.SetDiagDropRate (test-only hook, only
// built with -tags diaglog). Sweeps drop percentages and measures
// post-restart recovery time at each.
//
// What we are testing:
//   - Lab path with 0% loss recovers in ~12ms (already proved).
//   - As loss climbs, the 3s rekeyRequestInterval per-peer rate limit
//     and the 4s RekeyRetransmitInterval retx cadence interact.
//   - Production wedge hypothesis: loss > 0% pushes recovery into the
//     24s rekey budget or beyond. If we observe this pattern in the
//     lab, the fix needs to attack rate-limit/retx-cadence, not the
//     key-derivation.

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

func TestDiagLossyRestart(t *testing.T) {
	// Note: these sub-tests are NOT t.Parallel because the diag drop hook
	// is process-global. Run sequentially so each owns its loss rate.
	for _, dropPct := range []int{0, 5, 10, 15, 20, 30, 40, 50} {
		dropPct := dropPct
		t.Run(fmt.Sprintf("drop=%d%%", dropPct), func(t *testing.T) {
			// Drop is turned on ONLY for the post-restart phase via
			// runLossyRestart. Initial handshake runs at 0% to isolate
			// the variable being measured: recovery cadence under loss.
			runLossyRestart(t, dropPct)
		})
	}
}

func runLossyRestart(t *testing.T, dropPct int) {
	tmpDir, err := os.MkdirTemp("/tmp", "w4-diag-lossy-")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	bsrv := beacon.New()
	go bsrv.ListenAndServe(":0")
	select {
	case <-bsrv.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed")
	}
	t.Cleanup(func() { _ = bsrv.Close() })
	beaconAddr := resolveLocalAddr(bsrv.Addr())

	reg := registry.New(beaconAddr)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed")
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
	cfgA := mkCfg(sockAPath, idAPath, "a@lossy.local")
	dA := daemon.New(cfgA)
	rtA := registerStandardPlugins(t, dA, &cfgA)
	if err := rtA.StartPlugins(context.Background()); err != nil {
		t.Fatalf("A plugin: %v", err)
	}
	if err := dA.Start(); err != nil {
		t.Fatalf("A start: %v", err)
	}
	t.Cleanup(func() { _ = dA.Stop() })

	drvA, err := driver.Connect(sockAPath)
	if err != nil {
		t.Fatalf("drvA: %v", err)
	}
	t.Cleanup(func() { drvA.Close() })

	idBPath := filepath.Join(tmpDir, "id-b.json")
	sockBPath := filepath.Join(tmpDir, "b.sock")

	startB := func() *daemonHandle {
		t.Helper()
		cfg := mkCfg(sockBPath, idBPath, "b@lossy.local")
		d := daemon.New(cfg)
		rt := registerStandardPlugins(t, d, &cfg)
		if err := rt.StartPlugins(context.Background()); err != nil {
			t.Fatalf("B plugin: %v", err)
		}
		if err := d.Start(); err != nil {
			t.Fatalf("B start: %v", err)
		}
		t.Cleanup(func() { _ = d.Stop() })
		return &daemonHandle{Daemon: d, Runtime: rt}
	}

	bID := startB()
	drvB, err := driver.Connect(sockBPath)
	if err != nil {
		t.Fatalf("drvB: %v", err)
	}

	if _, err := drvA.Handshake(bID.Daemon.NodeID(), "lossy pre"); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	waitTrust(t, drvA, bID.Daemon.NodeID(), "A trusts B")
	waitTrust(t, drvB, dA.NodeID(), "B trusts A")

	const echoPort uint16 = 49494
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

	// Initial round-trip at 0% drop (handshake already done lossless).
	rtStart := time.Now()
	if err := roundTrip(drvB, addrA, echoPort, []byte("init"), 5*time.Second); err != nil {
		t.Fatalf("DIAG[drop=%d%%]: initial round-trip failed: %v", dropPct, err)
	}
	t.Logf("DIAG[drop=%d%%]: initial round-trip OK in %v (drop still 0%%)", dropPct, time.Since(rtStart))

	drvB.Close()
	if err := bID.Daemon.Stop(); err != nil {
		t.Fatalf("stop B: %v", err)
	}
	time.Sleep(250 * time.Millisecond)

	// Turn on loss BEFORE B comes back up.
	daemon.SetDiagDropRate(uint64(dropPct * 10))
	defer daemon.SetDiagDropRate(0)
	t.Logf("DIAG[drop=%d%%]: enabled drop_rate=%d per-mille; restarting B", dropPct, dropPct*10)
	_ = startB()

	drvB2, err := driver.Connect(sockBPath)
	if err != nil {
		t.Fatalf("drvB2: %v", err)
	}
	t.Cleanup(func() { drvB2.Close() })

	postStart := time.Now()
	deadline := postStart.Add(90 * time.Second)
	attempts := 0
	var postErr error
	for time.Now().Before(deadline) {
		attempts++
		postErr = roundTrip(drvB2, addrA, echoPort, []byte(fmt.Sprintf("p-%d", attempts)), 3*time.Second)
		if postErr == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	recovery := time.Since(postStart)
	if postErr != nil {
		t.Errorf("DIAG[drop=%d%%]: NEVER recovered in %v across %d attempts: %v",
			dropPct, recovery, attempts, postErr)
	} else {
		t.Logf("DIAG[drop=%d%%]: recovered in %v on attempt #%d (drop_rate=%d per-mille)",
			dropPct, recovery, attempts, dropPct*10)
	}
}

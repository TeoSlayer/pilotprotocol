// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/beacon"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

const (
	benchPayload   = 4 * 1024 * 1024 // 4 MB per bench iteration
	benchSmallPing = 512             // bytes per latency ping
	benchChunk     = 4096            // send chunk size
	benchPort      = uint16(9201)    // dedicated benchmark listener port
)

// benchEnv holds the shared infrastructure for benchmark tests.
type benchEnv struct {
	tmpDir   string
	Beacon   *beacon.Server
	Registry *registry.Server
	A, B     *DaemonInfo
}

// newBenchEnv creates and starts a complete benchmark environment with beacon,
// registry, and two daemons. Cleanup is registered via b.Cleanup.
func newBenchEnv(b *testing.B) *benchEnv {
	b.Helper()

	tmpDir, err := os.MkdirTemp("/tmp", "w4bench-")
	if err != nil {
		b.Fatalf("create temp dir: %v", err)
	}

	env := &benchEnv{tmpDir: tmpDir}

	// Start beacon on OS-assigned port.
	env.Beacon = beacon.New()
	go env.Beacon.ListenAndServe(":0")
	select {
	case <-env.Beacon.Ready():
	case <-time.After(5 * time.Second):
		b.Fatal("beacon failed to start within 5s")
	}
	beaconAddr := resolveLocalAddr(env.Beacon.Addr())

	// Start registry on OS-assigned port.
	env.Registry = registry.New(beaconAddr)
	env.Registry.SetAdminToken(TestAdminToken)
	go env.Registry.ListenAndServe(":0")
	select {
	case <-env.Registry.Ready():
	case <-time.After(5 * time.Second):
		b.Fatal("registry failed to start within 5s")
	}
	registryAddr := resolveLocalAddr(env.Registry.Addr())

	// startDaemon is a helper to launch a single daemon and connect a driver.
	startDaemon := func(idx int) *DaemonInfo {
		sockPath := filepath.Join(tmpDir, fmt.Sprintf("daemon-%d.sock", idx))
		identityPath := filepath.Join(tmpDir, fmt.Sprintf("identity-%d.json", idx))

		cfg := daemon.Config{
			RegistryAddr:        registryAddr,
			BeaconAddr:          beaconAddr,
			ListenAddr:          ":0",
			SocketPath:          sockPath,
			IdentityPath:        identityPath,
			Email:               fmt.Sprintf("bench-%d@pilot.local", idx),
			Public:              true,
			WebhookHTTPTimeout:  500 * time.Millisecond,
			WebhookRetryBackoff: 10 * time.Millisecond,
		}

		d := daemon.New(cfg)
		if err := d.Start(); err != nil {
			b.Fatalf("daemon %d start: %v", idx, err)
		}

		drv, err := driver.Connect(sockPath)
		if err != nil {
			b.Fatalf("driver %d connect: %v", idx, err)
		}

		return &DaemonInfo{Daemon: d, Driver: drv, SocketPath: sockPath}
	}

	env.A = startDaemon(0)
	env.B = startDaemon(1)

	b.Cleanup(func() {
		env.A.Driver.Close()
		env.B.Driver.Close()
		env.A.Daemon.Stop()
		env.B.Daemon.Stop()
		env.Beacon.Close()
		env.Registry.Close()
		os.RemoveAll(tmpDir)
	})

	return env
}

// lossProxy is a lossy UDP proxy that sits between two daemons, dropping
// packets with the configured probability.
type lossProxy struct {
	toB       *net.UDPConn // daemons A sends here; proxy forwards to realB
	toA       *net.UDPConn // daemon B sends here; proxy forwards to realA
	realAddrA *net.UDPAddr
	realAddrB *net.UDPAddr
	lossRate  float64
	rng       *rand.Rand
	stopped   atomic.Bool
}

// newLossProxy creates a lossy UDP proxy between addrA and addrB.
// After creation, wire daemons:
//
//	env.A.Daemon.AddTunnelPeer(env.B.Daemon.NodeID(), proxy.AddrForA())
//	env.B.Daemon.AddTunnelPeer(env.A.Daemon.NodeID(), proxy.AddrForB())
func newLossProxy(b testing.TB, addrA, addrB *net.UDPAddr, lossRate float64) *lossProxy {
	b.Helper()

	toB, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		b.Fatalf("lossProxy: listen toB: %v", err)
	}

	toA, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		toB.Close()
		b.Fatalf("lossProxy: listen toA: %v", err)
	}

	p := &lossProxy{
		toB:       toB,
		toA:       toA,
		realAddrA: addrA,
		realAddrB: addrB,
		lossRate:  lossRate,
		rng:       rand.New(rand.NewSource(42)),
	}

	// A → B forwarding goroutine.
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, _, err := toB.ReadFromUDP(buf)
			if p.stopped.Load() {
				return
			}
			if err != nil {
				return
			}
			if p.rng.Float64() < p.lossRate {
				continue
			}
			_, _ = toB.WriteTo(buf[:n], addrB)
		}
	}()

	// B → A forwarding goroutine.
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, _, err := toA.ReadFromUDP(buf)
			if p.stopped.Load() {
				return
			}
			if err != nil {
				return
			}
			if p.rng.Float64() < p.lossRate {
				continue
			}
			_, _ = toA.WriteTo(buf[:n], addrA)
		}
	}()

	b.Cleanup(p.Stop)

	return p
}

// AddrForA returns the proxy address that daemon A should use to reach B.
func (p *lossProxy) AddrForA() *net.UDPAddr {
	return p.toB.LocalAddr().(*net.UDPAddr)
}

// AddrForB returns the proxy address that daemon B should use to reach A.
func (p *lossProxy) AddrForB() *net.UDPAddr {
	return p.toA.LocalAddr().(*net.UDPAddr)
}

// Stop halts the proxy goroutines by setting the stopped flag and closing
// both UDP connections.
func (p *lossProxy) Stop() {
	p.stopped.Store(true)
	p.toB.Close()
	p.toA.Close()
}

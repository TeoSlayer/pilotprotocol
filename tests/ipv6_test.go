package tests

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/beacon"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// TestIPv6EndToEnd verifies that all Pilot components work over IPv6 loopback.
// The registry binds on [::1] and tunnels communicate over IPv6.
func TestIPv6EndToEnd(t *testing.T) {
	t.Parallel()
	// Skip if IPv6 loopback is unavailable
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	ln.Close()

	// Start beacon on wildcard so STUN discovery fails (standard pattern).
	// This ensures daemons register with their actual tunnel port.
	b := beacon.New()
	go b.ListenAndServe(":0")
	select {
	case <-b.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to start")
	}
	defer b.Close()
	beaconAddr := b.Addr().String()
	t.Logf("beacon on %s", beaconAddr)

	// Start registry on IPv6 loopback
	r := registry.New(beaconAddr)
	go r.ListenAndServe("[::1]:0")
	select {
	case <-r.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer r.Close()
	registryAddr := r.Addr().String()
	t.Logf("registry on %s (IPv6)", registryAddr)

	// Helper to start a daemon with tunnel on [::1]
	tmpDir := t.TempDir()
	startDaemon := func(idx int) (*daemon.Daemon, *driver.Driver) {
		t.Helper()
		sockPath := fmt.Sprintf("%s/d%d.sock", tmpDir, idx)
		d := daemon.New(daemon.Config{
			RegistryAddr: registryAddr,
			BeaconAddr:   beaconAddr,
			ListenAddr:   "[::1]:0",
			SocketPath:   sockPath,
			Public:       true,
		})
		if err := d.Start(); err != nil {
			t.Fatalf("daemon %d start: %v", idx, err)
		}
		drv, err := driver.Connect(sockPath)
		if err != nil {
			t.Fatalf("driver %d connect: %v", idx, err)
		}
		return d, drv
	}

	dA, drvA := startDaemon(0)
	defer dA.Stop()
	defer drvA.Close()
	t.Logf("daemon A: addr=%s node=%d", dA.Addr(), dA.NodeID())

	dB, drvB := startDaemon(1)
	defer dB.Stop()
	defer drvB.Close()
	t.Logf("daemon B: addr=%s node=%d", dB.Addr(), dB.NodeID())

	// Listen on port 1000 via daemon A
	lnA, err := drvA.Listen(1000)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	serverDone := make(chan string, 1)
	go func() {
		conn, err := lnA.Accept()
		if err != nil {
			serverDone <- fmt.Sprintf("accept: %v", err)
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			serverDone <- fmt.Sprintf("read: %v", err)
			return
		}
		received := string(buf[:n])
		conn.Write([]byte("echo:" + received))
		serverDone <- received
	}()

	// Dial from daemon B to daemon A over IPv6
	conn, err := drvB.DialAddr(dA.Addr(), 1000)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ipv6 works")); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	response := string(buf[:n])
	if response != "echo:ipv6 works" {
		t.Errorf("expected %q, got %q", "echo:ipv6 works", response)
	}
	t.Logf("IPv6 echo response: %q", response)

	select {
	case received := <-serverDone:
		if received != "ipv6 works" {
			t.Errorf("server received %q, want %q", received, "ipv6 works")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server timed out")
	}
}

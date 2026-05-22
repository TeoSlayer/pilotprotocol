// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/beacon"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	registry "github.com/pilot-protocol/rendezvous"
)

// protocolAddr constructs a protocol.Addr for the given network and node IDs.
func protocolAddr(network uint16, node uint32) protocol.Addr {
	return protocol.Addr{Network: network, Node: node}
}

// shortTempDir creates a temp dir under /tmp (short path) so Unix sockets
// don't blow past the 104-char SUN_PATH limit on macOS. Cleaned up via
// t.Cleanup. Falls back to t.TempDir() on platforms where /tmp doesn't
// work (Windows; the test then has whatever path length the runner gives).
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "mb-*")
	if err != nil {
		return t.TempDir()
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// startBeacon brings up a beacon on a chosen UDP port and returns its
// address once the listener is ready. Caller defers Close. Bound to
// 127.0.0.1 explicitly so STUN reflection doesn't return ::1 and force
// IPv6 dials between IPv4-bound daemons.
func startBeacon(t *testing.T) *beacon.Server {
	t.Helper()
	b := beacon.New()
	go func() {
		_ = b.ListenAndServe("127.0.0.1:0")
	}()
	select {
	case <-b.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to start")
	}
	t.Cleanup(func() { b.Close() })
	return b
}

// startRegistry brings up a registry pointing at the first beacon.
func startRegistry(t *testing.T, beaconAddr string) *registry.Server {
	t.Helper()
	r := registry.New(beaconAddr)
	go func() { _ = r.ListenAndServe("127.0.0.1:0") }()
	select {
	case <-r.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	t.Cleanup(func() { r.Close() })
	return r
}

// TestMultiBeaconBackCompatSingleEntryWorks: a daemon configured with
// the existing single-beacon syntax (`-beacon HOST:PORT`) must continue
// to register and exchange traffic with no behavior change.
func TestMultiBeaconBackCompatSingleEntryWorks(t *testing.T) {
	t.Parallel()
	b := startBeacon(t)
	r := startRegistry(t, b.Addr().String())

	tmpDir := shortTempDir(t)
	d := daemon.New(daemon.Config{
		RegistryAddr: r.Addr().String(),
		BeaconAddr:   b.Addr().String(), // SINGLE — existing format
		ListenAddr:   "127.0.0.1:0",
		SocketPath:   filepath.Join(tmpDir, "d.sock"),
		IdentityPath: filepath.Join(tmpDir, "id.json"),
		Email:        "single@pilot.local",
		Public:       true,
	})
	if err := d.Start(); err != nil {
		t.Fatalf("daemon start: %v", err)
	}
	defer d.Stop()

	drv, err := driver.Connect(filepath.Join(tmpDir, "d.sock"))
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	defer drv.Close()

	info, err := drv.Info()
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	nodeID := uint32(0)
	if v, ok := info["node_id"].(float64); ok {
		nodeID = uint32(v)
	}
	if nodeID == 0 {
		t.Fatalf("daemon never got a node_id; info=%+v", info)
	}
	t.Logf("single-beacon daemon registered: node_id=%d", nodeID)
}

// TestMultiBeaconCommaSeparatedRegisters: a daemon configured with
// `-beacon B1,B2` must successfully register. The picked beacon (one of
// the two, by hash-of-pubkey) needs to be reachable, and the other one
// is just there as a peer for the mesh.
func TestMultiBeaconCommaSeparatedRegisters(t *testing.T) {
	t.Parallel()
	b1 := startBeacon(t)
	b2 := startBeacon(t)
	// Registry uses b1 for its own beacon hookup; daemons get both.
	r := startRegistry(t, b1.Addr().String())

	tmpDir := shortTempDir(t)
	multiBeacon := fmt.Sprintf("%s,%s", b1.Addr(), b2.Addr())

	d := daemon.New(daemon.Config{
		RegistryAddr: r.Addr().String(),
		BeaconAddr:   multiBeacon,
		ListenAddr:   "127.0.0.1:0",
		SocketPath:   filepath.Join(tmpDir, "d.sock"),
		IdentityPath: filepath.Join(tmpDir, "id.json"),
		Email:        "multi@pilot.local",
		Public:       true,
	})
	if err := d.Start(); err != nil {
		t.Fatalf("daemon start: %v", err)
	}
	defer d.Stop()

	drv, err := driver.Connect(filepath.Join(tmpDir, "d.sock"))
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	defer drv.Close()

	info, err := drv.Info()
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	nodeID := uint32(0)
	if v, ok := info["node_id"].(float64); ok {
		nodeID = uint32(v)
	}
	if nodeID == 0 {
		t.Fatalf("multi-beacon daemon never got a node_id; info=%+v", info)
	}
	t.Logf("multi-beacon daemon registered: node_id=%d, beacons=%s", nodeID, multiBeacon)
}

// TestMultiBeaconTwoDaemonsExchangeTraffic is the actually-flows test.
// Two daemons configured with the same multi-beacon list register and
// exchange a payload. With FNV hashing, identical pubkeys would hit the
// same beacon, but each daemon has its OWN identity so the hash spreads
// them. We don't assert WHICH beacon each picked (that's an internal
// detail) — we assert that traffic survives the multi-beacon configuration.
func TestMultiBeaconTwoDaemonsExchangeTraffic(t *testing.T) {
	t.Parallel()
	b1 := startBeacon(t)
	b2 := startBeacon(t)
	r := startRegistry(t, b1.Addr().String())

	tmpDir := shortTempDir(t)
	multiBeacon := fmt.Sprintf("%s,%s", b1.Addr(), b2.Addr())

	startDaemon := func(idx int) *driver.Driver {
		t.Helper()
		sockPath := filepath.Join(tmpDir, fmt.Sprintf("d%d.sock", idx))
		idPath := filepath.Join(tmpDir, fmt.Sprintf("id%d.json", idx))
		d := daemon.New(daemon.Config{
			RegistryAddr: r.Addr().String(),
			BeaconAddr:   multiBeacon,
			ListenAddr:   "127.0.0.1:0",
			SocketPath:   sockPath,
			IdentityPath: idPath,
			Email:        fmt.Sprintf("multi-%d@pilot.local", idx),
			Public:       true,
		})
		if err := d.Start(); err != nil {
			t.Fatalf("daemon %d start: %v", idx, err)
		}
		t.Cleanup(func() { d.Stop() })
		drv, err := driver.Connect(sockPath)
		if err != nil {
			t.Fatalf("driver %d: %v", idx, err)
		}
		t.Cleanup(func() { drv.Close() })
		return drv
	}

	dA := startDaemon(0)
	dB := startDaemon(1)

	infoA, _ := dA.Info()
	infoB, _ := dB.Info()
	getID := func(m map[string]interface{}) uint32 {
		if v, ok := m["node_id"].(float64); ok {
			return uint32(v)
		}
		return 0
	}
	idA, idB := getID(infoA), getID(infoB)
	if idA == 0 || idB == 0 {
		t.Fatalf("daemons did not register: A=%+v B=%+v", infoA, infoB)
	}
	t.Logf("registered: A node=%d, B node=%d", idA, idB)

	// Exchange a payload via the data exchange port. Doesn't strictly
	// need relay (these are loopback daemons); the test asserts the
	// multi-beacon config doesn't break the basic daemon-daemon flow.
	// The hash-pick made the two daemons potentially talk to different
	// beacons; if the parsed list or pick logic is broken, registration
	// or this exchange would fail with "no beacon" / dial errors.
	const payload = "multi-beacon-flow-check-12345"
	respCh := make(chan string, 1)
	errCh := make(chan error, 1)
	listener, err := dB.Listen(7000)
	if err != nil {
		t.Fatalf("B listen: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			errCh <- fmt.Errorf("read: %w", err)
			return
		}
		respCh <- string(buf[:n])
	}()

	// Give the listener a beat to register.
	time.Sleep(200 * time.Millisecond)

	addr := protocolAddr(0, idB)
	conn, err := dA.DialAddr(addr, 7000)
	if err != nil {
		t.Fatalf("A→B dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case got := <-respCh:
		if got != payload {
			t.Fatalf("payload mismatch: got %q, want %q", got, payload)
		}
		t.Logf("multi-beacon flow OK: %d bytes A→B", len(payload))
	case err := <-errCh:
		t.Fatalf("listener error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatalf("payload never arrived; multi-beacon flow broken")
	}
}

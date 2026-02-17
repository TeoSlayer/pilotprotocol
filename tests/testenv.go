package tests

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/beacon"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// setClientSigner configures a registry client with a signer for the given identity.
// This is required for authenticated registry operations (H3 fix).
func setClientSigner(rc *registry.Client, id *crypto.Identity) {
	rc.SetSigner(func(challenge string) string {
		sig := id.Sign([]byte(challenge))
		return base64.StdEncoding.EncodeToString(sig)
	})
}

// resolveLocalAddr replaces wildcard hosts (::, 0.0.0.0, empty) with 127.0.0.1
// so that test daemons can actually connect to the local servers.
func resolveLocalAddr(addr net.Addr) string {
	s := addr.String()
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return s
	}
	if host == "" || host == "::" || host == "0.0.0.0" {
		return "127.0.0.1:" + port
	}
	return s
}

// TestAdminToken is the admin token used in tests for network creation.
const TestAdminToken = "test-admin-secret"

// TestEnv manages a complete Pilot Protocol test environment with
// OS-assigned ports and proper readiness signaling (no time.Sleep).
type TestEnv struct {
	t *testing.T

	Beacon   *beacon.Server
	Registry *registry.Server

	// Resolved addresses (only valid after Start)
	BeaconAddr   string
	RegistryAddr string
	AdminToken   string

	daemons []*daemon.Daemon
	drivers []*driver.Driver
	tmpDir  string
}

// DaemonInfo holds references for a started daemon and its driver.
type DaemonInfo struct {
	Daemon     *daemon.Daemon
	Driver     *driver.Driver
	SocketPath string
}

// NewTestEnv creates and starts a beacon + registry with OS-assigned ports.
// Call AddDaemon() to add daemons after creation.
func NewTestEnv(t *testing.T) *TestEnv {
	t.Helper()

	// Use /tmp for short socket paths — macOS limits unix socket paths to 104 bytes.
	// t.TempDir() paths include the full test name and can exceed this limit.
	tmpDir, err := os.MkdirTemp("/tmp", "w4-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}

	env := &TestEnv{
		t:      t,
		tmpDir: tmpDir,
	}

	// Start beacon on OS-assigned port
	env.Beacon = beacon.New()
	go env.Beacon.ListenAndServe(":0")
	select {
	case <-env.Beacon.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to start within 5s")
	}
	env.BeaconAddr = resolveLocalAddr(env.Beacon.Addr())

	// Start registry on OS-assigned port
	env.Registry = registry.New(env.BeaconAddr)
	env.Registry.SetAdminToken(TestAdminToken)
	env.AdminToken = TestAdminToken
	go env.Registry.ListenAndServe(":0")
	select {
	case <-env.Registry.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start within 5s")
	}
	env.RegistryAddr = resolveLocalAddr(env.Registry.Addr())

	t.Cleanup(func() {
		env.Close()
	})

	return env
}

// AddDaemon starts a daemon connected to this environment's registry/beacon.
// Optional config overrides can be applied via the opts function.
func (env *TestEnv) AddDaemon(opts ...func(*daemon.Config)) *DaemonInfo {
	env.t.Helper()

	idx := len(env.daemons)
	sockPath := filepath.Join(env.tmpDir, fmt.Sprintf("daemon-%d.sock", idx))

	cfg := daemon.Config{
		RegistryAddr: env.RegistryAddr,
		BeaconAddr:   env.BeaconAddr,
		ListenAddr:   ":0",
		SocketPath:   sockPath,
		Public:       true, // tests default to public for free connectivity
	}
	for _, fn := range opts {
		fn(&cfg)
	}

	d := daemon.New(cfg)
	if err := d.Start(); err != nil {
		env.t.Fatalf("daemon %d start: %v", idx, err)
	}
	env.daemons = append(env.daemons, d)

	drv, err := driver.Connect(sockPath)
	if err != nil {
		env.t.Fatalf("driver %d connect: %v", idx, err)
	}
	env.drivers = append(env.drivers, drv)

	return &DaemonInfo{Daemon: d, Driver: drv, SocketPath: sockPath}
}

// AddDaemonOnly starts a daemon without creating a driver (for tests that
// need to manage the driver lifecycle separately).
func (env *TestEnv) AddDaemonOnly(opts ...func(*daemon.Config)) (*daemon.Daemon, string) {
	env.t.Helper()

	idx := len(env.daemons)
	sockPath := filepath.Join(env.tmpDir, fmt.Sprintf("daemon-%d.sock", idx))

	cfg := daemon.Config{
		RegistryAddr: env.RegistryAddr,
		BeaconAddr:   env.BeaconAddr,
		ListenAddr:   ":0",
		SocketPath:   sockPath,
		Public:       true, // tests default to public for free connectivity
	}
	for _, fn := range opts {
		fn(&cfg)
	}

	d := daemon.New(cfg)
	if err := d.Start(); err != nil {
		env.t.Fatalf("daemon %d start: %v", idx, err)
	}
	env.daemons = append(env.daemons, d)

	return d, sockPath
}

// SocketPath returns a unique socket path within the temp directory.
func (env *TestEnv) SocketPath(name string) string {
	return filepath.Join(env.tmpDir, name+".sock")
}

// Close stops all drivers, daemons, and servers.
func (env *TestEnv) Close() {
	for _, drv := range env.drivers {
		drv.Close()
	}
	for _, d := range env.daemons {
		d.Stop()
	}
	env.Beacon.Close()
	env.Registry.Close()

	// Remove the temp directory and all socket files
	os.RemoveAll(env.tmpDir)
}

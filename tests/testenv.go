// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"context"
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
	registryclient "github.com/TeoSlayer/pilotprotocol/pkg/registry/client"
	registry "github.com/TeoSlayer/pilotprotocol/pkg/registry/server"
	"github.com/TeoSlayer/pilotprotocol/plugins/dataexchange"
	"github.com/pilot-protocol/eventstream"
	"github.com/TeoSlayer/pilotprotocol/plugins/handshake"
	"github.com/TeoSlayer/pilotprotocol/plugins/policy"
	pluginsruntime "github.com/TeoSlayer/pilotprotocol/plugins/runtime"
	"github.com/pilot-protocol/webhook"
)

// setClientSigner configures a registry client with a signer for the given identity.
// This is required for authenticated registry operations (H3 fix).
func setClientSigner(rc *registryclient.Client, id *crypto.Identity) {
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

	daemons  []*daemon.Daemon
	drivers  []*driver.Driver
	runtimes []*pluginsruntime.Runtime
	tmpDir   string
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
	identityPath := filepath.Join(env.tmpDir, fmt.Sprintf("identity-%d.json", idx))

	cfg := daemon.Config{
		RegistryAddr:        env.RegistryAddr,
		BeaconAddr:          env.BeaconAddr,
		ListenAddr:          ":0",
		SocketPath:          sockPath,
		IdentityPath:        identityPath, // persist identity to avoid pubkey mismatch on restart
		Email:               fmt.Sprintf("test-%d@pilot.local", idx),
		Public:              true,                   // tests default to public for free connectivity
		WebhookHTTPTimeout:  500 * time.Millisecond, // fast webhook timeouts for tests
		WebhookRetryBackoff: 10 * time.Millisecond,  // fast retry backoff for tests
	}
	for _, fn := range opts {
		fn(&cfg)
	}

	d := daemon.New(cfg)
	rt := registerStandardPlugins(env.t, d, &cfg)
	// T4.1: plugins must be subscribed to the bus BEFORE Daemon.Start
	// so the webhook plugin captures node.registered / agent.registered
	// (published from registerWithRegistry inside d.Start). Plugin
	// Start methods don't depend on d.Start having run; ports/tunnels
	// are constructed in daemon.New.
	if err := rt.StartPlugins(context.Background()); err != nil {
		env.t.Fatalf("daemon %d plugin startup: %v", idx, err)
	}
	if err := d.Start(); err != nil {
		env.t.Fatalf("daemon %d start: %v", idx, err)
	}
	env.daemons = append(env.daemons, d)
	env.runtimes = append(env.runtimes, rt)

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
	identityPath := filepath.Join(env.tmpDir, fmt.Sprintf("identity-%d.json", idx))

	cfg := daemon.Config{
		RegistryAddr:        env.RegistryAddr,
		BeaconAddr:          env.BeaconAddr,
		ListenAddr:          ":0",
		SocketPath:          sockPath,
		IdentityPath:        identityPath, // persist identity to avoid pubkey mismatch on restart
		Email:               fmt.Sprintf("test-%d@pilot.local", idx),
		Public:              true,                   // tests default to public for free connectivity
		WebhookHTTPTimeout:  500 * time.Millisecond, // fast webhook timeouts for tests
		WebhookRetryBackoff: 10 * time.Millisecond,  // fast retry backoff for tests
	}
	for _, fn := range opts {
		fn(&cfg)
	}

	d := daemon.New(cfg)
	rt := registerStandardPlugins(env.t, d, &cfg)
	// T4.1: see AddDaemon — plugins subscribe before d.Start.
	if err := rt.StartPlugins(context.Background()); err != nil {
		env.t.Fatalf("daemon %d plugin startup: %v", idx, err)
	}
	if err := d.Start(); err != nil {
		env.t.Fatalf("daemon %d start: %v", idx, err)
	}
	env.daemons = append(env.daemons, d)
	env.runtimes = append(env.runtimes, rt)

	return d, sockPath
}

// registerStandardPlugins wires the same L11 plugin set that
// cmd/daemon/main.go installs in production. Tests get the same
// behavior unless their cfg.Disable* flag is set, in which case the
// corresponding plugin is skipped. Returns the runtime so callers
// can call StartPlugins/StopPlugins around d.Start/d.Stop.
func registerStandardPlugins(t testingT, d *daemon.Daemon, cfg *daemon.Config) *pluginsruntime.Runtime {
	rt := pluginsruntime.New(d)
	if !cfg.DisableDataExchange {
		if err := rt.Register(dataexchange.NewService(dataexchange.ServiceConfig{})); err != nil {
			t.Fatalf("register dataexchange: %v", err)
		}
	}
	if !cfg.DisableEventStream {
		if err := rt.Register(eventstream.NewService()); err != nil {
			t.Fatalf("register eventstream: %v", err)
		}
	}
	if !cfg.DisablePolicyRunner {
		policySvc := policy.NewService(pluginsruntime.NewPolicyRuntime(d))
		if err := rt.Register(policySvc); err != nil {
			t.Fatalf("register policy: %v", err)
		}
		d.RegisterPolicyManager(pluginsruntime.AsDaemonPolicyManager(policySvc.Manager()))
	}
	// Handshake plugin (T3.3) — registered by default so production
	// behavior matches: tests that don't want it can flip a Disable*
	// flag on Config (none today, since smoke + e2e all need handshake).
	hsSvc := handshake.NewService(pluginsruntime.NewHandshakeRuntime(d))
	if err := rt.Register(hsSvc); err != nil {
		t.Fatalf("register handshake: %v", err)
	}
	d.RegisterHandshakeService(pluginsruntime.NewHandshakeServiceAdapter(hsSvc))
	// Webhook plugin (T4.1) — registered by default so any test that
	// sets cfg.WebhookURL gets the same dispatch path as production.
	// Tests that don't set WebhookURL see a no-op (Service starts but
	// its internal Client is nil).
	var webhookOpts []webhook.Option
	if cfg.WebhookHTTPTimeout > 0 {
		webhookOpts = append(webhookOpts, webhook.WithHTTPTimeout(cfg.WebhookHTTPTimeout))
	}
	if cfg.WebhookRetryBackoff > 0 {
		webhookOpts = append(webhookOpts, webhook.WithRetryBackoff(cfg.WebhookRetryBackoff))
	}
	webhookSvc := webhook.NewService(cfg.WebhookURL, webhookOpts...)
	if err := rt.Register(webhookSvc); err != nil {
		t.Fatalf("register webhook: %v", err)
	}
	d.RegisterWebhookManager(testWebhookAdapter{svc: webhookSvc})
	// trustedagents + skillinject left out of test default — most tests
	// don't exercise them and the embedded list fetch tries to reach
	// GitHub. Tests that need them register manually.
	return rt
}

// testWebhookAdapter bridges *webhook.Service to daemon.WebhookManager
// for the test harness. Mirrors the adapter cmd/daemon/main.go uses
// in production.
type testWebhookAdapter struct{ svc *webhook.Service }

func (a testWebhookAdapter) SetURL(url string) { a.svc.SetURL(url) }
func (a testWebhookAdapter) Stats() daemon.WebhookStats {
	s := a.svc.Stats()
	return daemon.WebhookStats{Dropped: s.Dropped, CircuitSkips: s.CircuitSkips}
}

// testingT is the minimal interface registerStandardPlugins needs.
// Defined here so we don't have to thread testing.TB through.
type testingT interface {
	Fatalf(format string, args ...interface{})
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
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	for _, rt := range env.runtimes {
		if err := rt.StopPlugins(stopCtx); err != nil {
			env.t.Logf("plugin shutdown error: %v", err)
		}
	}
	stopCancel()
	for _, d := range env.daemons {
		d.Stop()
	}
	env.Beacon.Close()
	env.Registry.Close()

	// Remove the temp directory and all socket files
	os.RemoveAll(env.tmpDir)
}

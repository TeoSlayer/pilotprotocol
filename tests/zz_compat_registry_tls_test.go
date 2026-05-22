// SPDX-License-Identifier: AGPL-3.0-or-later

// Compat-mode TLS-registry regression test. Spins up a registry server
// with an auto-generated self-signed cert and an in-process beacon
// with WSS bridge, then starts a compat daemon that pins the registry
// cert (using `-registry-trust=pinned` semantics — equivalent code
// path to the production `system` trust except we use a fingerprint
// instead of the OS root store, because the test cert is self-signed).
// Verifies that the registry channel completes a Register over TLS
// while the data plane goes over WSS — i.e. the v1.10.3 "compat mode
// is single-port-443-only" surface holds in code.
//
// For the system-trust path with a real Let's Encrypt cert, see
// docs/RUNBOOK-compat-443-only.md §6 (manual smoke-test against
// registry.pilotprotocol.network:443).

package tests

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	registry "github.com/pilot-protocol/rendezvous"
)

// TestCompatRegistryTLSPinned exercises the compat daemon's registry-tls
// code path end-to-end. The daemon uses `RegistryTrust=pinned` with the
// test cert's SHA-256 fingerprint; in production the same path runs with
// `RegistryTrust=system` against a Let's Encrypt cert at
// registry.pilotprotocol.network:443.
func TestCompatRegistryTLSPinned(t *testing.T) {
	t.Parallel()

	// Build beacon + WSS bridge (mirrors zz_compat_dial_test.go pattern).
	var regRef *registry.Server
	lookup := func(nodeID uint32) (ed25519.PublicKey, bool) {
		if regRef == nil {
			return nil, false
		}
		pk, ok := regRef.LookupPublicKey(nodeID)
		if !ok {
			return nil, false
		}
		return ed25519.PublicKey(pk), true
	}
	b, wssURL := startBeaconWithWSS(t, lookup)

	// Bring up a TLS-enabled registry with an auto self-signed cert.
	reg := registry.New(b.Addr().String())
	if err := reg.SetTLS("", ""); err != nil {
		t.Fatalf("SetTLS auto: %v", err)
	}
	go func() { _ = reg.ListenAndServe("127.0.0.1:0") }()
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	t.Cleanup(func() { reg.Close() })
	regRef = reg

	// Grab the registry's cert fingerprint so the test daemon can pin
	// it. In production the daemon uses RegistryTrust="system" against
	// a public CA cert — same Go code path, different trust store.
	tlsConn, err := tls.Dial("tcp", reg.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test handshake to read fingerprint
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("dial registry to read cert: %v", err)
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer cert presented")
	}
	hash := sha256.Sum256(state.PeerCertificates[0].Raw)
	fingerprint := hex.EncodeToString(hash[:])
	_ = tlsConn.Close()

	// Spin up the compat-mode daemon, pointing at the TLS registry.
	tmp := shortTempDir(t)
	sock := filepath.Join(tmp, "d.sock")
	d := daemon.New(daemon.Config{
		RegistryAddr:        reg.Addr().String(),
		RegistryTLS:         true,
		RegistryFingerprint: fingerprint,
		RegistryTrust:       "pinned",
		BeaconAddr:          b.Addr().String(),
		ListenAddr:          "127.0.0.1:0",
		SocketPath:          sock,
		IdentityPath:        filepath.Join(tmp, "id.json"),
		Email:               "compat-tls-test@pilot.local",
		Public:              true,
		Encrypt:             true,
		TransportMode:       "compat",
		CompatBeaconURL:     wssURL,
		CompatTLSTrust:      "system",
	})
	if err := d.Start(); err != nil {
		t.Fatalf("daemon start: %v", err)
	}
	t.Cleanup(func() { _ = d.Stop() })

	// Wait for registration + WSS to settle.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if d.NodeID() != 0 && b.WSSIsConnected(d.NodeID()) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if d.NodeID() == 0 {
		t.Fatalf("compat daemon never got a node_id from the TLS registry")
	}
	if !b.WSSIsConnected(d.NodeID()) {
		t.Fatalf("compat daemon %d not WSS-connected to beacon", d.NodeID())
	}

	// Sanity: pilotctl IPC works end-to-end (proves Register completed,
	// not just that the daemon started).
	drv, err := driver.Connect(sock)
	if err != nil {
		t.Fatalf("driver.Connect: %v", err)
	}
	defer drv.Close()
	info, err := drv.Info()
	if err != nil {
		t.Fatalf("Info via IPC: %v", err)
	}
	if v, _ := info["node_id"].(float64); uint32(v) == 0 {
		t.Fatalf("node_id zero in Info reply: %+v", info)
	}
	_ = protocol.Version // silence unused-import in case of future trim
}

// TestCompatRegistryTrustSystemRejectsBadCert pins that when
// RegistryTrust="system" is selected, the daemon refuses to dial a
// registry whose cert is not trusted by the OS root store. The
// production path against a real Let's Encrypt cert relies on this
// rejection to detect MITM attempts.
func TestCompatRegistryTrustSystemRejectsBadCert(t *testing.T) {
	t.Parallel()

	// Bring up a TLS registry with an auto self-signed cert (untrusted
	// by the OS root store by definition).
	reg := registry.New("127.0.0.1:0")
	if err := reg.SetTLS("", ""); err != nil {
		t.Fatalf("SetTLS auto: %v", err)
	}
	go func() { _ = reg.ListenAndServe("127.0.0.1:0") }()
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	t.Cleanup(func() { reg.Close() })

	tmp := shortTempDir(t)
	d := daemon.New(daemon.Config{
		RegistryAddr:  reg.Addr().String(),
		RegistryTLS:   true,
		RegistryTrust: "system", // OS root store — won't trust the self-signed cert
		ListenAddr:    "127.0.0.1:0",
		SocketPath:    filepath.Join(tmp, "d.sock"),
		IdentityPath:  filepath.Join(tmp, "id.json"),
		Email:         "compat-reject@pilot.local",
		Encrypt:       true,
		TransportMode: "udp", // simpler: registry-only check; beacon/WSS not needed here
	})
	// Start must fail (or, more precisely, the registry-dial loop must
	// exhaust its retries on TLS verify errors). Use a short window —
	// the daemon retries with exponential backoff but a self-signed
	// cert against system trust is a hard fail.
	startErr := make(chan error, 1)
	go func() { startErr <- d.Start() }()
	// The registry-dial loop retries up to maxRegistryDialAttempts (10) with
	// exponential backoff capped at 5s — full failure budget is ~40s once
	// the TLS handshake errors are factored in. Give it 75s.
	select {
	case err := <-startErr:
		if err == nil {
			t.Fatal("daemon Start succeeded against an untrusted self-signed cert; expected TLS verify failure")
		}
		// Successful rejection.
	case <-time.After(75 * time.Second):
		t.Fatal("daemon Start hung — registry-dial loop should have failed within retry budget")
	}
}

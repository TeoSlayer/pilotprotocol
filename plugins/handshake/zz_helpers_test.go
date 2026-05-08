// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	registryclient "github.com/TeoSlayer/pilotprotocol/pkg/registry/client"
	"github.com/TeoSlayer/pilotprotocol/tests/regtestutil"
)

// startTestRegistry is a thin alias for regtestutil.StartTestRegistry
// so the moved handshake tests keep the same short name they used in
// pkg/daemon. The fixture lives in tests/regtestutil to avoid an L11 →
// L11 cycle between plugins/handshake and pkg/registry/server.
var startTestRegistry = regtestutil.StartTestRegistry

// testRuntime is a hand-rolled Runtime built from primitive fields.
// Used by handshake unit tests that don't need a full daemon — the
// fake exposes setters so tests can install identities, registry
// clients, and the trust-auto-approve flag mid-test.
//
// Mirrors the production DaemonRuntime adapter shape so any code
// path that works against DaemonRuntime works here too.
type testRuntime struct {
	mu               sync.RWMutex
	nodeID           uint32
	identity         *crypto.Identity
	identityPath     string
	trustAutoApprove bool
	regClient        *registryclient.Client
	trustChecker     daemon.TrustChecker

	// Side-effect captures useful for test assertions. The handshake
	// manager has not historically asserted on event payloads inside
	// the moved tests, so this is mostly a sink.
	publishedMu sync.Mutex
	published   []publishedEvent

	// removeTunnelPeer is captured per call; tests can inspect.
	removedPeersMu sync.Mutex
	removedPeers   []uint32
}

type publishedEvent struct {
	Topic   string
	Payload map[string]any
}

func newTestRuntime() *testRuntime { return &testRuntime{} }

func (r *testRuntime) NodeID() uint32 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.nodeID
}

func (r *testRuntime) HasIdentity() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.identity != nil
}

func (r *testRuntime) PublicKey() ed25519.PublicKey {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.identity == nil {
		return nil
	}
	return r.identity.PublicKey
}

func (r *testRuntime) Sign(msg []byte) []byte {
	r.mu.RLock()
	id := r.identity
	r.mu.RUnlock()
	if id == nil {
		return nil
	}
	return id.Sign(msg)
}

func (r *testRuntime) IdentityPath() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.identityPath
}

func (r *testRuntime) TrustAutoApprove() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.trustAutoApprove
}

func (r *testRuntime) IsTrusted(nodeID uint32) (string, bool) {
	r.mu.RLock()
	tc := r.trustChecker
	r.mu.RUnlock()
	if tc == nil {
		return "", false
	}
	return tc.IsTrusted(nodeID)
}

func (r *testRuntime) PublishEvent(topic string, payload map[string]any) {
	r.publishedMu.Lock()
	r.published = append(r.published, publishedEvent{Topic: topic, Payload: payload})
	r.publishedMu.Unlock()
}

// PortListener / DialAndSend are all called from the listener-bind /
// send-message paths. The pure-logic tests don't exercise those paths,
// so the methods return errors that exercise the unhappy-path
// dial-failure logic in the manager (sendMessage returns an error →
// SendRequest falls through to relay).
func (r *testRuntime) PortListener(port uint16) (coreapi.Listener, error) {
	return nil, errStub("PortListener stub")
}

func (r *testRuntime) DialAndSend(peerNodeID uint32, port uint16, data []byte) error {
	return errStub("DialAndSend stub")
}

func (r *testRuntime) RemoveTunnelPeer(nodeID uint32) {
	r.removedPeersMu.Lock()
	r.removedPeers = append(r.removedPeers, nodeID)
	r.removedPeersMu.Unlock()
}

func (r *testRuntime) Registry() RegistryClient {
	r.mu.RLock()
	c := r.regClient
	r.mu.RUnlock()
	if c == nil {
		return nil
	}
	return c
}

// errStub is a small concrete error type so tests can identify it.
type errStub string

func (e errStub) Error() string { return string(e) }

// newTestHM returns a Manager wired to a bare testRuntime. identityPath
// can be "" to disable persistence.
func newTestHM(t *testing.T, identityPath string) *Manager {
	t.Helper()
	rt := newTestRuntime()
	rt.identityPath = identityPath
	return NewManager(rt)
}

// hsTestRuntime returns a runtime + manager wired to a real test
// registry, with self-identity registered. Use for tests where
// handleRequest or processMessage reaches sendAcceptLocked (which
// needs a non-nil registry).
func hsTestManager(t *testing.T, autoApprove bool) (*Manager, *testRuntime) {
	t.Helper()
	reg, rc := startTestRegistry(t)
	t.Cleanup(func() { reg.Close() })
	t.Cleanup(func() { rc.Close() })

	selfID, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("127.0.0.1:0", crypto.EncodePublicKey(selfID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register self: %v", err)
	}
	selfNodeID := uint32(resp["node_id"].(float64))

	rt := newTestRuntime()
	rt.identity = selfID
	rt.nodeID = selfNodeID
	rt.regClient = rc
	rt.trustAutoApprove = autoApprove
	rt.trustChecker = testTrustChecker{}

	hm := NewManager(rt)
	t.Cleanup(func() { hm.Stop() })
	return hm, rt
}

// testTrustChecker delegates to the package-global trustedagents
// allowlist (populated by setTestTrustedAgents).
type testTrustChecker struct{}

func (testTrustChecker) IsTrusted(nodeID uint32) (string, bool) {
	return testTrustedAgentsLookup(nodeID)
}

// waitForGoRPCDrain gives background goRPC goroutines time to fail
// cleanly (Resolve errors, dial-failure timeouts) before the test body
// exits.
func waitForGoRPCDrain() {
	time.Sleep(100 * time.Millisecond)
}

// testDaemonRuntime adapts *daemon.Daemon to Runtime for bootstrap tests
// that need real port-444 binding. Defined here (test-only) so the
// handshake package never imports plugins/runtime (L12).
type testDaemonRuntime struct{ d *daemon.Daemon }

func (r testDaemonRuntime) NodeID() uint32    { return r.d.NodeID() }
func (r testDaemonRuntime) HasIdentity() bool { return r.d.Identity() != nil }
func (r testDaemonRuntime) PublicKey() ed25519.PublicKey {
	id := r.d.Identity()
	if id == nil {
		return nil
	}
	return id.PublicKey
}
func (r testDaemonRuntime) Sign(msg []byte) []byte {
	id := r.d.Identity()
	if id == nil {
		return nil
	}
	return id.Sign(msg)
}
func (r testDaemonRuntime) IdentityPath() string   { return r.d.IdentityPath() }
func (r testDaemonRuntime) TrustAutoApprove() bool { return r.d.TrustAutoApprove() }
func (r testDaemonRuntime) IsTrusted(nodeID uint32) (string, bool) {
	tc := r.d.GetTrustChecker()
	if tc == nil {
		return "", false
	}
	return tc.IsTrusted(nodeID)
}
func (r testDaemonRuntime) PublishEvent(topic string, payload map[string]any) {
	r.d.PublishEvent(topic, payload)
}
func (r testDaemonRuntime) PortListener(port uint16) (coreapi.Listener, error) {
	ln, err := r.d.Ports().Bind(port)
	if err != nil {
		return nil, err
	}
	return &testDaemonListener{inner: ln, d: r.d}, nil
}
func (r testDaemonRuntime) DialAndSend(peerNodeID uint32, port uint16, data []byte) error {
	return errStub("DialAndSend stub")
}
func (r testDaemonRuntime) RemoveTunnelPeer(nodeID uint32) {
	r.d.Tunnels().RemovePeer(nodeID)
}
func (r testDaemonRuntime) Registry() RegistryClient { return nil }

// testDaemonListener wraps *daemon.Listener as coreapi.Listener.
type testDaemonListener struct {
	inner *daemon.Listener
	d     *daemon.Daemon
}

func (l *testDaemonListener) Accept() (coreapi.Stream, error) {
	conn, ok := <-l.inner.AcceptCh
	if !ok {
		return nil, errors.New("listener closed")
	}
	return &testStreamAdapter{d: l.d, conn: conn, rw: l.d.NewConnReadWriter(conn)}, nil
}
func (l *testDaemonListener) Close() error {
	l.d.Ports().Unbind(l.inner.Port)
	return nil
}
func (l *testDaemonListener) Addr() coreapi.Addr { return l.d.Addr() }
func (l *testDaemonListener) Port() uint16       { return l.inner.Port }

// testStreamAdapter wraps *daemon.Connection as coreapi.Stream.
type testStreamAdapter struct {
	d    *daemon.Daemon
	conn *daemon.Connection
	rw   daemon.ConnReadWriter
}

func (s *testStreamAdapter) Read(p []byte) (int, error)       { return s.rw.Read(p) }
func (s *testStreamAdapter) Write(p []byte) (int, error)      { return s.rw.Write(p) }
func (s *testStreamAdapter) Close() error                     { return s.rw.Close() }
func (s *testStreamAdapter) LocalAddr() coreapi.Addr          { return s.conn.LocalAddr }
func (s *testStreamAdapter) LocalPort() uint16                { return s.conn.LocalPort }
func (s *testStreamAdapter) RemoteAddr() coreapi.Addr         { return s.conn.RemoteAddr }
func (s *testStreamAdapter) RemotePort() uint16               { return s.conn.RemotePort }
func (s *testStreamAdapter) SetDeadline(time.Time) error      { return nil }
func (s *testStreamAdapter) SetReadDeadline(time.Time) error  { return nil }
func (s *testStreamAdapter) SetWriteDeadline(time.Time) error { return nil }

// Ensure protocol import is used (it's pulled in by coreapi.Addr alias).
var _ = protocol.ZeroAddr

// newDaemonBackedHM returns a Manager wired to a testDaemonRuntime over a
// bare *daemon.Daemon. Use for tests that need real port-444 binding
// (Start / accept-loop tests). Caller must call hm.Stop in cleanup.
func newDaemonBackedHM(t *testing.T) (*Manager, *daemon.Daemon) {
	t.Helper()
	d := daemon.New(daemon.Config{})
	rt := testDaemonRuntime{d: d}
	return NewManager(rt), d
}

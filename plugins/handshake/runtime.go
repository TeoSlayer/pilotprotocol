// SPDX-License-Identifier: AGPL-3.0-or-later

// Package handshake implements the manual trust-handshake protocol on
// port 444 (the Pilot Protocol PortHandshake well-known port).
//
// This is the higher-level "establish trust between two nodes" RPC, NOT
// the L5 wire-level key-exchange (which lives in pkg/daemon/tunnel.go).
// Two daemons that have not previously met exchange a JSON handshake
// message over a normal stream connection on port 444; both sides
// validate signatures, optionally consult an allowlist, and either
// auto-accept or stash the request for manual approval via pilotctl.
//
// Lifecycle: this plugin sits at L11. The composition root (cmd/daemon
// or test harness) constructs a Service via NewService(rt Runtime),
// registers it on the plugin runtime, and the daemon's Start() spawns
// the listener on PortHandshake via deps.Streams.Listen.
//
// Daemon coupling has been replaced by the Runtime interface below.
// The daemon-side adapter lives in daemon_runtime.go.
package handshake

import (
	"crypto/ed25519"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
)

// Runtime is the primitives-only contract the handshake manager needs
// from the surrounding daemon. Every dependency that crossed the old
// `hm.daemon.X` boundary now flows through one of these methods.
//
// The DaemonRuntime adapter (daemon_runtime.go) wraps a *daemon.Daemon
// to satisfy this interface. Tests can substitute a fake runtime to
// exercise the manager in isolation.
type Runtime interface {
	// NodeID returns this daemon's stable node ID. Returns 0 if
	// identity has not been initialized yet.
	NodeID() uint32

	// HasIdentity reports whether the daemon has loaded an Ed25519
	// identity. SendRequest / signing paths early-return when false.
	HasIdentity() bool

	// PublicKey returns the local Ed25519 public key (for inclusion in
	// outbound HandshakeMsg.PublicKey). Returns nil when HasIdentity is
	// false.
	PublicKey() ed25519.PublicKey

	// Sign signs the given payload with the local Ed25519 private key.
	// Returns nil when HasIdentity is false; callers handle that as
	// "no signature attached".
	Sign(msg []byte) []byte

	// IdentityPath returns the configured on-disk identity path; the
	// trust.json store sits in the same directory. Empty when the
	// daemon runs in-memory only (no persistence).
	IdentityPath() string

	// TrustAutoApprove reports whether the daemon was configured to
	// auto-approve all incoming handshake requests (trust-on-first-use
	// stance for friendly fleets).
	TrustAutoApprove() bool

	// IsTrusted consults the trustedagents allowlist. Returns the
	// agent's display name and ok=true on a match. Returns "", false
	// when no checker has been registered (treated as "not trusted").
	IsTrusted(nodeID uint32) (name string, ok bool)

	// PublishEvent emits a topic+payload event onto the daemon's event
	// bus. Non-blocking; events may be dropped under bus pressure.
	PublishEvent(topic string, payload map[string]any)

	// PortListener binds the given well-known port and returns a
	// daemon.Listener. The handshake plugin uses this for PortHandshake.
	PortListener(port uint16) (*daemon.Listener, error)

	// PortUnbind releases a previously-bound port. Called from Stop().
	PortUnbind(port uint16)

	// DialAndSend establishes a stream to (peerNodeID, port), writes
	// the JSON-encoded message, and closes after a brief grace period
	// to let the data flush. Wraps the daemon's DialConnection +
	// SendData + CloseConnection trio so the manager doesn't need to
	// handle *daemon.Connection directly.
	DialAndSend(peerNodeID uint32, port uint16, data []byte) error

	// RemoveTunnelPeer tears down the encrypted tunnel for the given
	// peer. Called from RevokeTrust so a revoked peer's tunnel state
	// (session keys, retransmit queues) is purged immediately.
	RemoveTunnelPeer(nodeID uint32)

	// Registry returns the L8 registry-side-channel client used for
	// peer lookups, trust-pair reporting, and relay-based handshake
	// when direct dial fails. Returns nil when the daemon is offline
	// or running without a registry connection — callers must nil-check.
	Registry() RegistryClient
}

// RegistryClient is the subset of pkg/registry/client.Client the
// handshake manager uses. Defined here as an interface so the manager
// stays free of import cycles and tests can supply a fake.
//
// Method signatures match *registry/client.Client exactly, so the
// daemon adapter can return the underlying client directly.
type RegistryClient interface {
	Lookup(nodeID uint32) (map[string]interface{}, error)
	ReportTrust(nodeID, peerID uint32) (map[string]interface{}, error)
	RevokeTrust(nodeID, peerID uint32) (map[string]interface{}, error)
	RequestHandshake(fromNodeID, toNodeID uint32, justification, signatureB64 string) (map[string]interface{}, error)
	RespondHandshake(nodeID, peerID uint32, accept bool, signatureB64 string) (map[string]interface{}, error)
	PollHandshakes(nodeID uint32) (map[string]interface{}, error)
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import "time"

// This file declares the daemon-local plugin-handle contract. Each
// interface is primitive-only (no struct or interface types from
// pkg/coreapi in any signature) so plugin implementations satisfy
// these via Go's structural typing — daemon never imports
// pkg/coreapi (T7.1).
//
// Plugins still implement coreapi.X for the canonical contract;
// pkg/coreapi.PolicyEventType is a type alias to `string` so the
// signatures match exactly across both interfaces.

// PolicyEventType is the kind of protocol event a policy is evaluated
// against. Type alias to string mirrors coreapi.PolicyEventType so
// plugin signatures match exactly via structural typing (T7.1).
type PolicyEventType = string

// PolicyEvent* are the event-type constants daemon code passes into
// PolicyManager / PolicyRunner. Match coreapi.PolicyEvent* values
// since both are aliases of string.
const (
	PolicyEventConnect  = "connect"
	PolicyEventDial     = "dial"
	PolicyEventDatagram = "datagram"
	PolicyEventJoin     = "join"
	PolicyEventLeave    = "leave"
	PolicyEventCycle    = "cycle"
)

// TrustChecker is the daemon-facing surface of the trustedagents
// plugin. The handshake handler consults this for auto-accept.
type TrustChecker interface {
	IsTrusted(nodeID uint32) (string, bool)
}

// HandshakeService is the daemon-facing surface of the manual
// trust-handshake plugin (port 444). The plugin's *Manager satisfies
// this via Go's structural typing — daemon never imports
// plugins/handshake (T3.3).
//
// All trust-handshake operations route through this interface: IPC
// command dispatch (ipc.go), trust-gate checks on inbound SYN /
// datagrams, registry-relay polling, and trust-pair re-sync after
// reconnect.
type HandshakeService interface {
	IsTrusted(nodeID uint32) bool
	TrustedPeers() []HandshakeTrustRecord
	PendingRequests() []HandshakePendingRecord
	PendingCount() int
	SendRequest(peerNodeID uint32, justification string) error
	ApproveHandshake(peerNodeID uint32) error
	RejectHandshake(peerNodeID uint32, reason string) error
	RevokeTrust(peerNodeID uint32) error

	// WaitForTrust blocks until the peer transitions to trusted, or the
	// timeout elapses. Returns true if trust was granted in time.
	// Wired through SubHandshakeWait so callers (typically pilotctl
	// before a first send to a trusted-list peer) can block bidirectional
	// operations on trust establishment instead of racing the data send
	// against the handshake reply.
	WaitForTrust(peerNodeID uint32, timeout time.Duration) bool

	// ProcessRelayedRequest / ProcessRelayedApproval / ProcessRelayedRejection
	// are invoked from Daemon.pollRelayedHandshakes after parsing the
	// registry-inbox payload.
	ProcessRelayedRequest(fromNodeID uint32, justification string)
	ProcessRelayedApproval(fromNodeID uint32)
	ProcessRelayedRejection(fromNodeID uint32)

	// Stop drains background RPCs and stops the replay reaper.
	Stop()
}

// HandshakeTrustRecord mirrors plugins/handshake.TrustRecord so the
// daemon-local HandshakeService interface stays primitive-only (no
// upward import). Field set is identical to the plugin's TrustRecord
// — Go's structural typing matches []HandshakeTrustRecord against the
// plugin method's []handshake.TrustRecord because the field shapes
// align, but only if the slices use the same named type. The plugin's
// adapter therefore returns a converted []HandshakeTrustRecord built
// from its own TrustRecord values.
type HandshakeTrustRecord struct {
	NodeID     uint32
	PublicKey  string
	ApprovedAt time.Time
	Mutual     bool
	Network    uint16
}

// HandshakePendingRecord mirrors plugins/handshake.PendingHandshake
// for the same reason as HandshakeTrustRecord above.
type HandshakePendingRecord struct {
	NodeID        uint32
	PublicKey     string
	Justification string
	ReceivedAt    time.Time
}

// PolicyRunner is the daemon-facing surface of a single network's
// running policy. The plugin's concrete *PolicyRunner satisfies this
// via structural typing.
type PolicyRunner interface {
	NetworkID() uint16
	HasMember(peerNodeID uint32) bool

	// EvaluatePortGate takes a string event-type ("connect", "dial",
	// "datagram", ...). plugins/policy.EventType is a type alias to
	// coreapi.PolicyEventType which is itself a type alias to string —
	// so plugin signatures match this exactly.
	EvaluatePortGate(eventType string, port uint16, peerNodeID uint32, payloadSize int, direction string, localTags, nodeInfoTags []string) bool

	EvaluateActions(eventType string, ctx map[string]any)
	Status() map[string]any
	PeerList() []map[string]interface{}
	ForceCycle() map[string]any
	ReconcileNow()
	PolicyJSON() ([]byte, error)
	Stop()
}

// PolicyManager owns the per-network registry of policy runners.
type PolicyManager interface {
	Start(netID uint16, policyJSON []byte) (PolicyRunner, error)
	Stop(netID uint16)
	Get(netID uint16) PolicyRunner
	All() []PolicyRunner
	StopAll()
	LoadPersisted() error
}

// WebhookManager is the daemon-local face of the webhook plugin
// (plugins/webhook). The plugin owns the HTTP client; daemon only
// needs to (a) hot-swap the URL when IPC's set-webhook fires and
// (b) read counters for the DaemonInfo health snapshot.
//
// Defined as an interface so daemon stays free of any plugin import
// (T4.1 webhook-inversion). cmd/daemon/main.go registers an adapter
// that satisfies this interface from plugins/webhook.Service.
type WebhookManager interface {
	// SetURL hot-swaps the active webhook URL. Empty URL disables
	// delivery (no-op until set again).
	SetURL(url string)

	// Stats returns dispatcher counters for daemon Info. All-zero
	// when no client is configured (nil-safe at the plugin level).
	Stats() WebhookStats
}

// WebhookStats is the daemon-local mirror of plugins/webhook.Stats.
// Same shape, different package — daemon can hold the value type
// without importing the plugin.
type WebhookStats struct {
	Dropped      uint64
	CircuitSkips uint64
}

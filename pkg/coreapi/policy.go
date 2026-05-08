// SPDX-License-Identifier: AGPL-3.0-or-later

package coreapi

// PolicyEventType is the kind of protocol event a policy is evaluated
// against. Type alias to string so daemon-local primitive interfaces
// can satisfy plugin signatures via structural typing without importing
// this package (T7.1).
type PolicyEventType = string

const (
	PolicyEventConnect  = "connect"
	PolicyEventDial     = "dial"
	PolicyEventDatagram = "datagram"
	PolicyEventJoin     = "join"
	PolicyEventLeave    = "leave"
	PolicyEventCycle    = "cycle"
)

// PolicyRunner is the daemon-facing surface of a single network's
// running policy. The plugin's concrete *PolicyRunner type implements
// this. The daemon never holds the concrete type — only this interface.
type PolicyRunner interface {
	NetworkID() uint16

	// HasMember returns true if peerNodeID is in this runner's
	// per-peer state. The daemon iterates all runners to consult
	// every network the peer belongs to (deny wins across networks).
	HasMember(peerNodeID uint32) bool

	// EvaluatePortGate is the daemon-facing gate API for inbound SYN
	// (Connect), outbound SYN (Dial), and datagram (in/out) events.
	// The plugin builds the per-peer ctx internally (peer_age_s,
	// peer_tags, members) using its peer state and the
	// daemon-supplied localTags + nodeInfoTags. Returns the
	// allow/deny verdict (default allow on no explicit deny).
	EvaluatePortGate(eventType PolicyEventType, port uint16, peerNodeID uint32, payloadSize int, direction string, localTags, nodeInfoTags []string) bool

	// EvaluateActions runs an action-event (cycle/join/leave) with a
	// caller-built ctx. Side-effect-only: no return value.
	EvaluateActions(eventType PolicyEventType, ctx map[string]any)

	Status() map[string]any
	PeerList() []map[string]any
	ForceCycle() map[string]any
	ReconcileNow()

	// PolicyJSON returns the marshaled policy document. Used by IPC
	// handlers that read the current policy back to admin tools.
	PolicyJSON() ([]byte, error)

	Stop()
}

// PolicyManager owns the per-network registry of policy runners. The
// daemon holds it as an interface field; cmd/daemon (L12) constructs
// the concrete plugin and calls Daemon.RegisterPolicyManager.
type PolicyManager interface {
	// Start compiles a policy JSON for the given network and registers
	// a runner. Returns the runner handle; existing runners for the
	// same network are stopped first.
	Start(netID uint16, policyJSON []byte) (PolicyRunner, error)

	// Stop stops the runner for netID (no-op if absent).
	Stop(netID uint16)

	// Get returns the runner for netID or nil.
	Get(netID uint16) PolicyRunner

	// All returns a snapshot of all running runners.
	All() []PolicyRunner

	// StopAll stops every runner. Called during daemon shutdown.
	StopAll()

	// LoadPersisted runs at daemon-Start to restore runners from disk.
	LoadPersisted() error
}

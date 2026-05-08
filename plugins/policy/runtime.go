// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import "time"

// Runtime is the per-daemon callback surface the policy runner needs
// to interact with daemon state (identity, trust subsystem, registry,
// event bus). The daemon (L7) implements this interface; the policy
// plugin (L11) calls into it via a stored reference. This inverts the
// previous *Daemon embedding so the runner code lives outside
// pkg/daemon without taking an L7-typed parameter.
type Runtime interface {
	// NodeID returns the daemon's own node ID.
	NodeID() uint32

	// PublishEvent is the bus.Publish wrapper.
	PublishEvent(topic string, payload map[string]any)

	// AdminToken returns the token used for authenticated registry ops
	// (list_nodes, set_member_tags). Empty when not configured.
	AdminToken() string

	// ListNodes returns the registry-side membership for a network.
	// Caller must already hold any required signature/admin auth via
	// the runtime's regConn signer.
	ListNodes(netID uint16, adminToken string) (map[string]any, error)

	// SetMemberTags updates the local node's per-network tag list.
	SetMemberTags(netID uint16, tags []string)

	// TrustedPeers returns the current trust map.
	TrustedPeers() []TrustRecord

	// RevokeTrust removes a peer from the trust list.
	RevokeTrust(nodeID uint32) error

	// SendHandshakeRequest initiates a trust handshake to the peer.
	SendHandshakeRequest(nodeID uint32, reason string) error
}

// TrustRecord is the runtime view of a single trusted peer. Mirrors
// pkg/daemon.TrustRecord (which the daemon-side Runtime adapter
// converts to). Defined here so the runner doesn't import pkg/daemon.
type TrustRecord struct {
	NodeID     uint32
	PublicKey  string
	ApprovedAt time.Time
	Mutual     bool
	Network    uint16
}

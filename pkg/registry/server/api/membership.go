// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"encoding/json"
	"time"
)

// Role is a member's permission level within a network. Values are
// the same string constants used today by server.Role.
type Role string

const (
	RoleOwner  Role = "owner"  // created the network, full control
	RoleAdmin  Role = "admin"  // can invite, remove members, change settings
	RoleMember Role = "member" // can communicate, cannot manage
)

// NetworkInvite is a read-only snapshot of a pending network invitation
// in the registry's invite inbox. Field shape mirrors
// pkg/registry/server.NetworkInvite for mechanical adoption.
type NetworkInvite struct {
	NetworkID uint16    `json:"network_id"`
	InviterID uint32    `json:"inviter_id"`
	Timestamp time.Time `json:"timestamp"`
}

// NetworkInfo is a read-only snapshot of a network record.
//
// Field shape mirrors pkg/registry/server.NetworkInfo. The server
// type's *wire.NetworkRules pointer is represented here as the
// marshaled rules document (json.RawMessage); a nil/empty value means
// the network has no managed rules. Internal atomic counters
// (requestCount) are intentionally absent from the snapshot.
type NetworkInfo struct {
	ID          uint16
	Name        string
	JoinRule    string
	Token       string // for token-gated networks
	Members     []uint32
	MemberRoles map[uint32]Role     // per-member RBAC roles
	MemberTags  map[uint32][]string // admin-assigned per-member tags
	AdminToken  string              // per-network admin token (optional)
	Policy      NetworkPolicy       // network policy (limits, port restrictions)
	Rules       json.RawMessage     // managed network rules document (nil = none)
	ExprPolicy  json.RawMessage     // programmable policy engine document (nil = none)
	Enterprise  bool                // enterprise network (gates phase 2-5 features)
	Created     time.Time
}

// MembershipView is the read-only contract over the registry's
// membership store. R7 (dashboard) and R4 (authz role check) consume
// this; only the membership store package produces it.
//
// Implementations must be safe for concurrent use.
type MembershipView interface {
	// GetNetwork returns a snapshot of the network and true if present.
	GetNetwork(networkID uint16) (*NetworkInfo, bool)

	// Count returns the total number of networks.
	Count() int

	// Networks returns a snapshot slice of every network.
	Networks() []*NetworkInfo

	// Members returns the node IDs that belong to networkID. Returns
	// nil if the network does not exist.
	Members(networkID uint16) []uint32

	// NetworksFor returns the network IDs nodeID is a member of.
	NetworksFor(nodeID uint32) []uint16

	// MemberRole returns the member's role in the network. The error
	// is non-nil when the network or membership does not exist.
	MemberRole(networkID uint16, nodeID uint32) (Role, error)

	// MemberTags returns the admin-assigned tags for the member.
	// Returns nil when no tags are set or the membership is absent.
	MemberTags(networkID uint16, nodeID uint32) []string

	// PendingInvites returns the count of pending network invites in
	// the node's inbox.
	PendingInvites(nodeID uint32) int
}

// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wal — this file defines the delta payload structs used by the WAL.
// Each struct corresponds to a DeltaType constant and carries the data needed
// to reconstruct that mutation on replay. These are pure data types with no
// dependency on the registry Server; they are moved here as part of R6.2.

package wal

// registerDelta carries the full state needed to recreate a new-node
// registration. Captured at the new-node assignment site (handleRegister)
// so a crash before flushSave doesn't reassign the same identity to a
// different node_id.
type RegisterDelta struct {
	NodeID    uint32   `json:"node_id"`
	Owner     string   `json:"owner,omitempty"`
	PublicKey string   `json:"public_key"` // base64
	RealAddr  string   `json:"real_addr,omitempty"`
	Hostname  string   `json:"hostname,omitempty"`
	LANAddrs  []string `json:"lan_addrs,omitempty"`
	Version   string   `json:"version,omitempty"`
	CreatedAt string   `json:"created_at,omitempty"` // RFC3339
}

// DeregisterDelta marks a node as removed.
type DeregisterDelta struct {
	NodeID uint32 `json:"node_id"`
}

// NetworkCreateDelta captures the parameters of a freshly-created network.
// Member set is empty at creation; the creator is added by a separate
// join delta if applicable.
type NetworkCreateDelta struct {
	NetworkID     uint16 `json:"network_id"`
	Name          string `json:"name"`
	JoinRule      string `json:"join_rule"`
	Token         string `json:"token,omitempty"`
	AdminToken    string `json:"admin_token,omitempty"`
	Enterprise    bool   `json:"enterprise,omitempty"`
	CreatorNodeID uint32 `json:"creator_node_id,omitempty"`
	CreatedAt     string `json:"created_at"` // RFC3339
}

// NetworkDeleteDelta marks a network as removed.
type NetworkDeleteDelta struct {
	NetworkID uint16 `json:"network_id"`
}

// NetworkMembershipDelta covers join AND leave; direction encoded in the
// DeltaType (DeltaNetworkJoin / DeltaNetworkLeave).
type NetworkMembershipDelta struct {
	NodeID    uint32 `json:"node_id"`
	NetworkID uint16 `json:"network_id"`
}

// KeyRotationDelta records a key rotation so the new pubkey survives a crash.
type KeyRotationDelta struct {
	NodeID       uint32 `json:"node_id"`
	NewPublicKey string `json:"new_public_key"` // base64
	RotatedAt    string `json:"rotated_at"`     // RFC3339
}

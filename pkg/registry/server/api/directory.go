// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import "time"

// NodeInfo is a read-only snapshot of a directory entry.
//
// Field shape mirrors pkg/registry/server.NodeInfo so that adoption
// (in later extraction tiers) is mechanical: the directory store will
// either type-alias api.NodeInfo or copy fields into it on read. The
// internal atomic counters that today live on server.NodeInfo
// (lastSeenNano, lastVerifiedNano) are intentionally absent — readers
// receive the resolved LastSeen value, not the raw atomic.
type NodeInfo struct {
	ID         uint32
	Owner      string // email or identifier (for key rotation)
	PublicKey  []byte
	RealAddr   string
	Networks   []uint16
	LastSeen   time.Time
	Public     bool   // if true, endpoint is visible in lookup/list_nodes
	Hostname   string // unique hostname for discovery (empty = none)
	Tags       []string
	TaskExec   bool     // node advertises task execution capability
	LANAddrs   []string // LAN addresses for same-network peer detection
	KeyMeta    KeyInfo  // key lifecycle metadata
	ExternalID string   // verified external identity (e.g., OIDC sub)
	Version    string   // binary version reported by daemon
	RelayOnly  bool     // peers must reach this node via beacon relay only
}

// DirectoryView is the read-only contract over the registry's directory
// store. R7 (dashboard, metrics) and R4 (authz) consume this; only the
// directory store package produces it.
//
// Implementations must be safe for concurrent use; callers may call
// any method from any goroutine without external synchronization.
type DirectoryView interface {
	// GetNode returns a snapshot of the node and true if present.
	GetNode(nodeID uint32) (*NodeInfo, bool)

	// NodeCount returns the total number of registered nodes.
	NodeCount() int

	// List returns a snapshot slice of every node. The returned slice
	// is owned by the caller; mutations do not affect the store.
	List() []*NodeInfo

	// Online returns the count of nodes whose LastSeen is at or after
	// threshold (i.e., considered live).
	Online(threshold time.Time) int

	// TaskExecutorCount returns the number of nodes advertising task
	// execution capability.
	TaskExecutorCount() int

	// LookupByPubKey returns the nodeID owning the given base64-encoded
	// Ed25519 public key. The bool is false on miss.
	LookupByPubKey(pubKeyB64 string) (uint32, bool)

	// LookupByHostname returns the nodeID with the given unique
	// hostname. The bool is false on miss.
	LookupByHostname(name string) (uint32, bool)
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package api

// NetworkPolicy is a read-only snapshot of a network's policy
// constraints. Field shape mirrors pkg/registry/server.NetworkPolicy
// for mechanical adoption.
type NetworkPolicy struct {
	MaxMembers   int      `json:"max_members"`   // 0 = unlimited
	AllowedPorts []uint16 `json:"allowed_ports"` // empty = all ports allowed
	Description  string   `json:"description"`   // human-readable description
}

// PolicyView is the read-only contract over the registry's per-network
// policy store. R7 and R4 consume this; only the policy store package
// produces it.
//
// Implementations must be safe for concurrent use.
type PolicyView interface {
	// Get returns the policy for networkID and true if set.
	Get(networkID uint16) (*NetworkPolicy, bool)

	// GetExpr returns the marshaled expression-policy document for
	// networkID, or (nil, false) when none is set. The bytes are
	// owned by the caller and may be retained or mutated freely.
	GetExpr(networkID uint16) ([]byte, bool)
}

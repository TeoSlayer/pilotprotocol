// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import "time"

// KeyInfo is a read-only snapshot of a node's key lifecycle metadata,
// surfaced for compliance reporting and trust decisions. Field shape
// mirrors pkg/registry/server.KeyInfo for mechanical adoption.
type KeyInfo struct {
	CreatedAt   time.Time `json:"created_at"`
	RotatedAt   time.Time `json:"rotated_at,omitempty"` // zero if never rotated
	RotateCount int       `json:"rotate_count"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"` // zero = no expiry
}

// IdentityView is the read-only contract over the registry's identity
// store (key lifecycle, IDP configuration). R7 (dashboard) and R4
// consume this; only the identity store package produces it.
//
// Implementations must be safe for concurrent use.
type IdentityView interface {
	// Configured reports whether an external IDP integration is set
	// up (mirrors today's "idpConfig != nil" check on Server).
	Configured() bool

	// GetKeyInfo returns the lifecycle metadata for nodeID's current
	// key and true if present.
	GetKeyInfo(nodeID uint32) (*KeyInfo, bool)
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package coreapi

// TrustChecker is the trusted-agents gate consumed by L11/tasks (and
// any other plugin that gates on peer reputation).
//
// IsTrusted: returns true if the peer is on the auto-approve allowlist
// (loaded from the trusted-agents JSON, refreshed hourly).
type TrustChecker interface {
	// IsTrusted reports whether the peer is on the auto-approve allowlist.
	// Returns the agent's display name when known. Both return values are
	// zero on miss.
	IsTrusted(nodeID uint32) (name string, ok bool)
}

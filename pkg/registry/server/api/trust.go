// SPDX-License-Identifier: AGPL-3.0-or-later

package api

// TrustView is the read-only contract over the registry's trust-pair
// store. R7 (dashboard) and R4 (authz) consume this; only the trust
// store package produces it.
//
// Implementations must be safe for concurrent use.
type TrustView interface {
	// Count returns the total number of trust pairs currently stored.
	Count() int

	// IsTrusted reports whether nodes a and b have an established
	// trust pair. The relation is symmetric: IsTrusted(a, b) ==
	// IsTrusted(b, a).
	IsTrusted(a, b uint32) bool
}

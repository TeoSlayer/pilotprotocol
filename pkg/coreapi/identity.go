// SPDX-License-Identifier: AGPL-3.0-or-later

package coreapi

import "crypto/ed25519"

// Identity is the daemon's own identity — its Ed25519 keypair, its
// stable nodeID, its 48-bit address. Plugins may sign arbitrary bytes
// (e.g., for plugin-level auth proofs) but cannot replace the identity.
type Identity interface {
	NodeID() uint32
	Address() Addr
	PublicKey() ed25519.PublicKey
	Sign(msg []byte) ([]byte, error)
}

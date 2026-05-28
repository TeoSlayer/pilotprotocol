// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange

import (
	"encoding/binary"

	"github.com/pilot-protocol/common/protocol"
)

// Wire-format constants. Frozen — golden-corpus tested.
const (
	// authKeyExchangeFrameSize is the on-wire size of an authenticated
	// key exchange (PILA): 4 magic + 4 nodeID + 32 X25519 + 32 Ed25519
	// + 64 signature.
	authKeyExchangeFrameSize = 4 + 4 + 32 + 32 + 64

	// keyExchangeFrameSize is the on-wire size of an unauthenticated
	// key exchange (PILK): 4 magic + 4 nodeID + 32 X25519.
	keyExchangeFrameSize = 4 + 4 + 32
)

// authChallenge builds the bytes signed by a peer's Ed25519 identity in
// the authenticated key-exchange handshake. Format: "auth"(4) ||
// nodeID(4 BE) || X25519-pubkey(32). Used by both sides — sender
// (BuildAuthFrame) signs it, receiver (HandleAuthFrame) verifies it.
func authChallenge(nodeID uint32, x25519PubKey []byte) []byte {
	out := make([]byte, 4+4+32)
	copy(out[0:4], []byte("auth"))
	binary.BigEndian.PutUint32(out[4:8], nodeID)
	copy(out[8:40], x25519PubKey)
	return out
}

// BuildAuthFrame builds an authenticated key exchange frame. Returns
// nil if our X25519 pubkey or Ed25519 identity is unavailable.
//
// Layout: [PILA(4)][nodeID(4 BE)][X25519 pubkey(32)][Ed25519 pubkey(32)][signature(64)] = 136 bytes.
func (m *Manager) BuildAuthFrame() []byte {
	m.keyMu.RLock()
	pub := m.pubKey
	m.keyMu.RUnlock()
	if pub == nil {
		return nil
	}
	id := m.Identity()
	if id == nil {
		return nil
	}
	nodeID := m.localNodeID()

	challenge := authChallenge(nodeID, pub)
	signature := id.Sign(challenge)
	ed25519PubKey := []byte(id.PublicKey)

	frame := make([]byte, authKeyExchangeFrameSize)
	copy(frame[0:4], protocol.TunnelMagicAuthEx[:])
	binary.BigEndian.PutUint32(frame[4:8], nodeID)
	copy(frame[8:40], pub)
	copy(frame[40:72], ed25519PubKey)
	copy(frame[72:136], signature)
	return frame
}

// BuildUnauthFrame builds an unauthenticated key exchange frame. Returns
// nil if our X25519 pubkey is unavailable.
//
// Layout: [PILK(4)][nodeID(4 BE)][X25519 pubkey(32)] = 40 bytes.
func (m *Manager) BuildUnauthFrame() []byte {
	m.keyMu.RLock()
	pub := m.pubKey
	m.keyMu.RUnlock()
	if pub == nil {
		return nil
	}
	frame := make([]byte, keyExchangeFrameSize)
	copy(frame[0:4], protocol.TunnelMagicKeyEx[:])
	binary.BigEndian.PutUint32(frame[4:8], m.localNodeID())
	copy(frame[8:40], pub)
	return frame
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"time"
)

// HKDFInfo is the domain-separation prefix for the HKDF info string.
// It is prepended to the sorted peer-pair public keys to form the
// full info string. Changing this prefix breaks wire compatibility.
const HKDFInfo = "pilot-tunnel-v1"

// DeriveSecret computes a shared AES-256-GCM cipher from the peer's
// X25519 public key, returning a fresh Crypto ready to be installed.
//
// Uses HKDF-SHA256 (info = "pilot-tunnel-v1", per HKDFInfo) to derive
// the AEAD key from the X25519 shared secret. Intermediate key material
// is zeroed before return (H4 fix).
func (m *Manager) DeriveSecret(peerPubKeyBytes []byte) (*Crypto, error) {
	priv := m.PrivKey()
	if priv == nil {
		return nil, fmt.Errorf("no private key")
	}

	curve := ecdh.X25519()
	peerKey, err := curve.NewPublicKey(peerPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse peer key: %w", err)
	}

	shared, err := priv.ECDH(peerKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}

	// HKDF-SHA256 key derivation (H1 fix). Info string is the bare
	// HKDFInfo constant for wire compatibility with peers that have not
	// yet upgraded to the peer-pair-bound variant (PILOT-144). Reintroduce
	// pair binding only once all production specialists are upgraded.
	mac := hmac.New(sha256.New, nil) // HKDF-Extract: PRK = HMAC-SHA256(nil salt, IKM)
	mac.Write(shared)
	prk := mac.Sum(nil)
	mac = hmac.New(sha256.New, prk) // HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
	mac.Write([]byte(HKDFInfo))
	mac.Write([]byte{0x01})
	key := mac.Sum(nil)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	// Zero intermediate key material.
	//   - shared: H4 fix
	//   - key: PILOT-147 — the HKDF-derived AES key. Go's aes.NewCipher
	//     copies the bytes into its internal expanded-key schedule, so
	//     zeroing the input slice doesn't reach the schedule itself
	//     (stdlib doesn't expose a way to reach it). But it does ensure
	//     the input bytes don't linger as a second copy on the heap.
	for i := range shared {
		shared[i] = 0
	}
	for i := range key {
		key[i] = 0
	}
	for i := range key {
		key[i] = 0
	}
	for i := range prk {
		prk[i] = 0
	}

	pc := &Crypto{AEAD: aead, Ready: true, CreatedAt: time.Now()}
	copy(pc.PeerX25519Key[:], peerPubKeyBytes)
	if _, err := rand.Read(pc.NoncePrefix[:]); err != nil {
		return nil, fmt.Errorf("nonce prefix: %w", err)
	}
	return pc, nil
}

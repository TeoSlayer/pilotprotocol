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

// HKDFInfo is the frozen HKDF info string used to derive AEAD keys
// from the X25519 shared secret. Changing it would break wire
// compatibility with every existing peer — DO NOT change.
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

	// HKDF-SHA256 key derivation (H1 fix).
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

	// Zero intermediate key material (H4 fix).
	for i := range shared {
		shared[i] = 0
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

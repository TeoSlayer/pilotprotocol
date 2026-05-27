// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/pilot-protocol/common/crypto"
)

func TestBuildKeyExchangeFrameWithoutPubKeyReturnsNil(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	// No EnableEncryption → pubKey nil
	if frame := tm.buildKeyExchangeFrame(); frame != nil {
		t.Fatalf("buildKeyExchangeFrame without pubKey should return nil, got %d bytes", len(frame))
	}
}

func TestBuildKeyExchangeFrameLayout(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	tm.SetNodeID(0xABCD0123)

	frame := tm.buildKeyExchangeFrame()
	if frame == nil {
		t.Fatalf("frame unexpectedly nil after EnableEncryption")
	}
	if len(frame) != 40 {
		t.Fatalf("frame len = %d, want 40 (4 magic + 4 nodeID + 32 pubKey)", len(frame))
	}
	if !bytes.Equal(frame[0:4], protocol.TunnelMagicKeyEx[:]) {
		t.Fatalf("magic bytes = %x, want %x", frame[0:4], protocol.TunnelMagicKeyEx[:])
	}
	if got := binary.BigEndian.Uint32(frame[4:8]); got != 0xABCD0123 {
		t.Fatalf("nodeID in frame = %x, want 0xABCD0123", got)
	}
	if !bytes.Equal(frame[8:40], tm.pubKey) {
		t.Fatalf("pubKey in frame does not match tm.pubKey")
	}
}

func TestBuildAuthKeyExchangeFrameWithoutPubKeyReturnsNil(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	tm.SetIdentity(id)
	// Still no pubKey (EnableEncryption not called) → nil
	if frame := tm.buildAuthKeyExchangeFrame(); frame != nil {
		t.Fatalf("buildAuthKeyExchangeFrame without pubKey should return nil")
	}
}

func TestBuildAuthKeyExchangeFrameWithoutIdentityReturnsNil(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	// No SetIdentity → tm.identity nil
	if frame := tm.buildAuthKeyExchangeFrame(); frame != nil {
		t.Fatalf("buildAuthKeyExchangeFrame without identity should return nil")
	}
}

func TestBuildAuthKeyExchangeFrameLayoutAndSignatureVerifies(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	tm.SetIdentity(id)
	tm.SetNodeID(0x00010203)

	frame := tm.buildAuthKeyExchangeFrame()
	if frame == nil {
		t.Fatalf("auth frame unexpectedly nil")
	}
	// 4 magic + 4 nodeID + 32 X25519 + 32 Ed25519 + 64 signature = 136
	if len(frame) != 136 {
		t.Fatalf("auth frame len = %d, want 136", len(frame))
	}
	if !bytes.Equal(frame[0:4], protocol.TunnelMagicAuthEx[:]) {
		t.Fatalf("magic bytes = %x, want %x", frame[0:4], protocol.TunnelMagicAuthEx[:])
	}
	if got := binary.BigEndian.Uint32(frame[4:8]); got != 0x00010203 {
		t.Fatalf("nodeID in frame = %x, want 0x00010203", got)
	}
	if !bytes.Equal(frame[8:40], tm.pubKey) {
		t.Fatalf("X25519 pubKey slot mismatch")
	}
	edPub := frame[40:72]
	sig := frame[72:136]

	// Reconstruct challenge and verify signature
	challenge := make([]byte, 4+4+32)
	copy(challenge[0:4], []byte("auth"))
	binary.BigEndian.PutUint32(challenge[4:8], 0x00010203)
	copy(challenge[8:40], tm.pubKey)

	if !byteSliceEqual(edPub, []byte(id.PublicKey)) {
		t.Fatalf("Ed25519 pubKey slot does not match identity public key")
	}
	if !ed25519.Verify(id.PublicKey, challenge, sig) {
		t.Fatalf("signature failed to verify")
	}
}

func TestEncryptFrameLayoutAndIncrementsEncryptOK(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	tm.SetNodeID(0xDEADBEEF)

	// Build a peer peerCrypto using tm.deriveSecret so pc.AEAD is populated.
	curve := ecdh.X25519()
	peerPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer keygen: %v", err)
	}
	pc, err := tm.deriveSecret(peerPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("deriveSecret: %v", err)
	}

	plaintext := []byte("hello tunnel")
	beforeOK := tm.EncryptOK

	frame := tm.encryptFrame(pc, plaintext)

	if tm.EncryptOK != beforeOK+1 {
		t.Fatalf("EncryptOK = %d, want %d", tm.EncryptOK, beforeOK+1)
	}

	nonceSize := pc.AEAD.NonceSize()
	expectedLen := 4 + 4 + nonceSize + len(plaintext) + 16 // AES-GCM tag is 16 bytes
	if len(frame) != expectedLen {
		t.Fatalf("frame len = %d, want %d (4 magic + 4 nodeID + %d nonce + %d plain + 16 tag)",
			len(frame), expectedLen, nonceSize, len(plaintext))
	}
	if !bytes.Equal(frame[0:4], protocol.TunnelMagicSecure[:]) {
		t.Fatalf("magic = %x, want %x", frame[0:4], protocol.TunnelMagicSecure[:])
	}
	if got := binary.BigEndian.Uint32(frame[4:8]); got != 0xDEADBEEF {
		t.Fatalf("nodeID = %x, want 0xDEADBEEF", got)
	}
	// Nonce prefix must match pc.NoncePrefix in first 4 bytes
	nonce := frame[8 : 8+nonceSize]
	if !bytes.Equal(nonce[0:4], pc.NoncePrefix[:]) {
		t.Fatalf("nonce prefix mismatch: frame=%x pc=%x", nonce[0:4], pc.NoncePrefix[:])
	}
	// Counter portion (last 8 bytes of nonce) should be 1 (first AddUint64 returns 1)
	counter := binary.BigEndian.Uint64(nonce[nonceSize-8:])
	if counter != 1 {
		t.Fatalf("counter = %d, want 1 (first Seal)", counter)
	}

	// Decrypt to verify round-trip with same AAD
	aad := make([]byte, 4)
	binary.BigEndian.PutUint32(aad, 0xDEADBEEF)
	got, err := pc.AEAD.Open(nil, nonce, frame[8+nonceSize:], aad)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted = %q, want %q", got, plaintext)
	}
}

func TestEncryptFrameCounterIsMonotonic(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	curve := ecdh.X25519()
	peerPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer keygen: %v", err)
	}
	pc, err := tm.deriveSecret(peerPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("deriveSecret: %v", err)
	}

	nonceSize := pc.AEAD.NonceSize()
	counters := make([]uint64, 5)
	for i := range counters {
		frame := tm.encryptFrame(pc, []byte("msg"))
		counters[i] = binary.BigEndian.Uint64(frame[8+nonceSize-8 : 8+nonceSize])
	}
	for i := 1; i < len(counters); i++ {
		if counters[i] != counters[i-1]+1 {
			t.Fatalf("counter not monotonic: %v", counters)
		}
	}
	if counters[0] != 1 {
		t.Fatalf("first counter = %d, want 1", counters[0])
	}
}

func TestFlushPendingDrainsQueuedFramesWhenCryptoReady(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	// Need a UDP socket for writeFrame path
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	// Pre-populate peerCrypto (ready=true) + peer endpoint + pending frames
	curve := ecdh.X25519()
	peerPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer keygen: %v", err)
	}
	pc, err := tm.deriveSecret(peerPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("deriveSecret: %v", err)
	}

	tm.mu.Lock()
	tm.peers[7] = mustUDPAddr(t, "127.0.0.1:1") // unreachable sink
	tm.envelope.Install(7, pc)
	tm.mu.Unlock()

	tm.pendMu.Lock()
	tm.pending[7] = [][]byte{[]byte("p1"), []byte("p2"), []byte("p3")}
	tm.pendMu.Unlock()

	beforeOK := tm.EncryptOK
	tm.flushPending(7)

	if tm.EncryptOK != beforeOK+3 {
		t.Fatalf("EncryptOK = %d, want %d (3 frames flushed)", tm.EncryptOK, beforeOK+3)
	}
	tm.pendMu.Lock()
	_, stillPending := tm.pending[7]
	tm.pendMu.Unlock()
	if stillPending {
		t.Fatalf("tm.pending[7] should be deleted after flush")
	}
}

func TestFlushPendingNoFramesIsNoop(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	// No pending entries; should simply return.
	before := tm.EncryptOK
	tm.flushPending(42)
	if tm.EncryptOK != before {
		t.Fatalf("flushPending(empty) should not encrypt anything")
	}
}

func TestFlushPendingNotReadyCryptoReturnsWithoutFlushing(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	tm.pendMu.Lock()
	tm.pending[9] = [][]byte{[]byte("x")}
	tm.pendMu.Unlock()

	// No crypto[9] → pc nil → early return, but pending was already deleted.
	before := tm.EncryptOK
	tm.flushPending(9)
	if tm.EncryptOK != before {
		t.Fatalf("no crypto: should skip encrypt")
	}
	tm.pendMu.Lock()
	_, ok := tm.pending[9]
	tm.pendMu.Unlock()
	if ok {
		t.Fatalf("pending[9] should be deleted even when crypto not ready")
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
)

// TestHandleKeyExchangeCapsUnauthPeers confirms that once the crypto map is
// at maxCryptoPeers, a spoofed unauth key-exchange packet from a *new*
// peerNodeID is dropped before deriveSecret runs. Without this cap, an
// attacker gets both an X25519 scalar-mult per packet (CPU) and an
// unbounded map entry (memory).
func TestHandleKeyExchangeCapsUnauthPeers(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	// Pre-fill crypto past the cap with zero-valued entries (any non-nil
	// pointer would do; the cap check only reads len()).
	for i := uint32(1); i <= maxCryptoPeers; i++ {
		tm.envelope.Install(i, &peerCrypto{})
	}

	// Forge a key-exchange packet from a peerNodeID we've never seen.
	curve := ecdh.X25519()
	peerPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	intruderID := uint32(0x7FFFFFFF)
	data := make([]byte, 36)
	binary.BigEndian.PutUint32(data[0:4], intruderID)
	copy(data[4:36], peerPriv.PublicKey().Bytes())

	tm.handleKeyExchange(data, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1111}, false)

	present := tm.envelope.Has(intruderID)
	size := tm.envelope.Len()

	if present {
		t.Fatal("new peerNodeID must be rejected when crypto map is full")
	}
	if size != maxCryptoPeers {
		t.Fatalf("crypto size=%d, want %d (unchanged)", size, maxCryptoPeers)
	}
}

// TestHandleKeyExchangeAllowsRekeyAtCap confirms that the cap does not block
// an existing peer from rekeying. The budget check only gates *new* entries,
// so a legitimate peer re-establishing its crypto context still succeeds
// even when the map is full.
func TestHandleKeyExchangeAllowsRekeyAtCap(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	existingID := uint32(42)
	for i := uint32(1); i <= maxCryptoPeers; i++ {
		tm.envelope.Install(i, &peerCrypto{})
	}
	// existingID is already present (i=42 fell in the loop above). Replace
	// it with a sentinel we can detect has been overwritten.
	sentinel := &peerCrypto{}
	tm.envelope.Install(existingID, sentinel)

	curve := ecdh.X25519()
	peerPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	data := make([]byte, 36)
	binary.BigEndian.PutUint32(data[0:4], existingID)
	copy(data[4:36], peerPriv.PublicKey().Bytes())

	tm.AddPeer(existingID, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999})
	tm.handleKeyExchange(data, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1111}, false)

	got := tm.envelope.Get(existingID)

	if got == sentinel {
		t.Fatal("existing peer's crypto should be replaced on rekey, even at cap")
	}
	if got == nil {
		t.Fatal("existing peer's crypto should not be nil after rekey")
	}
}

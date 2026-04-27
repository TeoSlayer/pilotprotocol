// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// TestHandleKeyExchangeDuplicatePreservesCryptoState pins the latent
// bug we identified during the P1-010 work: when a peer sends a SECOND
// key_exchange with the SAME X25519 ephemeral pubkey (e.g. their reply
// crossed our retransmit on the wire), our handleKeyExchange used to
// unconditionally replace tm.crypto[N] with a fresh peerCrypto. That
// reset the nonce counter and replay-window bitmap, which then caused
// our subsequent encrypted sends (using the now-zero counter) to fall
// outside the receiver's now-stale replay window — the receiver flagged
// them as "outside replay window" or "replay detected" and dropped them.
//
// Net effect: a duplicate handshake silently broke the data plane.
//
// The fix: skip replacement when peer's pubkey is unchanged. The
// shared secret is identical; preserving the existing peerCrypto keeps
// the nonce counter monotonic and the replay window valid.
func TestHandleKeyExchangeDuplicatePreservesCryptoState(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	const peerID uint32 = 100
	tm.AddPeer(peerID, mustUDPAddr(t, "127.0.0.1:9999"))

	// Generate the peer's X25519 ephemeral keypair. Same pubkey will be
	// reused for the duplicate.
	curve := ecdh.X25519()
	peerPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer keygen: %v", err)
	}
	peerPub := peerPriv.PublicKey().Bytes()

	frame := make([]byte, 36)
	binary.BigEndian.PutUint32(frame[0:4], peerID)
	copy(frame[4:36], peerPub)

	from := mustUDPAddr(t, "127.0.0.1:1111")
	tm.handleKeyExchange(frame, from, false)

	tm.mu.RLock()
	pc1 := tm.crypto[peerID]
	tm.mu.RUnlock()
	if pc1 == nil {
		t.Fatal("first handleKeyExchange did not install crypto")
	}

	// Simulate steady-state activity: advance the send counter to 100,
	// set the recv max to 100, mark bit 100 in the replay bitmap. A
	// well-behaved fix preserves all three across the duplicate.
	pc1.nonce = 100
	pc1.replayMu.Lock()
	pc1.maxRecvNonce = 100
	pc1.setReplayBit(100)
	pc1.replayMu.Unlock()

	// Same peer sends key_exchange AGAIN with the SAME pubkey. This is
	// what happens under the rekey retransmit loop — our reply crossed
	// peer's retransmit on the wire, so peer sends another to be safe.
	tm.handleKeyExchange(frame, from, false)

	tm.mu.RLock()
	pc2 := tm.crypto[peerID]
	tm.mu.RUnlock()
	if pc2 == nil {
		t.Fatal("crypto disappeared after duplicate handleKeyExchange")
	}

	// Pointer-identity is the strongest proof of "didn't replace."
	if pc2 != pc1 {
		t.Fatalf("duplicate key_exchange replaced peerCrypto pointer (was %p, now %p)", pc1, pc2)
	}

	// Even if the implementation chose to install a new pc with the
	// same fields, the counters MUST be preserved.
	if pc2.nonce != 100 {
		t.Errorf("send counter reset: nonce = %d, want 100", pc2.nonce)
	}
	pc2.replayMu.Lock()
	max := pc2.maxRecvNonce
	bitSet := pc2.replayBitmap[100/64]&(1<<(100%64)) != 0
	pc2.replayMu.Unlock()
	if max != 100 {
		t.Errorf("recv max reset: maxRecvNonce = %d, want 100", max)
	}
	if !bitSet {
		t.Error("replay bitmap reset: bit 100 not set after duplicate key_exchange")
	}
}

// TestHandleKeyExchangeNewPubkeyDoesReplace is the complement: when
// peer's pubkey actually CHANGES (peer restarted, new ephemeral keys),
// we MUST replace — the shared secret is different, so reusing the old
// peerCrypto would decrypt nothing.
func TestHandleKeyExchangeNewPubkeyDoesReplace(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	const peerID uint32 = 100
	tm.AddPeer(peerID, mustUDPAddr(t, "127.0.0.1:9999"))

	curve := ecdh.X25519()
	priv1, _ := curve.GenerateKey(rand.Reader)
	priv2, _ := curve.GenerateKey(rand.Reader)

	mkFrame := func(pub []byte) []byte {
		f := make([]byte, 36)
		binary.BigEndian.PutUint32(f[0:4], peerID)
		copy(f[4:36], pub)
		return f
	}

	from := mustUDPAddr(t, "127.0.0.1:1111")
	tm.handleKeyExchange(mkFrame(priv1.PublicKey().Bytes()), from, false)
	pc1 := tm.crypto[peerID]
	if pc1 == nil {
		t.Fatal("first install missing")
	}

	// Peer "restarts" with new ephemeral keys.
	tm.handleKeyExchange(mkFrame(priv2.PublicKey().Bytes()), from, false)
	pc2 := tm.crypto[peerID]
	if pc2 == nil {
		t.Fatal("second install missing")
	}
	if pc2 == pc1 {
		t.Fatal("crypto should have been replaced when pubkey changed")
	}
	// Different shared secret — peerX25519Key field reflects new pubkey.
	if pc2.peerX25519Key == pc1.peerX25519Key {
		t.Fatal("peerX25519Key did not update on rekey")
	}
}

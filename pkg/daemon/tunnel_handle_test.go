// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// --- handleKeyExchange ---

func TestHandleKeyExchangeShortDataIsNoop(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	// 35 bytes < 36 required
	tm.handleKeyExchange(make([]byte, 35), &net.UDPAddr{}, false)
	if tm.HasCrypto(0) {
		t.Fatalf("no crypto should be stored for short data")
	}
}

func TestHandleKeyExchangeDisabledEncryptionIsNoop(t *testing.T) {
	tm := NewTunnelManager()
	// No EnableEncryption
	data := make([]byte, 36)
	binary.BigEndian.PutUint32(data[0:4], 42)
	tm.handleKeyExchange(data, &net.UDPAddr{}, false)
	if tm.HasCrypto(42) {
		t.Fatalf("no crypto should be stored when encryption disabled")
	}
}

func TestHandleKeyExchangeValidStoresCryptoAndUpdatesPeer(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	// Listen so sendKeyExchangeToNode can attempt to write
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	// AddPeer so sendKeyExchangeToNode has a destination
	peerAddr := mustUDPAddr(t, "127.0.0.1:9999")
	tm.AddPeer(100, peerAddr)

	curve := ecdh.X25519()
	peerPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer keygen: %v", err)
	}

	data := make([]byte, 36)
	binary.BigEndian.PutUint32(data[0:4], 100)
	copy(data[4:36], peerPriv.PublicKey().Bytes())

	from := mustUDPAddr(t, "127.0.0.1:1111")
	tm.handleKeyExchange(data, from, false)

	if !tm.HasCrypto(100) {
		t.Fatalf("expected crypto stored for peer 100")
	}
	tm.mu.RLock()
	storedAddr := tm.peers[100]
	tm.mu.RUnlock()
	// AddPeer stored peerAddr; handleKeyExchange replaces with `from` because fromRelay=false
	if storedAddr.String() != from.String() {
		t.Fatalf("peer endpoint = %v, want %v", storedAddr, from)
	}
}

func TestHandleKeyExchangeFromRelayDoesNotUpdatePeerEndpoint(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	preexisting := mustUDPAddr(t, "127.0.0.1:7777")
	tm.AddPeer(101, preexisting)

	curve := ecdh.X25519()
	peerPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer keygen: %v", err)
	}

	data := make([]byte, 36)
	binary.BigEndian.PutUint32(data[0:4], 101)
	copy(data[4:36], peerPriv.PublicKey().Bytes())

	relayFrom := mustUDPAddr(t, "127.0.0.1:8888")
	tm.handleKeyExchange(data, relayFrom, true)

	tm.mu.RLock()
	storedAddr := tm.peers[101]
	tm.mu.RUnlock()
	if storedAddr.String() != preexisting.String() {
		t.Fatalf("fromRelay=true should NOT overwrite peer endpoint; got %v want %v", storedAddr, preexisting)
	}
	if !tm.HasCrypto(101) {
		t.Fatalf("crypto should still be stored even when fromRelay=true")
	}
}

func TestHandleKeyExchangeWithIdentityRejectsWhenPeerHasRegisteredPubKey(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	tm.SetIdentity(id)

	peerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	tm.SetPeerVerifyFunc(func(nodeID uint32) (ed25519.PublicKey, error) {
		return peerPub, nil
	})

	// AddPeer so the follow-up sendKeyExchangeToNode doesn't error silently
	peerAddr := mustUDPAddr(t, "127.0.0.1:9998")
	tm.AddPeer(202, peerAddr)

	curve := ecdh.X25519()
	peerPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer keygen: %v", err)
	}

	data := make([]byte, 36)
	binary.BigEndian.PutUint32(data[0:4], 202)
	copy(data[4:36], peerPriv.PublicKey().Bytes())

	tm.handleKeyExchange(data, mustUDPAddr(t, "127.0.0.1:1234"), false)

	// No crypto should have been derived — rejected before deriveSecret.
	if tm.HasCrypto(202) {
		t.Fatalf("crypto should NOT be stored when unauth key exchange is rejected")
	}
}

// --- handleAuthKeyExchange ---

func TestHandleAuthKeyExchangeShortDataIsNoop(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	// 131 bytes < 132 required (4+32+32+64)
	tm.handleAuthKeyExchange(make([]byte, 131), &net.UDPAddr{}, false)
	if tm.HasCrypto(0) {
		t.Fatalf("no crypto should be stored for short data")
	}
}

func TestHandleAuthKeyExchangeDisabledEncryptionIsNoop(t *testing.T) {
	tm := NewTunnelManager()
	// No EnableEncryption
	data := make([]byte, 132)
	binary.BigEndian.PutUint32(data[0:4], 42)
	tm.handleAuthKeyExchange(data, &net.UDPAddr{}, false)
	if tm.HasCrypto(42) {
		t.Fatalf("no crypto should be stored when encryption disabled")
	}
}

func TestHandleAuthKeyExchangeNoVerifyFuncRejects(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	// No SetPeerVerifyFunc → getPeerPubKey returns "no verify function" error
	data := make([]byte, 132)
	binary.BigEndian.PutUint32(data[0:4], 300)
	curve := ecdh.X25519()
	peerPriv, _ := curve.GenerateKey(rand.Reader)
	copy(data[4:36], peerPriv.PublicKey().Bytes())
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	copy(data[36:68], edPub)
	// signature zeros — won't matter, we reject before verify

	tm.handleAuthKeyExchange(data, mustUDPAddr(t, "127.0.0.1:1234"), false)

	if tm.HasCrypto(300) {
		t.Fatalf("crypto should NOT be stored when verify func absent")
	}
}

func TestHandleAuthKeyExchangePubkeyMismatchRejects(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	// VerifyFunc returns a different key than what the packet sends — mismatch.
	realPub, _, _ := ed25519.GenerateKey(rand.Reader)
	tm.SetPeerVerifyFunc(func(uint32) (ed25519.PublicKey, error) {
		return realPub, nil
	})

	// Packet carries a *different* ed25519 pubkey
	fakePub, _, _ := ed25519.GenerateKey(rand.Reader)

	curve := ecdh.X25519()
	peerPriv, _ := curve.GenerateKey(rand.Reader)

	data := make([]byte, 132)
	binary.BigEndian.PutUint32(data[0:4], 301)
	copy(data[4:36], peerPriv.PublicKey().Bytes())
	copy(data[36:68], fakePub)
	// signature zeros — will be rejected at verify step after re-fetch still mismatches

	tm.handleAuthKeyExchange(data, mustUDPAddr(t, "127.0.0.1:1234"), false)

	if tm.HasCrypto(301) {
		t.Fatalf("crypto should NOT be stored on pubkey mismatch")
	}
}

func TestHandleAuthKeyExchangeValidSignatureStoresCrypto(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	// Peer Ed25519 identity
	peerPub, peerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	tm.SetPeerVerifyFunc(func(uint32) (ed25519.PublicKey, error) {
		return peerPub, nil
	})

	// Peer X25519 key
	curve := ecdh.X25519()
	peerX, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("x25519 keygen: %v", err)
	}

	peerNodeID := uint32(0x50515253)

	// Build the challenge the same way handleAuthKeyExchange does
	challenge := make([]byte, 4+4+32)
	copy(challenge[0:4], []byte("auth"))
	binary.BigEndian.PutUint32(challenge[4:8], peerNodeID)
	copy(challenge[8:40], peerX.PublicKey().Bytes())
	sig := ed25519.Sign(peerPriv, challenge)

	// AddPeer so the reciprocal sendKeyExchangeToNode has an addr
	tm.AddPeer(peerNodeID, mustUDPAddr(t, "127.0.0.1:9997"))

	data := make([]byte, 132)
	binary.BigEndian.PutUint32(data[0:4], peerNodeID)
	copy(data[4:36], peerX.PublicKey().Bytes())
	copy(data[36:68], peerPub)
	copy(data[68:132], sig)

	from := mustUDPAddr(t, "127.0.0.1:1234")
	tm.handleAuthKeyExchange(data, from, false)

	if !tm.HasCrypto(peerNodeID) {
		t.Fatalf("expected crypto stored for peer %d after valid auth", peerNodeID)
	}
	tm.mu.RLock()
	pc := tm.crypto[peerNodeID]
	tm.mu.RUnlock()
	if pc == nil || !pc.authenticated {
		t.Fatalf("peerCrypto.authenticated should be true")
	}
	// Peer endpoint updated because fromRelay=false
	tm.mu.RLock()
	addr := tm.peers[peerNodeID]
	tm.mu.RUnlock()
	if addr.String() != from.String() {
		t.Fatalf("peer endpoint = %v, want %v", addr, from)
	}
}

// --- handleEncrypted ---

func TestHandleEncryptedShortDataIsNoop(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	// 31 bytes < 32 minimum (4 nodeID + 12 nonce + 16 tag)
	tm.handleEncrypted(make([]byte, 31), &net.UDPAddr{})
	if atomic.LoadUint64(&tm.PktsRecv) != 0 {
		t.Fatalf("PktsRecv should not advance on short data")
	}
}

func TestHandleEncryptedNoCryptoForPeerIsNoop(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	// Build valid-looking encrypted data but tm.crypto[42] is empty.
	// With no real UDP socket bound, maybeRequestRekey must bail out early
	// rather than panicking in writeFrame; behaviour observable externally is
	// still "no metrics move".
	data := make([]byte, 4+12+16)
	binary.BigEndian.PutUint32(data[0:4], 42)
	before := atomic.LoadUint64(&tm.EncryptFail)
	tm.handleEncrypted(data, &net.UDPAddr{})
	if atomic.LoadUint64(&tm.EncryptFail) != before {
		t.Fatalf("EncryptFail should not move when no crypto for peer")
	}
	if atomic.LoadUint64(&tm.PktsRecv) != 0 {
		t.Fatalf("PktsRecv should not advance when no crypto for peer")
	}
}

// When an encrypted packet arrives for which we have no crypto context (e.g.
// local restart wiped key, remote still uses stale keys), the receiver should
// prompt a rekey by sending a fresh key-exchange to the sender. Rate-limited
// per peer to prevent amplification.
func TestHandleEncryptedNoCryptoTriggersRekeyRequest(t *testing.T) {
	// Real UDP socket so sendKeyExchangeToNode can actually write.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	tm := NewTunnelManager()
	tm.conn = conn
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}

	// Peer "listener" — the remote that our rekey request should arrive at.
	peerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("peer listen: %v", err)
	}
	defer peerConn.Close()
	peerAddr := peerConn.LocalAddr().(*net.UDPAddr)

	peerNodeID := uint32(42)
	data := make([]byte, 4+12+16)
	binary.BigEndian.PutUint32(data[0:4], peerNodeID)

	// First call: should send a key-exchange frame to peerAddr.
	tm.handleEncrypted(data, peerAddr)
	if err := peerConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 256)
	n, _, err := peerConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("expected rekey frame at peer, got: %v", err)
	}
	// The frame should start with TunnelMagicKeyEx or TunnelMagicAuthEx.
	if n < 4 {
		t.Fatalf("rekey frame too short: %d bytes", n)
	}

	// Second call immediately after: rate-limiter should suppress it.
	tm.handleEncrypted(data, peerAddr)
	if err := peerConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, _, err := peerConn.ReadFromUDP(buf); err == nil {
		t.Fatalf("expected rate-limiter to suppress second rekey, got another frame")
	}
}

func TestHandleEncryptedDecryptErrorIncrementsEncryptFail(t *testing.T) {
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
	peerNodeID := uint32(77)
	tm.mu.Lock()
	tm.crypto[peerNodeID] = pc
	tm.mu.Unlock()

	// Bogus ciphertext + correct nonce layout — decrypt will fail.
	data := make([]byte, 4+12+32) // nodeID + nonce + random junk
	binary.BigEndian.PutUint32(data[0:4], peerNodeID)
	// Nonce: prefix + counter=1
	copy(data[4:8], pc.noncePrefix[:])
	binary.BigEndian.PutUint64(data[8:16], 1)
	// rest is garbage ciphertext

	before := atomic.LoadUint64(&tm.EncryptFail)
	tm.handleEncrypted(data, &net.UDPAddr{})
	if atomic.LoadUint64(&tm.EncryptFail) != before+1 {
		t.Fatalf("EncryptFail = %d, want %d (decrypt error)",
			atomic.LoadUint64(&tm.EncryptFail), before+1)
	}
	// Replay bit for counter=1 should be cleared (not left set on failure)
	pc.replayMu.Lock()
	bit := uint64(1) % replayWindowSize
	set := pc.replayBitmap[bit/64]&(1<<(bit%64)) != 0
	pc.replayMu.Unlock()
	if set {
		t.Fatalf("replay bit for failed decrypt should be cleared")
	}
}

func TestHandleEncryptedReplayIsRejected(t *testing.T) {
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
	peerNodeID := uint32(88)
	tm.mu.Lock()
	tm.crypto[peerNodeID] = pc
	tm.mu.Unlock()

	// Pre-populate: pretend counter=5 was already seen.
	pc.replayMu.Lock()
	pc.maxRecvNonce = 5
	bit := uint64(5) % replayWindowSize
	pc.replayBitmap[bit/64] |= 1 << (bit % 64)
	pc.replayMu.Unlock()

	// Craft an encrypted packet claiming counter=5 — will be rejected as replay.
	data := make([]byte, 4+12+16)
	binary.BigEndian.PutUint32(data[0:4], peerNodeID)
	copy(data[4:8], pc.noncePrefix[:])
	binary.BigEndian.PutUint64(data[8:16], 5)

	beforeFail := atomic.LoadUint64(&tm.EncryptFail)
	beforeRecv := atomic.LoadUint64(&tm.PktsRecv)
	tm.handleEncrypted(data, &net.UDPAddr{})
	// Replay path returns BEFORE decrypt, so EncryptFail must NOT increment
	if atomic.LoadUint64(&tm.EncryptFail) != beforeFail {
		t.Fatalf("EncryptFail should not move on replay; got %d want %d",
			atomic.LoadUint64(&tm.EncryptFail), beforeFail)
	}
	if atomic.LoadUint64(&tm.PktsRecv) != beforeRecv {
		t.Fatalf("PktsRecv should not move on replay")
	}
}

func TestHandleEncryptedValidDeliversToRecvCh(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	tm.SetNodeID(0xABCD1234) // unused here, handler uses sender's AAD from packet
	curve := ecdh.X25519()
	peerPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer keygen: %v", err)
	}
	pc, err := tm.deriveSecret(peerPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("deriveSecret: %v", err)
	}
	peerNodeID := uint32(0x11223344)
	tm.mu.Lock()
	tm.crypto[peerNodeID] = pc
	tm.mu.Unlock()

	// Build a real encrypted frame that handleEncrypted will accept:
	// nonce = prefix(4) || counter(8) ; AAD = BE(peerNodeID)
	pkt := newPacket("encrypted-payload")
	plaintext, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	nonce := make([]byte, pc.aead.NonceSize())
	copy(nonce[0:4], pc.noncePrefix[:])
	binary.BigEndian.PutUint64(nonce[4:12], 1)
	aad := make([]byte, 4)
	binary.BigEndian.PutUint32(aad, peerNodeID)
	ct := pc.aead.Seal(nil, nonce, plaintext, aad)

	data := make([]byte, 4+12+len(ct))
	binary.BigEndian.PutUint32(data[0:4], peerNodeID)
	copy(data[4:16], nonce)
	copy(data[16:], ct)

	tm.handleEncrypted(data, mustUDPAddr(t, "127.0.0.1:5555"))

	if atomic.LoadUint64(&tm.PktsRecv) != 1 {
		t.Fatalf("PktsRecv = %d, want 1", atomic.LoadUint64(&tm.PktsRecv))
	}
	select {
	case got := <-tm.RecvCh():
		if string(got.Packet.Payload) != "encrypted-payload" {
			t.Fatalf("payload = %q, want encrypted-payload", got.Packet.Payload)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected packet on recvCh")
	}
}

func TestHandleEncryptedPlaintextNotAPacketReturns(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	curve := ecdh.X25519()
	peerPriv, _ := curve.GenerateKey(rand.Reader)
	pc, err := tm.deriveSecret(peerPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("deriveSecret: %v", err)
	}
	peerNodeID := uint32(0x55555555)
	tm.mu.Lock()
	tm.crypto[peerNodeID] = pc
	tm.mu.Unlock()

	// Seal valid ciphertext but plaintext is NOT a valid protocol.Packet
	nonce := make([]byte, pc.aead.NonceSize())
	copy(nonce[0:4], pc.noncePrefix[:])
	binary.BigEndian.PutUint64(nonce[4:12], 1)
	aad := make([]byte, 4)
	binary.BigEndian.PutUint32(aad, peerNodeID)
	ct := pc.aead.Seal(nil, nonce, []byte("not a packet"), aad)

	data := make([]byte, 4+12+len(ct))
	binary.BigEndian.PutUint32(data[0:4], peerNodeID)
	copy(data[4:16], nonce)
	copy(data[16:], ct)

	beforeRecv := atomic.LoadUint64(&tm.PktsRecv)
	tm.handleEncrypted(data, &net.UDPAddr{})
	if atomic.LoadUint64(&tm.PktsRecv) != beforeRecv {
		t.Fatalf("PktsRecv should NOT advance on unmarshal failure")
	}
}

// --- readLoop dispatch ---

func TestReadLoopDispatchesPILTMagicToRecvCh(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	pkt := newPacket("via-readloop")
	pktBytes, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	frame := make([]byte, 4+len(pktBytes))
	copy(frame[0:4], protocol.TunnelMagic[:])
	copy(frame[4:], pktBytes)

	// Send to tm's listen addr from a separate conn
	sender, err := net.DialUDP("udp", nil, tm.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sender.Close()
	if _, err := sender.Write(frame); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case got := <-tm.RecvCh():
		if string(got.Packet.Payload) != "via-readloop" {
			t.Fatalf("payload = %q, want via-readloop", got.Packet.Payload)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected plaintext packet delivery via readLoop")
	}
}

func TestReadLoopPunchMagicIsSilentlyConsumed(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	sender, err := net.DialUDP("udp", nil, tm.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sender.Close()
	if _, err := sender.Write(protocol.TunnelMagicPunch[:]); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Nothing should be delivered to recvCh
	select {
	case got := <-tm.RecvCh():
		t.Fatalf("unexpected recv on punch: %+v", got)
	case <-time.After(150 * time.Millisecond):
		// expected
	}
	if atomic.LoadUint64(&tm.PktsRecv) != 0 {
		t.Fatalf("PktsRecv should not move on punch magic")
	}
}

func TestReadLoopUnknownMagicIsSilentlyIgnored(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	sender, err := net.DialUDP("udp", nil, tm.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sender.Close()
	// "ZZZZ" — not a known magic, all bytes >= 0x10 so not beacon
	if _, err := sender.Write([]byte{'Z', 'Z', 'Z', 'Z', 0, 0, 0, 0}); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case got := <-tm.RecvCh():
		t.Fatalf("unexpected recv on unknown magic: %+v", got)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestReadLoopShortPacketIsIgnored(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	sender, err := net.DialUDP("udp", nil, tm.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sender.Close()
	// 3 bytes — below the 4-byte magic threshold. Also buf[0]=0x50 (from 'P') is >= 0x10
	// so it won't go to handleBeaconMessage.
	if _, err := sender.Write([]byte{'P', 'I', 'L'}); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case got := <-tm.RecvCh():
		t.Fatalf("unexpected recv on short packet: %+v", got)
	case <-time.After(150 * time.Millisecond):
	}
}

// sanity helper: fails if handler panics under any of these crafted inputs
func TestHandlersAreRobustAgainstEmptyData(_ *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		return
	}
	tm.handleKeyExchange(nil, &net.UDPAddr{}, false)
	tm.handleAuthKeyExchange(nil, &net.UDPAddr{}, false)
	tm.handleEncrypted(nil, &net.UDPAddr{})
	tm.handleEncrypted([]byte{}, &net.UDPAddr{})
}

// Ensure compile-time coverage of stdlib imports unused in some builds
var _ = fmt.Errorf

// setupAuthKeyExchangeTest builds the common scaffolding: a tunnel
// manager with encryption enabled, a peer Ed25519 identity registered,
// and a valid signed auth key_exchange frame ready to feed into
// handleAuthKeyExchange.
func setupAuthKeyExchangeTest(t *testing.T) (*TunnelManager, uint32, []byte, *net.UDPAddr) {
	t.Helper()
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	peerPub, peerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	tm.SetPeerVerifyFunc(func(uint32) (ed25519.PublicKey, error) {
		return peerPub, nil
	})
	curve := ecdh.X25519()
	peerX, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("x25519 keygen: %v", err)
	}
	peerNodeID := uint32(0x50515253)

	challenge := make([]byte, 4+4+32)
	copy(challenge[0:4], []byte("auth"))
	binary.BigEndian.PutUint32(challenge[4:8], peerNodeID)
	copy(challenge[8:40], peerX.PublicKey().Bytes())
	sig := ed25519.Sign(peerPriv, challenge)

	tm.AddPeer(peerNodeID, mustUDPAddr(t, "127.0.0.1:9997"))

	data := make([]byte, 132)
	binary.BigEndian.PutUint32(data[0:4], peerNodeID)
	copy(data[4:36], peerX.PublicKey().Bytes())
	copy(data[36:68], peerPub)
	copy(data[68:132], sig)
	from := mustUDPAddr(t, "127.0.0.1:1234")
	return tm, peerNodeID, data, from
}

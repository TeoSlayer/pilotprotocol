// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
)

// TestReplayNeverTriggersRekey pins the v1.9.2 invariant: ErrReplay never
// causes a key-exchange request, regardless of counter value.
//
// Background: v1.9.1 triggered a rekey on ErrReplay when recvCounter < 1024,
// reasoning that "only a restarted peer would send counter=1." This was wrong:
//
//  1. A restarted peer generates a fresh X25519 keypair → their post-restart
//     frames fail AEAD against our old key (ErrAEAD, handled there). ErrReplay
//     can only fire when AEAD succeeds, meaning the same key session is still
//     active on both sides.
//
//  2. ErrReplay with a valid AEAD is duplicate delivery — the same encrypted
//     frame arriving on both the direct and relay paths simultaneously. Each
//     rekey produces a new session with early counters (1–40); the relay
//     re-delivers those frames back as ErrReplay, firing another rekey,
//     producing another storm, indefinitely.
//
// The correct recovery path for a restarted peer is ErrAEAD
// (handleEncrypted's existing rekey logic) or the peer's own KeyInit message.
func TestReplayNeverTriggersRekey(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })

	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	tm.SetNodeID(0xAAAAAAAA)

	const peerNodeID uint32 = 0xBBBBBBBB
	peerAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}

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
	tm.peers[peerNodeID] = peerAddr
	tm.envelope.Install(peerNodeID, pc)
	tm.mu.Unlock()

	build := func(counter uint64) []byte {
		t.Helper()
		pkt := newPacket("replay-payload")
		plaintext, err := pkt.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		nonce := make([]byte, pc.AEAD.NonceSize())
		copy(nonce[0:4], pc.NoncePrefix[:])
		binary.BigEndian.PutUint64(nonce[4:12], counter)
		aad := make([]byte, 4)
		binary.BigEndian.PutUint32(aad, peerNodeID)
		ct := pc.AEAD.Seal(nil, nonce, plaintext, aad)
		frame := make([]byte, 4+12+len(ct))
		binary.BigEndian.PutUint32(frame[0:4], peerNodeID)
		copy(frame[4:16], nonce)
		copy(frame[16:], ct)
		return frame
	}

	// Establish the session with two clean frames.
	tm.handleEncrypted(build(1), peerAddr)
	tm.handleEncrypted(build(5), peerAddr)

	tm.rekeyMu.Lock()
	_, hadRekeyAfterEstablish := tm.lastRekeyReq[peerNodeID]
	tm.rekeyMu.Unlock()
	if hadRekeyAfterEstablish {
		t.Fatalf("setup invariant: no rekey expected after clean establishment phase")
	}

	// Replay: re-deliver counter=1 (duplicate delivery, e.g. direct+relay).
	// This must NOT trigger a rekey — it's the relay re-delivering the same
	// frame, not a peer restart (which would produce ErrAEAD, not ErrReplay).
	tm.handleEncrypted(build(1), peerAddr)

	tm.rekeyMu.Lock()
	_, ok := tm.lastRekeyReq[peerNodeID]
	tm.rekeyMu.Unlock()
	if ok {
		t.Fatalf("ErrReplay must never trigger a rekey (would cause relay re-delivery storm)")
	}
}

// TestPeerRestartHighCounterReplayDoesNotTriggerRekey pins the symmetric
// guard: when a packet with a HIGH counter (within the replay window of
// a busy session) is replayed, NO rekey should fire. This is the real
// "replay attack" case — distinct from peer restart — and triggering a
// rekey here would let an attacker who captures a single old packet
// cause a key rotation on demand. The cost is small (rekey is cheap)
// but the heuristic should still hold.
func TestPeerRestartHighCounterReplayDoesNotTriggerRekey(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })

	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	tm.SetNodeID(0xCCCCCCCC)

	const peerNodeID uint32 = 0xDDDDDDDD
	peerAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 23456}

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
	tm.peers[peerNodeID] = peerAddr
	tm.envelope.Install(peerNodeID, pc)
	tm.mu.Unlock()

	build := func(counter uint64) []byte {
		pkt := newPacket("high-counter-payload")
		plaintext, _ := pkt.Marshal()
		nonce := make([]byte, pc.AEAD.NonceSize())
		copy(nonce[0:4], pc.NoncePrefix[:])
		binary.BigEndian.PutUint64(nonce[4:12], counter)
		aad := make([]byte, 4)
		binary.BigEndian.PutUint32(aad, peerNodeID)
		ct := pc.AEAD.Seal(nil, nonce, plaintext, aad)
		frame := make([]byte, 4+12+len(ct))
		binary.BigEndian.PutUint32(frame[0:4], peerNodeID)
		copy(frame[4:16], nonce)
		copy(frame[16:], ct)
		return frame
	}

	// Receive counter=5000 cleanly (busy session, large maxN).
	tm.handleEncrypted(build(5000), peerAddr)

	// Replay counter=4900 (within the 256-wide replay window of maxN=5000;
	// also far above the low-counter threshold for restart heuristic).
	tm.handleEncrypted(build(4900), peerAddr)

	// No rekey should have been triggered — this is a high-counter replay
	// (real attack pattern), not a peer restart.
	tm.rekeyMu.Lock()
	_, ok := tm.lastRekeyReq[peerNodeID]
	tm.rekeyMu.Unlock()
	if ok {
		t.Errorf("rekey should NOT fire on high-counter replay (would let attacker force key rotation)")
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// TestPeerRestartLowMaxNDeadlock reproduces the "peer restart silently
// stuck when maxN is small" bug.
//
// Symptom: a low-traffic peer pair has chatted briefly (our cached
// pc.maxRecvNonce sits at, say, 5). The peer process restarts and
// resumes sending; their fresh counter starts at 1. Their first packet
// is REJECTED by our replay window (we already recorded counter=1 from
// the pre-restart session, replay bit is still set), and we DO NOT
// trigger a rekey because the existing "low counter, far from maxN"
// branch only fires when `maxN-recvCounter >= replayWindowSize` (256).
// With maxN=5, the gap is 4, so we fall into the unconditional
// "replay detected" branch and just log + return forever.
//
// Code path (`pkg/daemon/tunnel.go::handleEncrypted` ~lines 977-1009):
//
//	ok := pc.checkAndRecordNonce(recvCounter)         // false (replay bit set)
//	maxN := pc.maxRecvNonce                           // 5
//	...
//	if recvCounter < maxN && maxN-recvCounter >= replayWindowSize {
//	    // not entered: 5-1 = 4 < 256
//	} else {
//	    // entered:
//	    slog.Warn("tunnel nonce replay detected", ...)
//	    tm.webhook.Emit("security.nonce_replay", ...)
//	    // NO rekey trigger — peer stays silently stuck
//	}
//
// Why this matters: every short-lived test pair, every just-bootstrapped
// peer, every "I sent five hello packets and went idle" session is
// vulnerable. The peer's daemon may be perfectly healthy; we will never
// rekey, and the connection stays a one-way black hole.
//
// What the v1.9.1 fix should change: the "replay detected" branch must
// also trigger a rate-limited rekey when `recvCounter` is small in
// absolute terms (e.g. < 1024), regardless of how far it is from maxN.
// A real replay attack would carry a HIGH counter (captured from an
// active session); only a peer that just restarted starts at 1.
//
// FIXED (v1.9.1): the "replay detected" branch now also triggers a
// rate-limited rekey when recvCounter is in the low-counter zone
// (< 1024). The post-fix assertion below verifies that one inbound
// low-counter "replay" (peer just restarted) brings the tunnel back
// without waiting for connection-layer retransmit timeout.
func TestPeerRestartLowMaxNDeadlock(t *testing.T) {
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })

	// Bind a real UDP socket so maybeRequestRekey can fire (it short-
	// circuits when tm.conn == nil).
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	tm.SetNodeID(0xAAAAAAAA)

	const peerNodeID uint32 = 0xBBBBBBBB
	peerAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}

	// Install a peerCrypto so handleEncrypted will accept our forged frames.
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
	tm.crypto[peerNodeID] = pc
	tm.mu.Unlock()

	// Build a frame at the given counter, encrypted with `pc`.
	build := func(counter uint64) []byte {
		t.Helper()
		pkt := newPacket("low-traffic-payload")
		plaintext, err := pkt.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		nonce := make([]byte, pc.aead.NonceSize())
		copy(nonce[0:4], pc.noncePrefix[:])
		binary.BigEndian.PutUint64(nonce[4:12], counter)
		aad := make([]byte, 4)
		binary.BigEndian.PutUint32(aad, peerNodeID)
		ct := pc.aead.Seal(nil, nonce, plaintext, aad)
		frame := make([]byte, 4+12+len(ct))
		binary.BigEndian.PutUint32(frame[0:4], peerNodeID)
		copy(frame[4:16], nonce)
		copy(frame[16:], ct)
		return frame
	}

	// Phase 1: simulate a brief pre-restart conversation.
	// Counter=1 → records bit 1, maxN=1.
	// Counter=5 → records bit 5, maxN=5.
	tm.handleEncrypted(build(1), peerAddr)
	tm.handleEncrypted(build(5), peerAddr)

	// Drain any rekey state set by the establishment phase. (None should
	// have been; our pc is good and frames decrypted cleanly. We assert
	// this to make the bug-reproduction unambiguous.)
	tm.rekeyMu.Lock()
	_, hadRekeyAfterEstablish := tm.lastRekeyReq[peerNodeID]
	tm.rekeyMu.Unlock()
	if hadRekeyAfterEstablish {
		t.Fatalf("setup invariant: no rekey expected after clean establishment phase")
	}

	// Phase 2: peer restarts, resumes from counter=1. Their X25519 key is
	// fresh, so even though we'd reject the replay, AEAD would also fail.
	// We don't care which: the point is the replay window catches it
	// FIRST and falls into the "replay detected" branch. No rekey fires.
	tm.handleEncrypted(build(1), peerAddr)

	// FIXED (v1.9.1): the "replay detected" branch now triggers a
	// rate-limited rekey when recvCounter is < 1024. The peer's fresh
	// post-restart counter is in this zone, so one inbound packet is
	// enough to start the recovery cycle (we send key_exchange, peer
	// installs new pc on receipt, peer's next send carries the new key
	// which AEADs cleanly).
	tm.rekeyMu.Lock()
	last, ok := tm.lastRekeyReq[peerNodeID]
	tm.rekeyMu.Unlock()
	if !ok {
		t.Fatalf("expected rekey to fire on low-counter replay (peer-restart resync); lastRekeyReq not set")
	}
	if time.Since(last) > 500*time.Millisecond {
		t.Errorf("lastRekeyReq is stale (%v ago), should be fresh from this handler call", time.Since(last))
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
	tm.crypto[peerNodeID] = pc
	tm.mu.Unlock()

	build := func(counter uint64) []byte {
		pkt := newPacket("high-counter-payload")
		plaintext, _ := pkt.Marshal()
		nonce := make([]byte, pc.aead.NonceSize())
		copy(nonce[0:4], pc.noncePrefix[:])
		binary.BigEndian.PutUint64(nonce[4:12], counter)
		aad := make([]byte, 4)
		binary.BigEndian.PutUint32(aad, peerNodeID)
		ct := pc.aead.Seal(nil, nonce, plaintext, aad)
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

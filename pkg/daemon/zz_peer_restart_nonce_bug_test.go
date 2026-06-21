// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

// TestReplayNeverTriggersRekey pins the v1.9.2 invariant for *isolated*
// ErrReplay events: a single (or small handful) of replays must never
// fire a rekey, regardless of counter value.
//
// Background: v1.9.1 triggered a rekey on every ErrReplay when
// recvCounter < 1024, reasoning that "only a restarted peer would send
// counter=1." This was wrong for two reasons:
//
//  1. The original storm: each rekey produces a new session with early
//     counters (1–40). The relay re-delivers those frames back as
//     ErrReplay, firing another rekey, producing another storm, ad
//     infinitum. Triggering on a single replay couples rekeys to relay
//     re-delivery noise.
//
//  2. The original assumption ("ErrAEAD handles restarted peer") held
//     ONLY when the peer rotated its X25519 keypair on restart. Peers
//     with persistent identity (the production agent fleet on
//     pilot-service-agents, after the rc5 rollout) restart without
//     rotating keys — their post-restart frames decrypt cleanly with
//     the same AEAD key. The peer's send counter resets to 1, our
//     MaxRecvNonce stays at the pre-restart watermark, every frame
//     lands as ErrReplay. ErrAEAD never fires. Without a recovery
//     path on this side, the session wedged indefinitely (rc5
//     list-agents bug, 2026-05-11).
//
// The rc6 fix introduces ShouldDropOnReplay: a threshold-gated
// (ReplayDropThreshold=30) + grace-gated (ReplayDropGrace=3s) +
// CompareAndDrop-guarded path that triggers a rekey only on
// *sustained* same-peer replays. Isolated replays — including the
// single duplicate-delivery case this test verifies — stay below
// the threshold and produce no rekey, preserving this invariant.
// TestSustainedReplayTriggersRekey covers the complementary case.
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

// TestSustainedReplayTriggersRekey is the rc6 complementary case to
// TestReplayNeverTriggersRekey: when ErrReplay fires *sustained*
// against the same peer (≥ReplayDropThreshold consecutive replays
// past ReplayDropGrace), tunnel.go must drop the wedged Crypto and
// request a rekey. This is the recovery for the rc5 list-agents bug
// (2026-05-11) where peers restarted with persistent identity, their
// send counter reset to 1, our MaxRecvNonce stayed at the pre-restart
// watermark, and every frame from the peer landed as ErrReplay.
//
// The threshold + grace + CompareAndDrop guards keep this safe from
// the original v1.9.1 storm: a fresh rekey-installed Crypto can see
// a small burst of legitimate replays (relay re-delivery of early
// counters) without tripping the gate, because (a) it stays under
// the threshold and (b) the new Crypto's CreatedAt is within grace.
func TestSustainedReplayTriggersRekey(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })

	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	tm.SetNodeID(0xEEEEEEEE)

	const peerNodeID uint32 = 0xFFFFFFFF
	peerAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 34567}

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
		pkt := newPacket("sustained-replay-payload")
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

	// Mirror the wedge scenario: deliver N frames cleanly so the
	// receive bitmap has N consecutive bits set and MaxRecvNonce sits
	// at N. This represents the pre-restart state of a busy peer.
	const frames = keyexchange.ReplayDropThreshold + 1
	delivered := make([][]byte, frames)
	for i := 0; i < frames; i++ {
		f := build(uint64(i + 1))
		delivered[i] = f
		tm.handleEncrypted(f, peerAddr)
	}

	// Backdate the installed Crypto past the grace window so the
	// drop gate is only blocked by the count threshold.
	pc.CreatedAt = time.Now().Add(-2 * keyexchange.ReplayDropGrace)

	// Pre-condition: no rekey fired during the clean delivery phase.
	tm.rekeyMu.Lock()
	_, hadRekeyBefore := tm.lastRekeyReq[peerNodeID]
	tm.rekeyMu.Unlock()
	if hadRekeyBefore {
		t.Fatalf("setup invariant: rekey fired during clean establishment")
	}

	// Re-deliver every frame — each lands as ErrReplay because the
	// bitmap bit at that counter is already set. After ≥threshold
	// the recovery should fire: ShouldDropOnReplay trips, the wedged
	// pc is removed via CompareAndDrop, and maybeRequestRekey records
	// a rekey request.
	for _, f := range delivered {
		tm.handleEncrypted(f, peerAddr)
	}

	tm.rekeyMu.Lock()
	_, hadRekeyAfter := tm.lastRekeyReq[peerNodeID]
	tm.rekeyMu.Unlock()
	if !hadRekeyAfter {
		t.Fatalf("rc5-bug regression: sustained ErrReplay did NOT trigger a rekey "+
			"(delivered %d clean + replayed %d, threshold=%d, grace satisfied)",
			frames, frames, keyexchange.ReplayDropThreshold)
	}

	// And the wedged pc must have been dropped — a subsequent lookup
	// returns nil (or a different instance, but never the diverged one).
	if got := tm.envelope.Get(peerNodeID); got == pc {
		t.Fatalf("wedged Crypto still installed after rekey trigger; CompareAndDrop did not fire")
	}
}

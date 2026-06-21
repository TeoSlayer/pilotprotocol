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

// TestModeratelyQuietPeerRestartRecoversFast pins the threshold-drop
// fix (ReplayDropThreshold 30→5): a peer that sends 5 frames after
// restart should recover within ~1 second. Before the threshold drop
// this required 30 frames, which a quiet control-plane peer might
// never send within a useful window.
//
// This is the threshold-only fix — the one-frame case is covered
// separately by TestSingleFramePeerRestartRecovers, which remains red
// until the active-probe path lands.
func TestModeratelyQuietPeerRestartRecoversFast(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })

	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	tm.SetNodeID(0x11111111)

	const peerNodeID uint32 = 0x22222222
	peerAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 45678}

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
		pkt := newPacket("quiet-peer-payload")
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

	// Establish the pre-restart state: peer has sent us 50 frames
	// (counters 1..50), all delivered cleanly. MaxRecvNonce=50,
	// bitmap bits 1..50 set.
	const established = 50
	for i := 1; i <= established; i++ {
		tm.handleEncrypted(build(uint64(i)), peerAddr)
	}

	// Backdate the Crypto well past every grace window. In production
	// the peer's Crypto has been installed for hours/days before the
	// restart event we're testing — the grace gate is never the
	// limiter, the count threshold is.
	pc.CreatedAt = time.Now().Add(-1 * time.Hour)

	// Sanity: nothing fired during the clean establishment phase.
	tm.rekeyMu.Lock()
	_, rekeyAfterEstablish := tm.lastRekeyReq[peerNodeID]
	tm.rekeyMu.Unlock()
	if rekeyAfterEstablish {
		t.Fatalf("setup invariant: rekey should not fire during clean establishment")
	}

	// Peer restarts (preserves identity / X25519 key, resets send counter).
	// First post-restart frame lands at counter=1 → in-window replay.
	// A moderately-quiet peer sends a small burst — heartbeat + a couple
	// of pings — within a few seconds. ReplayDropThreshold=5 should
	// recover from exactly this pattern.
	const burstFromQuietPeer = keyexchange.ReplayDropThreshold
	for i := 0; i < burstFromQuietPeer; i++ {
		tm.handleEncrypted(build(uint64(i+1)), peerAddr)
	}

	// Give the daemon a generous window to detect-and-recover.
	// A correctly-engineered recovery path (active probe, lower
	// threshold, or epoch handshake) completes in well under 1 second.
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		tm.rekeyMu.Lock()
		_, ok := tm.lastRekeyReq[peerNodeID]
		tm.rekeyMu.Unlock()
		if ok {
			return // recovery happened — test passes
		}
		// Also accept: wedged Crypto already removed via CompareAndDrop.
		if got := tm.envelope.Get(peerNodeID); got != pc {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Neither path fired. The wedge persists.
	pc.ReplayMu.Lock()
	replayCount := pc.ReplayCount
	pc.ReplayMu.Unlock()
	t.Fatalf(
		"BUG: moderately-quiet peer wedge unresolved after %d frames "+
			"over 1s (replay count=%d, threshold=%d). The threshold "+
			"drop did not deliver — recovery is still too slow.",
		burstFromQuietPeer, replayCount, keyexchange.ReplayDropThreshold,
	)
}

// TestSingleFramePeerRestartRecovers pins the next-stage invariant:
// a peer that sends EXACTLY ONE frame after restart must still
// recover within ~1 second. Below ReplayDropThreshold the rate-gated
// recovery never fires; the daemon must either send an active probe
// to elicit traffic from the peer (so the threshold can trip), or use
// a handshake epoch to detect the restart from the first frame.
//
// Currently FAILS — this is the next stage of the fix.
func TestSingleFramePeerRestartRecovers(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })

	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	tm.SetNodeID(0x33333333)

	const peerNodeID uint32 = 0x44444444
	peerAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 56789}

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
		pkt := newPacket("single-frame-payload")
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

	// Establish 50 frames so the bitmap has positions 1..50 set.
	for i := 1; i <= 50; i++ {
		tm.handleEncrypted(build(uint64(i)), peerAddr)
	}
	pc.CreatedAt = time.Now().Add(-1 * time.Hour)

	// The very quiet peer restarts and sends EXACTLY ONE frame.
	tm.handleEncrypted(build(1), peerAddr)

	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		tm.rekeyMu.Lock()
		_, ok := tm.lastRekeyReq[peerNodeID]
		tm.rekeyMu.Unlock()
		if ok {
			return
		}
		if got := tm.envelope.Get(peerNodeID); got != pc {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf(
		"BUG: single-frame peer restart unresolved after 1s. " +
			"Quiet peers stay wedged because count-based recovery " +
			"requires the peer to keep talking. Fix: active probe on " +
			"first ErrReplay from aged Crypto, OR handshake epoch.",
	)
}

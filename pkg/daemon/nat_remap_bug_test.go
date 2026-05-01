// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
)

// TestPeerNATRemapNotLearnedOnDecrypt reproduces the "stale peer endpoint
// after NAT remap" bug.
//
// Symptom: a peer behind a symmetric or port-restricted NAT loses and
// re-acquires its UDP source mapping (NAT box rebooted, mapping idle-timed
// out, ISP CGNAT rotated the public port). The peer keeps sending us
// encrypted frames from the NEW source address; we successfully decrypt
// them (the crypto context is intact). But every subsequent `tm.Send` from
// our side still goes to the OLD address — silent black hole — until the
// peer happens to issue a fresh `key_exchange` (one of the two paths that
// updates `tm.peers[peerNodeID]`).
//
// Code path (`pkg/daemon/tunnel.go::handleEncrypted` ~line 1044):
//
//	tm.mu.Lock()
//	cleared := tm.clearRelayOnDirectLocked(peerNodeID, from)
//	if from != nil {
//	    fromBeacon := ...
//	    if !fromBeacon {
//	        tm.lastDirectRecv[peerNodeID] = time.Now()
//	    }
//	}
//	tm.mu.Unlock()
//
// Note what's MISSING: `tm.peers[peerNodeID] = from` for the !fromBeacon
// case. The function records a timestamp but never learns the new address.
//
// Real-world impact (matches "tunnel goes silent for minutes after a
// transient network blip" reports):
//   - Application send returns success at the daemon layer (writeFrame
//     succeeds — UDP doesn't tell us the dst is dead)
//   - Inbound from peer keeps decrypting fine (we still process their packets)
//   - Outbound silently drops at the peer's old (now closed) NAT mapping
//   - Recovery requires either: peer re-keys (rare, only on rekey schedule),
//     blackhole heuristic flips us to relay (8s × 3 ≈ 24s minimum), or
//     the connection layer's retransmit eventually times out.
//
// What v1.9.1's address-learning fix should change:
//   - On every authenticated decrypt with non-beacon `from`, atomically
//     update `tm.peers[peerNodeID] = from` (already inside the same
//     `tm.mu.Lock()` block).
//   - Guard: never overwrite the stored address with the beacon's, even
//     transiently — that would break relay→direct probing.
//   - Guard: only update if peer is NOT currently in relay mode, OR is
//     in relay mode but the directClearCount is being incremented (i.e.
//     we're observing the direct path as healthy). The simplest correct
//     rule: update unconditionally when from != beacon, since the only
//     way `from` can be non-beacon is the peer reached us directly.
//
// FIXED (v1.9.1): handleEncrypted now atomically updates
// `tm.peers[peerNodeID] = from` on every authenticated direct decrypt
// (skipping the beacon-source case to preserve relay→direct probing).
// This test asserts the post-fix behavior: a NAT remap is learned within
// ONE inbound encrypted packet, with no key_exchange dependency.
func TestPeerNATRemapNotLearnedOnDecrypt(t *testing.T) {
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })

	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	tm.SetNodeID(0xDEADBEEF)

	const peerNodeID uint32 = 0x12345678

	// "Old" NAT mapping — what we currently believe the peer's address is.
	// We install the entry directly into tm.peers (bypassing AddPeer, which
	// would try to send a key-exchange via a UDP socket we never bound).
	addrOld := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 41000}

	// Establish a peerCrypto so handleEncrypted will decrypt successfully.
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
	tm.peers[peerNodeID] = addrOld
	tm.crypto[peerNodeID] = pc
	tm.mu.Unlock()

	// Build a real encrypted frame the way the peer would, then deliver
	// it via handleEncrypted with from=addrNew (the post-remap source).
	pkt := newPacket("post-nat-remap-payload")
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

	frame := make([]byte, 4+12+len(ct))
	binary.BigEndian.PutUint32(frame[0:4], peerNodeID)
	copy(frame[4:16], nonce)
	copy(frame[16:], ct)

	// "New" NAT mapping — peer's NAT box rotated their source port.
	addrNew := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 49152}

	tm.handleEncrypted(frame, addrNew)

	// FIXED (v1.9.1): handleEncrypted now atomically updates
	// tm.peers[peerNodeID] = from on every authenticated direct decrypt
	// (skipping beacon-source case). Subsequent tm.Send goes to the new
	// addr, no longer black-holing on the stale NAT mapping.
	tm.mu.RLock()
	stored := tm.peers[peerNodeID]
	tm.mu.RUnlock()

	if stored == nil {
		t.Fatalf("peer disappeared from tm.peers after decrypt")
	}
	if stored.Port != addrNew.Port || !stored.IP.Equal(addrNew.IP) {
		t.Errorf("address-learning failed: expected peer addr %v after decrypt, got %v",
			addrNew, stored)
	}

	// Symmetry: a SECOND remap (NAT churns again) should also be learned.
	addrNewer := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 51200}
	binary.BigEndian.PutUint64(nonce[4:12], 2)
	ct2 := pc.aead.Seal(nil, nonce, plaintext, aad)
	frame2 := make([]byte, 4+12+len(ct2))
	binary.BigEndian.PutUint32(frame2[0:4], peerNodeID)
	copy(frame2[4:16], nonce)
	copy(frame2[16:], ct2)
	tm.handleEncrypted(frame2, addrNewer)

	tm.mu.RLock()
	stored = tm.peers[peerNodeID]
	tm.mu.RUnlock()
	if stored.Port != addrNewer.Port {
		t.Errorf("second remap not learned: expected port %d, got %d",
			addrNewer.Port, stored.Port)
	}
}

// TestPeerNATRemapDoesNotPinToBeaconAddr pins the symmetric guard:
// when a frame arrives via beacon relay (from == beaconAddr), the
// address-learning path must NOT overwrite tm.peers[peerNodeID] with
// the beacon's address. Doing so would replace the peer's true direct
// endpoint with the beacon's listen port and break the relay→direct
// recovery probe (which checks for `addr != beacon`).
func TestPeerNATRemapDoesNotPinToBeaconAddr(t *testing.T) {
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })

	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	tm.SetNodeID(0xCAFEBABE)

	const peerNodeID uint32 = 0x87654321
	addrDirect := &net.UDPAddr{IP: net.ParseIP("198.51.100.5"), Port: 4000}
	beaconAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.99"), Port: 9001}

	if err := tm.SetBeaconAddr(beaconAddr.String()); err != nil {
		t.Fatalf("SetBeaconAddr: %v", err)
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
	tm.mu.Lock()
	tm.peers[peerNodeID] = addrDirect
	tm.crypto[peerNodeID] = pc
	tm.mu.Unlock()

	pkt := newPacket("relay-decrypted-payload")
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

	frame := make([]byte, 4+12+len(ct))
	binary.BigEndian.PutUint32(frame[0:4], peerNodeID)
	copy(frame[4:16], nonce)
	copy(frame[16:], ct)

	// Deliver "from" the beacon — this is what handleRelayDeliver does
	// when forwarding a relayed frame. The address-learning path must
	// reject this and keep the direct addr intact.
	tm.handleEncrypted(frame, beaconAddr)

	tm.mu.RLock()
	stored := tm.peers[peerNodeID]
	tm.mu.RUnlock()

	if stored == nil || !stored.IP.Equal(addrDirect.IP) || stored.Port != addrDirect.Port {
		t.Errorf("beacon-source decrypt overwrote direct peer addr: expected %v, got %v",
			addrDirect, stored)
	}
}

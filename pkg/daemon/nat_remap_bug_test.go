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
// This test pins the CURRENT (buggy) behavior so the fix has a concrete
// regression target. After the fix, the assertion below flips to assert
// that `tm.peers[peerNodeID]` equals the NEW from-addr.
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

	// CURRENT (buggy) behavior: handleEncrypted recorded lastDirectRecv but
	// did NOT update tm.peers — subsequent tm.Send still targets addrOld,
	// which is a dead NAT mapping the peer's network no longer accepts.
	tm.mu.RLock()
	stored := tm.peers[peerNodeID]
	tm.mu.RUnlock()

	if stored == nil {
		t.Fatalf("peer was removed from tm.peers; expected stale-but-present entry")
	}
	if stored.Port != addrOld.Port {
		t.Fatalf("BUG NOT REPRODUCED: peer addr already updates on decrypt — expected stale port %d, got %d",
			addrOld.Port, stored.Port)
	}
	// Pin the bug: we still believe the peer is at the old port.
	if stored.Port == addrNew.Port {
		t.Errorf("address-learning regression target: tm.peers should still be stale (=%d) before fix; got %d",
			addrOld.Port, stored.Port)
	}
}

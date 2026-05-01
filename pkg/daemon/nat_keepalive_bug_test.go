// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestKeepaliveAbsentForIdlePeer reproduces the "NAT mapping idle-times
// out for fully-silent peer pair" bug.
//
// Symptom: a peer pair establishes a tunnel, exchanges some traffic,
// then both sides go idle. Consumer-grade NATs purge UDP mappings
// after 30-90 s of no outbound traffic; CGNAT and enterprise NATs
// after a few minutes. When either side eventually wants to send,
// their packet arrives at the peer's NAT but there's no inbound
// mapping → silently dropped. Recovery requires the peer's app to
// send first AND for that send to trigger a key-exchange (which is
// only true if our pc became un-decryptable in the meantime — usually
// it's still good, so no rekey, no recovery).
//
// Real-world impact: this is precisely the failure mode that made
// iter 5 (NAT-remap address-learning) necessary. Iter 5 fixes the
// CONSEQUENCE (we learn the new addr after the peer manages to
// reach us). This iter fixes the CAUSE (we never let the mapping
// expire by sending a tiny periodic keepalive).
//
// Why per-Connection keepalives don't cover this: idleSweepLoop only
// sends keepalive ACKs for connections in StateEstablished. Tunnel
// peer state (tm.peers + tm.crypto) outlives individual connections.
// A long-lived peer relationship with bursty connection cycles can
// have NO active Connection for hours, during which no keepalive
// fires and the NAT mapping silently dies.
//
// What v1.9.1's tunnel-keepalive fix introduces:
//   - lastOutboundSend map[nodeID]time.Time tracking per writeFrame call
//   - TunnelKeepaliveInterval = 25 s (below consumer-NAT lower bound)
//   - keepaliveSweep(now) that enqueues a tiny ProtoControl/PortPing
//     encrypted frame to any peer whose lastOutboundSend is stale
//   - keepaliveLoop goroutine spawned from Listen()
//   - handleEncrypted filter that drops keepalives before recvCh
//
// FIXED (v1.9.1): keepaliveSweep now scans tm.peers, identifies stale
// peers (lastOutboundSend older than TunnelKeepaliveInterval), and
// emits a tiny encrypted ping per stale peer. keepaliveLoop runs the
// sweep periodically (spawned by Listen). handleEncrypted drops these
// pings before recvCh delivery. The post-fix assertion below verifies
// one stale peer produces one keepalive frame on the peer's socket.
func TestKeepaliveAbsentForIdlePeer(t *testing.T) {
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })

	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	tm.SetNodeID(0xAA000001)

	// Bind a peer-side UDP socket as the keepalive observation point.
	peerSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("peer listen: %v", err)
	}
	t.Cleanup(func() { peerSock.Close() })

	const peerNodeID uint32 = 0xBB000001
	peerAddr := peerSock.LocalAddr().(*net.UDPAddr)

	// Install crypto + peer entry so keepaliveSweep would have everything
	// it needs to encrypt and send.
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
	// Mark peer as "long-idle": last send was 1 minute ago, well beyond
	// any reasonable keepalive interval.
	tm.lastOutboundSend[peerNodeID] = time.Now().Add(-1 * time.Minute)
	tm.mu.Unlock()

	// Mark the peerCrypto as ready so keepaliveSweep emits to this peer.
	// (deriveSecret leaves ready=false until handleKeyExchange/auth seals it.)
	pc.ready = true

	// FIXED (v1.9.1): keepaliveSweep finds the stale peer and emits one
	// encrypted ping frame.
	sent := tm.keepaliveSweep(time.Now())
	if sent != 1 {
		t.Fatalf("expected keepaliveSweep to send 1 frame to stale peer; got %d", sent)
	}

	// Peer socket should receive one PILS-magic-prefixed encrypted frame.
	_ = peerSock.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1500)
	n, _, err := peerSock.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("expected keepalive frame on peer socket; read err: %v", err)
	}
	if n < 4+4+12+16 { // PILS magic + nodeID + nonce + GCM tag
		t.Errorf("keepalive frame too small: %d bytes", n)
	}
	// Verify lastOutboundSend was refreshed by writeFrame.
	tm.mu.RLock()
	last, ok := tm.lastOutboundSend[peerNodeID]
	tm.mu.RUnlock()
	if !ok || time.Since(last) > 500*time.Millisecond {
		t.Errorf("expected lastOutboundSend refreshed after keepalive send; last=%v", last)
	}
}

// TestKeepaliveSweepSkipsRecentlyActivePeers pins the inverse: peers
// whose lastOutboundSend is fresh (< TunnelKeepaliveInterval) must NOT
// receive a keepalive — that would be redundant traffic. The sweep
// must distinguish "active" from "silent" via the timestamp.
func TestKeepaliveSweepSkipsRecentlyActivePeers(t *testing.T) {
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })

	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}

	const peerNodeID uint32 = 0xDD000001
	peerSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("peer listen: %v", err)
	}
	t.Cleanup(func() { peerSock.Close() })

	curve := ecdh.X25519()
	peerPriv, _ := curve.GenerateKey(rand.Reader)
	pc, err := tm.deriveSecret(peerPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("deriveSecret: %v", err)
	}
	pc.ready = true

	tm.mu.Lock()
	tm.peers[peerNodeID] = peerSock.LocalAddr().(*net.UDPAddr)
	tm.crypto[peerNodeID] = pc
	// Recent send: 1 second ago, well under the 25 s threshold.
	tm.lastOutboundSend[peerNodeID] = time.Now().Add(-1 * time.Second)
	tm.mu.Unlock()

	if sent := tm.keepaliveSweep(time.Now()); sent != 0 {
		t.Errorf("active peer should not receive keepalive; got %d sends", sent)
	}
}

// TestHandleEncryptedDropsKeepaliveBeforeRecvCh pins the receiving half
// of the keepalive contract: an inbound keepalive must NOT appear on
// recvCh (else applications would see spurious pings every 25 s) but
// MUST trigger the side-effects (lastDirectRecv update, address-learning).
func TestHandleEncryptedDropsKeepaliveBeforeRecvCh(t *testing.T) {
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })

	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	tm.SetNodeID(0xEE000001)

	const peerNodeID uint32 = 0xFF000001
	peerAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12300}

	curve := ecdh.X25519()
	peerPriv, _ := curve.GenerateKey(rand.Reader)
	pc, err := tm.deriveSecret(peerPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("deriveSecret: %v", err)
	}
	pc.ready = true
	tm.mu.Lock()
	tm.peers[peerNodeID] = peerAddr
	tm.crypto[peerNodeID] = pc
	tm.mu.Unlock()

	// Build an empty ProtoControl/PortPing packet and frame it as peer
	// would (sender nodeID = peerNodeID, AAD bound to that). encryptFrame
	// would stamp tm.loadNodeID() — that's "us" not "peer", so we craft
	// the frame manually mirroring encryptFrame's wire format.
	ka := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoControl,
		DstPort:  protocol.PortPing,
	}
	plaintext, err := ka.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	nonce := make([]byte, pc.aead.NonceSize())
	copy(nonce[0:4], pc.noncePrefix[:])
	nonce[len(nonce)-1] = 1 // counter=1
	aad := []byte{0xFF, 0x00, 0x00, 0x01}
	ct := pc.aead.Seal(nil, nonce, plaintext, aad)
	body := make([]byte, 4+len(nonce)+len(ct))
	copy(body[0:4], aad)
	copy(body[4:4+len(nonce)], nonce)
	copy(body[4+len(nonce):], ct)
	tm.handleEncrypted(body, peerAddr)

	// Side-effect: lastDirectRecv was updated.
	tm.mu.RLock()
	_, gotRecv := tm.lastDirectRecv[peerNodeID]
	tm.mu.RUnlock()
	if !gotRecv {
		t.Errorf("expected lastDirectRecv to be set by inbound keepalive")
	}

	// Drop check: nothing on recvCh.
	select {
	case got := <-tm.RecvCh():
		t.Errorf("keepalive leaked to recvCh: %+v", got.Packet)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestRecordOutboundSendStampsTimestamp pins the half of the fix that
// already lands in RED: every successful writeFrame call must update
// tm.lastOutboundSend[nodeID] so the eventual keepaliveSweep can tell
// "active" from "silent" peers. Without this tracking, the GREEN
// keepaliveSweep would either send unnecessary keepalives to active
// peers (waste) or never know which peers are stale.
func TestRecordOutboundSendStampsTimestamp(t *testing.T) {
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })

	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	peerSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("peer listen: %v", err)
	}
	t.Cleanup(func() { peerSock.Close() })

	const peerNodeID uint32 = 0xCC000001
	peerAddr := peerSock.LocalAddr().(*net.UDPAddr)

	tm.mu.Lock()
	tm.peers[peerNodeID] = peerAddr
	tm.mu.Unlock()

	// Pre-condition: no entry yet.
	tm.mu.RLock()
	_, present := tm.lastOutboundSend[peerNodeID]
	tm.mu.RUnlock()
	if present {
		t.Fatalf("expected lastOutboundSend empty before any writeFrame call")
	}

	before := time.Now()
	if err := tm.writeFrame(peerNodeID, peerAddr, []byte("hello")); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}

	tm.mu.RLock()
	stamped, ok := tm.lastOutboundSend[peerNodeID]
	tm.mu.RUnlock()
	if !ok {
		t.Fatalf("expected lastOutboundSend stamped after writeFrame")
	}
	if stamped.Before(before) {
		t.Fatalf("lastOutboundSend = %v, expected >= %v", stamped, before)
	}
}

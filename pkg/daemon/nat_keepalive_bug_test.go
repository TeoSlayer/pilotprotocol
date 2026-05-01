// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"testing"
	"time"
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
// This test pins the CURRENT (buggy) behavior: the stub keepaliveSweep
// returns 0, peer's UDP socket sees zero unsolicited frames. After
// GREEN, the assertion flips: the sweep returns 1 and the peer's
// socket receives one keepalive frame.
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

	// CURRENT (buggy) behavior: keepaliveSweep is a stub returning 0.
	// No frame is sent; the peer's socket stays silent.
	sent := tm.keepaliveSweep(time.Now())
	if sent != 0 {
		t.Fatalf("BUG NOT REPRODUCED: keepaliveSweep returned %d (expected 0 stub); GREEN flips this assertion", sent)
	}

	// Drain peer socket with a short deadline — should observe nothing.
	_ = peerSock.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 1500)
	n, _, err := peerSock.ReadFromUDP(buf)
	if err == nil {
		t.Fatalf("BUG NOT REPRODUCED: unexpected packet on peer socket (%d bytes)", n)
	}
	netErr, ok := err.(net.Error)
	if !ok || !netErr.Timeout() {
		t.Fatalf("expected timeout on idle peer socket; got %v", err)
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

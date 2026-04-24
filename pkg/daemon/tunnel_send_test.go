// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

func newPacket(payload string) *protocol.Packet {
	return &protocol.Packet{
		Version:  1,
		Protocol: 1,
		SrcPort:  1000,
		DstPort:  2000,
		Payload:  []byte(payload),
	}
}

// mustListenUDP returns a bound UDP socket on 127.0.0.1:0.
func mustListenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	return c
}

func TestSendUnknownPeerReturnsError(t *testing.T) {
	tm := NewTunnelManager()
	err := tm.Send(9999, newPacket("x"))
	if err == nil {
		t.Fatalf("expected error for unknown peer")
	}
	if !strings.Contains(err.Error(), "no tunnel to node 9999") {
		t.Fatalf("error = %v, want \"no tunnel to node 9999\"", err)
	}
}

func TestSendRoutesThroughSendToAndWritesFrame(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()
	tm.SetNodeID(0x11223344)

	// Receiver peer UDP socket
	peerConn := mustListenUDP(t)
	defer peerConn.Close()
	peerAddr := peerConn.LocalAddr().(*net.UDPAddr)
	tm.AddPeer(7, peerAddr)

	pkt := newPacket("hello")
	if err := tm.Send(7, pkt); err != nil {
		t.Fatalf("Send: %v", err)
	}

	buf := make([]byte, 1500)
	if err := peerConn.SetReadDeadline(deadlineMS(500)); err != nil {
		t.Fatalf("setdeadline: %v", err)
	}
	n, _, err := peerConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("peer ReadFromUDP: %v", err)
	}
	// Plaintext (encrypt=false): magic is PILT
	if n < 4 {
		t.Fatalf("received %d bytes, want at least 4", n)
	}
	if string(buf[0:4]) != string(protocol.TunnelMagic[:]) {
		t.Fatalf("magic = %x, want PILT", buf[0:4])
	}
}

func TestSendToPlaintextEncapsulatesWithPILTMagic(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	peerConn := mustListenUDP(t)
	defer peerConn.Close()
	peerAddr := peerConn.LocalAddr().(*net.UDPAddr)

	if err := tm.SendTo(peerAddr, 42, newPacket("plain")); err != nil {
		t.Fatalf("SendTo: %v", err)
	}

	buf := make([]byte, 1500)
	if err := peerConn.SetReadDeadline(deadlineMS(500)); err != nil {
		t.Fatalf("setdeadline: %v", err)
	}
	n, _, err := peerConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("ReadFromUDP: %v", err)
	}
	if n < 4 || string(buf[0:4]) != string(protocol.TunnelMagic[:]) {
		t.Fatalf("expected PILT magic, got %x", buf[:min(n, 8)])
	}
	// Remaining bytes should be a valid marshaled packet — verify via Unmarshal
	got, err := protocol.Unmarshal(buf[4:n])
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(got.Payload) != "plain" {
		t.Fatalf("payload = %q, want \"plain\"", got.Payload)
	}
}

func TestSendToMarshalErrorPropagates(t *testing.T) {
	tm := NewTunnelManager()
	// Oversize payload: max 0xFFFF. 0x10000 triggers marshal error.
	pkt := &protocol.Packet{Payload: make([]byte, 0x10000)}
	err := tm.SendTo(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}, 1, pkt)
	if err == nil || !strings.Contains(err.Error(), "marshal") {
		t.Fatalf("expected marshal error, got %v", err)
	}
}

func TestSendToEncryptedBeforeKeyExchangeQueuesAndInitiates(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()
	tm.SetNodeID(99)

	peerConn := mustListenUDP(t)
	defer peerConn.Close()
	peerAddr := peerConn.LocalAddr().(*net.UDPAddr)

	// sendKeyExchangeToNode looks up addr from tm.peers, so register 77.
	tm.AddPeer(77, peerAddr)
	// Drain the AddPeer-triggered key-exchange frame so the real SendTo check is clean.
	drainBuf := make([]byte, 1500)
	peerConn.SetReadDeadline(deadlineMS(200))
	peerConn.ReadFromUDP(drainBuf)

	// No crypto for node 77 yet → SendTo should queue and initiate key exchange.
	if err := tm.SendTo(peerAddr, 77, newPacket("q1")); err != nil {
		t.Fatalf("SendTo: %v", err)
	}
	if err := tm.SendTo(peerAddr, 77, newPacket("q2")); err != nil {
		t.Fatalf("SendTo: %v", err)
	}

	tm.pendMu.Lock()
	queued := len(tm.pending[77])
	tm.pendMu.Unlock()
	if queued != 2 {
		t.Fatalf("pending[77] = %d, want 2", queued)
	}

	// Peer should have received at least one key-exchange frame (PILK magic).
	buf := make([]byte, 1500)
	if err := peerConn.SetReadDeadline(deadlineMS(500)); err != nil {
		t.Fatalf("setdeadline: %v", err)
	}
	n, _, err := peerConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("peer Read: %v", err)
	}
	if n < 4 {
		t.Fatalf("received %d bytes", n)
	}
	// Without identity set, sendKeyExchangeToNode uses unauth PILK frame.
	if string(buf[0:4]) != string(protocol.TunnelMagicKeyEx[:]) {
		t.Fatalf("expected PILK magic for key-exchange init, got %x", buf[0:4])
	}
}

func TestSendToEncryptedWithReadyCryptoSendsEncryptedFrame(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()
	tm.SetNodeID(5)

	// Set up pc.ready for peer 77
	pc, err := tm.deriveSecret(newPeerPubKey(t))
	if err != nil {
		t.Fatalf("deriveSecret: %v", err)
	}
	tm.mu.Lock()
	tm.crypto[77] = pc
	tm.mu.Unlock()

	peerConn := mustListenUDP(t)
	defer peerConn.Close()
	peerAddr := peerConn.LocalAddr().(*net.UDPAddr)

	beforeOK := tm.EncryptOK
	if err := tm.SendTo(peerAddr, 77, newPacket("secret")); err != nil {
		t.Fatalf("SendTo: %v", err)
	}
	if tm.EncryptOK != beforeOK+1 {
		t.Fatalf("EncryptOK = %d, want %d", tm.EncryptOK, beforeOK+1)
	}

	buf := make([]byte, 1500)
	if err := peerConn.SetReadDeadline(deadlineMS(500)); err != nil {
		t.Fatalf("setdeadline: %v", err)
	}
	n, _, err := peerConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("peer Read: %v", err)
	}
	if n < 4 || string(buf[0:4]) != string(protocol.TunnelMagicSecure[:]) {
		t.Fatalf("expected PILS magic, got %x", buf[0:4])
	}
}

func TestSendPlaintextToNodeLayout(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	peerConn := mustListenUDP(t)
	defer peerConn.Close()
	peerAddr := peerConn.LocalAddr().(*net.UDPAddr)

	data := []byte("rawdata")
	if err := tm.sendPlaintextToNode(12, peerAddr, data); err != nil {
		t.Fatalf("sendPlaintextToNode: %v", err)
	}

	buf := make([]byte, 1500)
	if err := peerConn.SetReadDeadline(deadlineMS(500)); err != nil {
		t.Fatalf("setdeadline: %v", err)
	}
	n, _, err := peerConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("ReadFromUDP: %v", err)
	}
	if n != 4+len(data) {
		t.Fatalf("n = %d, want %d", n, 4+len(data))
	}
	if string(buf[0:4]) != string(protocol.TunnelMagic[:]) {
		t.Fatalf("magic = %x, want PILT", buf[0:4])
	}
	if string(buf[4:n]) != "rawdata" {
		t.Fatalf("data = %q, want rawdata", buf[4:n])
	}
}

func TestWriteFrameNoAddrReturnsError(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	err := tm.writeFrame(55, nil, []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "no address for node 55") {
		t.Fatalf("expected no-address error, got %v", err)
	}
}

func TestWriteFrameRelayPathWrapsWithBeaconHeader(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()
	tm.SetNodeID(0x01020304)

	beaconConn := mustListenUDP(t)
	defer beaconConn.Close()
	if err := tm.SetBeaconAddr(beaconConn.LocalAddr().String()); err != nil {
		t.Fatalf("SetBeaconAddr: %v", err)
	}
	tm.SetRelayPeer(88, true)

	payload := []byte("payload-bytes")
	// addr is irrelevant when relay path is active
	if err := tm.writeFrame(88, nil, payload); err != nil {
		t.Fatalf("writeFrame relay: %v", err)
	}

	buf := make([]byte, 1500)
	if err := beaconConn.SetReadDeadline(deadlineMS(500)); err != nil {
		t.Fatalf("setdeadline: %v", err)
	}
	n, _, err := beaconConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("beacon Read: %v", err)
	}
	// Expected layout: [0x05][sender(4)][dest(4)][payload]
	if n != 1+4+4+len(payload) {
		t.Fatalf("beacon n = %d, want %d", n, 1+4+4+len(payload))
	}
	if buf[0] != protocol.BeaconMsgRelay {
		t.Fatalf("msg type = %x, want %x", buf[0], protocol.BeaconMsgRelay)
	}
	sender := binary.BigEndian.Uint32(buf[1:5])
	dest := binary.BigEndian.Uint32(buf[5:9])
	if sender != 0x01020304 {
		t.Fatalf("sender = %x, want 0x01020304", sender)
	}
	if dest != 88 {
		t.Fatalf("dest = %d, want 88", dest)
	}
	if string(buf[9:n]) != "payload-bytes" {
		t.Fatalf("payload = %q", buf[9:n])
	}
}

// Helpers: produce fresh X25519 peer pub; deadlineMS for read deadlines.
func newPeerPubKey(t *testing.T) []byte {
	t.Helper()
	c := newX25519Priv(t)
	return c.PublicKey().Bytes()
}

func newX25519Priv(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("x25519 keygen: %v", err)
	}
	return priv
}

func deadlineMS(ms int) time.Time {
	return time.Now().Add(time.Duration(ms) * time.Millisecond)
}

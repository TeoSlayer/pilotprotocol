// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// relayFrame builds the [srcNodeID(4)][inner] payload handleRelayDeliver
// consumes (the bytes after the BeaconMsgRelayDeliver type byte), wrapping a
// plaintext TunnelMagic inner packet.
func plaintextRelayPayload(t *testing.T, srcID uint32, payload string) []byte {
	t.Helper()
	pkt := newPacket(payload)
	pktData, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	inner := make([]byte, 4+len(pktData))
	copy(inner[0:4], protocol.TunnelMagic[:])
	copy(inner[4:], pktData)
	data := make([]byte, 4+len(inner))
	binary.BigEndian.PutUint32(data[0:4], srcID)
	copy(data[4:], inner)
	return data
}

// TestBeaconPunchCommandDroppedFromNonBeaconSource is the PPA-005 reflection
// fix: a punch command from any source other than the configured beacon is
// dropped, so the daemon cannot be used as an unauthenticated UDP reflector.
func TestBeaconPunchCommandDroppedFromNonBeaconSource(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()
	tm.SetBeaconAddr("127.0.0.1:9001")

	target := mustListenUDP(t)
	defer target.Close()
	targetAddr := target.LocalAddr().(*net.UDPAddr)
	ip4 := targetAddr.IP.To4()

	data := make([]byte, 1+1+4+2)
	data[0] = protocol.BeaconMsgPunchCommand
	data[1] = 4
	copy(data[2:6], ip4)
	binary.BigEndian.PutUint16(data[6:8], uint16(targetAddr.Port))

	spoofed := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 6666}
	tm.handleBeaconMessage(data, spoofed)

	target.SetReadDeadline(deadlineMS(200))
	buf := make([]byte, 16)
	if _, _, err := target.ReadFromUDP(buf); err == nil {
		t.Fatalf("punch reflected from a non-beacon source (PPA-005)")
	}
}

// TestBeaconRelayDeliverDroppedFromNonBeaconSource is the PPA-005 injection
// fix: relay deliveries from a non-beacon source are dropped before the inner
// frame is dispatched.
func TestBeaconRelayDeliverDroppedFromNonBeaconSource(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()
	tm.SetBeaconAddr("127.0.0.1:9001")

	data := append([]byte{protocol.BeaconMsgRelayDeliver}, plaintextRelayPayload(t, 55, "spoofed-relay")...)
	spoofed := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 6666}
	tm.handleBeaconMessage(data, spoofed)

	select {
	case got := <-tm.RecvCh():
		t.Fatalf("relay-injected frame from non-beacon source delivered: %q", got.Packet.Payload)
	case <-time.After(150 * time.Millisecond):
	}
}

// TestBeaconRelayDeliverAcceptedFromBeaconSource confirms honest relay
// traffic (from the configured beacon) still flows through.
func TestBeaconRelayDeliverAcceptedFromBeaconSource(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()
	tm.SetBeaconAddr("127.0.0.1:9001")

	data := append([]byte{protocol.BeaconMsgRelayDeliver}, plaintextRelayPayload(t, 55, "honest-relay")...)
	beacon := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	tm.handleBeaconMessage(data, beacon)

	select {
	case got := <-tm.RecvCh():
		if string(got.Packet.Payload) != "honest-relay" {
			t.Fatalf("payload = %q, want honest-relay", got.Packet.Payload)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("honest relay traffic from the beacon was dropped")
	}
}

// TestBeaconRelayDeliverAcceptedInCompatMode confirms compat-mode (WSS) relay
// still works: the WSS remote is a synthetic address that never matches the
// routing beacon, so the ForceRelay signal must vouch for it.
func TestBeaconRelayDeliverAcceptedInCompatMode(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()
	tm.routing.SetForceRelay(true)

	data := append([]byte{protocol.BeaconMsgRelayDeliver}, plaintextRelayPayload(t, 55, "compat-relay")...)
	synthetic := &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 0}
	tm.handleBeaconMessage(data, synthetic)

	select {
	case got := <-tm.RecvCh():
		if string(got.Packet.Payload) != "compat-relay" {
			t.Fatalf("payload = %q, want compat-relay", got.Packet.Payload)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("compat-mode relay traffic was dropped")
	}
}

// TestPlaintextTunnelMagicDroppedViaRelayWhenEncrypted is the PPA-007 fix on
// the relay path: with encryption enabled, a plaintext TunnelMagic data
// packet is dropped rather than delivered (it should have arrived as
// TunnelMagicSecure).
func TestPlaintextTunnelMagicDroppedViaRelayWhenEncrypted(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()
	tm.SetBeaconAddr("127.0.0.1:9001")

	tm.handleRelayDeliver(plaintextRelayPayload(t, 77, "plain-relay"))

	select {
	case got := <-tm.RecvCh():
		t.Fatalf("plaintext relay frame delivered despite encrypt=true: %q", got.Packet.Payload)
	case <-time.After(150 * time.Millisecond):
	}
}

// TestPlaintextTunnelMagicDroppedDirectWhenEncrypted is the PPA-007 fix on the
// direct readLoop path.
func TestPlaintextTunnelMagicDroppedDirectWhenEncrypted(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	local := tm.LocalAddr().(*net.UDPAddr)
	pkt := newPacket("plain-inject")
	pktData, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	frame := make([]byte, 4+len(pktData))
	copy(frame[0:4], protocol.TunnelMagic[:])
	copy(frame[4:], pktData)

	conn, err := net.DialUDP("udp", nil, local)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case got := <-tm.RecvCh():
		t.Fatalf("plaintext frame delivered on encrypted node: %q", got.Packet.Payload)
	case <-time.After(250 * time.Millisecond):
	}
}

// TestRelayKxRateLimiterBounds is the PPA-005/PPA-011 relay-KX limiter: relay
// key-exchange frames are metered per relay-asserted srcNodeID (they were
// fully exempt from the per-source-IP limiter because the source is always
// the beacon).
func TestRelayKxRateLimiterBounds(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()

	const src = uint32(4242)
	for i := 0; i < perRelaySrcKxLimit; i++ {
		if !tm.allowKxFromRelaySrc(src) {
			t.Fatalf("relay KX %d within budget was rejected", i+1)
		}
	}
	if tm.allowKxFromRelaySrc(src) {
		t.Fatal("relay KX past the per-src budget should be rejected")
	}
	if !tm.allowKxFromRelaySrc(src + 1) {
		t.Fatal("a distinct srcNodeID should have its own budget (honest peers keep working)")
	}
}

// TestRelayKxRateLimiterMapBounded pins the map cap so an attacker rotating
// srcNodeIDs cannot grow it without bound.
func TestRelayKxRateLimiterMapBounded(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()

	for i := 0; i < maxRelayKxEntries+256; i++ {
		tm.allowKxFromRelaySrc(uint32(i))
	}
	tm.relayKxMu.Lock()
	size := len(tm.relayKxLim)
	tm.relayKxMu.Unlock()
	if size > maxRelayKxEntries {
		t.Fatalf("relayKxLim grew to %d entries, want <= %d", size, maxRelayKxEntries)
	}
}

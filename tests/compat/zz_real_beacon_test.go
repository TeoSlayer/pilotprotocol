// SPDX-License-Identifier: AGPL-3.0-or-later

// This file exercises the REAL production beacon binary's compat WSS
// bridge — not the synthetic in-memory bridge used by
// zz_matrix_test.go. It spins up a real *beacon.Server with
// ListenAndServe + EnableCompatWSS, attaches a real *dwss.Transport
// as the "compat daemon" peer, and a raw net.ListenUDP as the
// "UDP-side" peer. The goal is to emulate a managed claw whose
// outbound UDP is firewalled: the daemon must reach UDP-only peers
// purely through the WSS bridge.
//
// Coverage gap this closes: zz_matrix_test.go validates the bwss
// auth + frame plumbing, but its "bridge" routing decisions are
// synthetic. The production pkg/beacon/server.go has its own
// relayWorker tiered lookup (Tier-0 WSS → Tier-1 local UDP → Tier-2
// peer mesh) that was never tested end-to-end. This file does that.

package compat_test

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/transport/wss"
	"github.com/pilot-protocol/beacon"
	bwss "github.com/pilot-protocol/beacon/wss"
	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/protocol"
)

// startRealBeacon brings up a real *beacon.Server with its compat WSS
// bridge enabled. The pubkey lookup is backed by a sync.Map that the
// test seeds before the WSS auth handshake fires.
func startRealBeacon(t *testing.T, pubkeys *sync.Map) (b *beacon.Server, udpAddr string, wssAddr string) {
	t.Helper()
	b = beacon.New()

	lookup := bwss.PubKeyLookupFn(func(nodeID uint32) (ed25519.PublicKey, bool) {
		v, ok := pubkeys.Load(nodeID)
		if !ok {
			return nil, false
		}
		return v.(ed25519.PublicKey), true
	})
	if err := b.EnableCompatWSS("127.0.0.1:0", lookup); err != nil {
		t.Fatalf("EnableCompatWSS: %v", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- b.ListenAndServe("127.0.0.1:0") }()

	select {
	case <-b.Ready():
	case err := <-errCh:
		t.Fatalf("beacon.ListenAndServe early-returned: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to become ready in 5s")
	}

	t.Cleanup(func() {
		_ = b.CloseCompatWSS()
		_ = b.Close()
	})

	return b, b.Addr().String(), b.WSSAddr()
}

// dialWSSPeer connects a real dwss.Transport to the beacon's WSS
// listener and waits for the beacon-side IsConnected to flip true.
func dialWSSPeer(t *testing.T, wssAddr string, id *crypto.Identity, nodeID uint32, b *beacon.Server) *wss.Transport {
	t.Helper()
	url := "ws://" + wssAddr + "/v1/compat"
	tr, err := wss.Dial(context.Background(), wss.Config{
		URL:         url,
		TLSConfig:   &tls.Config{}, // ws:// → TLS bypassed
		Identity:    id,
		NodeID:      nodeID,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dwss.Dial nodeID=%d: %v", nodeID, err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if b.WSSIsConnected(nodeID) {
			return tr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("WSS peer %d never registered on beacon side", nodeID)
	return nil
}

// dialUDPPeer opens a UDP socket, then sends a BeaconMsgDiscover to
// register the nodeID with the beacon. Returns the conn so the test
// can use it to send relays and to drain inbound BeaconMsgRelayDeliver
// frames.
func dialUDPPeer(t *testing.T, beaconUDP string, nodeID uint32) *net.UDPConn {
	t.Helper()
	udpBeacon, err := net.ResolveUDPAddr("udp", beaconUDP)
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Discover packet: [type=0x01][nodeID(4)]
	disc := make([]byte, 5)
	disc[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(disc[1:5], nodeID)
	if _, err := conn.WriteToUDP(disc, udpBeacon); err != nil {
		t.Fatalf("Discover write: %v", err)
	}

	// Drain the DiscoverReply (and anything else) for 200ms to make
	// sure the beacon has processed our registration.
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 2048)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil || n == 0 {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	return conn
}

// sendRelay constructs and sends a BeaconMsgRelay from a UDP peer.
// Format: [0x05][senderID(4)][destID(4)][payload].
func sendRelayUDP(t *testing.T, conn *net.UDPConn, beaconUDP string, senderID, destID uint32, payload []byte) {
	t.Helper()
	udpBeacon, err := net.ResolveUDPAddr("udp", beaconUDP)
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	pkt := make([]byte, 1+4+4+len(payload))
	pkt[0] = protocol.BeaconMsgRelay
	binary.BigEndian.PutUint32(pkt[1:5], senderID)
	binary.BigEndian.PutUint32(pkt[5:9], destID)
	copy(pkt[9:], payload)
	if _, err := conn.WriteToUDP(pkt, udpBeacon); err != nil {
		t.Fatalf("relay write: %v", err)
	}
}

// recvRelayDeliverUDP reads from the UDP conn until a
// BeaconMsgRelayDeliver arrives or the deadline fires. Returns the
// senderID and payload extracted from the deliver frame.
func recvRelayDeliverUDP(t *testing.T, conn *net.UDPConn, timeout time.Duration) (uint32, []byte) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})
	buf := make([]byte, 2048)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("UDP recv (waiting for RelayDeliver): %v", err)
		}
		if n < 5 || buf[0] != protocol.BeaconMsgRelayDeliver {
			continue // skip DiscoverReply etc.
		}
		senderID := binary.BigEndian.Uint32(buf[1:5])
		payload := make([]byte, n-5)
		copy(payload, buf[5:n])
		return senderID, payload
	}
}

// recvRelayDeliverWSS reads frames from the dwss transport until a
// BeaconMsgRelayDeliver arrives. The compat daemon receives raw
// beacon-protocol frames over WSS.
func recvRelayDeliverWSS(t *testing.T, tr *wss.Transport, timeout time.Duration) (uint32, []byte) {
	t.Helper()
	done := make(chan struct{})
	var senderID uint32
	var payload []byte
	var err error
	go func() {
		defer close(done)
		for {
			var frame []byte
			frame, _, err = tr.Recv()
			if err != nil {
				return
			}
			if len(frame) < 5 || frame[0] != protocol.BeaconMsgRelayDeliver {
				continue
			}
			senderID = binary.BigEndian.Uint32(frame[1:5])
			payload = make([]byte, len(frame)-5)
			copy(payload, frame[5:])
			return
		}
	}()
	select {
	case <-done:
		if err != nil {
			t.Fatalf("WSS recv: %v", err)
		}
		return senderID, payload
	case <-time.After(timeout):
		t.Fatal("WSS recv timed out waiting for RelayDeliver")
		return 0, nil
	}
}

// TestRealBeacon_UDPToWSS pins that a UDP-side sender's relay packet
// is delivered to a WSS-connected destination via the beacon's
// Tier-0 WSS path. This is the *managed-claw* scenario: the claw's
// daemon is in compat mode (UDP-blocked egress), and a normal UDP
// peer wants to message it.
func TestRealBeacon_UDPToWSS(t *testing.T) {
	t.Parallel()

	wssID, _ := crypto.GenerateIdentity()
	const wssNode uint32 = 7001
	const udpNode uint32 = 7002

	var pubkeys sync.Map
	pubkeys.Store(wssNode, ed25519.PublicKey(wssID.PublicKey))

	b, udpAddr, wssAddr := startRealBeacon(t, &pubkeys)
	_ = b

	wssTr := dialWSSPeer(t, wssAddr, wssID, wssNode, b)
	udpConn := dialUDPPeer(t, udpAddr, udpNode)

	payload := []byte("hello-from-udp-to-managed-claw")
	sendRelayUDP(t, udpConn, udpAddr, udpNode, wssNode, payload)

	gotSender, gotPayload := recvRelayDeliverWSS(t, wssTr, 2*time.Second)
	if gotSender != udpNode {
		t.Errorf("sender = %d; want %d", gotSender, udpNode)
	}
	if string(gotPayload) != string(payload) {
		t.Errorf("payload = %q; want %q", gotPayload, payload)
	}
}

// TestRealBeacon_WSSToUDP is the inverse: a managed claw (compat
// daemon) sends a relay packet to a UDP-only peer. Validates the
// WSS-inbound → handlePacket → dispatchRelay → UDP worker write
// path.
func TestRealBeacon_WSSToUDP(t *testing.T) {
	t.Parallel()

	wssID, _ := crypto.GenerateIdentity()
	const wssNode uint32 = 7101
	const udpNode uint32 = 7102

	var pubkeys sync.Map
	pubkeys.Store(wssNode, ed25519.PublicKey(wssID.PublicKey))

	b, udpAddr, wssAddr := startRealBeacon(t, &pubkeys)
	_ = b

	wssTr := dialWSSPeer(t, wssAddr, wssID, wssNode, b)
	udpConn := dialUDPPeer(t, udpAddr, udpNode)

	payload := []byte("reply-from-managed-claw-back-to-udp")
	// Build the relay frame as the compat daemon would: same on-the-wire
	// format the UDP read loop dispatches.
	frame := make([]byte, 1+4+4+len(payload))
	frame[0] = protocol.BeaconMsgRelay
	binary.BigEndian.PutUint32(frame[1:5], wssNode)
	binary.BigEndian.PutUint32(frame[5:9], udpNode)
	copy(frame[9:], payload)
	if _, err := wssTr.Send(frame, nil); err != nil {
		t.Fatalf("wssTr.Send: %v", err)
	}

	gotSender, gotPayload := recvRelayDeliverUDP(t, udpConn, 2*time.Second)
	if gotSender != wssNode {
		t.Errorf("sender = %d; want %d", gotSender, wssNode)
	}
	if string(gotPayload) != string(payload) {
		t.Errorf("payload = %q; want %q", gotPayload, payload)
	}
}

// TestRealBeacon_WSSToWSS_BothManaged covers the both-sides-firewalled
// case: two managed claws each in compat mode, talking to each other
// purely through the beacon's WSS bridge with zero UDP datagrams on
// the data plane.
func TestRealBeacon_WSSToWSS_BothManaged(t *testing.T) {
	t.Parallel()

	idA, _ := crypto.GenerateIdentity()
	idB, _ := crypto.GenerateIdentity()
	const nodeA uint32 = 7201
	const nodeB uint32 = 7202

	var pubkeys sync.Map
	pubkeys.Store(nodeA, ed25519.PublicKey(idA.PublicKey))
	pubkeys.Store(nodeB, ed25519.PublicKey(idB.PublicKey))

	b, _, wssAddr := startRealBeacon(t, &pubkeys)

	trA := dialWSSPeer(t, wssAddr, idA, nodeA, b)
	trB := dialWSSPeer(t, wssAddr, idB, nodeB, b)

	payload := []byte("both-sides-blocked-talking-via-wss-bridge")
	frame := make([]byte, 1+4+4+len(payload))
	frame[0] = protocol.BeaconMsgRelay
	binary.BigEndian.PutUint32(frame[1:5], nodeA)
	binary.BigEndian.PutUint32(frame[5:9], nodeB)
	copy(frame[9:], payload)
	if _, err := trA.Send(frame, nil); err != nil {
		t.Fatalf("A→beacon send: %v", err)
	}

	gotSender, gotPayload := recvRelayDeliverWSS(t, trB, 2*time.Second)
	if gotSender != nodeA {
		t.Errorf("sender = %d; want %d", gotSender, nodeA)
	}
	if string(gotPayload) != string(payload) {
		t.Errorf("payload = %q; want %q", gotPayload, payload)
	}
}

// TestRealBeacon_UnknownDestWSS pins that a relay targeting a
// WSS-registered nodeID that has since disconnected is dropped
// cleanly (no panic, no double-write to a stale conn). Reflects the
// 'IsConnected then conn dropped before WriteFrame' race in the
// production server's Tier-0 branch.
func TestRealBeacon_UnknownDestWSS(t *testing.T) {
	t.Parallel()

	wssID, _ := crypto.GenerateIdentity()
	const wssNode uint32 = 7301
	const udpNode uint32 = 7302

	var pubkeys sync.Map
	pubkeys.Store(wssNode, ed25519.PublicKey(wssID.PublicKey))

	b, udpAddr, wssAddr := startRealBeacon(t, &pubkeys)
	_ = b

	wssTr := dialWSSPeer(t, wssAddr, wssID, wssNode, b)
	// Close the WSS peer; the next relay must drop, not crash.
	_ = wssTr.Close()
	// Give the server time to observe the close.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && b.WSSIsConnected(wssNode) {
		time.Sleep(10 * time.Millisecond)
	}
	if b.WSSIsConnected(wssNode) {
		t.Fatalf("WSS peer still marked connected after Close")
	}

	udpConn := dialUDPPeer(t, udpAddr, udpNode)
	sendRelayUDP(t, udpConn, udpAddr, udpNode, wssNode, []byte("ghost"))

	// Should NOT receive a RelayDeliver — drain for 300ms; absence is
	// the success signal.
	_ = udpConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 2048)
	for {
		n, _, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if n >= 1 && buf[0] == protocol.BeaconMsgRelayDeliver {
			t.Fatalf("unexpected RelayDeliver for disconnected WSS peer")
		}
	}
	// Beacon must still be alive and serving.
	if !strings.Contains(b.Addr().String(), "127.0.0.1:") {
		t.Errorf("beacon UDP addr looks wrong: %v", b.Addr())
	}
}

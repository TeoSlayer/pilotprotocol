// SPDX-License-Identifier: AGPL-3.0-or-later

// Package compat_test exercises the 4-cell compat-mode transport
// matrix end-to-end: UDP↔UDP, UDP↔WSS, WSS↔UDP, WSS↔WSS. It uses an
// in-process "fake beacon" that bridges the UDP relay path and the
// WSS peer map — proving the architecture works without depending on
// the production beacon binary's UDP fast-path integration (planned
// follow-up; see docs/SPEC-compat-mode.md §Rollout phase 4).
package compat_test

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/transport"
	dwss "github.com/TeoSlayer/pilotprotocol/pkg/daemon/transport/wss"
	bwss "github.com/pilot-protocol/beacon/wss"
	"github.com/pilot-protocol/common/crypto"
)

// bridge ties together the new WSS surface and a synthetic "UDP side"
// (in-memory channels here, since spinning up a real pkg/beacon to
// route raw L2 packets is out of scope for a unit-scale integration
// test). For each cell of the 4-cell matrix the bridge demonstrates
// the routing decisions the real production beacon must make.
//
// Maps:
//
//	wssPeers   — node IDs reachable via the bwss.Server
//	udpPeers   — node IDs reachable via an in-memory UDP-side channel
//
// For each inbound frame (from either side), the bridge:
//
//  1. Reads the destination node ID from the FIRST 4 BYTES of the
//     frame (test framing — real Pilot packets carry their own
//     dst-routing info; this lets us assert routing without parsing
//     a 34-byte header).
//  2. Looks up the destination. WSS first, UDP fallback.
//  3. Writes the frame on the correct side.
type bridge struct {
	t          *testing.T
	wssServer  *bwss.Server
	udpInboxes sync.Map // nodeID(uint32) → chan []byte
}

func (b *bridge) registerUDPPeer(nodeID uint32) chan []byte {
	ch := make(chan []byte, 32)
	b.udpInboxes.Store(nodeID, ch)
	return ch
}

// routeFrame is invoked for every frame arriving from EITHER side.
// senderID is informational; destID is parsed from frame[0:4].
func (b *bridge) routeFrame(frame []byte) {
	if len(frame) < 4 {
		return
	}
	destID := uint32(frame[0])<<24 | uint32(frame[1])<<16 | uint32(frame[2])<<8 | uint32(frame[3])

	// Path A: WSS dest.
	if b.wssServer != nil && b.wssServer.IsConnected(destID) {
		if b.wssServer.WriteFrame(destID, frame) {
			return
		}
	}
	// Path B: UDP dest.
	if v, ok := b.udpInboxes.Load(destID); ok {
		ch := v.(chan []byte)
		select {
		case ch <- frame:
		default:
			b.t.Logf("udp inbox full for dest %d", destID)
		}
		return
	}
	b.t.Logf("no route for dest %d", destID)
}

// startBridge spins up a bwss.Server bound to 127.0.0.1:0 plus the
// in-memory UDP side. PubKeyLookup is closed over the provided map.
// OnFrame routes every WSS-inbound frame through routeFrame.
func startBridge(t *testing.T, pubKeys map[uint32]ed25519.PublicKey) *bridge {
	t.Helper()
	b := &bridge{t: t}
	s, err := bwss.New(bwss.Config{
		BindAddr: "127.0.0.1:0",
		PubKeyLookup: func(id uint32) (ed25519.PublicKey, bool) {
			k, ok := pubKeys[id]
			return k, ok
		},
		OnFrame: func(senderID uint32, frame []byte) {
			b.routeFrame(frame)
		},
		AuthTimeout: 2 * time.Second,
		IdleTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("bwss.New: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("bwss.Start: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	b.wssServer = s
	return b
}

// wsURL returns the ws:// URL pointing at /v1/compat. Waits briefly
// for the server to be ready (health check).
func wsURL(t *testing.T, s *bwss.Server) string {
	t.Helper()
	addr := s.Addr()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/health")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return "ws://" + addr + "/v1/compat"
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("bridge wss at %s never became ready", addr)
	return ""
}

// dialCompatDaemon attaches a wssTransport for the given identity +
// nodeID. Used by tests that need a "compat daemon" endpoint.
func dialCompatDaemon(t *testing.T, b *bridge, id *crypto.Identity, nodeID uint32) *dwss.Transport {
	t.Helper()
	tr, err := dwss.Dial(context.Background(), dwss.Config{
		URL:         wsURL(t, b.wssServer),
		TLSConfig:   &tls.Config{}, // plain ws://, TLS is bypassed
		Identity:    id,
		NodeID:      nodeID,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial compat daemon %d: %v", nodeID, err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	// Wait briefly for the bridge to register the peer.
	waitForConn(t, b.wssServer, nodeID, 500*time.Millisecond)
	return tr
}

func waitForConn(t *testing.T, s *bwss.Server, nodeID uint32, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.IsConnected(nodeID) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("peer %d not connected after %v", nodeID, timeout)
}

// destPrefix builds a 4-byte big-endian dst-node-ID prefix that the
// fake bridge uses to route. Real Pilot packets parse dst out of the
// 34-byte header; this is a synthetic test framing.
func destPrefix(destID uint32, payload []byte) []byte {
	b := make([]byte, 4+len(payload))
	b[0] = byte(destID >> 24)
	b[1] = byte(destID >> 16)
	b[2] = byte(destID >> 8)
	b[3] = byte(destID)
	copy(b[4:], payload)
	return b
}

// TestMatrix_WSS_to_WSS pins that two compat-mode daemons can talk
// through the bridge. Both register WSS peer connections; the bridge
// routes frame from A to B via WriteFrame.
func TestMatrix_WSS_to_WSS(t *testing.T) {
	t.Parallel()
	idA, _ := crypto.GenerateIdentity()
	idB, _ := crypto.GenerateIdentity()
	const nodeA, nodeB uint32 = 1001, 1002

	b := startBridge(t, map[uint32]ed25519.PublicKey{
		nodeA: ed25519.PublicKey(idA.PublicKey),
		nodeB: ed25519.PublicKey(idB.PublicKey),
	})

	trA := dialCompatDaemon(t, b, idA, nodeA)
	trB := dialCompatDaemon(t, b, idB, nodeB)

	// A sends to B.
	payload := []byte("alpha→bravo over wss")
	if _, err := trA.Send(destPrefix(nodeB, payload), nil); err != nil {
		t.Fatalf("A Send: %v", err)
	}

	got, _, err := readWithTimeout(t, trB, 1*time.Second)
	if err != nil {
		t.Fatalf("B Recv: %v", err)
	}
	if !bytesContain(got, payload) {
		t.Errorf("B received %q; want it to contain %q", got, payload)
	}
}

// TestMatrix_WSS_to_UDP pins that a compat-mode daemon (sender) can
// reach a UDP-side peer (receiver) via the bridge. UDP side is
// represented by an in-memory inbox channel that bridge.routeFrame
// writes to.
func TestMatrix_WSS_to_UDP(t *testing.T) {
	t.Parallel()
	idWSS, _ := crypto.GenerateIdentity()
	const wssNode, udpNode uint32 = 2001, 2002

	b := startBridge(t, map[uint32]ed25519.PublicKey{
		wssNode: ed25519.PublicKey(idWSS.PublicKey),
	})
	udpInbox := b.registerUDPPeer(udpNode)

	trWSS := dialCompatDaemon(t, b, idWSS, wssNode)

	payload := []byte("wss-side→udp-side")
	if _, err := trWSS.Send(destPrefix(udpNode, payload), nil); err != nil {
		t.Fatalf("WSS Send: %v", err)
	}

	select {
	case got := <-udpInbox:
		if !bytesContain(got, payload) {
			t.Errorf("UDP side got %q; want %q", got, payload)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("UDP side never received frame")
	}
}

// TestMatrix_UDP_to_WSS pins the reverse: a UDP-side peer pushing a
// frame into the bridge sees it routed to the connected WSS daemon.
// The bridge here simulates the production-beacon's UDP-readLoop:
// when a relay packet arrives whose destination is a WSS peer, it
// gets WriteFrame'd to that peer's conn.
func TestMatrix_UDP_to_WSS(t *testing.T) {
	t.Parallel()
	idWSS, _ := crypto.GenerateIdentity()
	const wssNode, udpNode uint32 = 3001, 3002

	b := startBridge(t, map[uint32]ed25519.PublicKey{
		wssNode: ed25519.PublicKey(idWSS.PublicKey),
	})
	_ = b.registerUDPPeer(udpNode) // sender side

	trWSS := dialCompatDaemon(t, b, idWSS, wssNode)

	// Simulate a UDP packet arriving at the bridge destined for wssNode.
	payload := []byte("udp-side→wss-side")
	b.routeFrame(destPrefix(wssNode, payload))

	got, _, err := readWithTimeout(t, trWSS, 1*time.Second)
	if err != nil {
		t.Fatalf("WSS Recv: %v", err)
	}
	if !bytesContain(got, payload) {
		t.Errorf("WSS got %q; want %q", got, payload)
	}
}

// TestMatrix_UDP_to_UDP_baseline is the no-WSS path. Both peers are
// UDP-side; the bridge just shuttles between two channels. The
// existing tests/ integration suite covers this case at the real-
// daemon level; this just confirms the bridge harness routes it
// correctly so the harness itself isn't biased toward the new paths.
func TestMatrix_UDP_to_UDP_baseline(t *testing.T) {
	t.Parallel()
	b := startBridge(t, map[uint32]ed25519.PublicKey{})
	udpInboxA := b.registerUDPPeer(4001)
	udpInboxB := b.registerUDPPeer(4002)

	payload := []byte("udp↔udp baseline")
	b.routeFrame(destPrefix(4002, payload))

	select {
	case got := <-udpInboxB:
		if !bytesContain(got, payload) {
			t.Errorf("B got %q; want %q", got, payload)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("B inbox empty")
	}

	// And ensure A didn't receive its own send (no loopback).
	select {
	case stray := <-udpInboxA:
		t.Errorf("A inbox unexpectedly received %q", stray)
	case <-time.After(100 * time.Millisecond):
		// expected
	}
}

// TestMatrix_WSSReconnectPreservesRouting pins that a compat daemon
// dropping and re-establishing its WSS connection retains routability.
// Mirrors what happens when a Docker container restarts.
func TestMatrix_WSSReconnectPreservesRouting(t *testing.T) {
	t.Parallel()
	idA, _ := crypto.GenerateIdentity()
	const nodeA uint32 = 5001

	b := startBridge(t, map[uint32]ed25519.PublicKey{
		nodeA: ed25519.PublicKey(idA.PublicKey),
	})

	trA1 := dialCompatDaemon(t, b, idA, nodeA)
	// Drop the connection.
	_ = trA1.Close()
	// Wait briefly for the server-side read loop to notice.
	time.Sleep(50 * time.Millisecond)

	// Reconnect.
	trA2 := dialCompatDaemon(t, b, idA, nodeA)

	// Bridge should now route to the new connection.
	payload := []byte("post-reconnect frame")
	b.routeFrame(destPrefix(nodeA, payload))

	got, _, err := readWithTimeout(t, trA2, 1*time.Second)
	if err != nil {
		t.Fatalf("Recv after reconnect: %v", err)
	}
	if !bytesContain(got, payload) {
		t.Errorf("got %q; want %q", got, payload)
	}
}

// TestMatrix_UnknownDestDropsCleanly pins that a frame for a node ID
// nobody knows is dropped silently (not panic, not delivered to a
// stale slot). This is what happens in the wild when a peer
// deregisters mid-conversation.
func TestMatrix_UnknownDestDropsCleanly(t *testing.T) {
	t.Parallel()
	b := startBridge(t, map[uint32]ed25519.PublicKey{})
	// No peers registered. A routed frame should just disappear.
	b.routeFrame(destPrefix(99999, []byte("nobody home")))
	// If routeFrame panics or wedges, the test fails.
}

// helpers ----------------------------------------------------------

func readWithTimeout(t *testing.T, tr *dwss.Transport, timeout time.Duration) ([]byte, *net.UDPAddr, error) {
	t.Helper()
	type result struct {
		frame []byte
		src   *net.UDPAddr
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		f, s, e := tr.Recv()
		ch <- result{frame: f, src: s, err: e}
	}()
	select {
	case r := <-ch:
		return r.frame, r.src, r.err
	case <-time.After(timeout):
		// Force a close so the Recv goroutine unblocks; we won't
		// drain that result (cleanup runs anyway).
		_ = tr.Close()
		return nil, nil, errors.New("recv timeout")
	}
}

func bytesContain(haystack, needle []byte) bool {
	return len(haystack) >= len(needle) && containsAt(haystack, needle)
}

func containsAt(h, n []byte) bool {
	if len(h) < len(n) {
		return false
	}
	for i := 0; i+len(n) <= len(h); i++ {
		if equal(h[i:i+len(n)], n) {
			return true
		}
	}
	return false
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Ensure all packages we depend on are at least referenced so the
// import list stays meaningful to the next reader.
var (
	_ = transport.ErrClosed
	_ = strings.Contains
	_ = httptest.NewServer
)

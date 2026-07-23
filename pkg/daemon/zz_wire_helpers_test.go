// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
	registry "github.com/pilot-protocol/common/registry/client"
)

// newWireDaemon wires a Daemon with a tunnel bound to a real 127.0.0.1 UDP
// socket and a bound-but-unused peer socket returned as *udpAddr. Callers may
// pre-add the peer with d.tunnels.AddPeer(nodeID, peerAddr) to receive frames.
func newWireDaemon(t *testing.T, client *registry.Client) (*Daemon, *net.UDPConn) {
	t.Helper()
	d := &Daemon{
		nodeID:       42,
		tunnels:      NewTunnelManager(),
		ports:        NewPortManager(),
		resolveCache: make(map[uint32]*resolveEntry),
		epCache:      make(map[uint32]*endpointEntry),
		netPolicies:  make(map[uint16][]uint16),
		managed:      make(map[uint16]*ManagedEngine),
		memberTags:   make(map[uint16][]string),
	}
	d.regConn.Store(client)
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("tunnel listen: %v", err)
	}

	peerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("peer listen: %v", err)
	}
	t.Cleanup(func() {
		peerConn.Close()
		d.tunnels.Close()
	})
	return d, peerConn
}

// readOneFrame reads one UDP datagram with a short deadline and returns the
// bytes, or nil if no frame arrived within the window.
func readOneFrame(t *testing.T, c *net.UDPConn) []byte {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, 2048)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

// --- discoverWithTempSocket -----------------------------------------------

func TestDiscoverWithTempSocketInvalidListenAddr(t *testing.T) {
	t.Parallel()
	_, err := discoverWithTempSocket("127.0.0.1:1", "not-a-valid-addr")
	if err == nil {
		t.Fatal("expected ResolveUDPAddr error for malformed listenAddr")
	}
}

func TestDiscoverWithTempSocketHappyPath(t *testing.T) {
	t.Parallel()
	// Fake beacon echoes back a BeaconMsgDiscoverReply with a crafted observed endpoint.
	beacon, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("beacon listen: %v", err)
	}
	defer beacon.Close()

	go func() {
		buf := make([]byte, 64)
		n, from, err := beacon.ReadFromUDP(buf)
		if err != nil || n < 5 || buf[0] != protocol.BeaconMsgDiscover {
			return
		}
		reply := make([]byte, 2+4+2)
		reply[0] = protocol.BeaconMsgDiscoverReply
		reply[1] = 4 // IPv4 length
		copy(reply[2:6], net.IPv4(203, 0, 113, 7).To4())
		binary.BigEndian.PutUint16(reply[6:8], 9876)
		beacon.WriteToUDP(reply, from)
	}()

	// Bind temp socket to an ephemeral loopback port.
	addr, err := discoverWithTempSocket(beacon.LocalAddr().String(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("discoverWithTempSocket: %v", err)
	}
	if addr != "203.0.113.7:9876" {
		t.Fatalf("observed = %q, want 203.0.113.7:9876", addr)
	}
}

func TestDiscoverWithTempSocketBeaconDown(t *testing.T) {
	t.Parallel()
	// Bind to an ephemeral port, then close it so the address is unused.
	blocker, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	addr := blocker.LocalAddr().String()
	blocker.Close()

	_, err := discoverWithTempSocket(addr, "127.0.0.1:0")
	if err == nil {
		t.Fatal("expected discover to time out against dead beacon")
	}
}

// --- autoJoinNetworks ------------------------------------------------------

func TestAutoJoinNetworksSkipsWhenNoAdminToken(t *testing.T) {
	t.Parallel()
	var calls int32
	client, cleanup := startFakeRegistry(t, func(map[string]interface{}) map[string]interface{} {
		atomic.AddInt32(&calls, 1)
		return map[string]interface{}{}
	})
	defer cleanup()

	d := newWireDaemonBare(t, client)
	d.config.Networks = []uint16{1, 2}
	// AdminToken left empty → early return.
	d.autoJoinNetworks()

	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("no admin token must not contact registry, got %d calls", got)
	}
}

func TestAutoJoinNetworksSkipsWhenNoNetworks(t *testing.T) {
	t.Parallel()
	var calls int32
	client, cleanup := startFakeRegistry(t, func(map[string]interface{}) map[string]interface{} {
		atomic.AddInt32(&calls, 1)
		return map[string]interface{}{}
	})
	defer cleanup()

	d := newWireDaemonBare(t, client)
	d.config.AdminToken = "tok"
	d.config.Networks = nil
	d.autoJoinNetworks()

	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("empty networks list must not contact registry, got %d calls", got)
	}
}

func TestAutoJoinNetworksJoinsEachAndContinuesOnError(t *testing.T) {
	t.Parallel()
	var joinCalls int32
	seen := make(map[uint16]int)
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		atomic.AddInt32(&joinCalls, 1)
		nid := uint16(req["network_id"].(float64))
		seen[nid]++
		// Fail on network 11 but succeed on 12 and 13.
		if nid == 11 {
			return map[string]interface{}{"error": "denied"}
		}
		return map[string]interface{}{"ok": true}
	})
	defer cleanup()

	d := newWireDaemonBare(t, client)
	d.config.AdminToken = "admin"
	d.config.Networks = []uint16{11, 12, 13}
	d.autoJoinNetworks()

	if got := atomic.LoadInt32(&joinCalls); got != 3 {
		t.Fatalf("expected 3 join calls across 3 networks, got %d", got)
	}
	for _, id := range []uint16{11, 12, 13} {
		if seen[id] != 1 {
			t.Errorf("network %d: seen %d times, want 1", id, seen[id])
		}
	}
}

// newWireDaemonBare wires a daemon WITHOUT listening on a tunnel — for tests
// that only need regConn and should not pay for UDP binds.
func newWireDaemonBare(t *testing.T, client *registry.Client) *Daemon {
	t.Helper()
	d := &Daemon{
		nodeID:       42,
		tunnels:      NewTunnelManager(),
		ports:        NewPortManager(),
		resolveCache: make(map[uint32]*resolveEntry),
		epCache:      make(map[uint32]*endpointEntry),
		netPolicies:  make(map[uint16][]uint16),
		managed:      make(map[uint16]*ManagedEngine),
		memberTags:   make(map[uint16][]string),
	}
	d.regConn.Store(client)
	return d
}

// --- sendRST ---------------------------------------------------------------

func TestSendRSTFlipsAddressesAndSendsFlagRST(t *testing.T) {
	t.Parallel()
	d, peer := newWireDaemon(t, nil)

	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	const peerNode = uint32(99)
	d.tunnels.AddPeer(peerNode, peerAddr)

	orig := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Network: 0, Node: peerNode},
		Dst:      protocol.Addr{Network: 0, Node: 42},
		SrcPort:  1234,
		DstPort:  5678,
		Seq:      0,
	}

	d.sendRST(orig)

	frame := readOneFrame(t, peer)
	if frame == nil {
		t.Fatal("peer did not receive RST frame")
	}
	if len(frame) < 4 {
		t.Fatalf("frame too short: %d bytes", len(frame))
	}
	if frame[0] != 'P' || frame[1] != 'I' || frame[2] != 'L' || frame[3] != 'T' {
		t.Fatalf("frame missing PILT magic, got %x", frame[:4])
	}

	pkt, err := protocol.Unmarshal(frame[4:])
	if err != nil {
		t.Fatalf("unmarshal frame: %v", err)
	}
	if pkt.Flags&protocol.FlagRST == 0 {
		t.Errorf("RST flag not set, flags=%x", pkt.Flags)
	}
	if pkt.Src != orig.Dst {
		t.Errorf("Src = %v, want %v (orig.Dst)", pkt.Src, orig.Dst)
	}
	if pkt.Dst != orig.Src {
		t.Errorf("Dst = %v, want %v (orig.Src)", pkt.Dst, orig.Src)
	}
	if pkt.SrcPort != orig.DstPort || pkt.DstPort != orig.SrcPort {
		t.Errorf("ports not flipped: src=%d dst=%d, want src=%d dst=%d",
			pkt.SrcPort, pkt.DstPort, orig.DstPort, orig.SrcPort)
	}
}

func TestSendRSTNoPeerIsSilentNoPanic(t *testing.T) {
	t.Parallel()
	d, _ := newWireDaemon(t, nil)
	// No AddPeer — tunnels.Send returns "no tunnel to node N" which sendRST ignores.
	orig := &protocol.Packet{
		Version: protocol.Version,
		Src:     protocol.Addr{Node: 500},
		Dst:     protocol.Addr{Node: 42},
	}
	d.sendRST(orig) // must not panic
}

// --- broadcastDatagram -----------------------------------------------------

func TestBroadcastDatagramBackboneRejected(t *testing.T) {
	t.Parallel()
	d := newWireDaemonBare(t, nil)
	err := d.broadcastDatagram(0, 100, 200, []byte("x"), "")
	if err == nil {
		t.Fatal("expected backbone broadcast to be rejected")
	}
}

func TestBroadcastDatagramListNodesErrorPropagates(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"error": "offline"}
	})
	defer cleanup()

	d := newWireDaemonBare(t, client)
	err := d.broadcastDatagram(7, 1, 2, []byte("x"), "")
	if err == nil {
		t.Fatal("expected list_nodes error to propagate")
	}
}

func TestBroadcastDatagramMissingNodesFieldReturnsNil(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{} // no "nodes" key
	})
	defer cleanup()

	d := newWireDaemonBare(t, client)
	if err := d.broadcastDatagram(7, 1, 2, []byte("x"), ""); err != nil {
		t.Fatalf("missing nodes field should be silent nil, got %v", err)
	}
}

func TestBroadcastDatagramNonMemberRejected(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{
			"nodes": []interface{}{
				map[string]interface{}{"node_id": float64(100)},
				map[string]interface{}{"node_id": float64(200)},
			},
		}
	})
	defer cleanup()

	d := newWireDaemonBare(t, client)
	// Daemon node 42 is NOT in the list; broadcast must be denied.
	err := d.broadcastDatagram(9, 1, 2, []byte("x"), "")
	if err == nil {
		t.Fatal("non-member broadcast must be rejected")
	}
}

func TestBroadcastDatagramMemberSendsToOthersSkippingSelf(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{
			"nodes": []interface{}{
				map[string]interface{}{"node_id": float64(42)},  // self — skipped
				map[string]interface{}{"node_id": float64(101)}, // real peer
				map[string]interface{}{"node_id": float64(102)}, // real peer
			},
		}
	})
	defer cleanup()

	d, peer1 := newWireDaemon(t, client)

	// Second peer listener so each destination gets exactly one frame.
	peer2, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("peer2 listen: %v", err)
	}
	defer peer2.Close()

	d.tunnels.AddPeer(101, peer1.LocalAddr().(*net.UDPAddr))
	d.tunnels.AddPeer(102, peer2.LocalAddr().(*net.UDPAddr))

	if err := d.broadcastDatagram(9, 10, 20, []byte("hello"), ""); err != nil {
		t.Fatalf("broadcastDatagram: %v", err)
	}

	for i, c := range []*net.UDPConn{peer1, peer2} {
		f := readOneFrame(t, c)
		if f == nil {
			t.Fatalf("peer %d did not receive broadcast", 101+i)
		}
	}
}

// --- CloseConnection -------------------------------------------------------

func TestCloseConnectionNonEstablishedOnlyClosesRecvBuf(t *testing.T) {
	t.Parallel()
	d, _ := newWireDaemon(t, nil)

	conn := d.ports.NewConnection(5000, protocol.Addr{Node: 123}, 6000)
	// State left as Closed — the FIN branch must not fire.
	prevSeq := conn.SendSeq

	d.CloseConnection(conn)

	conn.Mu.Lock()
	st := conn.State
	seq := conn.SendSeq
	conn.Mu.Unlock()
	if st != StateFinWait {
		t.Errorf("state = %v, want StateFinWait", st)
	}
	if seq != prevSeq {
		t.Errorf("SendSeq advanced from %d to %d despite non-Established state", prevSeq, seq)
	}
	select {
	case _, ok := <-conn.RecvBuf:
		if ok {
			t.Error("RecvBuf should be closed")
		}
	default:
		t.Error("RecvBuf not closed")
	}
}

func TestCloseConnectionEstablishedSendsFINAndAdvancesSeq(t *testing.T) {
	t.Parallel()
	d, peer := newWireDaemon(t, nil)

	const peerNode = uint32(321)
	d.tunnels.AddPeer(peerNode, peer.LocalAddr().(*net.UDPAddr))

	conn := d.ports.NewConnection(7000, protocol.Addr{Node: peerNode}, 8000)
	conn.LocalAddr = protocol.Addr{Node: 42}
	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.SendSeq = 10
	conn.Mu.Unlock()

	d.CloseConnection(conn)

	frame := readOneFrame(t, peer)
	if frame == nil {
		t.Fatal("peer did not receive FIN frame")
	}
	pkt, err := protocol.Unmarshal(frame[4:])
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if pkt.Flags&protocol.FlagFIN == 0 {
		t.Errorf("FIN flag not set, flags=%x", pkt.Flags)
	}
	if pkt.Seq != 10 {
		t.Errorf("FIN Seq = %d, want 10", pkt.Seq)
	}

	conn.Mu.Lock()
	st := conn.State
	seq := conn.SendSeq
	conn.Mu.Unlock()
	if st != StateFinWait {
		t.Errorf("state = %v, want StateFinWait", st)
	}
	if seq != 11 {
		t.Errorf("SendSeq = %d, want 11 (pre=10, +1 for FIN)", seq)
	}

	conn.RetxMu.Lock()
	retx := len(conn.Unacked)
	conn.RetxMu.Unlock()
	if retx != 1 {
		t.Errorf("Unacked = %d, want 1 (FIN tracked for retx)", retx)
	}
}

// --- SendDatagram ----------------------------------------------------------

func TestSendDatagramDeniedByPortPolicy(t *testing.T) {
	t.Parallel()
	d := newWireDaemonBare(t, nil)
	// Network 5 has a port policy that allows only port 80. Dst port 9000 → denied.
	d.netPolicies[5] = []uint16{80}

	err := d.SendDatagram(protocol.Addr{Network: 5, Node: 123}, 9000, []byte("x"))
	if err == nil {
		t.Fatal("expected policy denial error")
	}
}

func TestSendDatagramUnicastSendsFrame(t *testing.T) {
	t.Parallel()
	d, peer := newWireDaemon(t, nil)

	const peerNode = uint32(777)
	d.tunnels.AddPeer(peerNode, peer.LocalAddr().(*net.UDPAddr))

	if err := d.SendDatagram(protocol.Addr{Network: 3, Node: peerNode}, 8080, []byte("payload")); err != nil {
		t.Fatalf("SendDatagram: %v", err)
	}

	frame := readOneFrame(t, peer)
	if frame == nil {
		t.Fatal("peer did not receive datagram frame")
	}
	pkt, err := protocol.Unmarshal(frame[4:])
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if pkt.Protocol != protocol.ProtoDatagram {
		t.Errorf("Protocol = %v, want ProtoDatagram", pkt.Protocol)
	}
	if pkt.DstPort != 8080 {
		t.Errorf("DstPort = %d, want 8080", pkt.DstPort)
	}
	if string(pkt.Payload) != "payload" {
		t.Errorf("Payload = %q, want %q", pkt.Payload, "payload")
	}
}

func TestSendDatagramBroadcastRequiresAdminToken(t *testing.T) {
	t.Parallel()
	d := newWireDaemonBare(t, nil)
	bcast := protocol.Addr{Network: 9, Node: 0xFFFFFFFF}
	err := d.SendDatagram(bcast, 7, []byte("b"))
	if err == nil {
		t.Fatal("expected error for broadcast via SendDatagram, got nil")
	}
}

func TestBroadcastDatagramDelegatesToBroadcast(t *testing.T) {
	t.Parallel()
	// ListNodes must return just our node so broadcastDatagram falls through with
	// no recipients — we assert the path by observing the call type on the wire.
	var sawListNodes int32
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] == "list_nodes" {
			atomic.StoreInt32(&sawListNodes, 1)
			return map[string]interface{}{
				"nodes": []interface{}{map[string]interface{}{"node_id": float64(42)}},
			}
		}
		return map[string]interface{}{}
	})
	defer cleanup()

	d := newWireDaemonBare(t, client)
	d.config.AdminToken = "tok"
	if err := d.BroadcastDatagram(9, 7, []byte("b"), "tok"); err != nil {
		t.Fatalf("BroadcastDatagram: %v", err)
	}
	if atomic.LoadInt32(&sawListNodes) != 1 {
		t.Fatal("BroadcastDatagram must call list_nodes")
	}
}

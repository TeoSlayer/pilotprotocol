// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
	registry "github.com/pilot-protocol/common/registry/client"
)

// newPacketDaemon fully wires a Daemon for packet-dispatch tests: real UDP
// tunnel, ports, handshakes, IPC (unstarted), SYN rate-limit state, plus a
// bound peer UDP socket for reading outbound frames.
func newPacketDaemon(t *testing.T, client *registry.Client) (*Daemon, *net.UDPConn) {
	t.Helper()
	d := &Daemon{
		nodeID:       42,
		tunnels:      NewTunnelManager(),
		ports:        NewPortManager(),
		regConn:      client,
		resolveCache: make(map[uint32]*resolveEntry),
		epCache:      make(map[uint32]*endpointEntry),
		netPolicies:  make(map[uint16][]uint16),
		managed:      make(map[uint16]*ManagedEngine),
		memberTags:   make(map[uint16][]string),
		synTokens:    DefaultSYNRateLimit,
		synLastFill:  time.Now(),
		perSrcSYN:    make(map[uint32]*srcSYNBucket),
		stopCh:       make(chan struct{}),
	}
	d.ipc = NewIPCServer("", d)
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("tunnel listen: %v", err)
	}
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("peer listen: %v", err)
	}
	t.Cleanup(func() {
		peer.Close()
		d.tunnels.Close()
	})
	return d, peer
}

// --- handleControlPacket -------------------------------------------------

func TestHandleControlPacketNonPingDstPortIsNoop(t *testing.T) {
	t.Parallel()
	d, peer := newPacketDaemon(t, nil)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	const peerNode = uint32(99)
	d.tunnels.AddPeer(peerNode, peerAddr)

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoControl,
		Src:      protocol.Addr{Node: peerNode},
		Dst:      protocol.Addr{Node: 42},
		SrcPort:  3000,
		DstPort:  9999,
		Seq:      77,
	}
	d.handleControlPacket(pkt)
	if f := readOneFrame(t, peer); f != nil {
		t.Fatalf("unexpected frame for non-ping DstPort: %x", f)
	}
}

// --- handleDatagramPacket -------------------------------------------------

func TestHandleDatagramPacketTrustGateRejectsUntrusted(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"trusted": false}
	})
	defer cleanup()

	d, _ := newPacketDaemon(t, client)
	d.config.Public = false // private — trust gate active

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoDatagram,
		Src:      protocol.Addr{Node: 99},
		Dst:      protocol.Addr{Node: 42},
		SrcPort:  100,
		DstPort:  200,
		Payload:  []byte("hello"),
	}
	// Trust gate should drop. No client subscribed to ipc — verify no panic.
	d.handleDatagramPacket(pkt)
}

func TestHandleDatagramPacketPolicyDenyReturnsEarly(t *testing.T) {
	t.Parallel()
	d, _ := newPacketDaemon(t, nil)
	d.config.Public = true
	// Only port 80 is allowed on network 5.
	d.netPolicies[5] = []uint16{80}

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoDatagram,
		Src:      protocol.Addr{Node: 99},
		Dst:      protocol.Addr{Network: 5, Node: 42},
		SrcPort:  100,
		DstPort:  9000,
		Payload:  []byte("nope"),
	}
	d.handleDatagramPacket(pkt) // denied — returns silently.
}

func TestHandleDatagramPacketSuccessPathDelivers(t *testing.T) {
	t.Parallel()
	d, _ := newPacketDaemon(t, nil)
	d.config.Public = true
	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoDatagram,
		Src:      protocol.Addr{Node: 99},
		Dst:      protocol.Addr{Node: 42},
		SrcPort:  100,
		DstPort:  200,
		Payload:  []byte("hello"),
	}
	// Success path fans out via d.ipc.DeliverDatagram. With zero IPC clients
	// this is a noop but must not panic.
	d.handleDatagramPacket(pkt)
}

// --- handleStreamPacket SYN ------------------------------------------------

func TestHandleStreamSynNoListenerSendsRST(t *testing.T) {
	t.Parallel()
	d, peer := newPacketDaemon(t, nil)
	d.config.Public = true
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	const peerNode = uint32(99)
	d.tunnels.AddPeer(peerNode, peerAddr)

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Node: peerNode},
		Dst:      protocol.Addr{Node: 42},
		SrcPort:  3000,
		DstPort:  5678,
		Seq:      100,
	}
	d.handleStreamPacket(pkt)

	frame := readOneFrame(t, peer)
	if frame == nil {
		t.Fatal("no RST received")
	}
	rst, err := protocol.Unmarshal(frame[4:])
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rst.Flags&protocol.FlagRST == 0 {
		t.Errorf("FlagRST not set, flags=%x", rst.Flags)
	}
	if rst.DstPort != pkt.SrcPort {
		t.Errorf("DstPort = %d, want %d", rst.DstPort, pkt.SrcPort)
	}
	if rst.SrcPort != pkt.DstPort {
		t.Errorf("SrcPort = %d, want %d", rst.SrcPort, pkt.DstPort)
	}
}

func TestHandleStreamSynRetransmitResendsExistingSynAck(t *testing.T) {
	t.Parallel()
	d, peer := newPacketDaemon(t, nil)
	d.config.Public = true
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	const peerNode = uint32(99)
	d.tunnels.AddPeer(peerNode, peerAddr)

	if _, err := d.ports.Bind(5678); err != nil {
		t.Fatalf("bind: %v", err)
	}
	srcAddr := protocol.Addr{Node: peerNode}
	conn := d.ports.NewConnection(5678, srcAddr, 3000)
	conn.Mu.Lock()
	conn.State = StateSynReceived
	conn.SendSeq = 501 // retransmit replays Seq = SendSeq-1 = 500
	conn.RecvAck = 101
	conn.Mu.Unlock()

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      srcAddr,
		Dst:      protocol.Addr{Node: 42},
		SrcPort:  3000,
		DstPort:  5678,
		Seq:      100,
	}
	d.handleStreamPacket(pkt)

	frame := readOneFrame(t, peer)
	if frame == nil {
		t.Fatal("no SYN-ACK received on retransmit")
	}
	synack, err := protocol.Unmarshal(frame[4:])
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if synack.Flags&protocol.FlagSYN == 0 || synack.Flags&protocol.FlagACK == 0 {
		t.Errorf("expected SYN+ACK, flags=%x", synack.Flags)
	}
	if synack.Seq != 500 {
		t.Errorf("Seq = %d, want 500", synack.Seq)
	}
	if synack.Ack != 101 {
		t.Errorf("Ack = %d, want 101", synack.Ack)
	}
	// Existing connection should be reused, not replaced.
	if d.ports.FindConnection(5678, srcAddr, 3000) != conn {
		t.Error("retransmit spawned a new connection instead of reusing existing")
	}
}

func TestHandleStreamSynPrivateUntrustedDropsSilently(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"trusted": false}
	})
	defer cleanup()
	d, peer := newPacketDaemon(t, client)
	d.config.Public = false
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	const peerNode = uint32(99)
	d.tunnels.AddPeer(peerNode, peerAddr)

	// Bind the listener so we reach the trust gate, not the no-listener RST path.
	if _, err := d.ports.Bind(5678); err != nil {
		t.Fatalf("bind: %v", err)
	}

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Node: peerNode},
		Dst:      protocol.Addr{Node: 42},
		SrcPort:  3000,
		DstPort:  5678,
		Seq:      100,
	}
	d.handleStreamPacket(pkt)

	if f := readOneFrame(t, peer); f != nil {
		t.Fatalf("untrusted SYN must be silently dropped, got frame: %x", f)
	}
}

// --- handlePacket auto-add peer -------------------------------------------

func TestHandlePacketAutoAddsPeerInPlaintextMode(t *testing.T) {
	t.Parallel()
	d, peer := newPacketDaemon(t, nil)
	d.config.Public = true
	d.config.Encrypt = false
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	const peerNode = uint32(99)
	if d.tunnels.HasPeer(peerNode) {
		t.Fatal("peer should not pre-exist")
	}
	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoControl,
		Src:      protocol.Addr{Node: peerNode},
		Dst:      protocol.Addr{Node: 42},
		SrcPort:  100,
		DstPort:  9999, // unknown control dst → no-op inside handleControlPacket
	}
	d.handlePacket(pkt, peerAddr)
	if !d.tunnels.HasPeer(peerNode) {
		t.Error("peer should have been auto-added in plaintext mode")
	}
}

func TestHandlePacketSkipsAutoAddWhenEncryptedWithoutCrypto(t *testing.T) {
	t.Parallel()
	d, peer := newPacketDaemon(t, nil)
	d.config.Public = true
	d.config.Encrypt = true
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	const peerNode = uint32(99)

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoControl,
		Src:      protocol.Addr{Node: peerNode},
		Dst:      protocol.Addr{Node: 42},
		SrcPort:  100,
		DstPort:  9999,
	}
	d.handlePacket(pkt, peerAddr)
	if d.tunnels.HasPeer(peerNode) {
		t.Error("peer should NOT be auto-added when Encrypt=true without existing crypto context")
	}
}

// --- sendDelayedACK --------------------------------------------------------

func TestSendDelayedACKResetsStateAndEmitsFrame(t *testing.T) {
	t.Parallel()
	d, peer := newPacketDaemon(t, nil)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	const peerNode = uint32(99)
	d.tunnels.AddPeer(peerNode, peerAddr)

	remote := protocol.Addr{Node: peerNode}
	conn := d.ports.NewConnection(5678, remote, 3000)
	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Node: 42}
	conn.SendSeq = 501
	conn.RecvAck = 222
	conn.Mu.Unlock()

	conn.AckMu.Lock()
	conn.PendingACKs = 3
	conn.ACKTimer = time.AfterFunc(10*time.Second, func() {})
	conn.AckMu.Unlock()

	d.sendDelayedACK(conn)

	conn.AckMu.Lock()
	pending := conn.PendingACKs
	timer := conn.ACKTimer
	conn.AckMu.Unlock()
	if pending != 0 {
		t.Errorf("PendingACKs = %d, want 0", pending)
	}
	if timer != nil {
		t.Errorf("ACKTimer = %v, want nil", timer)
	}

	frame := readOneFrame(t, peer)
	if frame == nil {
		t.Fatal("no ACK frame received")
	}
	ack, err := protocol.Unmarshal(frame[4:])
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ack.Flags&protocol.FlagACK == 0 {
		t.Errorf("FlagACK not set, flags=%x", ack.Flags)
	}
	if ack.Protocol != protocol.ProtoStream {
		t.Errorf("Protocol = %d, want ProtoStream", ack.Protocol)
	}
	if ack.Seq != 501 {
		t.Errorf("Seq = %d, want 501", ack.Seq)
	}
	if ack.Ack != 222 {
		t.Errorf("Ack = %d, want 222", ack.Ack)
	}
	if ack.SrcPort != 5678 {
		t.Errorf("SrcPort = %d, want 5678", ack.SrcPort)
	}
	if ack.DstPort != 3000 {
		t.Errorf("DstPort = %d, want 3000", ack.DstPort)
	}
}

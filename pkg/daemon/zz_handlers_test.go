// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// setupDaemonWithPeer builds a Daemon that is wired to send packets to `peerConn`.
// It returns the daemon and the peerNode ID under which the peer is registered.
// The daemon is configured with Public:true so the trust gate is skipped.
func setupDaemonWithPeer(t *testing.T, cfg Config) (*Daemon, uint32, *net.UDPConn) {
	t.Helper()
	d := New(cfg)
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("tunnels.Listen: %v", err)
	}
	t.Cleanup(func() { d.tunnels.Close() })

	peerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("peerConn listen: %v", err)
	}
	t.Cleanup(func() { peerConn.Close() })

	peerAddr := peerConn.LocalAddr().(*net.UDPAddr)
	const peerNode uint32 = 0xDEAD0001
	d.AddTunnelPeer(peerNode, peerAddr)

	return d, peerNode, peerConn
}

func readPacket(t *testing.T, conn *net.UDPConn, timeout time.Duration) *protocol.Packet {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil
	}
	// Strip 4-byte PILT magic, then Unmarshal
	if n < 4 {
		return nil
	}
	pkt, err := protocol.Unmarshal(buf[4:n])
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return pkt
}

// --- handleControlPacket: ping ---

func TestHandleControlPacketPingSendsPong(t *testing.T) {
	t.Parallel()
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})

	ping := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    0, // ping is a non-ACK control frame
		Protocol: protocol.ProtoControl,
		Src:      protocol.Addr{Network: 0, Node: peerNode},
		Dst:      protocol.Addr{Network: 0, Node: d.NodeID()},
		SrcPort:  9999,
		DstPort:  protocol.PortPing,
		Seq:      42,
		Payload:  []byte("p"),
	}
	d.handleControlPacket(ping)

	pkt := readPacket(t, peerConn, 500*time.Millisecond)
	if pkt == nil {
		t.Fatalf("expected pong on peer socket")
	}
	if pkt.Protocol != protocol.ProtoControl {
		t.Fatalf("pong Protocol = %d, want ProtoControl", pkt.Protocol)
	}
	if !pkt.HasFlag(protocol.FlagACK) {
		t.Fatalf("pong should have FlagACK")
	}
	if pkt.SrcPort != protocol.PortPing {
		t.Fatalf("pong SrcPort = %d, want PortPing (%d)", pkt.SrcPort, protocol.PortPing)
	}
	if pkt.DstPort != 9999 {
		t.Fatalf("pong DstPort = %d, want 9999 (original SrcPort)", pkt.DstPort)
	}
	if pkt.Seq != 42 {
		t.Fatalf("pong Seq = %d, want 42 (echoed)", pkt.Seq)
	}
	if pkt.Ack != 43 {
		t.Fatalf("pong Ack = %d, want 43 (ping.Seq+1)", pkt.Ack)
	}
}

func TestHandleControlPacketNonPingIsNoop(t *testing.T) {
	t.Parallel()
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})

	ctrl := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoControl,
		Src:      protocol.Addr{Network: 0, Node: peerNode},
		Dst:      protocol.Addr{Network: 0, Node: d.NodeID()},
		SrcPort:  1234,
		DstPort:  5678, // NOT PortPing
	}
	d.handleControlPacket(ctrl)

	if pkt := readPacket(t, peerConn, 150*time.Millisecond); pkt != nil {
		t.Fatalf("expected no response for non-ping control; got %+v", pkt)
	}
}

// --- handleDatagramPacket ---

func TestHandleDatagramPacketEmptyPayloadIsNoop(t *testing.T) {
	t.Parallel()
	d, peerNode, _ := setupDaemonWithPeer(t, Config{Public: true})

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoDatagram,
		Src:      protocol.Addr{Network: 0, Node: peerNode},
		Dst:      protocol.Addr{Network: 0, Node: d.NodeID()},
		SrcPort:  1,
		DstPort:  2,
		Payload:  nil,
	}
	// Should return immediately without hitting the trust gate or ipc.
	d.handleDatagramPacket(pkt)
}

func TestHandleDatagramPacketPrivateUntrustedIsRejected(t *testing.T) {
	t.Parallel()
	// Config.Public=false triggers the trust gate. No handshake with peer =
	// untrusted, regConn nil so no fallback check, peer rejected.
	d := New(Config{Public: false})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { d.tunnels.Close() })

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoDatagram,
		Src:      protocol.Addr{Network: 0, Node: 0xBEEF1234},
		Dst:      protocol.Addr{Network: 0, Node: d.NodeID()},
		SrcPort:  1,
		DstPort:  2,
		Payload:  []byte("hello"),
	}
	// Should return without panicking; rejection logged + webhook emitted.
	// Nothing observable via the public API without ipc subscribers, but we verify
	// no crash and that the handler stays below timeout.
	done := make(chan struct{})
	go func() {
		d.handleDatagramPacket(pkt)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatalf("handleDatagramPacket hung on private/untrusted path")
	}
}

// --- sendRST ---

func TestSendRSTDeliversRSTPacketToPeer(t *testing.T) {
	t.Parallel()
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})

	orig := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Network: 0, Node: peerNode},
		Dst:      protocol.Addr{Network: 0, Node: d.NodeID()},
		SrcPort:  11111,
		DstPort:  22222,
	}
	d.sendRST(orig)

	pkt := readPacket(t, peerConn, 500*time.Millisecond)
	if pkt == nil {
		t.Fatalf("expected RST packet on peer socket")
	}
	if !pkt.HasFlag(protocol.FlagRST) {
		t.Fatalf("flags = %x, want FlagRST set", pkt.Flags)
	}
	// Src/Dst swapped, ports mirrored
	if pkt.Src.Node != d.NodeID() {
		t.Fatalf("RST Src.Node = %x, want daemon NodeID %x", pkt.Src.Node, d.NodeID())
	}
	if pkt.Dst.Node != peerNode {
		t.Fatalf("RST Dst.Node = %x, want peer %x", pkt.Dst.Node, peerNode)
	}
	if pkt.SrcPort != 22222 {
		t.Fatalf("RST SrcPort = %d, want 22222 (orig.DstPort)", pkt.SrcPort)
	}
	if pkt.DstPort != 11111 {
		t.Fatalf("RST DstPort = %d, want 11111 (orig.SrcPort)", pkt.DstPort)
	}
	if pkt.Protocol != protocol.ProtoStream {
		t.Fatalf("RST Protocol = %d, want ProtoStream", pkt.Protocol)
	}
}

// --- handleStreamPacket: SYN with no listener → RST ---

func TestHandleStreamPacketSYNNoListenerSendsRST(t *testing.T) {
	t.Parallel()
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})

	// SYN for a port that has no listener — no d.ports.Listen() was called.
	syn := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Network: 0, Node: peerNode},
		Dst:      protocol.Addr{Network: 0, Node: d.NodeID()},
		SrcPort:  55555,
		DstPort:  7, // nothing listening on port 7
	}
	d.handleStreamPacket(syn)

	pkt := readPacket(t, peerConn, 500*time.Millisecond)
	if pkt == nil {
		t.Fatalf("expected RST response for SYN with no listener")
	}
	if !pkt.HasFlag(protocol.FlagRST) {
		t.Fatalf("flags = %x, want RST", pkt.Flags)
	}
	if pkt.DstPort != 55555 {
		t.Fatalf("RST DstPort = %d, want 55555", pkt.DstPort)
	}
}

// --- handlePacket: dispatch + auto-add peer ---

func TestHandlePacketAutoAddsPlaintextPeer(t *testing.T) {
	t.Parallel()
	d, peerNode, _ := setupDaemonWithPeer(t, Config{Public: true, Encrypt: false})
	// Remove the pre-added tunnel peer so we can verify auto-add from handlePacket.
	d.tunnels.RemovePeer(peerNode)
	if d.tunnels.HasPeer(peerNode) {
		t.Fatalf("precondition: peer should have been removed")
	}

	fakeFrom := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	// Control packet with a non-ping port — dispatched to handleControlPacket
	// which is a no-op; we only care that auto-add ran.
	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoControl,
		Src:      protocol.Addr{Network: 0, Node: peerNode},
		Dst:      protocol.Addr{Network: 0, Node: d.NodeID()},
		SrcPort:  1,
		DstPort:  99,
	}
	d.handlePacket(pkt, fakeFrom)

	if !d.tunnels.HasPeer(peerNode) {
		t.Fatalf("handlePacket should auto-add plaintext peer")
	}
}

func TestHandlePacketEncryptSkipsAutoAddWithoutCrypto(t *testing.T) {
	t.Parallel()
	d, peerNode, _ := setupDaemonWithPeer(t, Config{Public: true, Encrypt: true})
	d.tunnels.RemovePeer(peerNode)

	fakeFrom := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoControl,
		Src:      protocol.Addr{Network: 0, Node: peerNode},
		Dst:      protocol.Addr{Network: 0, Node: d.NodeID()},
		SrcPort:  1,
		DstPort:  99,
	}
	d.handlePacket(pkt, fakeFrom)

	// In encrypt mode, auto-add requires an existing crypto context for the peer.
	if d.tunnels.HasPeer(peerNode) {
		t.Fatalf("encrypt mode should NOT auto-add peer without crypto")
	}
}

func TestHandlePacketDispatchesToControlHandler(t *testing.T) {
	t.Parallel()
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoControl,
		Src:      protocol.Addr{Network: 0, Node: peerNode},
		Dst:      protocol.Addr{Network: 0, Node: d.NodeID()},
		SrcPort:  1234,
		DstPort:  protocol.PortPing,
		Seq:      100,
	}
	d.handlePacket(pkt, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})

	pong := readPacket(t, peerConn, 500*time.Millisecond)
	if pong == nil || !pong.HasFlag(protocol.FlagACK) || pong.Ack != 101 {
		t.Fatalf("handlePacket did not dispatch ping to handleControlPacket: %+v", pong)
	}
}

func TestHandlePacketUnknownProtocolIsSilentlyIgnored(t *testing.T) {
	t.Parallel()
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: 0xFF, // not Stream / Datagram / Control
		Src:      protocol.Addr{Network: 0, Node: peerNode},
		Dst:      protocol.Addr{Network: 0, Node: d.NodeID()},
	}
	d.handlePacket(pkt, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1})

	if p := readPacket(t, peerConn, 150*time.Millisecond); p != nil {
		t.Fatalf("unknown protocol should not emit a response; got %+v", p)
	}
}

// --- handleDatagramPacket: public mode + allowed port delivers to IPC ---

func TestHandleDatagramPacketPublicModeDeliversThroughIPC(t *testing.T) {
	t.Parallel()
	// Public:true skips trust gate. With no policy runner + no netPolicies,
	// isPortAllowed returns true. So the handler reaches ipc.DeliverDatagram.
	// We don't have an IPC subscriber, but the call must not panic.
	d, peerNode, _ := setupDaemonWithPeer(t, Config{Public: true})
	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoDatagram,
		Src:      protocol.Addr{Network: 0, Node: peerNode},
		Dst:      protocol.Addr{Network: 0, Node: d.NodeID()},
		SrcPort:  42,
		DstPort:  1001,
		Payload:  []byte("payload"),
	}
	// Must not panic. The only observable effect without an IPC client is
	// that no RST/response flows back out the tunnel.
	done := make(chan struct{})
	go func() {
		d.handleDatagramPacket(pkt)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("handleDatagramPacket hung on public delivery path")
	}
}

package daemon

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

func TestRegisterWithBeaconNilBeaconAddrIsNoop(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	// No SetBeaconAddr → beaconAddr nil → RegisterWithBeacon returns without sending.
	before := tm.PktsSent
	tm.RegisterWithBeacon()
	if tm.PktsSent != before {
		t.Fatalf("PktsSent should not change when beaconAddr is nil")
	}
}

func TestRegisterWithBeaconNilConnIsNoop(t *testing.T) {
	tm := NewTunnelManager()
	// No Listen → tm.conn nil.
	tm.SetBeaconAddr("127.0.0.1:9001")
	before := tm.PktsSent
	tm.RegisterWithBeacon()
	if tm.PktsSent != before {
		t.Fatalf("PktsSent should not change when conn is nil")
	}
}

func TestRegisterWithBeaconSendsDiscoverWithNodeID(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()
	tm.SetNodeID(0xCAFEBABE)

	beaconConn := mustListenUDP(t)
	defer beaconConn.Close()
	if err := tm.SetBeaconAddr(beaconConn.LocalAddr().String()); err != nil {
		t.Fatalf("SetBeaconAddr: %v", err)
	}

	tm.RegisterWithBeacon()

	buf := make([]byte, 64)
	beaconConn.SetReadDeadline(deadlineMS(500))
	n, _, err := beaconConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("beacon read: %v", err)
	}
	if n != 5 {
		t.Fatalf("got %d bytes, want 5", n)
	}
	if buf[0] != protocol.BeaconMsgDiscover {
		t.Fatalf("type = %x, want %x", buf[0], protocol.BeaconMsgDiscover)
	}
	if got := binary.BigEndian.Uint32(buf[1:5]); got != 0xCAFEBABE {
		t.Fatalf("nodeID = %x, want 0xCAFEBABE", got)
	}
}

func TestRequestHolePunchNilBeaconIsNoop(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	before := tm.PktsSent
	tm.RequestHolePunch(42)
	if tm.PktsSent != before {
		t.Fatalf("PktsSent should not change when beaconAddr is nil")
	}
}

func TestRequestHolePunchNilConnIsNoop(t *testing.T) {
	tm := NewTunnelManager()
	tm.SetBeaconAddr("127.0.0.1:9001")
	// No Listen → tm.conn nil.
	before := tm.PktsSent
	tm.RequestHolePunch(42)
	if tm.PktsSent != before {
		t.Fatalf("PktsSent should not change when conn is nil")
	}
}

func TestRequestHolePunchSendsMsgWithSenderAndTarget(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()
	tm.SetNodeID(0x11110000)

	beaconConn := mustListenUDP(t)
	defer beaconConn.Close()
	if err := tm.SetBeaconAddr(beaconConn.LocalAddr().String()); err != nil {
		t.Fatalf("SetBeaconAddr: %v", err)
	}

	tm.RequestHolePunch(0x22223333)

	buf := make([]byte, 32)
	beaconConn.SetReadDeadline(deadlineMS(500))
	n, _, err := beaconConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("beacon read: %v", err)
	}
	if n != 9 {
		t.Fatalf("got %d bytes, want 9", n)
	}
	if buf[0] != protocol.BeaconMsgPunchRequest {
		t.Fatalf("type = %x, want %x", buf[0], protocol.BeaconMsgPunchRequest)
	}
	if sender := binary.BigEndian.Uint32(buf[1:5]); sender != 0x11110000 {
		t.Fatalf("sender = %x, want 0x11110000", sender)
	}
	if target := binary.BigEndian.Uint32(buf[5:9]); target != 0x22223333 {
		t.Fatalf("target = %x, want 0x22223333", target)
	}
}

func TestDiscoverEndpointResolveErrorReturnsError(t *testing.T) {
	conn := mustListenUDP(t)
	defer conn.Close()
	_, err := DiscoverEndpoint("bad-addr", 1, conn)
	if err == nil {
		t.Fatalf("expected error for bad beacon addr")
	}
}

func TestDiscoverEndpointReadTimeoutReturnsError(t *testing.T) {
	// Beacon that never replies.
	silentBeacon := mustListenUDP(t)
	defer silentBeacon.Close()

	conn := mustListenUDP(t)
	defer conn.Close()

	_, err := DiscoverEndpoint(silentBeacon.LocalAddr().String(), 1, conn)
	if err == nil {
		t.Fatalf("expected read timeout error")
	}
}

func TestDiscoverEndpointInvalidReplyTypeReturnsError(t *testing.T) {
	// Beacon that echoes back the wrong message type.
	beacon := mustListenUDP(t)
	defer beacon.Close()
	go func() {
		buf := make([]byte, 64)
		beacon.SetReadDeadline(deadlineMS(500))
		_, from, err := beacon.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Reply with wrong type (0xFF) — not BeaconMsgDiscoverReply
		beacon.WriteToUDP([]byte{0xFF, 0x04, 1, 2, 3, 4, 0, 0}, from)
	}()

	conn := mustListenUDP(t)
	defer conn.Close()
	_, err := DiscoverEndpoint(beacon.LocalAddr().String(), 1, conn)
	if err == nil {
		t.Fatalf("expected invalid reply error")
	}
}

func TestDiscoverEndpointValidIPv4Reply(t *testing.T) {
	beacon := mustListenUDP(t)
	defer beacon.Close()
	go func() {
		buf := make([]byte, 64)
		beacon.SetReadDeadline(deadlineMS(500))
		_, from, err := beacon.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Valid reply: [DiscoverReply][iplen=4][1.2.3.4][port=0x1F90 = 8080]
		reply := []byte{protocol.BeaconMsgDiscoverReply, 4, 1, 2, 3, 4, 0x1F, 0x90}
		beacon.WriteToUDP(reply, from)
	}()

	conn := mustListenUDP(t)
	defer conn.Close()

	addr, err := DiscoverEndpoint(beacon.LocalAddr().String(), 42, conn)
	if err != nil {
		t.Fatalf("DiscoverEndpoint: %v", err)
	}
	if addr.IP.String() != "1.2.3.4" {
		t.Fatalf("IP = %s, want 1.2.3.4", addr.IP)
	}
	if addr.Port != 8080 {
		t.Fatalf("Port = %d, want 8080", addr.Port)
	}
}

func TestHandleBeaconMessageEmptyDataReturns(t *testing.T) {
	tm := NewTunnelManager()
	// Should not panic or crash; just returns.
	tm.handleBeaconMessage(nil, &net.UDPAddr{})
	tm.handleBeaconMessage([]byte{}, &net.UDPAddr{})
}

func TestHandleBeaconMessageDiscoverReplyLogsAndReturns(t *testing.T) {
	tm := NewTunnelManager()
	// DiscoverReply path is a log-only noop. Just verify it doesn't panic.
	data := []byte{protocol.BeaconMsgDiscoverReply, 0x04, 1, 2, 3, 4, 0, 80}
	tm.handleBeaconMessage(data, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
}

func TestHandleBeaconMessageUnknownTypeIsNoop(t *testing.T) {
	tm := NewTunnelManager()
	// 0xAB is not a known beacon message type.
	tm.handleBeaconMessage([]byte{0xAB, 1, 2, 3}, &net.UDPAddr{})
}

func TestHandleBeaconMessagePunchCommandSendsPunchFrames(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	// Target peer that will receive the punches.
	target := mustListenUDP(t)
	defer target.Close()
	targetAddr := target.LocalAddr().(*net.UDPAddr)
	ip4 := targetAddr.IP.To4()

	// PunchCommand data (after the 1-byte type byte handled by switch):
	// [iplen=4][IP(4)][port(2)]
	data := make([]byte, 1+1+4+2)
	data[0] = protocol.BeaconMsgPunchCommand
	data[1] = 4
	copy(data[2:6], ip4)
	binary.BigEndian.PutUint16(data[6:8], uint16(targetAddr.Port))

	tm.handleBeaconMessage(data, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9})

	// Target should receive 3 punches (TunnelMagicPunch = PILP, 4 bytes).
	count := 0
	target.SetReadDeadline(deadlineMS(500))
	buf := make([]byte, 16)
	for i := 0; i < 3; i++ {
		n, _, err := target.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if n == 4 && string(buf[0:4]) == string(protocol.TunnelMagicPunch[:]) {
			count++
		}
	}
	if count != 3 {
		t.Fatalf("received %d punches, want 3", count)
	}
}

func TestHandleBeaconMessageRelayDeliverUpdatesRelayPeersAndDispatchesInnerFrame(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()
	tm.SetBeaconAddr("127.0.0.1:9001")

	// Inner frame: TunnelMagic + a marshaled protocol.Packet
	pkt := newPacket("inner")
	pktData, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	inner := make([]byte, 4+len(pktData))
	copy(inner[0:4], protocol.TunnelMagic[:])
	copy(inner[4:], pktData)

	// BeaconMsgRelayDeliver data: [type(1)][srcNodeID(4)][inner frame]
	srcID := uint32(55)
	data := make([]byte, 1+4+len(inner))
	data[0] = protocol.BeaconMsgRelayDeliver
	binary.BigEndian.PutUint32(data[1:5], srcID)
	copy(data[5:], inner)

	tm.handleBeaconMessage(data, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001})

	if !tm.IsRelayPeer(srcID) {
		t.Fatalf("peer %d should be marked relay after RelayDeliver", srcID)
	}
	select {
	case got := <-tm.RecvCh():
		if string(got.Packet.Payload) != "inner" {
			t.Fatalf("received payload = %q, want \"inner\"", got.Packet.Payload)
		}
	default:
		t.Fatalf("no IncomingPacket delivered to recvCh")
	}
}

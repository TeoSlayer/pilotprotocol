package tests

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/beacon"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func startTestBeacon(t *testing.T) (*beacon.Server, *net.UDPAddr) {
	t.Helper()
	s := beacon.New()
	go s.ListenAndServe("127.0.0.1:0")
	select {
	case <-s.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("beacon server did not start")
	}
	addr := s.Addr().(*net.UDPAddr)
	return s, addr
}

func sendUDP(t *testing.T, addr *net.UDPAddr, data []byte) []byte {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(200 * time.Millisecond))

	if _, err := conn.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil // timeout = no reply
	}
	return buf[:n]
}

// ---------------------------------------------------------------------------
// Discover message tests
// ---------------------------------------------------------------------------

func TestBeaconDiscoverExact5Bytes(t *testing.T) {
	s, addr := startTestBeacon(t)
	defer s.Close()

	// Discover: [type(1)][nodeID(4)] = 5 bytes
	msg := make([]byte, 5)
	msg[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(msg[1:], 42)

	reply := sendUDP(t, addr, msg)
	if reply == nil {
		t.Fatal("expected discover reply")
	}
	if reply[0] != protocol.BeaconMsgDiscoverReply {
		t.Fatalf("expected DiscoverReply, got 0x%02X", reply[0])
	}
}

func TestBeaconDiscoverLessThan5Bytes(t *testing.T) {
	s, addr := startTestBeacon(t)
	defer s.Close()

	// Only type byte + 3 bytes (< 4 bytes for nodeID)
	msg := []byte{protocol.BeaconMsgDiscover, 0x00, 0x00, 0x00}
	reply := sendUDP(t, addr, msg)
	// Should be silently dropped — no reply
	if reply != nil && reply[0] == protocol.BeaconMsgDiscoverReply {
		t.Fatal("should not get reply for truncated discover")
	}
}

func TestBeaconDiscoverExtraBytes(t *testing.T) {
	s, addr := startTestBeacon(t)
	defer s.Close()

	// Discover with extra bytes after nodeID — should still work
	msg := make([]byte, 20)
	msg[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(msg[1:], 42)

	reply := sendUDP(t, addr, msg)
	if reply == nil {
		t.Fatal("expected discover reply even with extra bytes")
	}
	if reply[0] != protocol.BeaconMsgDiscoverReply {
		t.Fatalf("expected DiscoverReply, got 0x%02X", reply[0])
	}
}

// ---------------------------------------------------------------------------
// PunchRequest message tests
// ---------------------------------------------------------------------------

func TestBeaconPunchRequestExact9Bytes(t *testing.T) {
	s, addr := startTestBeacon(t)
	defer s.Close()

	// First register a node via discover
	discover := make([]byte, 5)
	discover[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(discover[1:], 100)
	sendUDP(t, addr, discover)

	// PunchRequest: [type(1)][requesterID(4)][targetID(4)] = 9 bytes
	msg := make([]byte, 9)
	msg[0] = protocol.BeaconMsgPunchRequest
	binary.BigEndian.PutUint32(msg[1:], 200)
	binary.BigEndian.PutUint32(msg[5:], 100)

	// No reply expected (punch commands are sent to both nodes)
	sendUDP(t, addr, msg)
}

func TestBeaconPunchRequestTooShort(t *testing.T) {
	s, addr := startTestBeacon(t)
	defer s.Close()

	// Only type + 4 bytes (need 8 after type)
	msg := []byte{protocol.BeaconMsgPunchRequest, 0x00, 0x00, 0x00, 0x01}
	sendUDP(t, addr, msg)
	// Should be silently dropped
}

// ---------------------------------------------------------------------------
// Relay message tests
// ---------------------------------------------------------------------------

func TestBeaconRelayMinimumSize(t *testing.T) {
	s, addr := startTestBeacon(t)
	defer s.Close()

	// Relay: [type(1)][senderID(4)][destID(4)] = 9 bytes minimum (empty payload)
	msg := make([]byte, 9)
	msg[0] = protocol.BeaconMsgRelay
	binary.BigEndian.PutUint32(msg[1:], 1)
	binary.BigEndian.PutUint32(msg[5:], 2)

	sendUDP(t, addr, msg)
	// No crash = pass
}

func TestBeaconRelayTooShort(t *testing.T) {
	s, addr := startTestBeacon(t)
	defer s.Close()

	// Relay with only 5 bytes after type (need 8)
	msg := []byte{protocol.BeaconMsgRelay, 0x00, 0x00, 0x00, 0x01, 0x00}
	sendUDP(t, addr, msg)
	// Should be silently dropped
}

func TestBeaconRelayWithPayload(t *testing.T) {
	s, addr := startTestBeacon(t)
	defer s.Close()

	// Register destination node
	discover := make([]byte, 5)
	discover[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(discover[1:], 999)
	sendUDP(t, addr, discover)

	// Relay with payload
	payload := []byte("relay-data")
	msg := make([]byte, 9+len(payload))
	msg[0] = protocol.BeaconMsgRelay
	binary.BigEndian.PutUint32(msg[1:], 1)
	binary.BigEndian.PutUint32(msg[5:], 999)
	copy(msg[9:], payload)

	sendUDP(t, addr, msg)
}

// ---------------------------------------------------------------------------
// Sync message tests
// ---------------------------------------------------------------------------

func TestBeaconSyncValidPeerList(t *testing.T) {
	s, addr := startTestBeacon(t)
	defer s.Close()

	// Sync: [type(1)][beaconID(4)][nodeCount(2)][nodeID(4)...]
	nodeIDs := []uint32{10, 20, 30}
	msgLen := 1 + 4 + 2 + 4*len(nodeIDs)
	msg := make([]byte, msgLen)
	msg[0] = protocol.BeaconMsgSync
	binary.BigEndian.PutUint32(msg[1:5], 99) // peer beacon ID
	binary.BigEndian.PutUint16(msg[5:7], uint16(len(nodeIDs)))
	for i, id := range nodeIDs {
		binary.BigEndian.PutUint32(msg[7+4*i:], id)
	}

	sendUDP(t, addr, msg)

	// Check that peer nodes were registered
	if s.PeerNodeCount() != 3 {
		t.Fatalf("expected 3 peer nodes, got %d", s.PeerNodeCount())
	}
}

func TestBeaconSyncTruncatedPeerList(t *testing.T) {
	s, addr := startTestBeacon(t)
	defer s.Close()

	// Claims 5 nodes but only provides data for 2
	msg := make([]byte, 1+4+2+8) // room for 2 nodeIDs
	msg[0] = protocol.BeaconMsgSync
	binary.BigEndian.PutUint32(msg[1:5], 88)
	binary.BigEndian.PutUint16(msg[5:7], 5) // claims 5
	binary.BigEndian.PutUint32(msg[7:], 1)
	binary.BigEndian.PutUint32(msg[11:], 2)

	sendUDP(t, addr, msg)
	// Should be silently dropped (message too short)
}

func TestBeaconSyncZeroPeerCount(t *testing.T) {
	s, addr := startTestBeacon(t)
	defer s.Close()

	msg := make([]byte, 7) // type + beaconID + nodeCount(=0)
	msg[0] = protocol.BeaconMsgSync
	binary.BigEndian.PutUint32(msg[1:5], 77)
	binary.BigEndian.PutUint16(msg[5:7], 0)

	sendUDP(t, addr, msg)
	// Should not crash, 0 nodes is valid
}

func TestBeaconSyncTooShort(t *testing.T) {
	s, addr := startTestBeacon(t)
	defer s.Close()

	// Need at least 7 bytes (type + beaconID + nodeCount), send only 4
	msg := []byte{protocol.BeaconMsgSync, 0x00, 0x00, 0x00}
	sendUDP(t, addr, msg)
	// Silently dropped
}

// ---------------------------------------------------------------------------
// Unknown message type
// ---------------------------------------------------------------------------

func TestBeaconUnknownMessageType(t *testing.T) {
	s, addr := startTestBeacon(t)
	defer s.Close()

	// Send unknown message type 0xFF
	msg := []byte{0xFF, 0x00, 0x00, 0x00}
	reply := sendUDP(t, addr, msg)
	// Should be silently ignored
	_ = reply
}

// ---------------------------------------------------------------------------
// Empty and single-byte messages
// ---------------------------------------------------------------------------

func TestBeaconEmptyMessage(t *testing.T) {
	s, addr := startTestBeacon(t)
	defer s.Close()

	// Empty message — the server's ReadFromUDP skips n < 1
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// UDP doesn't really send 0-byte datagrams, but this tests the write
	conn.Write([]byte{})
}

func TestBeaconSingleByteMessage(t *testing.T) {
	s, addr := startTestBeacon(t)
	defer s.Close()

	// Single byte — type only, no payload
	for _, msgType := range []byte{
		protocol.BeaconMsgDiscover,
		protocol.BeaconMsgPunchRequest,
		protocol.BeaconMsgRelay,
		protocol.BeaconMsgSync,
		0x00, 0xFF,
	} {
		sendUDP(t, addr, []byte{msgType})
	}
	// Should not crash
}

// ---------------------------------------------------------------------------
// PunchCommand parsing (IPv4 and IPv6)
// ---------------------------------------------------------------------------

func TestBeaconDiscoverReplyIPv4(t *testing.T) {
	s, addr := startTestBeacon(t)
	defer s.Close()

	msg := make([]byte, 5)
	msg[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(msg[1:], 1)

	reply := sendUDP(t, addr, msg)
	if reply == nil {
		t.Fatal("expected reply")
	}
	if reply[0] != protocol.BeaconMsgDiscoverReply {
		t.Fatalf("expected DiscoverReply, got 0x%02X", reply[0])
	}
	// Format: [type(1)][iplen(1)][IP(4)][port(2)]
	ipLen := reply[1]
	if ipLen != 4 && ipLen != 16 {
		t.Fatalf("unexpected IP length: %d", ipLen)
	}
	if len(reply) < 2+int(ipLen)+2 {
		t.Fatal("reply too short")
	}
}

// ---------------------------------------------------------------------------
// Node counts
// ---------------------------------------------------------------------------

func TestBeaconLocalNodeCount(t *testing.T) {
	s, addr := startTestBeacon(t)
	defer s.Close()

	if s.LocalNodeCount() != 0 {
		t.Fatal("expected 0 local nodes initially")
	}

	// Register a node
	msg := make([]byte, 5)
	msg[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(msg[1:], 42)
	sendUDP(t, addr, msg)

	// Wait for registration
	time.Sleep(50 * time.Millisecond)

	if s.LocalNodeCount() != 1 {
		t.Fatalf("expected 1 local node, got %d", s.LocalNodeCount())
	}
}

func TestBeaconPeerNodeCount(t *testing.T) {
	s, addr := startTestBeacon(t)
	defer s.Close()

	if s.PeerNodeCount() != 0 {
		t.Fatal("expected 0 peer nodes initially")
	}

	// Send sync with 2 nodes
	msg := make([]byte, 1+4+2+8)
	msg[0] = protocol.BeaconMsgSync
	binary.BigEndian.PutUint32(msg[1:5], 99)
	binary.BigEndian.PutUint16(msg[5:7], 2)
	binary.BigEndian.PutUint32(msg[7:], 100)
	binary.BigEndian.PutUint32(msg[11:], 200)
	sendUDP(t, addr, msg)

	time.Sleep(50 * time.Millisecond)

	if s.PeerNodeCount() != 2 {
		t.Fatalf("expected 2 peer nodes, got %d", s.PeerNodeCount())
	}
}

// ---------------------------------------------------------------------------
// Health endpoint
// ---------------------------------------------------------------------------

func TestBeaconHealthStatus(t *testing.T) {
	s := beacon.New()
	defer s.Close()

	s.SetHealthy(true)
	s.SetHealthy(false)
	s.SetHealthy(true)
	// Just verifying no panic on state changes
}

func TestBeaconRelayWithSenderIDZero(t *testing.T) {
	s, addr := startTestBeacon(t)
	defer s.Close()

	// Relay with senderID = 0
	msg := make([]byte, 9+5)
	msg[0] = protocol.BeaconMsgRelay
	binary.BigEndian.PutUint32(msg[1:], 0) // senderID = 0
	binary.BigEndian.PutUint32(msg[5:], 1)
	copy(msg[9:], []byte("hello"))

	sendUDP(t, addr, msg)
	// Should not crash
}

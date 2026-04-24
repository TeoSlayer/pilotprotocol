// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// startTestRegistry spins up an in-process registry on 127.0.0.1:0 and returns
// (server, dialed client). The test is responsible for closing both.
func startTestRegistry(t *testing.T) (*registry.Server, *registry.Client) {
	t.Helper()
	reg := registry.New("")
	go func() { _ = reg.ListenAndServe(":0") }()
	select {
	case <-reg.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("registry failed to start")
	}
	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	return reg, rc
}

func addPeerOnDaemon(t *testing.T, d *Daemon, nodeID uint32) *net.UDPConn {
	t.Helper()
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("tunnels.Listen: %v", err)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("peer listen: %v", err)
	}
	d.AddTunnelPeer(nodeID, pc.LocalAddr().(*net.UDPAddr))
	return pc
}

func recvPacket(t *testing.T, pc *net.UDPConn, timeout time.Duration) *protocol.Packet {
	t.Helper()
	_ = pc.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)
	n, _, err := pc.ReadFromUDP(buf)
	if err != nil {
		return nil
	}
	if n < 4 {
		return nil
	}
	pkt, err := protocol.Unmarshal(buf[4:n])
	if err != nil {
		t.Fatalf("unmarshal: %v (n=%d)", err, n)
	}
	return pkt
}

// --- CloseConnection ---

func TestCloseConnectionNonEstablishedSkipsFINAndSetsFinWait(t *testing.T) {
	d := New(Config{})
	peerConn := addPeerOnDaemon(t, d, 0xABCD0001)

	conn := d.ports.NewConnection(1001, protocol.Addr{Network: 1, Node: 0xABCD0001}, 80)
	conn.LocalAddr = protocol.Addr{Network: 1, Node: 0x11111111}
	conn.State = StateSynSent
	prevSeq := uint32(42)
	conn.SendSeq = prevSeq

	d.CloseConnection(conn)

	// No FIN packet should appear on peer socket within 100ms.
	if pkt := recvPacket(t, peerConn, 100*time.Millisecond); pkt != nil {
		t.Fatalf("no FIN expected in non-Established path, got %+v", pkt)
	}

	conn.Mu.Lock()
	defer conn.Mu.Unlock()
	if conn.State != StateFinWait {
		t.Fatalf("state = %v, want StateFinWait", conn.State)
	}
	if conn.SendSeq != prevSeq {
		t.Fatalf("SendSeq = %d, want unchanged %d", conn.SendSeq, prevSeq)
	}
}

func TestCloseConnectionEstablishedSendsFINIncrementsSeqAndClosesRecvBuf(t *testing.T) {
	d := New(Config{})
	peerConn := addPeerOnDaemon(t, d, 0xABCD0002)

	conn := d.ports.NewConnection(2001, protocol.Addr{Network: 1, Node: 0xABCD0002}, 80)
	conn.LocalAddr = protocol.Addr{Network: 1, Node: 0x22222222}
	conn.RemoteAddr = protocol.Addr{Network: 1, Node: 0xABCD0002}
	conn.RemotePort = 80
	conn.State = StateEstablished
	conn.SendSeq = 500

	d.CloseConnection(conn)

	pkt := recvPacket(t, peerConn, 500*time.Millisecond)
	if pkt == nil {
		t.Fatal("expected FIN packet on peer socket")
	}
	if pkt.Flags&protocol.FlagFIN == 0 {
		t.Fatalf("expected FlagFIN set, got flags=%b", pkt.Flags)
	}
	if pkt.Seq != 500 {
		t.Fatalf("FIN Seq = %d, want 500", pkt.Seq)
	}

	conn.Mu.Lock()
	st := conn.State
	seq := conn.SendSeq
	conn.Mu.Unlock()
	if st != StateFinWait {
		t.Fatalf("state = %v, want StateFinWait", st)
	}
	if seq != 501 {
		t.Fatalf("SendSeq = %d, want 501 (FIN consumes one seq)", seq)
	}

	// RecvBuf should be closed — non-blocking recv returns ok=false.
	select {
	case _, ok := <-conn.RecvBuf:
		if ok {
			t.Fatal("RecvBuf should be closed after CloseConnection")
		}
	default:
		t.Fatal("RecvBuf recv should not block (should be closed)")
	}
}

// --- SendDatagram ---

func TestSendDatagramPortPolicyDeniedReturnsError(t *testing.T) {
	d := New(Config{})
	// Set an allowlist that does NOT include port 443 on network 1.
	d.netPolicyMu.Lock()
	d.netPolicies[1] = []uint16{80}
	d.netPolicyMu.Unlock()

	err := d.SendDatagram(protocol.Addr{Network: 1, Node: 99}, 443, []byte("payload"))
	if err == nil {
		t.Fatal("expected port-not-allowed error")
	}
}

func TestSendDatagramDirectPathSendsPacketToPeer(t *testing.T) {
	d := New(Config{})
	const peerNode uint32 = 0xBEEF0001
	peerConn := addPeerOnDaemon(t, d, peerNode)
	d.setNodeID_testhelper(0x11110000)

	dst := protocol.Addr{Network: 7, Node: peerNode}
	if err := d.SendDatagram(dst, 1234, []byte("hello-dgram")); err != nil {
		t.Fatalf("SendDatagram: %v", err)
	}

	pkt := recvPacket(t, peerConn, 500*time.Millisecond)
	if pkt == nil {
		t.Fatal("expected datagram on peer socket")
	}
	if pkt.Protocol != protocol.ProtoDatagram {
		t.Fatalf("Protocol = %d, want ProtoDatagram", pkt.Protocol)
	}
	if pkt.DstPort != 1234 {
		t.Fatalf("DstPort = %d, want 1234", pkt.DstPort)
	}
	if string(pkt.Payload) != "hello-dgram" {
		t.Fatalf("Payload = %q, want hello-dgram", pkt.Payload)
	}
	if pkt.Src.Node != 0x11110000 || pkt.Src.Network != 7 {
		t.Fatalf("Src = %+v, want {7, 0x11110000}", pkt.Src)
	}
}

// SetNodeID is a small convenience used by tests that want a specific Src.
func (d *Daemon) setNodeID_testhelper(id uint32) {
	d.addrMu.Lock()
	d.nodeID = id
	d.addrMu.Unlock()
}

// --- broadcastDatagram ---

func TestBroadcastDatagramBackboneNetworkZeroRejected(t *testing.T) {
	d := New(Config{})
	err := d.broadcastDatagram(0, 1000, 80, []byte("x"))
	if err == nil {
		t.Fatal("broadcast on network 0 should be rejected")
	}
}

func TestSendDatagramBroadcastOnNetworkZeroRejected(t *testing.T) {
	d := New(Config{})
	dst := protocol.BroadcastAddr(0)
	err := d.SendDatagram(dst, 80, []byte("x"))
	if err == nil {
		t.Fatal("broadcast SendDatagram on network 0 should return an error")
	}
}

func TestBroadcastDatagramRegistryClosedReturnsError(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	rc.Close() // force ListNodes to fail

	d := New(Config{})
	d.regConn = rc

	err := d.broadcastDatagram(5, 1000, 80, []byte("x"))
	if err == nil {
		t.Fatal("expected error when registry is closed")
	}
}

func TestBroadcastDatagramNonMemberDenied(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()

	// Register a different node (not us) into network 5.
	otherID, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("127.0.0.1:5000", crypto.EncodePublicKey(otherID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register other: %v", err)
	}
	otherNodeID := uint32(resp["node_id"].(float64))

	d := New(Config{})
	d.regConn = rc
	d.setNodeID_testhelper(0xDEAD0000) // our node is NOT in the registry at all

	err = d.broadcastDatagram(5, 1000, 80, []byte("x"))
	if err == nil {
		t.Fatal("expected non-member denial error")
	}
	_ = otherNodeID
}

// --- lookupPeerPubKey ---

func TestLookupPeerPubKeyRegistryClosedReturnsError(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	rc.Close()

	d := New(Config{})
	d.regConn = rc

	_, err := d.lookupPeerPubKey(42)
	if err == nil {
		t.Fatal("expected error when registry is closed")
	}
}

func TestLookupPeerPubKeyUnknownNodeReturnsError(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()

	d := New(Config{})
	d.regConn = rc

	_, err := d.lookupPeerPubKey(999999) // never registered
	if err == nil {
		t.Fatal("expected error for unregistered node")
	}
}

func TestLookupPeerPubKeySuccessReturnsKey(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()

	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("127.0.0.1:4000", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	d := New(Config{})
	d.regConn = rc

	got, err := d.lookupPeerPubKey(nodeID)
	if err != nil {
		t.Fatalf("lookupPeerPubKey: %v", err)
	}
	if len(got) != len(id.PublicKey) {
		t.Fatalf("key length = %d, want %d", len(got), len(id.PublicKey))
	}
	for i := range got {
		if got[i] != id.PublicKey[i] {
			t.Fatalf("key[%d] = %d, want %d", i, got[i], id.PublicKey[i])
		}
	}
}

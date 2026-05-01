// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// broadcastFixture sets up a registry with a network that has the daemon's
// own node + `peerCount` other nodes as members. The returned peerNodeIDs can
// be used to observe packets via peerConns (parallel slices).
type broadcastFixture struct {
	reg        interface{ Close() error }
	d          *Daemon
	netID      uint16
	selfNodeID uint32
	peerIDs    []uint32
	peerConns  []*net.UDPConn
}

func setupBroadcastFixture(t *testing.T, peerCount int) *broadcastFixture {
	t.Helper()
	reg, rc := startTestRegistry(t)
	t.Cleanup(func() { reg.Close() })
	t.Cleanup(func() { rc.Close() })
	reg.SetAdminToken("admin-token")

	// Register self node.
	selfID, _ := crypto.GenerateIdentity()
	selfResp, err := rc.RegisterWithKey("127.0.0.1:5000", crypto.EncodePublicKey(selfID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("self register: %v", err)
	}
	selfNodeID := uint32(selfResp["node_id"].(float64))

	// Create network owned by self.
	createResp, err := rc.CreateNetwork(selfNodeID, "bcast-net", "open", "", "admin-token", false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(createResp["network_id"].(float64))

	d := New(Config{})
	d.regConn = rc
	d.setNodeID_testhelper(selfNodeID)

	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("tunnels.Listen: %v", err)
	}
	t.Cleanup(func() { d.tunnels.Close() })

	peerIDs := make([]uint32, 0, peerCount)
	peerConns := make([]*net.UDPConn, 0, peerCount)
	for i := 0; i < peerCount; i++ {
		pid, _ := crypto.GenerateIdentity()
		pResp, err := rc.RegisterWithKey("127.0.0.1:"+itoa(6000+i), crypto.EncodePublicKey(pid.PublicKey), "", nil)
		if err != nil {
			t.Fatalf("peer %d register: %v", i, err)
		}
		peerNodeID := uint32(pResp["node_id"].(float64))
		if _, err := rc.JoinNetwork(peerNodeID, netID, "", selfNodeID, "admin-token"); err != nil {
			t.Fatalf("peer %d join: %v", i, err)
		}
		peerIDs = append(peerIDs, peerNodeID)

		pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("peer %d UDP listen: %v", i, err)
		}
		t.Cleanup(func() { pc.Close() })
		d.AddTunnelPeer(peerNodeID, pc.LocalAddr().(*net.UDPAddr))
		peerConns = append(peerConns, pc)
	}

	return &broadcastFixture{
		reg:        reg,
		d:          d,
		netID:      netID,
		selfNodeID: selfNodeID,
		peerIDs:    peerIDs,
		peerConns:  peerConns,
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// --- broadcastDatagram happy-path delivery ---

func TestBroadcastDatagramMemberDeliversToOnePeer(t *testing.T) {
	fx := setupBroadcastFixture(t, 1)

	err := fx.d.broadcastDatagram(fx.netID, 1000, 80, []byte("hello-broadcast"), "")
	if err != nil {
		t.Fatalf("broadcastDatagram: %v", err)
	}

	pkt := readPacket(t, fx.peerConns[0], 500*time.Millisecond)
	if pkt == nil {
		t.Fatal("expected datagram on peer 0")
	}
	if pkt.Protocol != protocol.ProtoDatagram {
		t.Fatalf("Protocol = %d, want ProtoDatagram", pkt.Protocol)
	}
	if string(pkt.Payload) != "hello-broadcast" {
		t.Fatalf("Payload = %q, want 'hello-broadcast'", pkt.Payload)
	}
	if pkt.Src.Network != fx.netID || pkt.Dst.Network != fx.netID {
		t.Fatalf("addr networks: src=%d dst=%d, want both %d", pkt.Src.Network, pkt.Dst.Network, fx.netID)
	}
	if pkt.Src.Node != fx.selfNodeID {
		t.Fatalf("Src.Node = %d, want %d", pkt.Src.Node, fx.selfNodeID)
	}
	if pkt.Dst.Node != fx.peerIDs[0] {
		t.Fatalf("Dst.Node = %d, want %d", pkt.Dst.Node, fx.peerIDs[0])
	}
	if pkt.SrcPort != 1000 || pkt.DstPort != 80 {
		t.Fatalf("ports: src=%d dst=%d, want 1000/80", pkt.SrcPort, pkt.DstPort)
	}
}

func TestBroadcastDatagramSkipsSelf(t *testing.T) {
	fx := setupBroadcastFixture(t, 2)

	// Add a peerConn to observe self-addressed deliveries, if any.
	// Since ensureTunnel for self would need a registered endpoint + AddPeer to
	// self-loop UDP, we don't add such a peer — instead we rely on the explicit
	// `if nodeID == d.NodeID() { continue }` branch in broadcastDatagram.
	err := fx.d.broadcastDatagram(fx.netID, 1000, 80, []byte("no-self"), "")
	if err != nil {
		t.Fatalf("broadcastDatagram: %v", err)
	}

	// Both peers should receive the packet.
	for i, pc := range fx.peerConns {
		pkt := readPacket(t, pc, 500*time.Millisecond)
		if pkt == nil {
			t.Fatalf("peer %d did not receive packet", i)
		}
		if pkt.Dst.Node == fx.selfNodeID {
			t.Fatalf("peer %d received self-addressed packet (self-skip broken)", i)
		}
	}
}

func TestBroadcastDatagramPolicyDeniedPerPeerSkipped(t *testing.T) {
	fx := setupBroadcastFixture(t, 2)

	// Install a netPolicy that denies port 9999 entirely for this network.
	// isPortAllowed returns false when ports is non-empty and port not in list.
	fx.d.netPolicyMu.Lock()
	fx.d.netPolicies[fx.netID] = []uint16{80} // allow only 80
	fx.d.netPolicyMu.Unlock()

	if err := fx.d.broadcastDatagram(fx.netID, 1000, 9999, []byte("denied"), ""); err != nil {
		t.Fatalf("broadcastDatagram: %v", err)
	}

	// Neither peer should receive anything — policy denied for all.
	for i, pc := range fx.peerConns {
		if pkt := readPacket(t, pc, 150*time.Millisecond); pkt != nil {
			t.Fatalf("peer %d received packet despite policy denial: %v", i, pkt.Flags)
		}
	}
}

func TestBroadcastDatagramNilNodesSliceReturnsNilNoPanic(t *testing.T) {
	// When the network exists but has no nodes listed, the handler returns
	// nil early from the type assertion — no panic.
	// We simulate this by creating a fixture with zero peers but still a
	// member self — verify no panic and no errors.
	fx := setupBroadcastFixture(t, 0)

	err := fx.d.broadcastDatagram(fx.netID, 1000, 80, []byte("alone"), "")
	if err != nil {
		t.Fatalf("broadcastDatagram with only self member: %v", err)
	}
	// No peers → no packets sent, nothing to verify beyond no panic / no error.
}

func TestBroadcastDatagramMultiplePeersAllReceive(t *testing.T) {
	fx := setupBroadcastFixture(t, 3)

	err := fx.d.broadcastDatagram(fx.netID, 1000, 80, []byte("fan-out"), "")
	if err != nil {
		t.Fatalf("broadcastDatagram: %v", err)
	}

	seen := make(map[uint32]bool)
	for i, pc := range fx.peerConns {
		pkt := readPacket(t, pc, 500*time.Millisecond)
		if pkt == nil {
			t.Fatalf("peer %d (node %d) did not receive packet", i, fx.peerIDs[i])
		}
		if string(pkt.Payload) != "fan-out" {
			t.Fatalf("peer %d payload = %q, want 'fan-out'", i, pkt.Payload)
		}
		seen[pkt.Dst.Node] = true
	}
	for _, pid := range fx.peerIDs {
		if !seen[pid] {
			t.Fatalf("peer %d (expected recipient) not seen in dst nodes", pid)
		}
	}
}

// --- BroadcastDatagram (public, admin-token gated) ---

func TestBroadcastDatagramTokenEmptyConfigDenied(t *testing.T) {
	fx := setupBroadcastFixture(t, 1)
	// Daemon has Config.AdminToken == "" — broadcast must be denied even
	// when the caller passes a non-empty token.
	err := fx.d.BroadcastDatagram(fx.netID, 80, []byte("x"), "anything")
	if err == nil {
		t.Fatal("expected denial when daemon has no admin token configured")
	}
	if pkt := readPacket(t, fx.peerConns[0], 100*time.Millisecond); pkt != nil {
		t.Fatalf("no packet should have been delivered: %v", pkt.Payload)
	}
}

func TestBroadcastDatagramTokenMismatchDenied(t *testing.T) {
	fx := setupBroadcastFixture(t, 1)
	fx.d.config.AdminToken = "real-token"
	if err := fx.d.BroadcastDatagram(fx.netID, 80, []byte("x"), "wrong-token"); err == nil {
		t.Fatal("expected denial on token mismatch")
	}
	if pkt := readPacket(t, fx.peerConns[0], 100*time.Millisecond); pkt != nil {
		t.Fatalf("no packet should have been delivered: %v", pkt.Payload)
	}
}

func TestBroadcastDatagramTokenEmptyCallerDenied(t *testing.T) {
	fx := setupBroadcastFixture(t, 1)
	fx.d.config.AdminToken = "real-token"
	if err := fx.d.BroadcastDatagram(fx.netID, 80, []byte("x"), ""); err == nil {
		t.Fatal("expected denial on empty caller token")
	}
}

func TestBroadcastDatagramTokenValidDelivers(t *testing.T) {
	fx := setupBroadcastFixture(t, 2)
	fx.d.config.AdminToken = "secret"
	if err := fx.d.BroadcastDatagram(fx.netID, 80, []byte("auth-ok"), "secret"); err != nil {
		t.Fatalf("BroadcastDatagram with valid token: %v", err)
	}
	for i, pc := range fx.peerConns {
		pkt := readPacket(t, pc, 500*time.Millisecond)
		if pkt == nil {
			t.Fatalf("peer %d did not receive auth-gated broadcast", i)
		}
		if string(pkt.Payload) != "auth-ok" {
			t.Fatalf("peer %d payload = %q", i, pkt.Payload)
		}
	}
}

// Network 0 (backbone) was previously hard-blocked. With admin-token
// gating, it is permitted.
func TestBroadcastDatagramNetworkZeroAllowedWithToken(t *testing.T) {
	reg, rc := startTestRegistry(t)
	t.Cleanup(func() { reg.Close() })
	t.Cleanup(func() { rc.Close() })
	// Backbone listing is admin-gated at the registry. Daemon's
	// Config.AdminToken must match the registry's admin token so the
	// list_nodes(0) call is unlocked.
	reg.SetAdminToken("secret")

	// Register self + a peer; the peer is automatically a member of
	// network 0 (backbone) by virtue of being registered.
	selfID, _ := crypto.GenerateIdentity()
	selfResp, err := rc.RegisterWithKey("127.0.0.1:5000", crypto.EncodePublicKey(selfID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("self register: %v", err)
	}
	selfNodeID := uint32(selfResp["node_id"].(float64))

	peerID, _ := crypto.GenerateIdentity()
	pResp, err := rc.RegisterWithKey("127.0.0.1:5001", crypto.EncodePublicKey(peerID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("peer register: %v", err)
	}
	peerNodeID := uint32(pResp["node_id"].(float64))

	d := New(Config{AdminToken: "secret"})
	d.regConn = rc
	d.setNodeID_testhelper(selfNodeID)
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("tunnels.Listen: %v", err)
	}
	t.Cleanup(func() { d.tunnels.Close() })

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("peer UDP listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	d.AddTunnelPeer(peerNodeID, pc.LocalAddr().(*net.UDPAddr))

	if err := d.BroadcastDatagram(0, 80, []byte("backbone"), "secret"); err != nil {
		t.Fatalf("backbone broadcast with token: %v", err)
	}
	if pkt := readPacket(t, pc, 500*time.Millisecond); pkt == nil {
		t.Fatal("peer did not receive backbone broadcast")
	}
}

// Admin token bypasses sender-membership: a node not in the network can
// still broadcast to it as long as it presents a valid token.
func TestBroadcastDatagramNonMemberAllowedWithToken(t *testing.T) {
	fx := setupBroadcastFixture(t, 1)
	fx.d.config.AdminToken = "secret"
	// Pretend this daemon is some other node entirely — definitely not a
	// member of fx.netID.
	fx.d.setNodeID_testhelper(0xDEAD0000)

	if err := fx.d.BroadcastDatagram(fx.netID, 80, []byte("admin-override"), "secret"); err != nil {
		t.Fatalf("non-member admin broadcast: %v", err)
	}
	if pkt := readPacket(t, fx.peerConns[0], 500*time.Millisecond); pkt == nil {
		t.Fatal("peer did not receive admin-override broadcast")
	}
}

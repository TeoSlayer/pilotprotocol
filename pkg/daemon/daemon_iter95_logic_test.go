package daemon

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// Iter-95 batched pure-logic coverage for three functions whose error/edge
// branches were already covered but whose happy-path branches required more
// setup: HandshakeManager.sharedNetwork (wired registry + joined network),
// PortManager.portInUse (state filter), PortManager.ConnectionList (field
// marshalling).

// --- HandshakeManager.sharedNetwork ---

// hmWithPeersSharingNetwork returns (hm, selfID, peerID, netID) where both
// nodes have joined the network (so Lookup returns it in "networks").
func hmWithPeersSharingNetwork(t *testing.T) (*HandshakeManager, uint32, uint32, uint16) {
	t.Helper()
	reg, rc := startTestRegistry(t)
	t.Cleanup(func() { reg.Close() })
	t.Cleanup(func() { rc.Close() })
	reg.SetAdminToken("admin-token")

	// Use admin-token path for both create + join (no signer wiring required,
	// which also avoids the self-signer signing peer-scoped messages).
	selfID, _ := crypto.GenerateIdentity()
	selfResp, err := rc.RegisterWithKey("127.0.0.1:5900", crypto.EncodePublicKey(selfID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("self register: %v", err)
	}
	selfNodeID := uint32(selfResp["node_id"].(float64))

	peerID, _ := crypto.GenerateIdentity()
	peerResp, err := rc.RegisterWithKey("127.0.0.1:5901", crypto.EncodePublicKey(peerID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("peer register: %v", err)
	}
	peerNodeID := uint32(peerResp["node_id"].(float64))

	createResp, err := rc.CreateNetwork(selfNodeID, "shared-net", "open", "", "admin-token", false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(createResp["network_id"].(float64))

	if _, err := rc.JoinNetwork(peerNodeID, netID, "", 0, "admin-token"); err != nil {
		t.Fatalf("peer join: %v", err)
	}

	d := New(Config{})
	d.regConn = rc
	d.identity = selfID
	d.setNodeID_testhelper(selfNodeID)
	t.Cleanup(func() { d.handshakes.Stop() })

	return d.handshakes, selfNodeID, peerNodeID, netID
}

func TestSharedNetworkBothNodesInSameNetworkReturnsNetID(t *testing.T) {
	hm, _, peerID, netID := hmWithPeersSharingNetwork(t)
	got := hm.sharedNetwork(peerID)
	if got != netID {
		t.Fatalf("sharedNetwork = %d, want %d", got, netID)
	}
}

func TestSameNetworkBothNodesInSameNetworkReturnsTrue(t *testing.T) {
	hm, _, peerID, _ := hmWithPeersSharingNetwork(t)
	if !hm.sameNetwork(peerID) {
		t.Fatal("sameNetwork should be true when both nodes joined the same network")
	}
}

func TestSharedNetworkPeerOnlyInBackboneReturnsZero(t *testing.T) {
	// Self in netID=X, peer only in backbone (net 0). Even though backbone is
	// technically shared, sharedNetwork explicitly skips network 0. Expect 0.
	reg, rc := startTestRegistry(t)
	t.Cleanup(func() { reg.Close() })
	t.Cleanup(func() { rc.Close() })
	reg.SetAdminToken("admin-token")

	selfID, _ := crypto.GenerateIdentity()
	selfResp, err := rc.RegisterWithKey("127.0.0.1:5902", crypto.EncodePublicKey(selfID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("self register: %v", err)
	}
	selfNodeID := uint32(selfResp["node_id"].(float64))

	// Peer only in backbone.
	peerID, _ := crypto.GenerateIdentity()
	peerResp, err := rc.RegisterWithKey("127.0.0.1:5903", crypto.EncodePublicKey(peerID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("peer register: %v", err)
	}
	peerNodeID := uint32(peerResp["node_id"].(float64))

	// Self creates + auto-joins a non-backbone net; peer doesn't join it.
	if _, err := rc.CreateNetwork(selfNodeID, "self-only", "open", "", "admin-token", false); err != nil {
		t.Fatalf("create network: %v", err)
	}

	d := New(Config{})
	d.regConn = rc
	d.identity = selfID
	d.setNodeID_testhelper(selfNodeID)
	t.Cleanup(func() { d.handshakes.Stop() })

	if got := d.handshakes.sharedNetwork(peerNodeID); got != 0 {
		t.Fatalf("sharedNetwork with peer only in backbone = %d, want 0", got)
	}
}

func TestSharedNetworkDisjointNetworksReturnsZero(t *testing.T) {
	reg, rc := startTestRegistry(t)
	t.Cleanup(func() { reg.Close() })
	t.Cleanup(func() { rc.Close() })
	reg.SetAdminToken("admin-token")

	selfID, _ := crypto.GenerateIdentity()
	selfResp, err := rc.RegisterWithKey("127.0.0.1:5904", crypto.EncodePublicKey(selfID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("self register: %v", err)
	}
	selfNodeID := uint32(selfResp["node_id"].(float64))

	peerID, _ := crypto.GenerateIdentity()
	peerResp, err := rc.RegisterWithKey("127.0.0.1:5905", crypto.EncodePublicKey(peerID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("peer register: %v", err)
	}
	peerNodeID := uint32(peerResp["node_id"].(float64))

	// Self creates+joins net A, peer joins a separate net B.
	if _, err := rc.CreateNetwork(selfNodeID, "net-a", "open", "", "admin-token", false); err != nil {
		t.Fatalf("create net-a: %v", err)
	}
	createB, err := rc.CreateNetwork(peerNodeID, "net-b", "open", "", "admin-token", false)
	if err != nil {
		t.Fatalf("create net-b: %v", err)
	}
	netBID := uint16(createB["network_id"].(float64))

	d := New(Config{})
	d.regConn = rc
	d.identity = selfID
	d.setNodeID_testhelper(selfNodeID)
	t.Cleanup(func() { d.handshakes.Stop() })

	got := d.handshakes.sharedNetwork(peerNodeID)
	if got == netBID {
		t.Fatalf("sharedNetwork = %d (netB), peer's own net should not match", got)
	}
	if got != 0 {
		t.Fatalf("sharedNetwork = %d, want 0 (no overlap)", got)
	}
}

// --- PortManager.portInUse ---

func TestPortInUseEmptyManagerReturnsFalse(t *testing.T) {
	pm := NewPortManager()
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.portInUse(80) {
		t.Fatal("portInUse on empty PortManager should return false")
	}
}

func TestPortInUseDifferentPortReturnsFalse(t *testing.T) {
	pm := NewPortManager()
	c := pm.NewConnection(443, protocol.Addr{}, 0)
	c.State = StateEstablished
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.portInUse(80) {
		t.Fatal("portInUse(80) with connection on 443 should return false")
	}
}

func TestPortInUseSamePortEstablishedReturnsTrue(t *testing.T) {
	pm := NewPortManager()
	c := pm.NewConnection(80, protocol.Addr{}, 0)
	c.State = StateEstablished
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if !pm.portInUse(80) {
		t.Fatal("portInUse(80) with established connection on 80 should return true")
	}
}

func TestPortInUseSamePortClosedOrTimeWaitReturnsFalse(t *testing.T) {
	pm := NewPortManager()
	cClosed := pm.NewConnection(80, protocol.Addr{}, 0)
	cClosed.State = StateClosed
	cTW := pm.NewConnection(80, protocol.Addr{}, 0)
	cTW.State = StateTimeWait
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.portInUse(80) {
		t.Fatal("portInUse(80) with only Closed+TimeWait should return false")
	}
}

// --- PortManager.ConnectionList ---

func TestConnectionListEmptyReturnsEmpty(t *testing.T) {
	pm := NewPortManager()
	if got := pm.ConnectionList(); len(got) != 0 {
		t.Fatalf("ConnectionList on empty PM = %d entries, want 0", len(got))
	}
}

func TestConnectionListReportsPerConnectionFields(t *testing.T) {
	pm := NewPortManager()
	remote := protocol.Addr{Network: 7, Node: 0xDEADBEEF}
	c := pm.NewConnection(80, remote, 1234)
	c.State = StateEstablished
	c.SendSeq = 100
	c.RecvAck = 200
	c.CongWin = 4096
	c.SSThresh = 8192
	c.PeerRecvWin = 9000
	c.InRecovery = true
	c.Stats = ConnStats{BytesSent: 42, BytesRecv: 7, SegsSent: 3, SegsRecv: 2}

	list := pm.ConnectionList()
	if len(list) != 1 {
		t.Fatalf("ConnectionList len = %d, want 1", len(list))
	}
	info := list[0]
	if info.ID != c.ID {
		t.Fatalf("ID = %d, want %d", info.ID, c.ID)
	}
	if info.LocalPort != 80 {
		t.Fatalf("LocalPort = %d, want 80", info.LocalPort)
	}
	if info.RemotePort != 1234 {
		t.Fatalf("RemotePort = %d, want 1234", info.RemotePort)
	}
	if info.State != StateEstablished.String() {
		t.Fatalf("State = %q, want %q", info.State, StateEstablished.String())
	}
	if info.SendSeq != 100 {
		t.Fatalf("SendSeq = %d, want 100", info.SendSeq)
	}
	if info.RecvAck != 200 {
		t.Fatalf("RecvAck = %d, want 200", info.RecvAck)
	}
	if info.CongWin != 4096 {
		t.Fatalf("CongWin = %d, want 4096", info.CongWin)
	}
	if info.SSThresh != 8192 {
		t.Fatalf("SSThresh = %d, want 8192", info.SSThresh)
	}
	if info.PeerRecvWin != 9000 {
		t.Fatalf("PeerRecvWin = %d, want 9000", info.PeerRecvWin)
	}
	if !info.InRecovery {
		t.Fatal("InRecovery = false, want true")
	}
	if info.Stats.BytesSent != 42 {
		t.Fatalf("Stats.BytesSent = %d, want 42", info.Stats.BytesSent)
	}
	if info.Stats.BytesRecv != 7 {
		t.Fatalf("Stats.BytesRecv = %d, want 7", info.Stats.BytesRecv)
	}
	// RemoteAddr string is the stringified protocol.Addr — ensure non-empty.
	if info.RemoteAddr == "" {
		t.Fatal("RemoteAddr should be non-empty")
	}
	// RecvWin is derived from RecvWindow()*MaxSegmentSize. Empty RecvBuf ⇒ full window.
	if info.RecvWin <= 0 {
		t.Fatalf("RecvWin = %d, want > 0", info.RecvWin)
	}
}

func TestConnectionListMultipleConnections(t *testing.T) {
	pm := NewPortManager()
	c1 := pm.NewConnection(80, protocol.Addr{Node: 1}, 100)
	c1.State = StateEstablished
	c2 := pm.NewConnection(443, protocol.Addr{Node: 2}, 200)
	c2.State = StateSynSent

	list := pm.ConnectionList()
	if len(list) != 2 {
		t.Fatalf("ConnectionList len = %d, want 2", len(list))
	}
	// Order is not guaranteed — check IDs present.
	seen := map[uint32]bool{}
	for _, info := range list {
		seen[info.ID] = true
	}
	if !seen[c1.ID] || !seen[c2.ID] {
		t.Fatalf("ConnectionList missing IDs: %v", seen)
	}
}

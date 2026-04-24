// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// --- helpers ---

func newStreamSYNPkt(srcNode, dstNode uint32, srcPort, dstPort uint16, seq uint32) *protocol.Packet {
	return &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Network: 0, Node: srcNode},
		Dst:      protocol.Addr{Network: 0, Node: dstNode},
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Seq:      seq,
		Window:   1024,
	}
}

func streamPacket(flags uint8, srcNode, dstNode uint32, srcPort, dstPort uint16, seq, ack uint32) *protocol.Packet {
	return &protocol.Packet{
		Version:  protocol.Version,
		Flags:    flags,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Network: 0, Node: srcNode},
		Dst:      protocol.Addr{Network: 0, Node: dstNode},
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Seq:      seq,
		Ack:      ack,
		Window:   1024,
	}
}

// --- SYN branches ---

func TestHandleStreamSYNNoListenerSendsRST(t *testing.T) {
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD0001)

	syn := newStreamSYNPkt(peerNode, d.NodeID(), 7777, 8080, 100)
	d.handleStreamPacket(syn)

	pkt := readPacket(t, peerConn, 500*time.Millisecond)
	if pkt == nil {
		t.Fatal("expected RST on peer socket for SYN with no listener")
	}
	if !pkt.HasFlag(protocol.FlagRST) {
		t.Fatalf("flags = %d, want FlagRST", pkt.Flags)
	}
}

func TestHandleStreamSYNListenerPublicSendsSYNACKAndAccepts(t *testing.T) {
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD0002)

	ln, err := d.ports.Bind(8080)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	syn := newStreamSYNPkt(peerNode, d.NodeID(), 7777, 8080, 100)
	d.handleStreamPacket(syn)

	pkt := readPacket(t, peerConn, 500*time.Millisecond)
	if pkt == nil {
		t.Fatal("expected SYN-ACK on peer socket")
	}
	if !pkt.HasFlag(protocol.FlagSYN) || !pkt.HasFlag(protocol.FlagACK) {
		t.Fatalf("flags = %d, want FlagSYN|FlagACK", pkt.Flags)
	}
	if pkt.Ack != 101 {
		t.Fatalf("Ack = %d, want 101 (syn.Seq+1)", pkt.Ack)
	}

	// Accept queue should contain the connection.
	select {
	case conn := <-ln.AcceptCh:
		if conn.State != StateEstablished {
			t.Fatalf("conn.State = %v, want StateEstablished", conn.State)
		}
		if conn.LocalPort != 8080 || conn.RemotePort != 7777 {
			t.Fatalf("port mismatch: local=%d remote=%d", conn.LocalPort, conn.RemotePort)
		}
		close(conn.RetxStop) // stop retxLoop goroutine
	case <-time.After(500 * time.Millisecond):
		t.Fatal("connection not delivered to AcceptCh")
	}
}

func TestHandleStreamSYNRetransmitResendsSYNACK(t *testing.T) {
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD0003)

	ln, err := d.ports.Bind(8080)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	// First SYN → creates connection + sends SYN-ACK.
	syn := newStreamSYNPkt(peerNode, d.NodeID(), 7777, 8080, 100)
	d.handleStreamPacket(syn)
	if first := readPacket(t, peerConn, 500*time.Millisecond); first == nil {
		t.Fatal("expected first SYN-ACK")
	}
	conn := <-ln.AcceptCh
	defer close(conn.RetxStop)

	// Retransmitted SYN (same 4-tuple) → should take the existing-connection branch.
	d.handleStreamPacket(syn)
	retrans := readPacket(t, peerConn, 500*time.Millisecond)
	if retrans == nil {
		t.Fatal("expected retransmitted SYN-ACK")
	}
	if !retrans.HasFlag(protocol.FlagSYN) || !retrans.HasFlag(protocol.FlagACK) {
		t.Fatalf("retrans flags = %d, want FlagSYN|FlagACK", retrans.Flags)
	}
	if retrans.Ack != 101 {
		t.Fatalf("retrans Ack = %d, want 101", retrans.Ack)
	}

	// Only one connection — retransmit must not create a duplicate.
	if n := d.ports.TotalActiveConnections(); n != 1 {
		t.Fatalf("connections = %d, want 1 after SYN retransmit", n)
	}
}

func TestHandleStreamSYNPrivateModeUntrustedIsSilentDropNoRST(t *testing.T) {
	// Public:false + no handshakes + nil regConn → trust check fails, silent drop.
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: false})
	d.setNodeID_testhelper(0xABCD0004)

	_, err := d.ports.Bind(8080)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	syn := newStreamSYNPkt(peerNode, d.NodeID(), 7777, 8080, 100)
	d.handleStreamPacket(syn)

	// Must be silent — no RST, no SYN-ACK.
	if pkt := readPacket(t, peerConn, 150*time.Millisecond); pkt != nil {
		t.Fatalf("expected silent drop on untrusted SYN, got flags=%d", pkt.Flags)
	}
	if n := d.ports.TotalActiveConnections(); n != 0 {
		t.Fatalf("connections = %d, want 0 (SYN rejected)", n)
	}
}

// --- SYN-ACK branches ---

func TestHandleStreamSYNACKNoConnectionIsSilentDrop(t *testing.T) {
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD0005)

	synack := streamPacket(protocol.FlagSYN|protocol.FlagACK, peerNode, d.NodeID(), 443, 55555, 999, 1)
	d.handleStreamPacket(synack)

	if pkt := readPacket(t, peerConn, 150*time.Millisecond); pkt != nil {
		t.Fatalf("expected no response for SYN-ACK with no matching connection, got flags=%d", pkt.Flags)
	}
}

func TestHandleStreamSYNACKEstablishedStateIsIgnored(t *testing.T) {
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD0006)

	// Pre-create a connection in Established state (not StateSynSent).
	conn := d.ports.NewConnection(55555, protocol.Addr{Network: 0, Node: peerNode}, 443)
	conn.LocalAddr = protocol.Addr{Network: 0, Node: d.NodeID()}
	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.SendSeq = 5000
	conn.Mu.Unlock()

	// Incoming SYN-ACK: since state != StateSynSent, handler returns silently.
	synack := streamPacket(protocol.FlagSYN|protocol.FlagACK, peerNode, d.NodeID(), 443, 55555, 999, 1)
	d.handleStreamPacket(synack)

	if pkt := readPacket(t, peerConn, 150*time.Millisecond); pkt != nil {
		t.Fatalf("expected no ACK for SYN-ACK in non-SynSent state, got flags=%d", pkt.Flags)
	}
	// State must remain Established (unchanged).
	conn.Mu.Lock()
	st := conn.State
	conn.Mu.Unlock()
	if st != StateEstablished {
		t.Fatalf("state = %v, want StateEstablished (unchanged)", st)
	}
}

func TestHandleStreamSYNACKInSynSentTransitionsToEstablished(t *testing.T) {
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD0007)

	conn := d.ports.NewConnection(55555, protocol.Addr{Network: 0, Node: peerNode}, 443)
	conn.LocalAddr = protocol.Addr{Network: 0, Node: d.NodeID()}
	conn.Mu.Lock()
	conn.State = StateSynSent
	conn.SendSeq = 5000
	conn.Mu.Unlock()

	synack := streamPacket(protocol.FlagSYN|protocol.FlagACK, peerNode, d.NodeID(), 443, 55555, 999, 5000)
	d.handleStreamPacket(synack)

	// Expect ACK completing handshake.
	pkt := readPacket(t, peerConn, 500*time.Millisecond)
	if pkt == nil {
		t.Fatal("expected ACK completing three-way handshake")
	}
	if !pkt.HasFlag(protocol.FlagACK) || pkt.HasFlag(protocol.FlagSYN) {
		t.Fatalf("flags = %d, want pure FlagACK", pkt.Flags)
	}
	if pkt.Ack != 1000 {
		t.Fatalf("Ack = %d, want 1000 (syn.Seq+1)", pkt.Ack)
	}

	conn.Mu.Lock()
	st := conn.State
	conn.Mu.Unlock()
	if st != StateEstablished {
		t.Fatalf("state = %v, want StateEstablished", st)
	}
}

// --- FIN branches ---

func TestHandleStreamFINEstablishedClosesAndSendsFINACK(t *testing.T) {
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD0008)

	conn := d.ports.NewConnection(55555, protocol.Addr{Network: 0, Node: peerNode}, 443)
	conn.LocalAddr = protocol.Addr{Network: 0, Node: d.NodeID()}
	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.SendSeq = 42
	conn.Mu.Unlock()

	fin := streamPacket(protocol.FlagFIN, peerNode, d.NodeID(), 443, 55555, 9000, 0)
	d.handleStreamPacket(fin)

	pkt := readPacket(t, peerConn, 500*time.Millisecond)
	if pkt == nil {
		t.Fatal("expected FIN-ACK")
	}
	if !pkt.HasFlag(protocol.FlagFIN) || !pkt.HasFlag(protocol.FlagACK) {
		t.Fatalf("flags = %d, want FlagFIN|FlagACK", pkt.Flags)
	}
	if pkt.Ack != 9001 {
		t.Fatalf("Ack = %d, want 9001 (fin.Seq+1)", pkt.Ack)
	}

	conn.Mu.Lock()
	st := conn.State
	conn.Mu.Unlock()
	if st != StateTimeWait {
		t.Fatalf("state = %v, want StateTimeWait", st)
	}
}

func TestHandleStreamFINWaitClearsUnackedRetxBuffer(t *testing.T) {
	d, peerNode, _ := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD0009)

	conn := d.ports.NewConnection(55555, protocol.Addr{Network: 0, Node: peerNode}, 443)
	conn.LocalAddr = protocol.Addr{Network: 0, Node: d.NodeID()}
	conn.Mu.Lock()
	conn.State = StateFinWait
	conn.SendSeq = 42
	conn.Mu.Unlock()
	conn.RetxMu.Lock()
	conn.Unacked = []*retxEntry{{seq: 1, data: []byte("x")}}
	conn.RetxMu.Unlock()

	fin := streamPacket(protocol.FlagFIN, peerNode, d.NodeID(), 443, 55555, 9000, 0)
	d.handleStreamPacket(fin)

	conn.RetxMu.Lock()
	ua := len(conn.Unacked)
	conn.RetxMu.Unlock()
	if ua != 0 {
		t.Fatalf("Unacked = %d, want 0 (FIN-ACK should clear retx buffer in FinWait)", ua)
	}
}

func TestHandleStreamFINNoConnectionIsNoop(t *testing.T) {
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD000A)

	fin := streamPacket(protocol.FlagFIN, peerNode, d.NodeID(), 443, 55555, 9000, 0)
	d.handleStreamPacket(fin)

	if pkt := readPacket(t, peerConn, 150*time.Millisecond); pkt != nil {
		t.Fatalf("expected no response, got flags=%d", pkt.Flags)
	}
}

// --- RST branches ---

func TestHandleStreamRSTEstablishedClosesAndRemoves(t *testing.T) {
	d, peerNode, _ := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD000B)

	conn := d.ports.NewConnection(55555, protocol.Addr{Network: 0, Node: peerNode}, 443)
	conn.LocalAddr = protocol.Addr{Network: 0, Node: d.NodeID()}
	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.Mu.Unlock()
	connID := conn.ID

	rst := streamPacket(protocol.FlagRST, peerNode, d.NodeID(), 443, 55555, 9000, 0)
	d.handleStreamPacket(rst)

	conn.Mu.Lock()
	st := conn.State
	conn.Mu.Unlock()
	if st != StateClosed {
		t.Fatalf("state = %v, want StateClosed", st)
	}
	// Must be removed from ports.
	conns := d.ports.AllConnections()
	for _, c := range conns {
		if c.ID == connID {
			t.Fatal("connection should have been removed on RST")
		}
	}
}

func TestHandleStreamRSTNoConnectionIsNoop(t *testing.T) {
	d, peerNode, _ := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD000C)

	rst := streamPacket(protocol.FlagRST, peerNode, d.NodeID(), 443, 55555, 9000, 0)
	d.handleStreamPacket(rst) // must not panic
}

// --- Pure ACK branches ---

func TestHandleStreamACKPureUpdatesLastActivityNoResponse(t *testing.T) {
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD000D)

	conn := d.ports.NewConnection(55555, protocol.Addr{Network: 0, Node: peerNode}, 443)
	conn.LocalAddr = protocol.Addr{Network: 0, Node: d.NodeID()}
	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.LastActivity = time.Now().Add(-time.Hour)
	before := conn.LastActivity
	conn.KeepaliveUnacked = 5
	conn.Mu.Unlock()

	ack := streamPacket(protocol.FlagACK, peerNode, d.NodeID(), 443, 55555, 0, 1)
	d.handleStreamPacket(ack)

	// No response expected for pure ACK with no payload.
	if pkt := readPacket(t, peerConn, 150*time.Millisecond); pkt != nil {
		t.Fatalf("expected no response to pure ACK, got flags=%d", pkt.Flags)
	}

	conn.Mu.Lock()
	after := conn.LastActivity
	ku := conn.KeepaliveUnacked
	conn.Mu.Unlock()
	if !after.After(before) {
		t.Fatalf("LastActivity not updated: before=%v after=%v", before, after)
	}
	if ku != 0 {
		t.Fatalf("KeepaliveUnacked = %d, want 0 (reset on ACK)", ku)
	}
}

func TestHandleStreamACKNoConnectionIsNoop(t *testing.T) {
	d, peerNode, _ := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD000E)

	ack := streamPacket(protocol.FlagACK, peerNode, d.NodeID(), 443, 55555, 0, 1)
	d.handleStreamPacket(ack) // must not panic
}

func TestHandleStreamACKWithDataDeliversAndSchedulesDelayedACK(t *testing.T) {
	d, peerNode, _ := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD000F)

	conn := d.ports.NewConnection(55555, protocol.Addr{Network: 0, Node: peerNode}, 443)
	conn.LocalAddr = protocol.Addr{Network: 0, Node: d.NodeID()}
	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.ExpectedSeq = 1000
	conn.Mu.Unlock()

	data := streamPacket(protocol.FlagACK, peerNode, d.NodeID(), 443, 55555, 1000, 1)
	data.Payload = []byte("hello")
	d.handleStreamPacket(data)

	conn.Mu.Lock()
	recvAck := conn.RecvAck
	bytesRecv := conn.Stats.BytesRecv
	segsRecv := conn.Stats.SegsRecv
	conn.Mu.Unlock()
	if recvAck != 1005 {
		t.Fatalf("RecvAck = %d, want 1005 (ExpectedSeq+len)", recvAck)
	}
	if bytesRecv != 5 {
		t.Fatalf("BytesRecv = %d, want 5", bytesRecv)
	}
	if segsRecv != 1 {
		t.Fatalf("SegsRecv = %d, want 1", segsRecv)
	}

	// PendingACKs should be incremented (delayed ACK path — only 1 segment so far).
	conn.AckMu.Lock()
	pending := conn.PendingACKs
	hasTimer := conn.ACKTimer != nil
	conn.AckMu.Unlock()
	if pending != 1 {
		t.Fatalf("PendingACKs = %d, want 1", pending)
	}
	if !hasTimer {
		t.Fatal("expected delayed ACK timer to be armed")
	}

	// Clean up the timer so it doesn't fire during test teardown.
	conn.AckMu.Lock()
	if conn.ACKTimer != nil {
		conn.ACKTimer.Stop()
	}
	conn.AckMu.Unlock()
}

func TestHandleStreamACKWithDataNonEstablishedIsIgnoredPayloadNotDelivered(t *testing.T) {
	d, peerNode, _ := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD0010)

	conn := d.ports.NewConnection(55555, protocol.Addr{Network: 0, Node: peerNode}, 443)
	conn.LocalAddr = protocol.Addr{Network: 0, Node: d.NodeID()}
	conn.Mu.Lock()
	conn.State = StateSynSent // not Established — data should be dropped
	conn.ExpectedSeq = 1000
	conn.Mu.Unlock()

	data := streamPacket(protocol.FlagACK, peerNode, d.NodeID(), 443, 55555, 1000, 1)
	data.Payload = []byte("late")
	d.handleStreamPacket(data)

	conn.Mu.Lock()
	bytesRecv := conn.Stats.BytesRecv
	segsRecv := conn.Stats.SegsRecv
	conn.Mu.Unlock()
	if bytesRecv != 0 || segsRecv != 0 {
		t.Fatalf("non-Established conn received data: bytes=%d segs=%d", bytesRecv, segsRecv)
	}
}

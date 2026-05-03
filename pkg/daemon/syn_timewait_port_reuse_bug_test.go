// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestSYNToTimeWaitConnBlocksNewConnection verifies that a fresh SYN on a
// TIME_WAIT 4-tuple creates a new connection instead of replaying the stale
// SYN-ACK.
//
// Bug (pre-v1.9.1): handleStreamPacket's retransmitted-SYN dedup check called
// FindConnection without filtering by state. A TIME_WAIT connection found for
// the same (DstPort, Src, SrcPort) 4-tuple caused the handler to resend the
// old SYN-ACK seq and return, blocking the new connection for up to 25 s
// (TimeWaitDuration + IdleSweepInterval). High-churn workloads (CI, proxies,
// NAT port reuse) hit this as random multi-second dial timeouts.
//
// Fix (v1.9.1): the dedup check now gates on State == SynReceived || Established.
// TIME_WAIT and CLOSED connections fall through to create a fresh connection.
//
// GREEN assertion: after a SYN to a TIME_WAIT 4-tuple, ln.AcceptCh has a new
// connection. Against unpatched code, AcceptCh is empty (handler short-circuited
// after replaying the stale SYN-ACK).
func TestSYNToTimeWaitConnBlocksNewConnection(t *testing.T) {
	d, peerNode, _ := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD0060)

	// Bind a server listener port.
	ln, err := d.ports.Bind(9090)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { d.ports.Unbind(9090) })

	peerAddr := protocol.Addr{Network: 0, Node: peerNode}
	const peerSrcPort = 49300

	// Pre-populate the port table with a stale connection in TIME_WAIT on
	// the same 4-tuple that the new SYN will use.
	staleConn := d.ports.NewConnection(9090, peerAddr, peerSrcPort)
	staleConn.Mu.Lock()
	staleConn.LocalAddr = protocol.Addr{Network: 0, Node: d.NodeID()}
	staleConn.SynAckSeq = 9999
	staleConn.SynAckSeqSet = true
	staleConn.SendSeq = 10000
	staleConn.RecvAck = 500
	staleConn.State = StateTimeWait
	staleConn.Mu.Unlock()

	// Send a fresh SYN from the same 4-tuple (port reuse / rapid cycling).
	syn := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      peerAddr,
		Dst:      protocol.Addr{Network: 0, Node: d.NodeID()},
		SrcPort:  peerSrcPort,
		DstPort:  9090,
		Seq:      100,
		Window:   256,
	}
	d.handleStreamPacket(syn)

	// FIXED: a new connection is pushed to AcceptCh because the TIME_WAIT
	// conn was correctly identified as ineligible for SYN-ACK replay.
	select {
	case newConn := <-ln.AcceptCh:
		if newConn.ID == staleConn.ID {
			t.Errorf("got stale connection ID %d instead of a new one", staleConn.ID)
		}
		newConn.Mu.Lock()
		st := newConn.State
		newConn.Mu.Unlock()
		if st != StateEstablished {
			t.Errorf("new connection state = %v, want Established", st)
		}
	default:
		t.Errorf("AcceptCh is empty — SYN to TIME_WAIT 4-tuple did not create new connection (fix not applied)")
	}
}

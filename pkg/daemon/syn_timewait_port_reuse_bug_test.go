// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestSYNToTimeWaitConnBlocksNewConnection reproduces the
// "SYN to a TIME_WAIT 4-tuple resends stale SYN-ACK, blocking new connection"
// bug.
//
// Symptom: handleStreamPacket's duplicate-SYN dedup path calls
// FindConnection(DstPort, Src, SrcPort) without checking the connection
// state. If a connection is in TIME_WAIT (or CLOSED, pending idleSweep
// cleanup) and a new SYN arrives from the same (src_addr, src_port) →
// (dst_port) 4-tuple, the handler:
//
//  1. Finds the stale TIME_WAIT connection
//  2. Resends a SYN-ACK with the OLD sequence numbers
//  3. Returns without creating a new connection
//
// The new SYN's client receives a SYN-ACK with a sequence number that does
// not match any in-flight SYN (the client sent a fresh SYN with a new seq,
// but the server responded with the old SYN-ACK seq). The client's retries
// keep seeing the stale SYN-ACK until idleSweepLoop finally reaps the
// TIME_WAIT connection (up to DefaultTimeWaitDuration + DefaultIdleSweepInterval
// = 25 s). Only then does the next SYN create a fresh connection.
//
// Scenario: high-churn workloads (CI health checks, short-lived proxy
// connections, NAT port reuse) that cycle through the same source port
// within the TIME_WAIT window suffer multi-second connection failures
// that appear as random dial timeouts.
//
// What v1.9.1's fix should change: the retransmitted-SYN dedup check
// in handleStreamPacket must verify the existing connection is in an
// active state (SynReceived or Established). A TIME_WAIT or CLOSED
// connection is ineligible for SYN-ACK replay — fall through to create
// a new connection.
//
// This test pins the CURRENT (buggy) behavior: a SYN to a TIME_WAIT
// 4-tuple does NOT produce a new accepted connection (ln.AcceptCh stays
// empty because the handler short-circuits after resending the stale
// SYN-ACK). After GREEN the assertion flips: a new connection appears
// in ln.AcceptCh.
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
	staleConn.SynAckSeq = 9999 // stale seq from old handshake
	staleConn.SynAckSeqSet = true
	staleConn.SendSeq = 10000 // drifted forward after data
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
		Seq:      100, // fresh seq from the new client SYN
		Window:   256,
	}
	d.handleStreamPacket(syn)

	// CURRENT (buggy) behavior: the handler found the TIME_WAIT conn and
	// resent the stale SYN-ACK (seq=9999), returning without creating a new
	// connection. AcceptCh has nothing.
	select {
	case <-ln.AcceptCh:
		// GREEN: new connection was created and pushed to AcceptCh — correct behavior.
		t.Fatalf("BUG NOT REPRODUCED: a new connection was accepted (fix may be in place); GREEN flips this")
	default:
		// BUG confirmed: no new connection despite valid SYN.
		t.Logf("AcceptCh is empty — SYN to TIME_WAIT 4-tuple sent stale SYN-ACK, new connection blocked")
	}

	// Also verify the stale TIME_WAIT conn is still there (it was not replaced).
	existing := d.ports.FindConnection(9090, peerAddr, peerSrcPort)
	if existing == nil || existing.ID != staleConn.ID {
		t.Errorf("expected stale conn %d still present; got %v", staleConn.ID, existing)
	}
}

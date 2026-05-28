// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"

	"github.com/pilot-protocol/common/protocol"
)

// TestSACKPayloadSuppressesDupACKCounting verifies that a SACK-carrying ACK
// (pure ACK with SACK blocks in the payload, no user data) is correctly
// treated as a pure ACK for duplicate ACK detection purposes.
//
// Bug (pre-v1.9.1): handleStreamPacket computes:
//
//	isPureACK := len(pkt.Payload) == 0
//
// A SACK-carrying ACK has a non-empty payload (the SACK block encoding), so
// isPureACK is FALSE. ProcessAck is then called with pureACK=false, which
// causes the dup-ACK early return to fire:
//
//	if ack == c.LastAck {
//	    if !pureACK {
//	        return  // ← SACK ACKs hit this path; DupAckCount never increments
//	    }
//	    ...
//	}
//
// Consequence: when a receiver reports out-of-order data via SACK blocks (the
// common fast-path), every ACK from that receiver carries a non-empty SACK
// payload. None of these count as duplicate ACKs. DupAckCount stays at 0,
// the 3-dup-ACK fast-retransmit threshold (RFC 5681) is never crossed, and
// loss detection falls back to the much slower RTO-based path. Under 1% loss
// at 100 Mbit/s this can reduce effective throughput by 10–30×.
//
// Fix (v1.9.1): decode the payload before computing isPureACK:
//
//	sackBlocks, isSACK := DecodeSACK(pkt.Payload)
//	isPureACK := len(pkt.Payload) == 0 || isSACK  // SACK = no user data
//
// GREEN assertion: after three SACK-carrying ACKs whose cumulative Ack equals
// conn.LastAck (dup ACKs), DupAckCount reaches 3 and Stats.FastRetx is 1.
// Against unpatched code DupAckCount stays 0 and Stats.FastRetx stays 0.
func TestSACKPayloadSuppressesDupACKCounting(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	peerConn := addPeerOnDaemon(t, d, 0xBEEF0001)
	t.Cleanup(func() { peerConn.Close() })
	d.setNodeID_testhelper(0xCAFE0001)

	const (
		localPort  = uint16(8250)
		remotePort = uint16(9090)
		remoteNode = uint32(0xBEEF0001)
	)

	conn := d.ports.NewConnection(localPort,
		protocol.Addr{Network: 0, Node: remoteNode}, remotePort)
	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0xCAFE0001}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: remoteNode}
	conn.State = StateEstablished
	conn.SendSeq = 2000
	conn.Mu.Unlock()
	conn.RetxStop = make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-conn.RetxStop:
		default:
			close(conn.RetxStop)
		}
		d.ports.RemoveConnection(conn.ID)
	})

	// Place a sent-but-unacked segment so ProcessAck can detect dup ACKs
	// (without Unacked the function returns immediately on dup detection).
	conn.RetxMu.Lock()
	conn.LastAck = 1000
	conn.Unacked = []*retxEntry{
		{seq: 1000, data: make([]byte, 100), attempts: 1},
	}
	conn.RetxMu.Unlock()

	// Craft three SACK-carrying ACKs: Ack=LastAck=1000 (dup) with SACK
	// blocks reporting out-of-order data the peer already received.
	// The payload is non-empty (SACK encoding) but carries NO user data.
	sackPayload := EncodeSACK([]SACKBlock{{Left: 1500, Right: 1600}})

	for i := 0; i < 3; i++ {
		sackPkt := &protocol.Packet{
			Version:  protocol.Version,
			Flags:    protocol.FlagACK,
			Protocol: protocol.ProtoStream,
			Src:      protocol.Addr{Network: 0, Node: remoteNode},
			Dst:      protocol.Addr{Network: 0, Node: 0xCAFE0001},
			SrcPort:  remotePort,
			DstPort:  localPort,
			Seq:      500,
			Ack:      1000, // == LastAck → dup ACK
			Window:   100,
			Payload:  sackPayload,
		}
		d.handleStreamPacket(sackPkt)
	}

	conn.RetxMu.Lock()
	dupAckCount := conn.DupAckCount
	conn.RetxMu.Unlock()
	conn.Mu.Lock()
	fastRetx := conn.Stats.FastRetx
	conn.Mu.Unlock()

	// FIXED: SACK-carrying ACKs are pure ACKs (no user data); they must
	// increment DupAckCount and trigger fast retransmit on the 3rd dup.
	if dupAckCount < 3 && fastRetx == 0 {
		t.Errorf("3 SACK-carrying ACKs with Ack=LastAck: DupAckCount=%d, FastRetx=%d "+
			"— 'isPureACK := len(pkt.Payload) == 0' is FALSE when SACK payload is "+
			"present, causing ProcessAck to skip dup-ACK detection for every ACK "+
			"that carries SACK blocks; DupAckCount never reaches 3 and fast retransmit "+
			"is permanently suppressed for connections that report OOO data via SACK, "+
			"forcing loss detection onto the much slower RTO timeout path; "+
			"fix: compute isPureACK = len(pkt.Payload)==0 || isSACK(pkt.Payload) "+
			"by decoding the payload before the ProcessAck call",
			dupAckCount, fastRetx)
	}
}

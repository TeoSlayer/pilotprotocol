// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestHandleStreamPacketZeroAckSkipsWraparound verifies that an ACK packet
// with Ack=0 (the legitimate cumulative ACK value after a 4 GiB sequence-
// number wraparound) causes ProcessAck to run and remove fully-acked segments
// from conn.Unacked.
//
// Bug (pre-v1.9.1): handleStreamPacket guards ProcessAck with:
//
//	if pkt.Ack > 0 {
//	    conn.ProcessAck(pkt.Ack, isPureACK)
//	}
//
// The intent was to skip "no ACK" packets (e.g. a bare SYN whose Ack field is
// zero).  However, in circular uint32 sequence space, Ack=0 is the correct
// cumulative ACK value once the receiver has consumed exactly 4 GiB of data:
// the peer's next expected sequence number wraps to 0x00000000.
//
// Consequence: when the peer sends Ack=0 (legitimate wraparound):
//  1. ProcessAck is skipped.
//  2. Segments whose endSeq <= 0x00000000 (i.e. segments near the wrap point)
//     are never removed from conn.Unacked.
//  3. retxLoop retransmits them on the next RTO tick; the peer discards the
//     duplicates but sends another Ack=0, which is again skipped — a perpetual
//     spurious-retransmit loop until the peer ACKs more data (Ack > 0).
//
// Fix (v1.9.1): remove the pkt.Ack > 0 guard.  ProcessAck's internal logic
// (seqAfter for "behind" check, uint32 arithmetic for bytesAcked) already
// handles Ack=0 correctly for both the wraparound case and the fresh-
// connection case where LastAck==0.
//
// GREEN assertion: after handleStreamPacket with Ack=0 and a connection whose
// LastAck=0xFFFFF000, the segment with seq=0xFFFFF000 and segEnd=0x00000000
// is removed from conn.Unacked.  Against unpatched code, Unacked is unchanged.
func TestHandleStreamPacketZeroAckSkipsWraparound(t *testing.T) {
	d := New(Config{})
	peerConn := addPeerOnDaemon(t, d, 0xEE440001)
	t.Cleanup(func() { peerConn.Close() })
	d.setNodeID_testhelper(0x77770000)

	const (
		localPort  = uint16(8100)
		remotePort = uint16(9090)
		remoteNode = uint32(0xEE440001)
	)

	conn := d.ports.NewConnection(localPort,
		protocol.Addr{Network: 0, Node: remoteNode}, remotePort)
	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x77770000}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: remoteNode}
	conn.State = StateEstablished
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

	// Simulate a segment whose endSeq wraps to 0x00000000.
	// seq = 0xFFFFF000, len(data) = 0x1000 → endSeq = 0x00000000 (mod 2^32).
	wrapData := make([]byte, 0x1000)
	conn.RetxMu.Lock()
	conn.LastAck = 0xFFFFF000 // cumulative ACK already reached this point
	conn.Unacked = []*retxEntry{
		{seq: 0xFFFFF000, data: wrapData, attempts: 1},
	}
	conn.RetxMu.Unlock()

	// Craft a pure ACK with Ack=0 — the legitimate wraparound value.
	// pkt.Ack > 0 is FALSE, so the current code skips ProcessAck entirely.
	ackPkt := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagACK,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Network: 0, Node: remoteNode},
		Dst:      protocol.Addr{Network: 0, Node: 0x77770000},
		SrcPort:  remotePort,
		DstPort:  localPort,
		Seq:      0x00000100, // peer's current send position
		Ack:      0x00000000, // wraparound ACK — fully acks our segment
		Window:   1024,
	}

	d.handleStreamPacket(ackPkt)

	conn.RetxMu.Lock()
	remaining := len(conn.Unacked)
	conn.RetxMu.Unlock()

	// FIXED: removing the pkt.Ack > 0 guard lets ProcessAck run for Ack=0,
	// which correctly removes fully-acked wraparound segments from Unacked.
	if remaining != 0 {
		t.Errorf("handleStreamPacket with Ack=0 (wraparound): %d segment(s) "+
			"still in Unacked, want 0 — 'if pkt.Ack > 0' guard skips ProcessAck "+
			"for the legitimate cumulative-ACK value Ack=0 that occurs after a "+
			"4 GiB sequence-number wraparound, leaving near-wrap segments in "+
			"Unacked indefinitely and triggering spurious retransmission on every "+
			"RTO tick until the peer sends Ack > 0; "+
			"fix: remove the pkt.Ack > 0 guard — ProcessAck's seqAfter check "+
			"already handles Ack=0 correctly for both wraparound and fresh connections",
			remaining)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestWindowUpdateDoesNotIncrementDupAckCount verifies that a pure window
// update (same cumulative ACK number, larger advertised Window field) does
// NOT increment DupAckCount and does NOT trigger fast retransmit.
//
// Bug (current): ProcessAck counts any pure ACK with ack==LastAck as a
// duplicate ACK, regardless of the Window field:
//
//	if ack == c.LastAck {
//	    if !pureACK { return }
//	    if c.BytesInFlight() == 0 { return }
//	    c.DupAckCount++           // ← increments for window updates too
//	    ...
//	}
//
// RFC 5681 §3.1 defines a duplicate ACK as satisfying ALL five conditions,
// including condition (e): "the advertised window in the incoming
// acknowledgment equals the advertised window in the last incoming
// acknowledgment."  A window update — where the peer grows its receive
// window — violates condition (e) and is therefore NOT a duplicate ACK.
//
// Consequence: if the peer sends 3 consecutive window updates without a new
// cumulative ACK (e.g., three rapid receive-buffer drains while the sender's
// window is full), DupAckCount reaches 3 and handleStreamPacket triggers
// fast retransmit plus SSThresh halving — a spurious congestion event that
// reduces throughput even though no packet was lost.
//
// Concrete example (sender has 4 segments in flight, peer's recv buffer slowly drains):
//
//	BytesInFlight = 4*MSS, LastAck = 500
//	3 consecutive window updates:
//	  pkt1: Ack=500, Window=2  → PeerRecvWin = 2*MSS (was 1*MSS)
//	  pkt2: Ack=500, Window=3  → PeerRecvWin = 3*MSS
//	  pkt3: Ack=500, Window=4  → PeerRecvWin = 4*MSS
//
//	bug:  DupAckCount reaches 3 → SSThresh halved, fast retransmit
//	fix:  Window changes → condition (e) false → DupAckCount stays 0
//
// GREEN assertion: after 3 pure window updates with growing Window, DupAckCount==0
// and SSThresh/CongWin are unchanged.
func TestWindowUpdateDoesNotIncrementDupAckCount(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peerNode uint32 = 0xDA7ADA7A
	peerConn := addPeerOnDaemon(t, d, peerNode)
	t.Cleanup(func() { peerConn.Close() })

	d.setNodeID_testhelper(0x55550000)

	remoteAddr := protocol.Addr{Network: 0, Node: peerNode}
	localPort := uint16(7460)
	remotePort := uint16(80)

	conn := d.ports.NewConnection(localPort, remoteAddr, remotePort)
	t.Cleanup(func() {
		conn.Mu.Lock()
		conn.State = StateClosed
		conn.Mu.Unlock()
		d.ports.RemoveConnection(conn.ID)
	})

	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x55550000}
	conn.RemoteAddr = remoteAddr
	conn.State = StateEstablished
	conn.Mu.Unlock()

	const initialCongWin = 8 * MaxSegmentSize
	const initialSSThresh = 16 * MaxSegmentSize

	conn.RetxMu.Lock()
	conn.LastAck = 500
	conn.CongWin = initialCongWin
	conn.SSThresh = initialSSThresh
	conn.PeerRecvWin = 1 * MaxSegmentSize // initial peer window: 1 segment
	// 4 in-flight segments — window is full (PeerRecvWin = 1*MSS is the limit,
	// but BytesInFlight > 0 is what matters for the dup-ACK guard).
	for i := 0; i < 4; i++ {
		conn.Unacked = append(conn.Unacked, &retxEntry{
			seq:      uint32(500 + i*MaxSegmentSize),
			data:     make([]byte, MaxSegmentSize),
			attempts: 1,
			sentAt:   time.Now(),
			sacked:   false,
		})
	}
	conn.RetxMu.Unlock()

	// Verify BytesInFlight > 0 so the BytesInFlight==0 guard in ProcessAck
	// does NOT fire — we want the dup-ACK path to be exercised.
	conn.RetxMu.Lock()
	bif := conn.BytesInFlight()
	conn.RetxMu.Unlock()
	if bif == 0 {
		t.Fatal("test setup error: BytesInFlight() should be > 0")
	}

	// 3 consecutive pure window updates: Ack unchanged, Window grows each time.
	// Each is a window update, not a dup-ACK per RFC 5681 §3.1 condition (e).
	for i, winSegs := range []uint16{2, 3, 4} {
		pkt := &protocol.Packet{
			Version:  protocol.Version,
			Flags:    protocol.FlagACK,
			Protocol: protocol.ProtoStream,
			Src:      remoteAddr,
			Dst:      conn.LocalAddr,
			SrcPort:  remotePort,
			DstPort:  localPort,
			Seq:      uint32(100 + i),
			Ack:      500,    // == conn.LastAck → same cumulative ACK
			Window:   winSegs, // grows: 2, 3, 4 segments
		}
		d.handleStreamPacket(pkt)
	}

	conn.RetxMu.Lock()
	dupAckCount := conn.DupAckCount
	ssthresh := conn.SSThresh
	congWin := conn.CongWin
	conn.RetxMu.Unlock()

	// DupAckCount must NOT have reached 3 — window updates are not dup-ACKs.
	if dupAckCount >= 3 {
		t.Errorf("3 pure window updates (Ack=LastAck, Window growing): DupAckCount=%d, want < 3; "+
			"RFC 5681 §3.1 condition (e) requires advertised window to be unchanged for dup-ACK; "+
			"growing window violates condition (e); fix: in handleStreamPacket, "+
			"set isPureACK=false when PeerRecvWin changed and !isSACK",
			dupAckCount)
	}

	// SSThresh must NOT be halved — no real loss occurred.
	if ssthresh != initialSSThresh {
		t.Errorf("3 pure window updates: SSThresh=%d, want %d (unchanged); "+
			"spurious fast retransmit incorrectly halved SSThresh",
			ssthresh, initialSSThresh)
	}

	// CongWin must NOT be changed by spurious fast-retransmit path.
	if congWin != initialCongWin {
		t.Errorf("3 pure window updates: CongWin=%d, want %d (unchanged); "+
			"spurious fast-retransmit path changed CongWin",
			congWin, initialCongWin)
	}
}

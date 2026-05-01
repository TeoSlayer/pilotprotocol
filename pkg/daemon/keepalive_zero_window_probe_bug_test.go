// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestKeepaliveProbeZeroWindowSetsZeroPeerRecvWin verifies that a keepalive
// probe with Window=0 (as currently emitted by idleSweepLoop) causes the
// receiver's PeerRecvWin to drop to 0, blocking subsequent sends.
//
// Bug (pre-v1.9.1): the keepalive probe in idleSweepLoop omits the Window
// field, so Go's zero-value initialisation sets it to 0:
//
//	probe := &protocol.Packet{
//	    Flags: protocol.FlagACK,
//	    Seq:   sendSeq,
//	    Ack:   recvAck,
//	    // Window not set → 0
//	}
//
// The receiver's handleStreamPacket unconditionally updates PeerRecvWin:
//
//	conn.PeerRecvWin = int(pkt.Window) * MaxSegmentSize  // = 0
//
// PeerRecvWin=0 makes WindowAvailable() return false.  The receiver's
// sendSegment enters the zero-window probe loop and waits
// ZeroWinProbeInitial (500 ms) before retrying.  Every connection that has
// been idle for ≥ 1 keepalive interval (60 s by default) pays a ~500 ms
// stall on its first send after the idle period.
//
// Fix (v1.9.1): set Window: conn.RecvWindow() in the keepalive probe so
// the receiver never sets PeerRecvWin to 0 on a healthy connection.
//
// RED assertion: after handleStreamPacket receives a pure ACK with Window=0
// on a registered connection where PeerRecvWin was previously > 0,
// PeerRecvWin becomes 0 and WindowAvailable() returns false.
func TestKeepaliveProbeZeroWindowSetsZeroPeerRecvWin(t *testing.T) {
	d := New(Config{})

	// Register the connection via PortManager so handleStreamPacket can find it.
	remoteAddr := protocol.Addr{Network: 0, Node: 0xBBBBBBBB}
	remotePort := uint16(80)
	localPort := uint16(7800)
	conn := d.ports.NewConnection(localPort, remoteAddr, remotePort)
	t.Cleanup(func() { d.ports.RemoveConnection(conn.ID) })

	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0xAAAAAAAA}
	conn.RemoteAddr = remoteAddr
	conn.State = StateEstablished
	conn.RecvAck = 50
	conn.Mu.Unlock()

	// Prime PeerRecvWin to a healthy positive value (as it would be after
	// initial handshake).
	conn.RetxMu.Lock()
	conn.PeerRecvWin = 512 * MaxSegmentSize
	conn.LastAck = 100
	conn.RetxMu.Unlock()

	// Construct the keepalive probe exactly as idleSweepLoop currently does —
	// without a Window field (Window defaults to 0).
	buggyProbe := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagACK,
		Protocol: protocol.ProtoStream,
		Src:      remoteAddr,
		Dst:      conn.LocalAddr,
		SrcPort:  remotePort,
		DstPort:  localPort,
		Seq:      200,
		Ack:      100, // == conn.LastAck → dup-ACK path (no new data)
		// Window not set → 0 (this is the bug: idleSweepLoop doesn't set Window)
	}

	d.handleStreamPacket(buggyProbe)

	conn.RetxMu.Lock()
	peerRecvWin := conn.PeerRecvWin
	avail := conn.WindowAvailable()
	conn.RetxMu.Unlock()

	// FIXED: keepalive probe must include Window: conn.RecvWindow() so
	// PeerRecvWin is not set to 0 by the receiver.
	// FAILS against unpatched code: peerRecvWin=0, avail=false — the receiver's
	// sendSegment enters the zero-window probe loop for ~500ms on every idle
	// period, even though the connection's receive buffer is wide open.
	if peerRecvWin == 0 {
		t.Errorf("keepalive probe with Window=0 set PeerRecvWin=0 (WindowAvailable=%v); "+
			"idleSweepLoop probe omits Window (zero-value uint16=0), so the peer "+
			"sees a zero-window advertisement and stalls all sends for ~500ms; "+
			"this affects every connection after a ≥60s idle period; "+
			"fix: add Window: conn.RecvWindow() to the keepalive probe packet in idleSweepLoop",
			avail)
	}
}

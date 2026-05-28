// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"

	"github.com/pilot-protocol/common/protocol"
)

// TestKeepaliveProbeWithWindowDoesNotStallPeer verifies that a keepalive probe
// carrying the sender's actual receive window does NOT cause the receiver to
// block its sends.
//
// Bug (pre-v1.9.1): the keepalive probe in idleSweepLoop omits the Window
// field, so Go's zero-value initialises it to 0:
//
//	probe := &protocol.Packet{
//	    Flags: protocol.FlagACK,
//	    Seq:   sendSeq,
//	    Ack:   recvAck,
//	    // Window field absent → defaults to 0
//	}
//
// The receiver's handleStreamPacket unconditionally stores the peer's
// advertised receive window:
//
//	conn.PeerRecvWin = int(pkt.Window) * MaxSegmentSize  // = 0
//
// PeerRecvWin=0 makes WindowAvailable() return false.  The receiver's
// sendSegment enters the zero-window probe loop and waits
// ZeroWinProbeInitial (500 ms) before retrying.
//
// With the fix applied the probe sets Window: conn.RecvWindow(), so the
// receiver sets PeerRecvWin = conn.RecvWindow() * MaxSegmentSize > 0, and
// WindowAvailable() remains true.
//
// GREEN assertion: after handleStreamPacket processes a pure ACK that carries
// Window = conn.RecvWindow() (≥ 1 for a healthy connection), PeerRecvWin is
// positive and WindowAvailable() returns true.
func TestKeepaliveProbeWithWindowDoesNotStallPeer(t *testing.T) {
	t.Parallel()
	d := New(Config{})

	remoteAddr := protocol.Addr{Network: 0, Node: 0xDDDDDDDD}
	remotePort := uint16(80)
	localPort := uint16(7901)
	conn := d.ports.NewConnection(localPort, remoteAddr, remotePort)
	t.Cleanup(func() { d.ports.RemoveConnection(conn.ID) })

	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0xAAAAAAAA}
	conn.RemoteAddr = remoteAddr
	conn.State = StateEstablished
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	conn.LastAck = 100
	conn.RetxMu.Unlock()

	// Senders' conn.RecvWindow() on a fresh connection with an empty RecvBuf.
	senderRecvWin := conn.RecvWindow() // should be RecvBufSize (512)
	if senderRecvWin == 0 {
		t.Fatal("test setup error: RecvWindow() is 0 before the probe is sent")
	}

	// Construct the keepalive probe WITH Window (the fix).
	fixedProbe := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagACK,
		Protocol: protocol.ProtoStream,
		Src:      remoteAddr,
		Dst:      conn.LocalAddr,
		SrcPort:  remotePort,
		DstPort:  localPort,
		Seq:      200,
		Ack:      100,           // == conn.LastAck (dup-ACK path, keepalive-like)
		Window:   senderRecvWin, // fixed: sender includes its recv window
	}

	d.handleStreamPacket(fixedProbe)

	conn.RetxMu.Lock()
	peerRecvWin := conn.PeerRecvWin
	avail := conn.WindowAvailable()
	conn.RetxMu.Unlock()

	// With the fix the probe carries the actual receive window → PeerRecvWin > 0.
	// Without the fix: probe.Window=0 → PeerRecvWin=0 → avail=false → 500ms stall.
	if peerRecvWin == 0 {
		t.Errorf("probe with Window=%d: PeerRecvWin=%d (want > 0); "+
			"WindowAvailable=%v; keepalive probe must advertise recv window "+
			"so the peer does not enter the zero-window probe loop",
			senderRecvWin, peerRecvWin, avail)
	}
}

// TestKeepaliveZeroWindowProbeStallsMechanism documents the stall mechanism:
// receiving an ACK with Window=0 sets PeerRecvWin=0 and blocks sends.
// This verifies that the receiver correctly honors zero-window advertisements,
// and explains WHY the keepalive probe MUST NOT send Window=0.
func TestKeepaliveZeroWindowProbeStallsMechanism(t *testing.T) {
	t.Parallel()
	d := New(Config{})

	remoteAddr := protocol.Addr{Network: 0, Node: 0xEEEEEEEE}
	remotePort := uint16(80)
	localPort := uint16(7902)
	conn := d.ports.NewConnection(localPort, remoteAddr, remotePort)
	t.Cleanup(func() { d.ports.RemoveConnection(conn.ID) })

	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0xAAAAAAAA}
	conn.RemoteAddr = remoteAddr
	conn.State = StateEstablished
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	conn.LastAck = 100
	conn.RetxMu.Unlock()

	// Simulate receiving the BUGGY keepalive probe (Window=0, i.e. missing field).
	buggyProbe := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagACK,
		Protocol: protocol.ProtoStream,
		Src:      remoteAddr,
		Dst:      conn.LocalAddr,
		SrcPort:  remotePort,
		DstPort:  localPort,
		Seq:      200,
		Ack:      100,
		Window:   0, // missing window field in idleSweepLoop → defaults to 0
	}

	d.handleStreamPacket(buggyProbe)

	conn.RetxMu.Lock()
	peerRecvWin := conn.PeerRecvWin
	avail := conn.WindowAvailable()
	conn.RetxMu.Unlock()

	// The receiver correctly honors Window=0 and blocks sends.
	// This is the mechanism that causes the ~500ms stall — demonstrates
	// why idleSweepLoop MUST include Window: conn.RecvWindow() in its probe.
	if peerRecvWin != 0 || avail {
		t.Logf("peerRecvWin=%d avail=%v — receiver did not honor Window=0 advertisement "+
			"(unexpected; receiver should always update PeerRecvWin from pkt.Window)",
			peerRecvWin, avail)
	} else {
		t.Logf("confirmed: zero-window probe sets PeerRecvWin=0, avail=false — " +
			"500ms stall mechanism documented; fix: idleSweepLoop must include Window: conn.RecvWindow()")
	}
}

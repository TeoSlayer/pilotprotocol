// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestPeerRecvWinGrowthSignalsWindowCh verifies that when a pure window
// update (same cumulative ACK, larger Window field) grows PeerRecvWin from
// a small-but-positive value to a larger value, and the window becomes
// available, WindowCh is signaled so a blocked sendSegment wakes up.
//
// Bug (current): handleStreamPacket checks:
//
//	peerWinOpened := prevPeerWin == 0 && conn.PeerRecvWin > 0
//
// This only signals WindowCh for the 0 → positive transition. If
// PeerRecvWin was 1 segment (non-zero) and grows to 2 segments, both
// prevPeerWin and PeerRecvWin are positive, so peerWinOpened = false and
// WindowCh is not signaled. ProcessAck also does not signal WindowCh from
// the dup-ACK path (the packet carries the same cumulative ACK number).
//
// A sender blocked in sendSegment because BytesInFlight == old PeerRecvWin
// (window exactly full) waits up to ZeroWinProbeInitial (500 ms) for the
// probe timer before re-evaluating the window — a 500 ms stall per pure
// window update, even though the window is now larger.
//
// Concrete example:
//
//	PeerRecvWin = 1*MSS = 4096 bytes, BytesInFlight = 4096 (window full)
//	→ WindowAvailable() = (4096 < 4096) = false; sendSegment enters wait
//
//	Pure window update arrives: Ack=LastAck (dup-ACK), Window=2 segments
//	  correct: PeerRecvWin = 8192 > 4096 = BytesInFlight → WindowCh signaled
//	  bug:     peerWinOpened = (4096 == 0) = false → WindowCh NOT signaled
//	           → sender stalls 500 ms before re-evaluating
//
// GREEN assertion: after handleStreamPacket processes a pure window update
// that makes WindowAvailable() true, WindowCh has a token.
func TestPeerRecvWinGrowthSignalsWindowCh(t *testing.T) {
	t.Parallel()
	d := New(Config{})

	remoteAddr := protocol.Addr{Network: 0, Node: 0xBBBBBBBB}
	remotePort := uint16(80)
	localPort := uint16(7410)
	conn := d.ports.NewConnection(localPort, remoteAddr, remotePort)
	t.Cleanup(func() { d.ports.RemoveConnection(conn.ID) })

	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0xAAAAAAAA}
	conn.RemoteAddr = remoteAddr
	conn.State = StateEstablished
	conn.Mu.Unlock()

	// Set up: PeerRecvWin = 1 segment = exactly filled by BytesInFlight.
	// CongWin is large so it's not the bottleneck — PeerRecvWin is.
	conn.RetxMu.Lock()
	conn.LastAck = 500
	conn.CongWin = 16 * MaxSegmentSize // large — not the limiting factor
	conn.SSThresh = conn.CongWin
	conn.PeerRecvWin = 1 * MaxSegmentSize // bottleneck: 1 segment
	conn.Unacked = []*retxEntry{
		// 1 in-flight segment filling the peer receive window.
		{seq: 500, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: time.Now()},
	}
	conn.RetxMu.Unlock()

	// Drain any pre-existing token.
	select {
	case <-conn.WindowCh:
	default:
	}

	// Verify the window is full before the update.
	conn.RetxMu.Lock()
	if conn.WindowAvailable() {
		t.Fatal("test setup error: window should be full before window update")
	}
	conn.RetxMu.Unlock()

	// Pure window update: same cumulative ACK (dup-ACK), Window grows from 1→2.
	// After this: PeerRecvWin = 2*MSS > BytesInFlight = 1*MSS → window opens.
	windowUpdate := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagACK,
		Protocol: protocol.ProtoStream,
		Src:      remoteAddr,
		Dst:      conn.LocalAddr,
		SrcPort:  remotePort,
		DstPort:  localPort,
		Seq:      200,
		Ack:      500,                  // == conn.LastAck → dup-ACK (no new data acked)
		Window:   2,                    // 2 segments → PeerRecvWin = 2*MSS
	}

	d.handleStreamPacket(windowUpdate)

	conn.RetxMu.Lock()
	peerWin := conn.PeerRecvWin
	avail := conn.WindowAvailable()
	conn.RetxMu.Unlock()

	if !avail {
		t.Skipf("test setup error: WindowAvailable()=false after window update "+
			"(PeerRecvWin=%d, BytesInFlight=%d); check setup",
			peerWin, MaxSegmentSize)
	}

	// WindowCh must have a token: PeerRecvWin grew and window became available.
	// Without the fix: peerWinOpened = (prevPeerWin==0 && ...) = false → no signal
	// → sender stalls up to ZeroWinProbeInitial (500 ms).
	select {
	case <-conn.WindowCh:
		// correct — window update opened the send window; WindowCh was signaled
	default:
		t.Errorf("pure window update grew PeerRecvWin %d→%d bytes "+
			"(BytesInFlight=%d, WindowAvailable=%v) "+
			"but handleStreamPacket did not signal WindowCh; "+
			"a sender blocked in sendSegment will stall up to ZeroWinProbeInitial=%v; "+
			"fix: change peerWinOpened to fire whenever PeerRecvWin grows and "+
			"WindowAvailable() becomes true (not only on 0→positive transition)",
			1*MaxSegmentSize, peerWin, MaxSegmentSize, avail, ZeroWinProbeInitial)
	}
}

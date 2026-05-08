// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon_test

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestZeroWindowAdvertisementNotHonored verifies that when the peer advertises
// a receive window of zero (pkt.Window = 0), WindowAvailable returns false and
// the effective send window is zero — preventing the sender from transmitting
// new data until the peer opens its window.
//
// Bug (pre-v1.9.1): EffectiveWindow() guards the PeerRecvWin cap with:
//
//	if c.PeerRecvWin > 0 && c.PeerRecvWin < win {
//	    win = c.PeerRecvWin
//	}
//
// NewConnection zero-initializes PeerRecvWin (Go default int value = 0).  The
// intent is that 0 means "no window advertisement received yet — don't cap the
// window."  However, when the peer explicitly advertises Window=0 (zero-window
// flow control), handleStreamPacket sets:
//
//	conn.PeerRecvWin = int(pkt.Window) * MaxSegmentSize  // = 0
//
// The guard then reads PeerRecvWin=0 and concludes "not received" — the same
// sentinel — so EffectiveWindow returns CongWin unchanged.  WindowAvailable()
// returns true, and the sender is free to transmit data the peer cannot buffer.
//
// Consequence: zero-window flow control is completely broken.  The sender ignores
// the peer's explicit stop signal and keeps pumping data; the peer drops every
// segment, and loss-recovery amplifies the traffic storm until timeouts
// (RFC 6429 calls this a TCP persist-timer violation when sustained).
//
// Fix (v1.9.1): use -1 as the "not yet received" sentinel for PeerRecvWin:
//   - NewConnection initializes PeerRecvWin to -1.
//   - EffectiveWindow changes the guard to c.PeerRecvWin >= 0 so that
//     PeerRecvWin==0 is correctly treated as an explicit zero-window
//     advertisement that caps the effective window to zero.
//
// GREEN assertion: after setting conn.PeerRecvWin=0 (explicit zero-window),
// WindowAvailable() returns false.  Against unpatched code it returns true
// because the c.PeerRecvWin > 0 guard treats 0 as "not received."
func TestZeroWindowAdvertisementNotHonored(t *testing.T) {
	t.Parallel()
	pm := daemon.NewPortManager()
	conn := pm.NewConnection(7050, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	conn.RetxMu.Lock()
	// Simulate peer sending Window=0: handleStreamPacket sets
	// PeerRecvWin = int(pkt.Window) * MaxSegmentSize = 0
	conn.PeerRecvWin = 0
	conn.CongWin = daemon.InitialCongWin // plenty of congestion window
	available := conn.WindowAvailable()
	conn.RetxMu.Unlock()

	// FIXED: EffectiveWindow must cap to PeerRecvWin=0 → WindowAvailable=false.
	// FAILS against unpatched code: PeerRecvWin>0 guard treats 0 as "unknown",
	// EffectiveWindow returns CongWin=InitialCongWin, WindowAvailable=true.
	if available {
		t.Errorf("zero-window advertisement not honored: WindowAvailable()=true "+
			"when PeerRecvWin=0 (peer sent Window=0); "+
			"EffectiveWindow() guard 'c.PeerRecvWin > 0' treats 0 as the "+
			"uninitialized/unknown sentinel, so an explicit zero-window "+
			"advertisement is silently ignored and the sender is allowed to "+
			"transmit data that the peer has no buffer space to accept; "+
			"fix: initialize PeerRecvWin to -1 in NewConnection and change "+
			"the guard to c.PeerRecvWin >= 0")
	}
}

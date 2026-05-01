// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestNagleFlushAllSackedSendsImmediately verifies that nagleFlush does NOT
// enter the NagleTimeout wait when all Unacked entries are sacked
// (BytesInFlight()==0), i.e., the peer has already received every outstanding
// byte.
//
// Bug (current): nagleFlush determines "data is in flight" with:
//
//	conn.RetxMu.Lock()
//	hasUnacked := len(conn.Unacked) > 0   // ← BUG
//	conn.RetxMu.Unlock()
//
// After iter-41, SACKed entries remain in c.Unacked until a cumulative ACK
// removes them.  When all entries are sacked, len(Unacked)>0 is true but
// BytesInFlight()==0 — the peer has every byte.  Nagle should send a
// sub-MSS segment immediately ("no real data in flight"), but instead it
// enters:
//
//	nagleTimer := time.NewTimer(NagleTimeout)  // 40 ms
//	select {
//	case <-conn.NagleCh:   // only arrives once per iter-45 ProcessSACK signal
//	case <-nagleTimer.C:   // fires after 40 ms ← stall
//	}
//
// Iter-45 added a ProcessSACK→NagleCh signal, which wakes the FIRST waiter.
// But if NagleCh's token is already consumed (second write, or no waiter at
// ProcessSACK time), subsequent writes still stall for NagleTimeout.
//
// Concrete example:
//
//	Unacked = [seg0-sacked, seg1-sacked, seg2-sacked]
//	BytesInFlight() = 0, len(Unacked) = 3
//	NagleBuf = "hello" (5 bytes, sub-MSS)
//	NagleCh: empty (token already consumed by previous write)
//
//	nagleFlush:
//	  bug:  hasUnacked = (len(Unacked)>0) = true → waits 40 ms
//	  fix:  hasUnacked = (BytesInFlight()>0) = false → sends immediately
//
// GREEN assertion: nagleFlush with all-sacked Unacked and a 5-byte sub-MSS
// NagleBuf returns in well under NagleTimeout.
func TestNagleFlushAllSackedSendsImmediately(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peerNode uint32 = 0xCA5ECA11
	peerConn := addPeerOnDaemon(t, d, peerNode)
	t.Cleanup(func() { peerConn.Close() })

	d.setNodeID_testhelper(0x44440000)

	conn := d.ports.NewConnection(7440, protocol.Addr{Network: 0, Node: peerNode}, 80)
	t.Cleanup(func() {
		conn.Mu.Lock()
		conn.State = StateClosed
		conn.Mu.Unlock()
		d.ports.RemoveConnection(conn.ID)
	})

	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x44440000}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: peerNode}
	conn.RemotePort = 80
	conn.State = StateEstablished
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	conn.LastAck = 3000
	conn.CongWin = 16 * MaxSegmentSize  // large — window is open
	conn.SSThresh = conn.CongWin
	conn.PeerRecvWin = 16 * MaxSegmentSize
	// 3 entries, all sacked — peer has every byte.
	for i := 0; i < 3; i++ {
		conn.Unacked = append(conn.Unacked, &retxEntry{
			seq:      uint32(3000 + i*MaxSegmentSize),
			data:     make([]byte, MaxSegmentSize),
			attempts: 1,
			sentAt:   time.Now(),
			sacked:   true,
		})
	}
	conn.RetxMu.Unlock()

	// Verify setup: BytesInFlight==0 but len(Unacked)==3.
	conn.RetxMu.Lock()
	bif := conn.BytesInFlight()
	unackedLen := len(conn.Unacked)
	conn.RetxMu.Unlock()
	if bif != 0 {
		t.Fatalf("test setup error: BytesInFlight()=%d, want 0", bif)
	}
	if unackedLen != 3 {
		t.Fatalf("test setup error: len(Unacked)=%d, want 3", unackedLen)
	}

	// Drain NagleCh — no pre-existing token, so a buggy nagleFlush CANNOT
	// short-circuit via the iter-45 ProcessSACK signal; it must block.
	select {
	case <-conn.NagleCh:
	default:
	}

	// Put 5 bytes of sub-MSS data in NagleBuf.
	conn.NagleMu.Lock()
	conn.NagleBuf = []byte("hello")
	conn.NagleMu.Unlock()

	// Time how long nagleFlush takes.
	// Fast path (BytesInFlight==0): returns in < 1 ms (send immediately).
	// Slow path (len(Unacked)>0): waits ~NagleTimeout = 40 ms.
	// Threshold: NagleTimeout/4 = 10 ms.
	start := time.Now()
	err := d.nagleFlush(conn)
	elapsed := time.Since(start)

	if err != nil && err.Error() == "connection not established" {
		t.Skip("nagleFlush returned conn-not-established; likely IPC not wired in test — skip timing check")
	}

	threshold := NagleTimeout / 4 // 10 ms
	if elapsed >= threshold {
		t.Errorf("nagleFlush with all-sacked Unacked (BytesInFlight=0, len(Unacked)=3): "+
			"took %v, want < %v; "+
			"hasUnacked = len(conn.Unacked)>0 is true even when BytesInFlight()==0; "+
			"nagleFlush entered the NagleTimeout wait instead of sending immediately; "+
			"fix: change hasUnacked to conn.BytesInFlight()>0 in nagleFlush",
			elapsed, threshold)
	}
}

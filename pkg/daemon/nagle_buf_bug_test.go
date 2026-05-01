// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestSendDataNagleBufGrowsUnbounded reproduces the NagleBuf-OOM bug.
//
// Symptom (theoretical, observed-once-and-cleared in pilot service-agent
// memory profiling): an application that calls SendData faster than the
// network can drain (slow peer, packet loss, full cwnd) accumulates the
// unsent bytes in conn.NagleBuf without bound. There is currently NO
// per-connection send-buffer cap. With many connections in this state,
// daemon RSS climbs linearly with offered-but-undeliverable load until
// the host OOM-kills the process.
//
// Reproducer: a real UDP peer is reachable but never ACKs anything, so
// the daemon's cwnd fills after IW10 (10 × 4 KB = 40 KB). The 11th
// MSS-sized chunk's sendSegment call blocks waiting for cwnd to open
// (which it never will). The single goroutine calling SendData is
// stuck in nagleFlush; meanwhile, the data slice the application
// passed (5 MiB here) sits in conn.NagleBuf, well over any reasonable
// memory budget. Multiple writers would amplify this further.
//
// What v1.9.1's NagleBuf cap fix will change:
//   - introduce MaxNagleBuf = 8 * MaxSegmentSize (32 KB)
//   - SendData returns ErrSendBufFull when len(NagleBuf) + len(data) > MaxNagleBuf
//   - test assertion flips: NagleBuf plateaus at MaxNagleBuf;
//     SendData returns ErrSendBufFull on the oversized write.
//
// This test pins CURRENT (buggy) behavior so the cap patch has a
// concrete regression target. After the fix, the bug-asserting block
// below is replaced with the post-fix block (already drafted in
// comments).
func TestSendDataNagleBufGrowsUnbounded(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peerNode uint32 = 0xBA5EBA11
	peerConn := addPeerOnDaemon(t, d, peerNode)
	t.Cleanup(func() { peerConn.Close() })

	d.setNodeID_testhelper(0x33330000)

	// Build a Connection in StateEstablished, wired to the peer. We
	// don't go through DialConnection; constructing directly keeps the
	// test fast and deterministic.
	conn := d.ports.NewConnection(40000, protocol.Addr{Network: 0, Node: peerNode}, 80)
	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x33330000}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: peerNode}
	conn.RemotePort = 80
	conn.State = StateEstablished
	conn.PeerRecvWin = 1 << 20 // advertise 1 MB receive window so cwnd is the binding constraint
	conn.Mu.Unlock()

	// Kick off a 5 MiB write in a goroutine. It'll block in nagleFlush →
	// sendSegment after IW10 (10 segments × 4 KB MSS = 40 KB) when cwnd
	// fills up with no incoming ACKs to retire.
	const payloadSize = 5 * 1024 * 1024
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	done := make(chan error, 1)
	go func() { done <- d.SendData(conn, payload) }()

	// Give nagleFlush time to push the initial cwnd of segments and
	// block on the next sendSegment call.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn.NagleMu.Lock()
		bufLen := len(conn.NagleBuf)
		conn.NagleMu.Unlock()
		// Once the buffer has more than 1 MiB queued, we've reproduced
		// the unbounded-growth condition.
		if bufLen > 1<<20 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	conn.NagleMu.Lock()
	bufLen := len(conn.NagleBuf)
	conn.NagleMu.Unlock()

	// CURRENT BUG: NagleBuf holds nearly all 5 MiB minus the cwnd that
	// already went out. There is no cap.
	if bufLen <= 1<<20 {
		t.Errorf("expected NagleBuf > 1 MiB (current bug — no cap); got %d bytes", bufLen)
	}

	// POST-FIX: replace the assertion above with
	//   if bufLen > MaxNagleBuf {
	//       t.Errorf("NagleBuf exceeded cap %d; got %d", MaxNagleBuf, bufLen)
	//   }
	// And add a follow-up assertion that SendData returned
	// ErrSendBufFull on the original oversized write:
	//   select {
	//   case err := <-done:
	//       if !errors.Is(err, ErrSendBufFull) {
	//           t.Errorf("expected ErrSendBufFull on oversized write; got %v", err)
	//       }
	//   case <-time.After(500 * time.Millisecond):
	//       t.Errorf("SendData did not return within 500 ms after cap rejection")
	//   }

	// Cleanup: tear down the goroutine. The simplest abort path is to
	// close the tunnels (writes in nagleFlush will fail) and remove
	// the connection. The goroutine returns within ~1 RTO check tick.
	d.tunnels.Close()
	conn.Mu.Lock()
	conn.State = StateClosed
	conn.Mu.Unlock()
	d.ports.RemoveConnection(conn.ID)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Log("SendData goroutine did not exit cleanly within 5s — may need a stronger abort path; this is OK for the bug-pin test")
	}
}

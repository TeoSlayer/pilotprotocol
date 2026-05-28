// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"

	"github.com/pilot-protocol/common/protocol"
)

// TestSendSegmentTunnelErrorLosesData verifies that a segment whose tunnel
// send fails is still tracked in Unacked so the retransmit loop can retry it.
//
// Bug (post-v1.9.0 / introduced in iter-23): sendSegment pre-increments
// conn.SendSeq inside conn.Mu (the iter-23 fix for duplicate seq numbers), but
// calls conn.TrackSend AFTER d.tunnels.Send:
//
//	conn.Mu.Lock()
//	seq := conn.SendSeq
//	conn.SendSeq += uint32(len(data))   // seq slot reserved here
//	conn.Mu.Unlock()
//	pkt := ...
//	if err := d.tunnels.Send(...); err != nil {
//	    return err                        // ← early return, TrackSend never called
//	}
//	conn.TrackSend(seq, data)            // ← only reached on success
//
// When d.tunnels.Send fails (e.g. peer removed from tunnel map, key-exchange
// queue full, UDP write error), the sequence slot is consumed but the segment
// is absent from conn.Unacked.  Consequences:
//
//  1. The data is permanently gone — retxLoop never retransmits it because it
//     has no entry to retry.
//  2. conn.SendSeq has advanced past the gap; all subsequent segments arrive
//     out-of-order at the peer, which is waiting for the missing seq.
//  3. The peer's OOO buffer fills up (MaxOOOBuf = 128 segments) and subsequent
//     out-of-order segments start being dropped.  The connection is silently
//     corrupted.
//
// Fix (v1.9.1): call conn.TrackSend(seq, data) BEFORE d.tunnels.Send.
// If Send fails, the entry is already in Unacked; retxLoop will retry until
// the tunnel recovers or MaxRetxAttempts is exceeded (clean abort via RST).
// If Send succeeds, Unacked is populated exactly as before.
//
// GREEN assertion: after sendSegment returns a tunnel error, conn.Unacked
// contains the segment entry.  Against unpatched code, Unacked is empty.
func TestSendSegmentTunnelErrorLosesData(t *testing.T) {
	t.Parallel()
	// Create a daemon with NO peer registered for the target node.
	// d.tunnels.Send will return "no tunnel to node X" immediately —
	// the tunnel map check fires before any socket I/O.
	d := New(Config{})

	const remoteNode = uint32(0xDEAD0001)
	conn := d.ports.NewConnection(7100, protocol.Addr{Network: 0, Node: remoteNode}, 80)
	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0xCAFE0001}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: remoteNode}
	conn.State = StateEstablished
	conn.SendSeq = 1000
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

	data := make([]byte, 64)

	err := d.sendSegment(conn, data)
	if err == nil {
		// Test setup assumption: no peer → Send should fail.
		// If Send somehow succeeded, the test is invalid.
		t.Skip("sendSegment succeeded (unexpected); test requires a tunnel-send failure")
	}

	// The error is expected — what we care about is whether TrackSend was called.
	conn.RetxMu.Lock()
	unackedLen := len(conn.Unacked)
	conn.RetxMu.Unlock()

	// FIXED: TrackSend is called before tunnels.Send so the segment survives
	// a transient send failure and can be retried by retxLoop.
	if unackedLen == 0 {
		conn.Mu.Lock()
		finalSeq := conn.SendSeq
		conn.Mu.Unlock()
		t.Errorf("sendSegment error path: seq slot consumed (SendSeq advanced to %d) "+
			"but segment not tracked in Unacked — data permanently lost on tunnel failure; "+
			"subsequent sends advance SendSeq past the gap, corrupting the connection "+
			"sequence stream at the peer; "+
			"fix: call conn.TrackSend(seq, data) before d.tunnels.Send(...) so "+
			"retxLoop can retry the undelivered segment",
			finalSeq)
	}
}

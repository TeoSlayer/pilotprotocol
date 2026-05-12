// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestKeepaliveDeadPeerSendsFinNotRst is the regression test for the
// keepalive-reaper RST-poisoning bug.
//
// Pre-fix behaviour:
//
//	Once a connection's KeepaliveUnacked counter reached 3, keepaliveSweep
//	constructed a raw RST packet inline, sent it to the peer, and set the
//	connection state to StateClosed. The RST poisoned the peer's session
//	table for that conn_id — when the peer's next dial attempted to reach
//	us, it raced with the tombstone of the just-RST'd session and got
//	"dial: connection refused". A burst of N successful sends → N idle
//	established connections → N simultaneous RSTs once the keepalive
//	threshold hit. Observed fleet-wide:
//
//	  time=2026-05-11T23:26:08.711Z level=WARN
//	    msg="dead peer detected (3 keepalives unanswered), sending RST"
//	    conn_id=5142 remote_addr=0:0000.0002.D9EB remote_port=49156
//	  (×5 more, simultaneous)
//
// Post-fix behaviour:
//
//	The reaper calls CloseConnection(), which sends a proper FIN with
//	retx tracking and transitions the conn to StateFinWait. The peer's
//	daemon handles the FIN cleanly (FIN-ACK → StateTimeWait → reap),
//	no poisoning.
//
// What we assert:
//
//  1. Exactly ONE packet leaves the daemon for this connection's reap
//     event.
//  2. That packet has FlagFIN set.
//  3. That packet does NOT have FlagRST set.
//  4. The connection's State transitions to StateFinWait (CloseConnection's
//     end state), NOT StateClosed (the pre-fix end state).
func TestKeepaliveDeadPeerSendsFinNotRst(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	peerConn := addPeerOnDaemon(t, d, 0xAABBCCDD)
	t.Cleanup(func() { peerConn.Close() })

	conn := d.ports.NewConnection(
		1001,
		protocol.Addr{Network: 0, Node: 0xAABBCCDD},
		49156,
	)
	t.Cleanup(func() { d.ports.RemoveConnection(conn.ID) })

	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x11111111}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: 0xAABBCCDD}
	conn.State = StateEstablished
	conn.SendSeq = 1000
	conn.RecvAck = 2000
	// Force this conn to look idle past any reasonable keepalive interval
	// AND simulate that 3 prior probes already went unanswered. This is
	// the exact precondition the reaper trips on.
	conn.LastActivity = time.Now().Add(-2 * time.Hour)
	conn.KeepaliveUnacked = 3
	conn.Mu.Unlock()

	// Drive a single sweep with a very short interval — the conn is
	// hours-stale so it qualifies regardless of interval.
	d.keepaliveSweep(1 * time.Second)

	pkt := recvPacket(t, peerConn, 250*time.Millisecond)
	if pkt == nil {
		t.Fatal("expected daemon to emit a packet after keepalive-reap; got none")
	}
	if pkt.HasFlag(protocol.FlagRST) {
		t.Fatalf("REGRESSION: keepalive reaper emitted RST (pre-fix behaviour). "+
			"Got pkt with flags=0x%02x (RST set). Should be FIN.", pkt.Flags)
	}
	if !pkt.HasFlag(protocol.FlagFIN) {
		t.Fatalf("expected FIN flag set on reap packet; got flags=0x%02x", pkt.Flags)
	}

	conn.Mu.Lock()
	endState := conn.State
	conn.Mu.Unlock()
	if endState == StateClosed {
		t.Fatalf("REGRESSION: keepalive reaper transitioned conn to StateClosed " +
			"(pre-fix behaviour). CloseConnection's FIN path should leave us in StateFinWait.")
	}
	if endState != StateFinWait {
		t.Fatalf("expected StateFinWait after reap; got %v", endState)
	}
}

// TestKeepaliveBudgetNotExhaustedSendsProbe verifies the OTHER branch of
// the reaper: when KeepaliveUnacked is below 3, the reaper increments the
// counter and emits a probe packet (FlagACK only, no FIN, no RST). This
// is the "still alive, just confirming" path that should not be perturbed
// by the FIN-instead-of-RST change.
func TestKeepaliveBudgetNotExhaustedSendsProbe(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	peerConn := addPeerOnDaemon(t, d, 0xDEAD0001)
	t.Cleanup(func() { peerConn.Close() })

	conn := d.ports.NewConnection(
		2001,
		protocol.Addr{Network: 0, Node: 0xDEAD0001},
		50000,
	)
	t.Cleanup(func() { d.ports.RemoveConnection(conn.ID) })

	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x22222222}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: 0xDEAD0001}
	conn.State = StateEstablished
	conn.SendSeq = 500
	conn.RecvAck = 600
	conn.LastActivity = time.Now().Add(-2 * time.Hour)
	conn.KeepaliveUnacked = 1 // below threshold
	conn.Mu.Unlock()

	d.keepaliveSweep(1 * time.Second)

	pkt := recvPacket(t, peerConn, 250*time.Millisecond)
	if pkt == nil {
		t.Fatal("expected daemon to emit a keepalive probe; got none")
	}
	if pkt.HasFlag(protocol.FlagRST) {
		t.Fatalf("budget not exhausted but reaper sent RST (flags=0x%02x)", pkt.Flags)
	}
	if pkt.HasFlag(protocol.FlagFIN) {
		t.Fatalf("budget not exhausted but reaper sent FIN (flags=0x%02x) — "+
			"FIN must only fire on exhaustion", pkt.Flags)
	}
	if !pkt.HasFlag(protocol.FlagACK) {
		t.Fatalf("probe should be FlagACK only; got flags=0x%02x", pkt.Flags)
	}

	// Counter should have been incremented from 1 → 2.
	conn.Mu.Lock()
	ka := conn.KeepaliveUnacked
	st := conn.State
	conn.Mu.Unlock()
	if ka != 2 {
		t.Fatalf("expected KeepaliveUnacked == 2 after probe; got %d", ka)
	}
	if st != StateEstablished {
		t.Fatalf("conn state should remain StateEstablished after probe; got %v", st)
	}
}

// TestKeepaliveSweepSkipsNonEstablishedConns verifies that the reaper
// does not touch connections that are NOT in StateEstablished. Pre-fix
// and post-fix, this branch should be a no-op.
func TestKeepaliveSweepSkipsNonEstablishedConns(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	peerConn := addPeerOnDaemon(t, d, 0xBEEF0001)
	t.Cleanup(func() { peerConn.Close() })

	for _, st := range []ConnState{StateSynSent, StateFinWait, StateTimeWait, StateClosed} {
		conn := d.ports.NewConnection(
			3001,
			protocol.Addr{Network: 0, Node: 0xBEEF0001},
			51000,
		)
		conn.Mu.Lock()
		conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x33333333}
		conn.RemoteAddr = protocol.Addr{Network: 0, Node: 0xBEEF0001}
		conn.State = st
		conn.LastActivity = time.Now().Add(-2 * time.Hour)
		conn.KeepaliveUnacked = 5 // would trigger reaper if state were Established
		conn.Mu.Unlock()

		d.keepaliveSweep(1 * time.Second)

		if pkt := recvPacket(t, peerConn, 100*time.Millisecond); pkt != nil {
			t.Errorf("state=%v: expected no packet from non-Established conn; got flags=0x%02x",
				st, pkt.Flags)
		}
		d.ports.RemoveConnection(conn.ID)
	}
}

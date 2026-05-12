// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

// Regression tests for the keepalive-reaper RST-poisoning bug
// observed fleet-wide on 2026-05-11.
//
// Pre-fix: when a connection's KeepaliveUnacked counter hit 3, the
// keepalive loop in idleSweepLoop constructed a raw RST packet inline,
// sent it to the peer, and forced the connection to StateClosed. The
// RST poisoned the peer's session table for that conn_id — when the
// peer's next dial attempted to reach us it raced with the tombstone
// of the just-RST'd session and got "dial: connection refused". The
// observable pattern: a burst of N successful sends produces N idle
// established connections; once the keepalive threshold trips for any
// of them, an RST goes out and the peer's next outbound to us starts
// failing. Fleet-wide manifestation: rendezvous "relay dest not found"
// flood from agents whose queued packets pointed at clients we'd just
// RST-poisoned.
//
// Post-fix: the reaper calls CloseConnection(), which sends a proper
// FIN with retx tracking and transitions the conn to StateFinWait.
// The peer handles the FIN cleanly (FIN-ACK → StateTimeWait → reap),
// no session-table tombstone race.

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestKeepaliveDeadPeerSendsFinNotRst is the smoking-gun regression:
// when KeepaliveUnacked >= 3 the reaper must emit a FIN (clean close)
// rather than an RST (poison). The conn must end in StateFinWait, not
// StateClosed.
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
	// hours-stale so it qualifies regardless.
	d.keepaliveSweep(1 * time.Second)

	pkt := recvPacket(t, peerConn, 250*time.Millisecond)
	if pkt == nil {
		t.Fatal("expected daemon to emit a packet after keepalive-reap; got none")
	}
	if pkt.HasFlag(protocol.FlagRST) {
		t.Fatalf("REGRESSION: keepalive reaper emitted RST (pre-fix behaviour). "+
			"Got pkt with flags=0x%02x. Should be FIN — RST poisons the peer's "+
			"session table and breaks subsequent dials.", pkt.Flags)
	}
	if !pkt.HasFlag(protocol.FlagFIN) {
		t.Fatalf("expected FIN flag set on reap packet; got flags=0x%02x", pkt.Flags)
	}

	conn.Mu.Lock()
	endState := conn.State
	conn.Mu.Unlock()
	if endState == StateClosed {
		t.Fatalf("REGRESSION: keepalive reaper transitioned conn to StateClosed " +
			"(pre-fix end state). CloseConnection's FIN path leaves us in StateFinWait.")
	}
	if endState != StateFinWait {
		t.Fatalf("expected StateFinWait after reap; got %v", endState)
	}
}

// TestKeepaliveBudgetNotExhaustedSendsProbe pins the OTHER branch of
// the reaper: when KeepaliveUnacked is below 3, the sweep increments
// the counter and emits a probe packet (FlagACK only, no FIN, no RST).
// This is the steady-state "still alive, just confirming" path that
// must not be perturbed by the FIN-instead-of-RST change. It also
// doubles as a NAT-keepalive (bumps the consumer-NAT idle timer for
// our external mapping).
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

// TestKeepaliveSweepSkipsNonEstablishedConns pins the early-return:
// connections in any state other than StateEstablished must be left
// alone by the reaper. Pre-fix and post-fix this branch is a no-op,
// but pin it so a future refactor can't quietly start RST'ing or
// FIN'ing a SynSent / FinWait / TimeWait / Closed conn.
func TestKeepaliveSweepSkipsNonEstablishedConns(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	peerConn := addPeerOnDaemon(t, d, 0xBEEF0001)
	t.Cleanup(func() { peerConn.Close() })

	for _, st := range []ConnState{StateSynSent, StateFinWait, StateTimeWait, StateClosed} {
		st := st
		t.Run(st.String(), func(t *testing.T) {
			conn := d.ports.NewConnection(
				3001,
				protocol.Addr{Network: 0, Node: 0xBEEF0001},
				51000,
			)
			t.Cleanup(func() { d.ports.RemoveConnection(conn.ID) })

			conn.Mu.Lock()
			conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x33333333}
			conn.RemoteAddr = protocol.Addr{Network: 0, Node: 0xBEEF0001}
			conn.State = st
			conn.LastActivity = time.Now().Add(-2 * time.Hour)
			conn.KeepaliveUnacked = 3 // would trip in StateEstablished
			conn.Mu.Unlock()

			d.keepaliveSweep(1 * time.Second)

			if pkt := recvPacket(t, peerConn, 50*time.Millisecond); pkt != nil {
				t.Fatalf("non-established conn (state=%v) should not produce any packet from reaper; got flags=0x%02x",
					st, pkt.Flags)
			}
		})
	}
}

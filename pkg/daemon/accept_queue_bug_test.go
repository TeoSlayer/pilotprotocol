// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestSYNDropOnFullAcceptCqueueIsInvisible reproduces the
// "accept-queue overflow has no operator-visible signal" bug.
//
// Symptom: when a Listener's AcceptCh is full (the application is slow
// to call Accept and the queue has filled to AcceptQueueLen=64), the
// SYN handler at pkg/daemon/daemon.go:1841 currently:
//
//  1. Sends the SYN-ACK back to the dialer
//  2. Marks the connection StateEstablished
//  3. Tries to push to AcceptCh
//  4. On full: hits the `default` branch, sends a RST, removes the
//     Connection, logs WARN
//
// The RST is good — peer learns immediately. But:
//   - No Daemon-level counter is incremented (no AcceptQueueDrops)
//   - No webhook event is emitted (operators have no programmatic
//     way to detect this is happening)
//   - The connection.established + connection.rst webhook pair fires
//     for a connection that never reached the application — looks
//     like a peer-initiated abort, not a queue overflow
//
// Real-world impact: an application that is GC-paused, blocked, or
// just slow to Accept silently loses inbound connections. The dialer
// sees "connection refused" / RST and gives up. The receiving daemon
// has no metric or event for the operator to discover. The first
// signal of trouble is users complaining their connections fail.
//
// What v1.9.1's fix should change:
//   - Add `AcceptQueueDrops uint64` counter on Daemon, increment on
//     every accept-queue overflow drop (atomic.AddUint64).
//   - Emit a `conn.accept_queue_full` webhook event with port,
//     src_addr, drops_total — operators can wire this to a paging
//     channel or autoscale signal.
//
// FIXED (v1.9.1): the overflow branch now increments AcceptQueueDrops
// atomically and emits a `conn.accept_queue_full` webhook with the
// dst port, src addr/port, and the drop counter total. Operators can
// scrape the counter for autoscaling signals or wire the webhook to
// paging.
func TestSYNDropOnFullAcceptQueueIsInvisible(t *testing.T) {
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD0010)

	const dstPort uint16 = 8080
	ln, err := d.ports.Bind(dstPort)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	// Pre-fill AcceptCh to capacity. We push raw nil/sentinel pointers —
	// the test never drains, so the queue stays at capacity for the
	// duration of the test.
	for i := 0; i < AcceptQueueLen; i++ {
		ln.AcceptCh <- &Connection{} // nil-effective sentinel
	}

	syn := newStreamSYNPkt(peerNode, d.NodeID(), 7777, dstPort, 100)
	d.handleStreamPacket(syn)

	// The SYN handler did its full work (SYN-ACK sent, then RST on full).
	// Drain whatever the peer received — we just want to confirm the RST
	// path fired, but we don't care which order they appear.
	sawRST := false
	for {
		pkt := readPacket(t, peerConn, 100*time.Millisecond)
		if pkt == nil {
			break
		}
		if pkt.HasFlag(protocol.FlagRST) {
			sawRST = true
		}
	}
	if !sawRST {
		t.Fatalf("expected RST on peer socket after AcceptCh-full drop")
	}

	// FIXED: counter increments to 1 on the single overflow drop.
	got := atomic.LoadUint64(&d.AcceptQueueDrops)
	if got != 1 {
		t.Errorf("expected AcceptQueueDrops=1 after one overflow drop; got %d", got)
	}
}

// TestAcceptQueueDropsAggregateAcrossSYNs pins that successive
// overflow drops accumulate — counter is monotonic, not reset per SYN.
// Operators querying it should see the total drops since daemon start.
func TestAcceptQueueDropsAggregateAcrossSYNs(t *testing.T) {
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD0011)

	const dstPort uint16 = 8081
	ln, err := d.ports.Bind(dstPort)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	for i := 0; i < AcceptQueueLen; i++ {
		ln.AcceptCh <- &Connection{}
	}

	// Drive 3 distinct SYNs (different src ports → distinct 4-tuples,
	// not retransmits) and observe the counter climb.
	for i := uint16(0); i < 3; i++ {
		syn := newStreamSYNPkt(peerNode, d.NodeID(), 7000+i, dstPort, 100+uint32(i))
		d.handleStreamPacket(syn)
	}
	// Drain whatever the peer received.
	for {
		if pkt := readPacket(t, peerConn, 50*time.Millisecond); pkt == nil {
			break
		}
	}

	got := atomic.LoadUint64(&d.AcceptQueueDrops)
	if got != 3 {
		t.Errorf("expected AcceptQueueDrops=3 after three overflow drops; got %d", got)
	}
}

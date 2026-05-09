// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestDialContextPreCancelledStillSendsSYN reproduces the
// "dial ignores ctx until after the SYN is on the wire" bug.
//
// Symptom: DialConnectionContext (introduced in iter 2) was meant to
// give callers a way to abort an in-flight dial. The retry loop
// correctly selects on ctx.Done. BUT the path BEFORE the loop —
// ensureTunnel + port alloc + initial SYN send — does NOT check
// ctx at all. With a context that's already cancelled (e.g., the
// IPC client disconnected before the daemon picked up its dial
// request, or an upstream timeout fired during request queueing),
// the daemon still:
//
//  1. Calls ensureTunnel (potentially up to 30 s blocked on a slow registry)
//  2. Allocates an ephemeral port
//  3. Creates a Connection in StateSynSent
//  4. Sends a SYN over the tunnel to the peer
//
// Only AFTER all of that does the for-loop's ctx.Done case fire.
// The peer received a phantom SYN they'll respond to (SYN-ACK)
// for a connection the dialer already abandoned. Wasted bandwidth,
// log noise on both sides, peer-side retx of the SYN-ACK that
// nobody is listening for.
//
// Real-world impact:
//   - Cron-bursty IPC clients that connect, queue many dials,
//     then disconnect → daemon emits a SYN per dial regardless.
//   - Application-level timeouts (e.g., http.Client) firing
//     during a slow registry resolve → caller cancels but daemon
//     still sends the SYN once registry returns.
//
// What v1.9.1's fix should change: at the top of
// dialConnectionLocked, check ctx.Err() before any side-effecting
// work. If already cancelled, return ctx.Err() immediately.
//
// FIXED (v1.9.1): dialConnectionLocked checks ctx.Err() at the top,
// before any side-effecting work. A pre-cancelled ctx returns
// context.Canceled immediately with NO wire traffic — peer's UDP
// socket stays silent, no Connection is created, no port is
// allocated.
func TestDialContextPreCancelledStillSendsSYN(t *testing.T) {
	t.Parallel()
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD0050)

	// Drain whatever any setup steps emitted on peerConn — we want a
	// clean slate to detect the SYN.
	for {
		_ = peerConn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		buf := make([]byte, 2048)
		if _, _, err := peerConn.ReadFromUDP(buf); err != nil {
			break
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel: the dial should bail before any side-effect

	conn, err := d.DialConnectionContext(ctx,
		protocol.Addr{Network: 0, Node: peerNode}, 8080)

	if conn != nil {
		t.Errorf("expected conn=nil on pre-cancelled ctx; got %+v", conn)
		d.CloseConnection(conn)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled error; got %v", err)
	}

	// FIXED: peer's UDP socket stays silent. No SYN was emitted
	// because ctx.Err() short-circuited dialConnectionLocked before
	// any wire-side work.
	pkt := readPacket(t, peerConn, 100*time.Millisecond)
	if pkt != nil {
		t.Errorf("expected no packet on peer socket after pre-cancelled dial; got flags=%d srcPort=%d",
			pkt.Flags, pkt.SrcPort)
	}

	// Also verify no Connection lingered in the daemon's port table.
	if cs := d.ports.AllConnections(); len(cs) != 0 {
		t.Errorf("expected no Connection allocated after pre-cancelled dial; got %d", len(cs))
	}
}

// TestDialContextPreCancelledReturnsCanceledError pins the half of
// the fix that's already in place via iter 2: a pre-cancelled ctx
// must surface context.Canceled (not e.g. dial-timeout or
// connection-refused). This invariant matters for upstream callers
// that distinguish user-cancellation from other dial failures.
func TestDialContextPreCancelledReturnsCanceledError(t *testing.T) {
	t.Parallel()
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})
	t.Cleanup(func() { peerConn.Close() })
	d.setNodeID_testhelper(0xABCD0051)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := d.DialConnectionContext(ctx,
		protocol.Addr{Network: 0, Node: peerNode}, 8080)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled; got %v", err)
	}

	// Sanity: the test compiles and the peerConn cleanup runs.
	_ = net.Conn(peerConn)
}

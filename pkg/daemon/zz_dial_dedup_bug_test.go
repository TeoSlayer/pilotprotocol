// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// TestDialConcurrentToSamePeerCreatesIndependentSynSent pins the
// BSD-socket semantics for concurrent dials to the same (peer, port):
// each call returns a fresh independent *Connection.
//
// History:
//   - v1.9.1 introduced a per-(peer, dst_port) dedup that returned the
//     SAME *Connection to every concurrent caller. This pinned the
//     "exactly 1 SYN_SENT" cosmetic improvement in `pilotctl info`
//     but broke fan-in correctness: 10 concurrent callers all
//     received the same conn-ID and their writes muxed into one stream,
//     producing JSON-decode errors on the receiver and indefinite
//     hangs on the senders (issue #105).
//   - Issue #105 reverted the dedup. Each Dial allocates its own
//     ephemeral port + SYN. The shared work that genuinely benefits
//     from per-peer dedup is the X25519 tunnel handshake, which is
//     already idempotent inside TunnelManager.
//
// Three concurrent DialConnectionContext calls to the same (peer, dport) MUST
// each end up in their own SYN_SENT entry. countSynSentTo == N.
func TestDialConcurrentToSamePeerCreatesIndependentSynSent(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peerNode uint32 = 0xCAFEBABE

	// Fake peer: real UDP socket so SYN packets land there, but nothing
	// reads them — no SYN-ACK comes back. We use a cancellable context so
	// teardown is O(ms) instead of grinding through the full retry budget
	// (~32 s with DialMaxRetries=7 at DialMaxRTO=8s).
	peerConn := addPeerOnDaemon(t, d, peerNode)
	t.Cleanup(func() { peerConn.Close() })

	d.setNodeID_testhelper(0x11110000)

	dst := protocol.Addr{Network: 0, Node: peerNode}
	const dport uint16 = 1001 // dataexchange port

	ctx, cancel := context.WithCancel(context.Background())

	const N = 3
	var wg sync.WaitGroup
	wg.Add(N)
	started := make(chan struct{}, N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			started <- struct{}{}
			_, _ = d.DialConnectionContext(ctx, dst, dport)
		}()
	}
	for i := 0; i < N; i++ {
		<-started
	}

	// Give each goroutine enough time to reach SYN_SENT.
	deadline := time.Now().Add(2 * time.Second)
	var synSentCount int
	for time.Now().Before(deadline) {
		synSentCount = countSynSentTo(d, peerNode)
		if synSentCount >= N {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Issue #105: BSD-socket semantics — each concurrent dial allocates
	// its own SYN_SENT entry. Without independent connections, fan-in
	// workloads (10 concurrent callers) collide on a single
	// conn-ID and the IPC driver's recvCh map sees their data muxed
	// together — see the concurrent dial test.
	if synSentCount != N {
		t.Errorf("expected %d independent SYN_SENT entries (one per Dial), got %d", N, synSentCount)
	}

	// Teardown: cancel the context so all dial goroutines exit within ~1 RTO check
	// tick (DialCheckInterval=10ms) instead of grinding through the full retry budget.
	cancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("dial goroutines did not exit within 2s of context cancel")
	}
}

// TestDialAbandonedGoroutineLeavesOrphanSynSent (post-fix) verifies the
// "Ctrl+C clears SYN_SENT immediately" property. The fix is a context
// parameter on DialConnectionContext: when the caller cancels (in
// production: when the IPC client disconnects), the dial loop's select
// hits ctx.Done(), removes the in-flight conn, and returns
// context.Canceled. No more orphans grinding through the 14-31 s
// retry budget.
//
// Pre-fix: this test asserted "orphan persists 5 s after caller
// abandoned". v1.9.1 commit on `v1.9.1-tunnel-reliability` flipped the
// assertion to expect the orphan gone within 200 ms.
func TestDialAbandonedGoroutineLeavesOrphanSynSent(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peerNode uint32 = 0xDEADBEEF
	peerConn := addPeerOnDaemon(t, d, peerNode)
	t.Cleanup(func() { peerConn.Close() })

	d.setNodeID_testhelper(0x22220000)

	dst := protocol.Addr{Network: 0, Node: peerNode}
	const dport uint16 = 1001

	// Cancellable context simulates the IPC handler's per-dial context.
	// In production, ipcConn.Close fires its registered cancels when
	// the client disconnects.
	ctx, cancel := context.WithCancel(context.Background())
	dialDone := make(chan error, 1)
	go func() {
		_, err := d.DialConnectionContext(ctx, dst, dport)
		dialDone <- err
	}()

	// Wait until the connection appears in SYN_SENT.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if countSynSentTo(d, peerNode) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if countSynSentTo(d, peerNode) != 1 {
		t.Fatalf("setup: expected 1 SYN_SENT after dial start; got %d",
			countSynSentTo(d, peerNode))
	}

	// FIXED: cancel the context. The dial loop's select must pick up
	// ctx.Done(), remove the conn from PortManager, and return
	// context.Canceled — all within ~1 RTO check tick (10 ms) plus a
	// generous slack budget. Pinning at 200 ms.
	cancel()
	deadline = time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if countSynSentTo(d, peerNode) == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := countSynSentTo(d, peerNode); got != 0 {
		t.Errorf("expected orphan SYN_SENT removed within 200 ms of cancel; got %d", got)
	}

	// And the goroutine itself should have returned context.Canceled.
	select {
	case err := <-dialDone:
		if err != context.Canceled {
			t.Errorf("dial goroutine returned %v, want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Errorf("dial goroutine did not exit within 500 ms of cancel")
	}
}

// countSynSentTo walks the daemon's connection table and counts entries
// to the given peer node that are in StateSynSent. Holds the table's
// read lock for the duration of the walk.
func countSynSentTo(d *Daemon, peerNode uint32) int {
	d.ports.mu.RLock()
	defer d.ports.mu.RUnlock()
	count := 0
	for _, c := range d.ports.connections {
		c.Mu.Lock()
		state := c.State
		remote := c.RemoteAddr.Node
		c.Mu.Unlock()
		if remote == peerNode && state == StateSynSent {
			count++
		}
	}
	return count
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestDialConcurrentToSamePeerCreatesIndependentSynSent reproduces the
// user-visible "3 SYN_SENT to the same peer" bug.
//
// Symptom (from `pilotctl info` after running send-message a few times in
// quick succession to a cold peer):
//
//	Active connections: 3
//	  ID  LOCAL  REMOTE ADDR             RPORT  STATE     CWND     FLIGHT
//	  13  49159  0:0000.0000.400E        1001   SYN_SENT  40.0 KB  0 B
//	  14  49160  0:0000.0000.400E        1001   SYN_SENT  40.0 KB  0 B
//	  15  49161  0:0000.0000.400E        1001   SYN_SENT  40.0 KB  0 B
//
// Three concurrent DialConnection calls to the same (peer, dport) each
// allocate their own connection, send their own SYN, and sit in SYN_SENT
// independently. None of them benefit from the others' work; none of them
// know the others exist. When the X25519 handshake-per-pair eventually
// completes (or all three retry budgets exhaust), you get N independent
// outcomes for what should have been one operation.
//
// What v1.9.1's dial-dedup fix will change (target post-fix assertion):
//   - synSentCount == 1   (only the first call drives the SYN)
//   - the other two callers park on the in-flight dial's done channel
//     and return the same *Connection (or share the same outcome)
//
// This test pins the CURRENT behavior so the dedup patch has a concrete
// regression target. After the patch lands, flip the assertion in the
// section marked POST-FIX so a future regression that re-introduces
// independent dials gets caught.
func TestDialConcurrentToSamePeerCreatesIndependentSynSent(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peerNode uint32 = 0xCAFEBABE

	// Fake peer: real UDP socket so SYN packets land there, but nothing
	// reads them — no SYN-ACK comes back, connections stay in SYN_SENT
	// until each dial-loop retry budget (~14–31 s) exhausts.
	peerConn := addPeerOnDaemon(t, d, peerNode)
	t.Cleanup(func() { peerConn.Close() })

	d.setNodeID_testhelper(0x11110000)

	dst := protocol.Addr{Network: 0, Node: peerNode}
	const dport uint16 = 1001 // dataexchange port

	const N = 3
	var wg sync.WaitGroup
	wg.Add(N)
	started := make(chan struct{}, N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			started <- struct{}{}
			// Best-effort dial; we don't care about the eventual return
			// value, only that all N goroutines reach SYN_SENT during
			// their retry loop. Goroutines drain on tunnel close in the
			// teardown below.
			_, _ = d.DialConnection(dst, dport)
		}()
	}
	for i := 0; i < N; i++ {
		<-started
	}

	// Give each goroutine enough time to reach SYN_SENT.
	// AllocEphemeralPort + NewConnection + first SYN send take
	// microseconds on local UDP; 200 ms is generous.
	deadline := time.Now().Add(2 * time.Second)
	var synSentCount int
	for time.Now().Before(deadline) {
		synSentCount = countSynSentTo(d, peerNode)
		if synSentCount >= N {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// FIXED (v1.9.1): the dialFlight sync.Map deduplicates concurrent
	// dials to the same (peer, dport). The first caller drives the SYN;
	// the other N-1 park on its done channel. Exactly 1 SYN_SENT is
	// outstanding regardless of how many goroutines called Dial.
	if synSentCount != 1 {
		t.Errorf("expected dedup → exactly 1 SYN_SENT in flight (v1.9.1 dialFlight map), got %d", synSentCount)
	}

	// Teardown: closing tunnels makes subsequent retries fail and lets
	// the dial loops exit on their next retry tick. Bound the wait so
	// the test doesn't hang the suite if behavior regresses.
	d.tunnels.Close()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(45 * time.Second):
		t.Fatal("dial goroutines did not exit after tunnels.Close() — possible regression in retry-loop bail-out path")
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

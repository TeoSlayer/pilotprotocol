// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
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

	// CURRENT BEHAVIOR (the bug): every concurrent dial gets its own
	// SYN_SENT connection. There is no in-flight-dial dedup map.
	if synSentCount != N {
		t.Errorf("expected %d independent SYN_SENT connections (no dedup today); got %d",
			N, synSentCount)
	}

	// POST-FIX: when v1.9.1 lands, replace the assertion above with
	//   if synSentCount != 1 {
	//       t.Errorf("expected dedup → 1 SYN_SENT in flight, got %d", synSentCount)
	//   }
	// and add a follow-up assertion that all N goroutines returned the
	// same Connection pointer (or that N-1 of them returned without
	// allocating their own conn ID).

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

// TestDialAbandonedGoroutineLeavesOrphanSynSent reproduces the
// related "Ctrl+C on pilotctl leaves orphaned SYN_SENT" bug.
//
// User-visible: pressing Ctrl+C on `pilotctl ping <peer>` while the
// dial is still in flight kills the pilotctl process. The daemon's
// IPC handler goroutine eventually notices the IPC connection dropped
// — but the dial it had already started inside DialConnection keeps
// running for the full 14–31 s retry budget. The connection sits in
// SYN_SENT the whole time, visible in `pilotctl info` as an orphan.
//
// What v1.9.1's cancellable-dial fix will change:
//   DialConnection takes context.Context; when the IPC handler's
//   ctx fires Done (because the IPC connection closed), the dial
//   loop exits immediately, removes the conn, and returns
//   context.Canceled.
//
// This test pins the CURRENT behavior (orphan persists for >5 s).
// After the fix, the assertion flips: orphan is gone within 200 ms.
func TestDialAbandonedGoroutineLeavesOrphanSynSent(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peerNode uint32 = 0xDEADBEEF
	peerConn := addPeerOnDaemon(t, d, peerNode)
	t.Cleanup(func() { peerConn.Close() })

	d.setNodeID_testhelper(0x22220000)

	dst := protocol.Addr{Network: 0, Node: peerNode}
	const dport uint16 = 1001

	// Spawn the dial. We never wait for it (simulating pilotctl Ctrl+C
	// → IPC handler's caller goroutine is detached/abandoned from the
	// test's perspective, but DialConnection itself keeps grinding).
	go func() { _, _ = d.DialConnection(dst, dport) }()

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

	// CURRENT BEHAVIOR: 5 s after we "abandoned" the dial, the orphan
	// is STILL in SYN_SENT — DialConnection has no way to know the
	// caller is gone.
	time.Sleep(5 * time.Second)
	if got := countSynSentTo(d, peerNode); got != 1 {
		t.Errorf("expected orphan SYN_SENT still present 5 s after caller abandoned (current bug); got %d", got)
	}

	// POST-FIX: replace the block above with
	//   cancel()  // the context the test passed into DialConnection
	//   time.Sleep(200 * time.Millisecond)
	//   if got := countSynSentTo(d, peerNode); got != 0 {
	//       t.Errorf("expected orphan removed within 200 ms; got %d", got)
	//   }

	// Tear down the orphan so the test exits cleanly.
	d.tunnels.Close()
	time.Sleep(100 * time.Millisecond)
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

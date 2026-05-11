// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

// Isolation test for the orphan SYN_SENT issue observed against the
// live list-agents agent on 2026-05-11: a `pilotctl ping` whose SYN
// arrives at a peer that silently drops it (e.g. via the rc3 outside-
// replay-window path) leaves a conn entry in StateSynSent that the
// user observes via `pilotctl info`.
//
// This file verifies the *intended* cleanup contract: the dial loop's
// retry-budget exhaustion (retries > DialMaxRetries) MUST remove the
// conn from PortManager and return ErrDialTimeout. If this assertion
// holds, the user's observation was simply within the retry window.
// If it fails, we have a real leak to fix.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestDialRetryBudgetCleansUpOrphanSynSent dials an unresponsive peer
// (real UDP socket that never reads/writes back), lets the dial loop
// run its full retry budget without context cancellation, and asserts
// the conn is removed and ErrDialTimeout is returned.
//
// With no beacon configured, the loop walks the full DialMaxRetries
// (7) with exponential backoff 250ms→500ms→1s→2s→4s→8s→8s→8s, plus
// the initial SYN. Total ~31.75s.
func TestDialRetryBudgetCleansUpOrphanSynSent(t *testing.T) {
	if testing.Short() {
		t.Skip("long retry-budget test")
	}

	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peerNode uint32 = 0xCAFEBABE
	peerConn := addPeerOnDaemon(t, d, peerNode)
	t.Cleanup(func() { peerConn.Close() })

	d.setNodeID_testhelper(0x33330000)

	dst := protocol.Addr{Network: 0, Node: peerNode}
	const dport uint16 = 1001

	// Run dial in foreground goroutine; capture result.
	type result struct {
		conn *Connection
		err  error
	}
	dialDone := make(chan result, 1)
	go func() {
		conn, err := d.DialConnectionContext(context.Background(), dst, dport)
		dialDone <- result{conn, err}
	}()

	// Phase 1: SYN_SENT should appear quickly.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if countSynSentTo(d, peerNode) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := countSynSentTo(d, peerNode); got != 1 {
		t.Fatalf("setup: expected 1 SYN_SENT after dial start; got %d", got)
	}

	// Phase 2: dial loop runs to completion. Without beacon configured,
	// the budget is ~31.75s — wait up to 40s for cleanup.
	select {
	case res := <-dialDone:
		if res.err == nil {
			t.Fatalf("dial returned conn=%v, err=nil; want ErrDialTimeout", res.conn)
		}
		if !errors.Is(res.err, protocol.ErrDialTimeout) {
			t.Fatalf("dial returned err=%v; want ErrDialTimeout", res.err)
		}
	case <-time.After(40 * time.Second):
		t.Fatalf("BUG-3: dial loop did not return after 40s — orphan SYN_SENT still present (count=%d)",
			countSynSentTo(d, peerNode))
	}

	// Phase 3: conn must be gone from the ports table.
	if got := countSynSentTo(d, peerNode); got != 0 {
		t.Errorf("BUG-3: orphan SYN_SENT not removed after dial returned ErrDialTimeout; got %d", got)
	}
}

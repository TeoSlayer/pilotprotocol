// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"sync/atomic"
	"testing"
)

// TestInfoOmitsHealthCounters reproduces the "Daemon.Info() doesn't
// surface tunnel-reliability counters" bug.
//
// Symptom: previous iters added several health counters that operators
// need to monitor:
//   - AcceptQueueDrops (iter 10): inbound SYNs dropped because the
//     application is slow to Accept
//   - WebhookClient.Dropped() (pre-existing): webhook events lost
//     because the dispatcher queue is full
//   - WebhookClient.CircuitSkips() (iter 11): events skipped because
//     the circuit breaker is open against a dead URL
//
// All three counters live ON the daemon (or its WebhookClient) but
// NONE of them are populated into the DaemonInfo struct returned by
// Info(). Result: `pilotctl info` shows them as zero (Go's default for
// uint64) regardless of actual state. Operators have to scrape logs
// or write custom probes to see them.
//
// What v1.9.1's fix should change: Info() reads the counters and
// populates AcceptQueueDrops, WebhookQueueDropped, WebhookCircuitSkips
// in the returned DaemonInfo. No new mutex needed — the counters are
// already atomic.
//
// This test pins the CURRENT (buggy) behavior: even after we set
// non-zero values on the underlying counters, Info() returns zeros
// for the new fields. After GREEN, the assertion flips: Info()
// surfaces the actual values.
func TestInfoOmitsHealthCounters(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()

	d := New(Config{})
	d.regConn = rc
	t.Cleanup(func() { d.tunnels.Close() })

	// Set the underlying counters to non-zero values via the same
	// mechanisms the code uses in production. d.webhook is nil
	// because Config has no WebhookURL — Info() must handle nil
	// webhook gracefully and still populate AcceptQueueDrops.
	atomic.StoreUint64(&d.AcceptQueueDrops, 7)

	info := d.Info()

	// CURRENT (buggy) behavior: AcceptQueueDrops is zero in the
	// returned struct because Info() doesn't populate it. GREEN
	// flips this assertion.
	if info.AcceptQueueDrops != 0 {
		t.Fatalf("BUG NOT REPRODUCED: AcceptQueueDrops already populated (=%d); GREEN flips this", info.AcceptQueueDrops)
	}
	if info.WebhookQueueDropped != 0 {
		t.Fatalf("BUG NOT REPRODUCED: WebhookQueueDropped already populated (=%d); GREEN flips this", info.WebhookQueueDropped)
	}
	if info.WebhookCircuitSkips != 0 {
		t.Fatalf("BUG NOT REPRODUCED: WebhookCircuitSkips already populated (=%d); GREEN flips this", info.WebhookCircuitSkips)
	}
}

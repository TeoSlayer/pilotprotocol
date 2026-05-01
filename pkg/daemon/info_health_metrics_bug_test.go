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
// FIXED (v1.9.1): Info() now reads the underlying counters with
// atomic.LoadUint64 / nil-safe accessors and populates the new
// DaemonInfo fields. WebhookClient.Dropped() and CircuitSkips() are
// nil-receiver-safe (return 0 when daemon has no webhook configured),
// so tests with d.webhook == nil work without special-casing.
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

	// FIXED: AcceptQueueDrops surfaces the value we set; webhook
	// counters are zero because no webhook is configured (nil-safe).
	if info.AcceptQueueDrops != 7 {
		t.Errorf("expected AcceptQueueDrops=7 in Info(); got %d", info.AcceptQueueDrops)
	}
	if info.WebhookQueueDropped != 0 {
		t.Errorf("expected WebhookQueueDropped=0 (no webhook configured); got %d", info.WebhookQueueDropped)
	}
	if info.WebhookCircuitSkips != 0 {
		t.Errorf("expected WebhookCircuitSkips=0 (no webhook configured); got %d", info.WebhookCircuitSkips)
	}
}

// TestInfoSurfacesWebhookCounters pins the webhook side of the fix:
// when a WebhookClient IS configured and its internal counters have
// non-zero values, Info() reads them through.
func TestInfoSurfacesWebhookCounters(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()

	d := New(Config{})
	d.regConn = rc
	t.Cleanup(func() { d.tunnels.Close() })

	// Build a WebhookClient pointed at an unreachable URL — we don't
	// need it to actually send anything; we'll set the internal
	// counters directly to simulate accumulated state.
	wc := NewWebhookClient("http://127.0.0.1:1/noop", func() uint32 { return 1 })
	t.Cleanup(func() { wc.Close() })
	wc.dropped.Store(13)
	wc.circuitSkips.Store(42)
	d.webhook = wc

	info := d.Info()
	if info.WebhookQueueDropped != 13 {
		t.Errorf("expected WebhookQueueDropped=13; got %d", info.WebhookQueueDropped)
	}
	if info.WebhookCircuitSkips != 42 {
		t.Errorf("expected WebhookCircuitSkips=42; got %d", info.WebhookCircuitSkips)
	}
}

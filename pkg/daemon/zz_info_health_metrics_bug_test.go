// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"sync/atomic"
	"testing"
)

// TestInfoSurfacesHealthCountersFromWebhookManager pins the contract
// that Info() reads webhook counters from the registered
// WebhookManager (T4.1 webhook-inversion). Pre-T4.1 the daemon
// dispatched the webhook itself; now plugins/webhook owns the
// dispatcher and exposes counters via the manager interface.
//
// Three counters operators need:
//   - AcceptQueueDrops: inbound SYNs dropped (set on Daemon directly).
//   - Webhook.Dropped: events lost because the plugin's queue is full.
//   - Webhook.CircuitSkips: events skipped because the plugin's
//     circuit breaker is open against a dead URL.

type infoFakeWebhookManager struct{ stats WebhookStats }

func (f *infoFakeWebhookManager) SetURL(string)       {}
func (f *infoFakeWebhookManager) SetTopics([]string)  {}
func (f *infoFakeWebhookManager) Topics() []string    { return nil }
func (f *infoFakeWebhookManager) Stats() WebhookStats { return f.stats }

func TestInfoZerosWebhookCountersWhenNoManagerRegistered(t *testing.T) {
	t.Parallel()
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()

	d := New(Config{})
	d.regConn = rc
	t.Cleanup(func() { d.tunnels.Close() })

	atomic.StoreUint64(&d.AcceptQueueDrops, 7)

	info := d.Info()
	if info.AcceptQueueDrops != 7 {
		t.Errorf("expected AcceptQueueDrops=7 in Info(); got %d", info.AcceptQueueDrops)
	}
	if info.WebhookQueueDropped != 0 {
		t.Errorf("expected WebhookQueueDropped=0 (no manager configured); got %d", info.WebhookQueueDropped)
	}
	if info.WebhookCircuitSkips != 0 {
		t.Errorf("expected WebhookCircuitSkips=0 (no manager configured); got %d", info.WebhookCircuitSkips)
	}
}

func TestInfoSurfacesWebhookCountersFromManager(t *testing.T) {
	t.Parallel()
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()

	d := New(Config{})
	d.regConn = rc
	t.Cleanup(func() { d.tunnels.Close() })

	wm := &infoFakeWebhookManager{stats: WebhookStats{Dropped: 13, CircuitSkips: 42}}
	d.RegisterWebhookManager(wm)

	info := d.Info()
	if info.WebhookQueueDropped != 13 {
		t.Errorf("expected WebhookQueueDropped=13; got %d", info.WebhookQueueDropped)
	}
	if info.WebhookCircuitSkips != 42 {
		t.Errorf("expected WebhookCircuitSkips=42; got %d", info.WebhookCircuitSkips)
	}
}

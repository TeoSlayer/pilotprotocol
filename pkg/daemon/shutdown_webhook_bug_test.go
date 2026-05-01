// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestDaemonStopEmitsNoShutdownWebhook reproduces the
// "graceful shutdown is invisible to operators" bug.
//
// Symptom: Daemon.Stop() / doStop() runs the full shutdown sequence
// (FIN every ESTABLISHED conn, drain handshakes, close registry, IPC,
// tunnel, webhook) but emits NO `daemon.shutting_down` event before
// teardown. Operators / orchestrators (k8s pre-stop hooks, autoscaler
// drain logic, monitoring dashboards) have no programmatic signal
// that this daemon is intentionally going down vs. crashing — the
// only difference visible from outside is "events stop arriving."
//
// Real-world impact:
//   - Auto-scaling controllers can't distinguish planned drain from
//     crash → may spin up replacement nodes unnecessarily, or fail
//     to drain inflight work to a peer before this node disappears.
//   - Webhook-driven dashboards show "node went silent" instead of
//     "node shutting down" → noisier alerts, slower triage.
//   - The natural place for a "shutting down" signal is at the START
//     of doStop, before any state teardown — so observers can record
//     a clean transition rather than reconstructing it from the gap
//     between conn.rst events and the eventual heartbeat-TTL reap.
//
// What v1.9.1 should change: emit `daemon.shutting_down` as the FIRST
// action in doStop, with a payload that lets operators correlate with
// pre-shutdown state — open_connections, known_peers, uptime_seconds.
// The existing webhook.Close() at the end of doStop drains the queue,
// so the event reliably reaches the receiver before the goroutine
// exits.
//
// FIXED (v1.9.1): doStop now emits `daemon.shutting_down` as the
// FIRST action with metadata payload (open_connections, known_peers,
// uptime_seconds). The webhook.Close() at the end of doStop drains
// the queue, so the event reliably reaches the receiver before the
// goroutine exits.
func TestDaemonStopEmitsNoShutdownWebhook(t *testing.T) {
	type captured struct {
		Event string                 `json:"event"`
		Data  map[string]interface{} `json:"data"`
	}
	var mu sync.Mutex
	var events []captured

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev captured
		if err := json.Unmarshal(body, &ev); err == nil {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("tunnels.Listen: %v", err)
	}
	d.startTime = time.Now()
	d.webhook = NewWebhookClient(srv.URL, func() uint32 { return d.NodeID() },
		WithRetryBackoff(1*time.Millisecond),
		WithHTTPTimeout(50*time.Millisecond))

	// Run the shutdown sequence directly. Stop() wraps doStop in
	// stopOnce + close(stopCh); doStop is the body that should emit
	// the webhook.
	d.doStop()

	// FIXED: events contains exactly one daemon.shutting_down entry
	// with the expected metadata keys. The event was emitted before
	// teardown started, so all other shutdown-time events follow it.
	mu.Lock()
	defer mu.Unlock()
	var shutdown *captured
	for i, ev := range events {
		if ev.Event == "daemon.shutting_down" {
			shutdown = &events[i]
			break
		}
	}
	if shutdown == nil {
		t.Fatalf("expected daemon.shutting_down event; got events=%v", events)
	}
	for _, key := range []string{"open_connections", "known_peers", "uptime_seconds"} {
		if _, ok := shutdown.Data[key]; !ok {
			t.Errorf("daemon.shutting_down missing payload key %q; data=%v", key, shutdown.Data)
		}
	}
}

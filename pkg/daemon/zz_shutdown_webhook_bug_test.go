// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"
)

// TestDaemonStopPublishesShutdownEvent pins the contract that
// Daemon.Stop() / doStop() publishes a `daemon.shutting_down` event
// to the bus BEFORE teardown begins. Operators / autoscalers / k8s
// preStop hooks consume this event (via the L11 webhook plugin or
// any other bus subscriber) to distinguish planned drain from crash.
//
// Pre-T4.1 the event was sent directly through d.webhook.Emit; T4.1
// inverted that — the daemon publishes to the in-process bus and the
// webhook plugin subscribes. This test attaches a bus subscriber
// directly so the assertion does not depend on any plugin being
// loaded.
func TestDaemonStopPublishesShutdownEvent(t *testing.T) {
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("tunnels.Listen: %v", err)
	}
	d.startTime = time.Now()

	ch, cancel := d.bus.Subscribe("daemon.shutting_down")
	defer cancel()

	// Run the shutdown sequence directly. Stop() wraps doStop in
	// stopOnce + close(stopCh); doStop is the body that publishes the
	// event before tearing down ports/IPC/tunnels.
	go d.doStop()

	select {
	case ev := <-ch:
		if ev.Topic != "daemon.shutting_down" {
			t.Fatalf("topic = %q, want daemon.shutting_down", ev.Topic)
		}
		for _, key := range []string{"open_connections", "known_peers", "uptime_seconds"} {
			if _, ok := ev.Payload[key]; !ok {
				t.Errorf("daemon.shutting_down missing payload key %q; payload=%v", key, ev.Payload)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("daemon.shutting_down was not published within 2s of doStop()")
	}
}

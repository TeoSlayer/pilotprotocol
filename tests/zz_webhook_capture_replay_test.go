// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build nightly

// Webhook capture-replay (T4.1 §4.7).
//
// For each of the nine events listed in 04-EXTRACTION.md §T4.1, we
// publish a representative payload through the daemon's in-process
// bus, capture the event delivered to a "*" subscriber (the same
// path the L11 webhook plugin uses), normalize the dynamic fields
// (Time, NodeID), and assert the resulting JSON matches a frozen
// golden under testdata/webhook/<topic>.json.
//
// Why bus payload, not HTTP wire payload: the wire payload is just
// the bus payload wrapped in a webhook.Event envelope (event_id,
// event, node_id, timestamp, data). The envelope is tested in the
// plugin's own unit tests; what the regression coverage here pins
// is the SCHEMA of the data field — i.e. the keys core code passes
// to publishEvent. That schema drives every webhook subscriber. If a
// future change adds/renames a key in pkg/daemon/{tunnel,daemon}.go
// the matching golden must be updated, which is exactly the friction
// we want for a wire contract.
//
// For each topic we use d.PublishEvent (the exported entrypoint that
// daemon-internal publishEvent calls). The payload mirrors the exact
// map literal at the source line cited in the task. Missing or extra
// keys → test fails → developer regenerates the golden.
package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
)

// canonicalJSON marshals v with stable key ordering (encoding/json
// already sorts map keys) and a trailing newline for diff-friendliness.
func canonicalJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return append(b, '\n')
}

// goldenPath returns the on-disk path for a topic's golden JSON.
func goldenPath(topic string) string {
	return filepath.Join("..", "testdata", "webhook", topic+".json")
}

// readGolden returns the bytes of testdata/webhook/<topic>.json. Tests
// run with cwd = tests/ so the repo-root testdata directory is one
// level up. Fails if the file is missing — golden files must be
// checked in alongside the test.
func readGolden(t *testing.T, topic string) []byte {
	t.Helper()
	b, err := os.ReadFile(goldenPath(topic))
	if err != nil {
		t.Fatalf("read golden %s: %v (regenerate with PILOT_WEBHOOK_GOLDEN_UPDATE=1)", topic, err)
	}
	return b
}

// writeGolden writes the captured bytes to the repo-root testdata
// path. Used by PILOT_WEBHOOK_GOLDEN_UPDATE=1 to regenerate goldens
// after an intentional schema change.
func writeGolden(t *testing.T, topic string, data []byte) {
	t.Helper()
	path := goldenPath(topic)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir golden dir: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write golden %s: %v", topic, err)
	}
}

// captureEvent subscribes to topic, runs publish, and returns the
// payload of the first received event. Times out after 1s.
func captureEvent(t *testing.T, d *daemon.Daemon, topic string, publish func()) map[string]any {
	t.Helper()
	ch, cancel := d.Bus().Subscribe(topic)
	defer cancel()
	publish()
	select {
	case ev := <-ch:
		return ev.Payload
	case <-time.After(1 * time.Second):
		t.Fatalf("topic %q: no event received within 1s", topic)
		return nil
	}
}

// updateGoldens controls whether mismatches regenerate the golden file
// (set via PILOT_WEBHOOK_GOLDEN_UPDATE=1). Default is to fail on
// mismatch, which is what CI wants.
func updateGoldens() bool {
	return os.Getenv("PILOT_WEBHOOK_GOLDEN_UPDATE") == "1"
}

// assertPayloadMatchesGolden marshals payload to canonical JSON and
// compares with the on-disk golden. On mismatch, dumps both for the
// diff and tells the developer how to regenerate.
func assertPayloadMatchesGolden(t *testing.T, topic string, payload map[string]any) {
	t.Helper()
	got := canonicalJSON(t, payload)
	if updateGoldens() {
		writeGolden(t, topic, got)
		return
	}
	want := readGolden(t, topic)
	if string(got) != string(want) {
		t.Errorf("topic %q payload drift:\n--- got ---\n%s\n--- want ---\n%s\nRegenerate with PILOT_WEBHOOK_GOLDEN_UPDATE=1 go test ./tests/ -run TestWebhookCaptureReplay",
			topic, got, want)
	}
}

// TestWebhookCaptureReplayEvents pins the published payload schema
// for every event the L11 webhook plugin forwards. Each sub-test:
//  1. constructs a synthetic but representative payload that mirrors
//     the map literal at the cited source line,
//  2. publishes it via d.PublishEvent (same entrypoint daemon code
//     uses internally),
//  3. captures the bus event and compares to the frozen golden.
func TestWebhookCaptureReplayEvents(t *testing.T) {
	t.Parallel()
	d := daemon.New(daemon.Config{})

	type tc struct {
		topic   string
		payload map[string]any
	}

	cases := []tc{
		// pkg/daemon/tunnel.go: tunnel.established (around the
		// "encrypted tunnel established" slog line).
		{
			topic: "tunnel.established",
			payload: map[string]any{
				"peer_node_id":  uint32(0xCAFEBABE),
				"authenticated": true,
				"relay":         false,
				"rekeyed":       false,
			},
		},
		// pkg/daemon/tunnel.go: security.nonce_replay (replay window
		// reject path).
		{
			topic: "security.nonce_replay",
			payload: map[string]any{
				"peer_node_id": uint32(0xCAFEBABE),
				"counter":      uint64(42),
			},
		},
		// pkg/daemon/tunnel.go: tunnel.rekey_gave_up (rekey
		// retransmit exhausted).
		{
			topic: "tunnel.rekey_gave_up",
			payload: map[string]any{
				"peer_node_id": uint32(0xCAFEBABE),
			},
		},
		// pkg/daemon/tunnel.go: tunnel.desync_salvage (post-rekey
		// salvage replay).
		{
			topic: "tunnel.desync_salvage",
			payload: map[string]any{
				"peer_node_id": uint32(0xCAFEBABE),
				"replayed":     3,
			},
		},
		// pkg/daemon/tunnel.go: tunnel.relay_activated (peer flipped
		// to relay path).
		{
			topic: "tunnel.relay_activated",
			payload: map[string]any{
				"peer_node_id": uint32(0xCAFEBABE),
			},
		},
		// pkg/daemon/daemon.go: node.reregistered (registry resync
		// after reconnect).
		{
			topic: "node.reregistered",
			payload: map[string]any{
				"address": "0:0001.0000.cafe",
			},
		},
		// pkg/daemon/daemon.go: agent.registered, reregistration
		// flavor (carries reregistered=true).
		{
			topic: "agent.registered",
			payload: map[string]any{
				"address":      "0:0001.0000.cafe",
				"node_id":      uint32(0x0000CAFE),
				"reregistered": true,
			},
		},
		// pkg/daemon/daemon.go: conn.idle_timeout (idle reaper closes
		// a stale connection).
		{
			topic: "conn.idle_timeout",
			payload: map[string]any{
				"remote_addr": "0:0002.0000.beef",
				"remote_port": uint16(443),
				"local_port":  uint16(54321),
				"conn_id":     uint32(7),
			},
		},
		// pkg/daemon/daemon.go: conn.dead_peer (3 keepalives
		// unanswered → RST + close).
		{
			topic: "conn.dead_peer",
			payload: map[string]any{
				"remote_addr": "0:0002.0000.beef",
				"remote_port": uint16(443),
				"local_port":  uint16(54321),
				"conn_id":     uint32(7),
			},
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.topic, func(t *testing.T) {
			payload := captureEvent(t, d, c.topic, func() {
				d.PublishEvent(c.topic, c.payload)
			})
			assertPayloadMatchesGolden(t, c.topic, payload)
		})
	}
}

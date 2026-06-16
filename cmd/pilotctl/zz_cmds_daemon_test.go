// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Each test follows the same shape:
//   d := newFakeDaemon(t)
//   d.useDaemon(t)            // sets PILOT_SOCKET + HOME to a tmp dir
//   d.onJSON(req, replyOK, …) // queues canned reply
//   captureStdout(...)        // exercises the cmd, asserts the human/JSON output
//
// All happy-path coverage — fatal/error paths live in subprocess tests
// because fatalCode calls os.Exit.

// --- info / health / peers / connections ---

func TestCmdInfoHumanOutput(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	body := `{
		"node_id": 42, "address": "0:0000.0000.002A", "hostname": "host-x",
		"uptime_secs": 3725, "connections": 3, "ports": 1, "peers": 2,
		"bytes_sent": 1024, "bytes_recv": 2048, "pkts_sent": 4, "pkts_recv": 5,
		"encrypt": true, "encrypted_peers": 2, "authenticated_peers": 2,
		"relay_peer_count": 1, "handshake_pending_count": 0,
		"beacon_addr": "b.example:9001", "identity": true,
		"public_key": "deadbeefcafef00d12345678",
		"version": "test-v1"
	}`
	d.onJSON(tdCmdInfo, tdCmdInfoOK, body)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdInfo(nil) })

	for _, want := range []string{
		"pilot-daemon", "host-x", "node 42",
		"0:0000.0000.002A", "beacon b.example:9001",
		"persistent", "Ed25519 deadbeef…",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestCmdInfoJSONOutput(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdInfo, tdCmdInfoOK, `{
		"node_id": 7, "address": "0:0000.0000.0007", "uptime_secs": 0,
		"connections": 0, "ports": 0, "peers": 0,
		"bytes_sent": 0, "bytes_recv": 0, "pkts_sent": 0, "pkts_recv": 0
	}`)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdInfo(nil) })

	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["node_id"].(float64) != 7 {
		t.Errorf("node_id = %v", data["node_id"])
	}
}

func TestCmdHealthHumanOutput(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdHealth, tdCmdHealthOK, `{
		"status": "ok", "uptime_seconds": 60, "connections": 1, "peers": 2,
		"encrypted_peers": 2, "relay_peer_count": 0,
		"handshake_pending_count": 0, "bytes_sent": 100, "bytes_recv": 200
	}`)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdHealth() })

	for _, want := range []string{"pilot-daemon", "ok", "1 connection(s)", "peers"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in: %s", want, out)
		}
	}
}

func TestCmdHealthJSON(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdHealth, tdCmdHealthOK, `{
		"status": "ok", "uptime_seconds": 1, "connections": 0, "peers": 0,
		"bytes_sent": 0, "bytes_recv": 0
	}`)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdHealth() })

	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["status"] != "ok" {
		t.Errorf("status = %v", data["status"])
	}
}

func TestCmdPeersEmpty(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdInfo, tdCmdInfoOK, `{
		"node_id": 1, "address": "0:0000.0000.0001",
		"uptime_secs": 0, "connections": 0, "ports": 0, "peers": 0,
		"bytes_sent": 0, "bytes_recv": 0, "pkts_sent": 0, "pkts_recv": 0,
		"peer_list": []
	}`)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdPeers(nil) })
	if !strings.Contains(out, "no peers connected") {
		t.Errorf("expected 'no peers connected', got: %s", out)
	}
}

func TestCmdPeersWithData(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdInfo, tdCmdInfoOK, `{
		"node_id": 1, "address": "0:0000.0000.0001",
		"uptime_secs": 0, "connections": 0, "ports": 0, "peers": 1,
		"bytes_sent": 0, "bytes_recv": 0, "pkts_sent": 0, "pkts_recv": 0,
		"peer_list": [
			{"node_id": 99, "encrypted": true, "authenticated": true, "relay": false}
		]
	}`)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdPeers(nil) })

	// Encrypted+authenticated peers are the norm — only the summary shows.
	for _, want := range []string{"1 peer", "1 encrypted+authenticated", "0 relay", "1 direct"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in: %s", want, out)
		}
	}

	// --all expands to the full table with the node id. The fake daemon
	// serves a single connection, so spin up a fresh one.
	d2 := newFakeDaemon(t)
	d2.useDaemon(t)
	d2.onJSON(tdCmdInfo, tdCmdInfoOK, `{
		"node_id": 1, "address": "0:0000.0000.0001",
		"uptime_secs": 0, "connections": 0, "ports": 0, "peers": 1,
		"bytes_sent": 0, "bytes_recv": 0, "pkts_sent": 0, "pkts_recv": 0,
		"peer_list": [
			{"node_id": 99, "encrypted": true, "authenticated": true, "relay": false}
		]
	}`)
	outAll := captureStdout(t, func() { cmdPeers([]string{"--all"}) })
	for _, want := range []string{"NODE ID", "99", "yes", "direct"} {
		if !strings.Contains(outAll, want) {
			t.Errorf("missing %q in --all output: %s", want, outAll)
		}
	}
}

func TestCmdPeersJSON(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdInfo, tdCmdInfoOK, `{
		"node_id": 1, "address": "0:0000.0000.0001",
		"uptime_secs": 0, "connections": 0, "ports": 0, "peers": 1,
		"bytes_sent": 0, "bytes_recv": 0, "pkts_sent": 0, "pkts_recv": 0,
		"peer_list": [
			{"node_id": 42, "encrypted": false, "authenticated": false, "relay": true,
			 "endpoint": "1.2.3.4:5", "real_addr": "leakme"}
		]
	}`)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdPeers(nil) })
	// Endpoint must NOT leak through peers output even in JSON mode.
	if strings.Contains(out, "1.2.3.4") || strings.Contains(out, "leakme") {
		t.Errorf("peer endpoint leaked into output: %s", out)
	}
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["total"].(float64) != 1 {
		t.Errorf("total = %v", data["total"])
	}
}

func TestCmdPeersSearchFiltersOut(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdInfo, tdCmdInfoOK, `{
		"node_id": 1, "address": "0:0000.0000.0001",
		"uptime_secs": 0, "connections": 0, "ports": 0, "peers": 1,
		"bytes_sent": 0, "bytes_recv": 0, "pkts_sent": 0, "pkts_recv": 0,
		"peer_list": [
			{"node_id": 100, "encrypted": false, "authenticated": false, "relay": false}
		]
	}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdPeers([]string{"--search", "999"}) })
	if !strings.Contains(out, "no peers matching") {
		t.Errorf("expected 'no peers matching', got: %s", out)
	}
}

func TestCmdConnectionsEmpty(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdInfo, tdCmdInfoOK, `{
		"node_id": 1, "address": "0:0000.0000.0001",
		"uptime_secs": 0, "connections": 0, "ports": 0, "peers": 0,
		"bytes_sent": 0, "bytes_recv": 0, "pkts_sent": 0, "pkts_recv": 0,
		"conn_list": []
	}`)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdConnections() })
	if !strings.Contains(out, "no active connections") {
		t.Errorf("expected 'no active connections', got: %s", out)
	}
}

func TestCmdConnectionsJSON(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdInfo, tdCmdInfoOK, `{
		"node_id": 1, "address": "0:0000.0000.0001",
		"uptime_secs": 0, "connections": 0, "ports": 0, "peers": 0,
		"bytes_sent": 0, "bytes_recv": 0, "pkts_sent": 0, "pkts_recv": 0,
		"conn_list": []
	}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdConnections() })
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["total"].(float64) != 0 {
		t.Errorf("total = %v", data["total"])
	}
}

// --- registration / identity ---

func TestCmdRotateKey(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdRotateKey, tdCmdRotateKeyOK, `{"public_key": "newkey"}`)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdRotateKey(nil) })
	if !strings.Contains(out, "newkey") {
		t.Errorf("missing newkey: %s", out)
	}
}

func TestCmdSetPublic(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdSetVisibility, tdCmdSetVisibilityOK, `{"public": true}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdSetPublic(nil) })
	if !strings.Contains(out, "true") {
		t.Errorf("expected true in: %s", out)
	}
}

func TestCmdSetPrivate(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdSetVisibility, tdCmdSetVisibilityOK, `{"public": false}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdSetPrivate(nil) })
	if !strings.Contains(out, "false") {
		t.Errorf("expected false in: %s", out)
	}
}

func TestCmdDeregister(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdDeregister, tdCmdDeregisterOK, `{"deregistered": true}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdDeregister(nil) })
	if !strings.Contains(out, "deregistered") {
		t.Errorf("expected deregistered in: %s", out)
	}
}

func TestCmdSetHostname(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdSetHostname, tdCmdSetHostnameOK, `{"hostname": "agent-x", "node_id": 7}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdSetHostname([]string{"agent-x"}) })
	if !strings.Contains(out, "hostname set") || !strings.Contains(out, "agent-x") {
		t.Errorf("missing hostname set: %s", out)
	}
}

func TestCmdSetHostnameJSON(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdSetHostname, tdCmdSetHostnameOK, `{"hostname": "agent-x", "node_id": 7}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdSetHostname([]string{"agent-x"}) })
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["hostname"] != "agent-x" {
		t.Errorf("hostname = %v", data["hostname"])
	}
}

func TestCmdClearHostname(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdSetHostname, tdCmdSetHostnameOK, `{"hostname": ""}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdClearHostname() })
	if !strings.Contains(out, "hostname cleared") {
		t.Errorf("missing 'hostname cleared': %s", out)
	}
}

func TestCmdSetTagsHuman(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdSetTags, tdCmdSetTagsOK, `{"node_id": 1, "tags": ["alpha","beta"]}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdSetTags([]string{"alpha", "beta"}) })
	for _, want := range []string{"tags set", "#alpha", "#beta"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q: %s", want, out)
		}
	}
}

func TestCmdClearTags(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdSetTags, tdCmdSetTagsOK, `{"tags": []}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdClearTags() })
	if !strings.Contains(out, "tags cleared") {
		t.Errorf("missing 'tags cleared': %s", out)
	}
}

// --- webhook ---

func TestCmdSetWebhookPersistsConfigEvenWithoutDaemon(t *testing.T) {
	// No daemon stub — the cmd still persists to config and reports
	// "will take effect on next daemon start".
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("PILOT_SOCKET", "/tmp/no-such-pilot.sock")
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() {
		cmdSetWebhook([]string{"https://example.com/hook"})
	})
	if !strings.Contains(out, "webhook set") {
		t.Errorf("missing 'webhook set': %s", out)
	}
	if !strings.Contains(out, "next daemon start") {
		t.Errorf("missing follow-up: %s", out)
	}
	// Config must be written.
	cfg := loadConfig()
	if cfg["webhook"] != "https://example.com/hook" {
		t.Errorf("config not persisted: %v", cfg)
	}
}

func TestCmdSetWebhookAppliesToDaemon(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdSetWebhook, tdCmdSetWebhookOK, `{"webhook": "https://x/h"}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdSetWebhook([]string{"https://x/h"}) })
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["applied"] != true {
		t.Errorf("applied = %v, want true", data["applied"])
	}
}

func TestCmdClearWebhookPersistsConfig(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("PILOT_SOCKET", "/tmp/no-such-pilot.sock")
	// Seed an existing webhook.
	_ = saveConfig(map[string]interface{}{"webhook": "https://old/hook"})

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdClearWebhook() })
	if !strings.Contains(out, "webhook cleared") {
		t.Errorf("missing 'webhook cleared': %s", out)
	}
	cfg := loadConfig()
	if _, ok := cfg["webhook"]; ok {
		t.Errorf("webhook should be removed from config: %v", cfg)
	}
}

// --- trust / handshake ---

func TestCmdHandshakeNumeric(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{"status": "sent"}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStderr(t, func() {
		_ = captureStdout(t, func() { cmdHandshake([]string{"42", "test reason"}) })
	})
	if !strings.Contains(out, "handshake") {
		t.Errorf("missing handshake msg in stderr: %s", out)
	}
}

func TestCmdHandshakeJSON(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{"status": "sent"}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdHandshake([]string{"42"}) })
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["node_id"].(float64) != 42 {
		t.Errorf("node_id = %v", data["node_id"])
	}
}

func TestCmdHandshakeAlreadyTrusted(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{"status": "already_trusted"}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdHandshake([]string{"5"}) })
	if !strings.Contains(out, "already trusted") {
		t.Errorf("missing 'already trusted': %s", out)
	}
}

func TestCmdApprove(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{"status": "approved"}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdApprove([]string{"77"}) })
	if !strings.Contains(out, "trust established") {
		t.Errorf("missing 'trust established': %s", out)
	}
}

func TestCmdReject(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{"status": "rejected"}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdReject([]string{"77", "no reason"}) })
	if !strings.Contains(out, "rejected") {
		t.Errorf("missing 'rejected': %s", out)
	}
}

func TestCmdUntrust(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{"revoked": true}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdUntrust([]string{"77"}) })
	if !strings.Contains(out, "node_id") {
		t.Errorf("expected node_id in output: %s", out)
	}
}

func TestCmdPendingEmpty(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{"pending": []}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdPending() })
	if !strings.Contains(out, "no pending handshake") {
		t.Errorf("missing 'no pending handshake': %s", out)
	}
}

func TestCmdPendingHasOne(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdHandshake, tdCmdHandshakeOK,
		`{"pending": [{"node_id": 7, "justification": "hi", "received_at": 0}]}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdPending() })
	if !strings.Contains(out, "node 7") || !strings.Contains(out, "hi") {
		t.Errorf("missing pending row: %s", out)
	}
	if !strings.Contains(out, "pilotctl approve 7") {
		t.Errorf("missing inline approve hint: %s", out)
	}
}

func TestCmdTrustEmpty(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{"trusted": []}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdTrust(nil) })
	if !strings.Contains(out, "no trusted peers") {
		t.Errorf("missing 'no trusted peers': %s", out)
	}
}

func TestCmdTrustHasEntries(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdHandshake, tdCmdHandshakeOK,
		`{"trusted": [{"node_id": 9, "mutual": true, "network": 1, "approved_at": 0}]}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdTrust(nil) })
	for _, want := range []string{"Trusted peers — 1", "node 9", "net 1", "pilotctl untrust"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q: %s", want, out)
		}
	}
	// Mutual trust is the norm — it must NOT be tagged.
	if strings.Contains(out, "one-way") {
		t.Errorf("mutual peer wrongly tagged one-way: %s", out)
	}
}

// --- find / disconnect ---

func TestCmdFindHuman(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdResolveHostname, tdCmdResolveHostnameOK,
		`{"node_id": 42, "address": "0:0000.0000.002A", "public": true}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdFind([]string{"agent-x"}) })
	for _, want := range []string{"Hostname:  agent-x", "Node ID:   42", "Visible:   public"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q: %s", want, out)
		}
	}
}

func TestCmdFindJSON(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdResolveHostname, tdCmdResolveHostnameOK,
		`{"node_id": 42, "address": "0:0000.0000.002A", "public": false}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdFind([]string{"agent-x"}) })
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["hostname"] != "agent-x" {
		t.Errorf("hostname = %v", data["hostname"])
	}
	if data["public"].(bool) {
		t.Errorf("public should be false")
	}
}

func TestCmdDisconnect(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	// Disconnect is fire-and-forget; the daemon needs no reply for the
	// driver to return — d.Disconnect just calls ipc.send.
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdDisconnect([]string{"42"}) })
	if !strings.Contains(out, "conn_id") || !strings.Contains(out, "42") {
		t.Errorf("expected conn_id 42 in: %s", out)
	}
}

// --- network commands ---

func TestCmdNetworkListEmpty(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{"networks": []}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdNetworkList() })
	if !strings.Contains(out, "no networks") {
		t.Errorf("missing 'no networks': %s", out)
	}
}

func TestCmdNetworkListWithEntries(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{"networks": [
		{"id": 1, "name": "alpha", "join_rule": "open"},
		{"id": 2, "name": "beta", "join_rule": "token", "members": 5}
	]}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdNetworkList() })
	for _, want := range []string{"ID", "alpha", "beta", "open", "token", "5"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q: %s", want, out)
		}
	}
}

func TestCmdNetworkJoinDaemonPath(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{"network_id": 5}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdNetworkJoin([]string{"5"}) })
	if !strings.Contains(out, "joined network 5") {
		t.Errorf("missing 'joined network 5': %s", out)
	}
}

func TestCmdNetworkLeaveDaemonPath(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{"network_id": 5}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdNetworkLeave([]string{"5"}) })
	if !strings.Contains(out, "left network 5") {
		t.Errorf("missing 'left network 5': %s", out)
	}
}

func TestCmdNetworkMembersEmpty(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{"nodes": []}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdNetworkMembers([]string{"5"}) })
	if !strings.Contains(out, "no members") {
		t.Errorf("missing 'no members': %s", out)
	}
}

func TestCmdNetworkMembersWithRows(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{"nodes": [
		{"node_id": 100, "hostname": "a", "version": "v1", "public": true},
		{"node_id": 200, "hostname": "", "version": "", "public": false}
	]}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdNetworkMembers([]string{"5"}) })
	for _, want := range []string{"NODE ID", "100", "200", "v1", "public", "private"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q: %s", want, out)
		}
	}
}

func TestCmdNetworkInvitesEmpty(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{"invites": []}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdNetworkInvites() })
	if !strings.Contains(out, "no pending invites") {
		t.Errorf("missing 'no pending invites': %s", out)
	}
}

func TestCmdNetworkInvitesPopulated(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{"invites": [
		{"network_id": 9, "inviter_id": 42, "timestamp": "2026-01-01T00:00:00Z"}
	]}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdNetworkInvites() })
	for _, want := range []string{"NETWORK", "9", "42"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q: %s", want, out)
		}
	}
}

func TestCmdNetworkAccept(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{"network_id": 9, "accepted": true}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdNetworkAccept([]string{"9"}) })
	if !strings.Contains(out, "accepted invite to network 9") {
		t.Errorf("missing accept msg: %s", out)
	}
}

func TestCmdNetworkReject(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{"network_id": 9, "accepted": false}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdNetworkReject([]string{"9"}) })
	if !strings.Contains(out, "rejected invite to network 9") {
		t.Errorf("missing reject msg: %s", out)
	}
}

func TestCmdNetworkInviteWithNumericTarget(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	// cmdNetworkInvite calls resolveToNodeID — numeric path needs no daemon.
	// But the cmd opens a driver connection (defer d.Close), so the daemon
	// must accept the connection. Then it sends the invite frame.
	d.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{"network_id": 1, "node_id": 7}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdNetworkInvite([]string{"1", "7"}) })
	if !strings.Contains(out, "invited node 7 to network 1") {
		t.Errorf("missing invite msg: %s", out)
	}
}

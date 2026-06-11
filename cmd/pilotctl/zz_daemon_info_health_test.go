// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Round-4 bonus: drive cmdInfo + cmdHealth + cmdPeers + cmdConnections
// + cmdTrust + cmdNetworkList success paths against the streamDaemon
// from round-3 by overriding the relevant per-cmd handlers with rich
// canned JSON. The pre-wired Info/Health handlers in newStreamDaemon
// only return minimal payloads — cmdInfo casts many fields that must
// exist, so we replace them per-test.

// fullInfoPayload supplies every field cmdInfo's human-mode renderer
// uses. Each cast is a separate branch in the cover profile.
const fullInfoPayload = `{
	"version": "v1.7.1",
	"node_id": 42,
	"address": "0:0000.0000.002A",
	"hostname": "alice",
	"uptime_secs": 3725,
	"connections": 3,
	"ports": 2,
	"peers": 5,
	"relay_peer_count": 1,
	"authenticated_peers": 4,
	"encrypted_peers": 4,
	"encrypt": true,
	"handshake_pending_count": 2,
	"beacon_addr": "34.71.57.205:9001",
	"identity": true,
	"public_key": "0123456789abcdef0123456789abcdef",
	"email": "alice@example.com",
	"networks": [
		{"network_id": 5, "address": "5:0000.0000.002A"},
		{"network_id": 7, "address": "7:0000.0000.002A"}
	],
	"bytes_sent": 1048576,
	"bytes_recv": 524288,
	"pkts_sent": 100,
	"pkts_recv": 95,
	"conn_list": [
		{
			"id": 1, "local_port": 1000, "remote_addr": "1.2.3.4",
			"remote_port": 2000, "state": "ESTABLISHED",
			"cong_win": 8192, "in_flight": 1024, "srtt_ms": 12.5,
			"in_recovery": false
		}
	]
}`

const fullHealthPayload = `{
	"status": "ok",
	"uptime_seconds": 3725,
	"connections": 3,
	"peers": 5,
	"encrypted_peers": 4,
	"relay_peer_count": 1,
	"handshake_pending_count": 2,
	"bytes_sent": 1048576,
	"bytes_recv": 524288,
	"accept_queue_drops": 0,
	"webhook_queue_dropped": 0
}`

func TestCmdInfoText(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdInfo, tdCmdInfoOK, fullInfoPayload)

	out := captureStdout(t, func() {
		withText(func() { cmdInfo(nil) })
	})
	if !strings.Contains(out, "pilot-daemon") {
		t.Errorf("missing banner: %s", out)
	}
	if !strings.Contains(out, "v1.7.1") {
		t.Errorf("missing version: %s", out)
	}
	if !strings.Contains(out, "node 42") {
		t.Errorf("missing node id: %s", out)
	}
	if !strings.Contains(out, "alice") {
		t.Errorf("missing hostname: %s", out)
	}
	if !strings.Contains(out, "up 1h2m") {
		t.Errorf("missing uptime: %s", out)
	}
	if !strings.Contains(out, "5 peers (4 encrypted · 1 relay · 4 direct)") {
		t.Errorf("missing peer breakdown: %s", out)
	}
	if !strings.Contains(out, "2 pending handshake(s)") || !strings.Contains(out, "pilotctl pending") {
		t.Errorf("missing pending handshake warning with hint: %s", out)
	}
	if !strings.Contains(out, "beacon 34.71.57.205:9001") {
		t.Errorf("missing beacon line: %s", out)
	}
	if !strings.Contains(out, "Ed25519 01234567…") || !strings.Contains(out, "persistent") {
		t.Errorf("missing identity line: %s", out)
	}
	if !strings.Contains(out, "networks") || !strings.Contains(out, "5:0000.0000.002A") {
		t.Errorf("missing networks line: %s", out)
	}
	// Connections are summarized, not dumped — detail lives in
	// `pilotctl connections`.
	if !strings.Contains(out, "3 connections") || !strings.Contains(out, "pilotctl connections") {
		t.Errorf("missing connections summary: %s", out)
	}
	if !strings.Contains(out, "↑ 1.0 MB") || !strings.Contains(out, "↓ 512.0 KB") {
		t.Errorf("missing traffic line: %s", out)
	}
}

func TestCmdInfoJSON(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdInfo, tdCmdInfoOK, fullInfoPayload)

	out := captureStdout(t, func() {
		withJSON(func() { cmdInfo(nil) })
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	data, _ := env["data"].(map[string]interface{})
	if data["hostname"] != "alice" {
		t.Errorf("hostname = %v", data["hostname"])
	}
}

func TestCmdInfoEphemeralIdentity(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	// "identity": false → ephemeral branch
	payload := `{
		"version": "", "node_id": 1, "address": "0:0000.0000.0001",
		"uptime_secs": 1, "connections": 0, "ports": 0,
		"peers": 0, "encrypt": false, "identity": false,
		"bytes_sent": 0, "bytes_recv": 0, "pkts_sent": 0, "pkts_recv": 0
	}`
	sd.onJSON(tdCmdInfo, tdCmdInfoOK, payload)
	out := captureStdout(t, func() {
		withText(func() { cmdInfo(nil) })
	})
	if !strings.Contains(out, "ephemeral (not persisted)") {
		t.Errorf("missing ephemeral identity: %s", out)
	}
	if !strings.Contains(out, "encryption disabled") {
		t.Errorf("missing disabled encryption: %s", out)
	}
}

func TestCmdInfoSyntheticEmail(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	payload := `{
		"node_id": 1, "address": "0:0000.0000.0001",
		"uptime_secs": 1, "connections": 0, "ports": 0,
		"peers": 0, "encrypt": false, "identity": true,
		"public_key": "abcd",
		"email": "node-x@nodes.pilotprotocol.network",
		"bytes_sent": 0, "bytes_recv": 0, "pkts_sent": 0, "pkts_recv": 0
	}`
	sd.onJSON(tdCmdInfo, tdCmdInfoOK, payload)
	out := captureStdout(t, func() {
		withText(func() { cmdInfo(nil) })
	})
	if !strings.Contains(out, "auto-generated") {
		t.Errorf("missing auto-generated tag: %s", out)
	}
}

func TestCmdHealthText(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdHealth, tdCmdHealthOK, fullHealthPayload)
	out := captureStdout(t, func() {
		withText(func() { cmdHealth() })
	})
	if !strings.Contains(out, "pilot-daemon") {
		t.Errorf("missing banner: %s", out)
	}
	if !strings.Contains(out, "ok") {
		t.Errorf("missing status: %s", out)
	}
	if !strings.Contains(out, "uptime 01:02:05") {
		t.Errorf("missing uptime: %s", out)
	}
	if !strings.Contains(out, "2 pending handshake(s)") {
		t.Errorf("missing handshake line: %s", out)
	}
}

func TestCmdHealthWithDrops(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	payload := `{
		"status": "degraded",
		"uptime_seconds": 60,
		"connections": 1,
		"peers": 1,
		"encrypted_peers": 0,
		"relay_peer_count": 0,
		"handshake_pending_count": 0,
		"bytes_sent": 100,
		"bytes_recv": 50,
		"accept_queue_drops": 5,
		"webhook_queue_dropped": 3
	}`
	sd.onJSON(tdCmdHealth, tdCmdHealthOK, payload)
	out := captureStdout(t, func() {
		withText(func() { cmdHealth() })
	})
	if !strings.Contains(out, "5 accept-queue drop(s)") {
		t.Errorf("missing queue drops: %s", out)
	}
	if !strings.Contains(out, "3 webhook event(s) dropped") {
		t.Errorf("missing webhook drops: %s", out)
	}
}

func TestCmdHealthJSONRich(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdHealth, tdCmdHealthOK, fullHealthPayload)
	out := captureStdout(t, func() {
		withJSON(func() { cmdHealth() })
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	data, _ := env["data"].(map[string]interface{})
	if data["status"] != "ok" {
		t.Errorf("status = %v", data["status"])
	}
}

// ---- cmdPeers (uses Info + filters peer_list) ----------------------------

func TestCmdPeersTextWithPeers(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	payload := `{
		"node_id": 1, "address": "0:0000.0000.0001",
		"uptime_secs": 0, "connections": 0, "ports": 0, "peers": 2,
		"bytes_sent": 0, "bytes_recv": 0, "pkts_sent": 0, "pkts_recv": 0,
		"encrypt": true,
		"peer_list": [
			{"node_id": 42, "encrypted": true, "authenticated": true, "relay": false,
			 "endpoint": "1.2.3.4:4000", "real_addr": "1.2.3.4:4000"},
			{"node_id": 99, "encrypted": false, "authenticated": false, "relay": true}
		]
	}`
	sd.onJSON(tdCmdInfo, tdCmdInfoOK, payload)
	out := captureStdout(t, func() {
		withText(func() { cmdPeers(nil) })
	})
	// Headline summary + exceptions: node 99 is unencrypted so it is the
	// only row; node 42 is healthy and stays in the summary count.
	if !strings.Contains(out, "2 peers") {
		t.Errorf("missing peer count: %s", out)
	}
	if !strings.Contains(out, "1 encrypted+authenticated") {
		t.Errorf("missing secure count: %s", out)
	}
	if !strings.Contains(out, "1 relay") || !strings.Contains(out, "1 direct") {
		t.Errorf("missing path breakdown: %s", out)
	}
	if !strings.Contains(out, "node 99") || !strings.Contains(out, "unencrypted") {
		t.Errorf("missing exception row for node 99: %s", out)
	}
	if strings.Contains(out, "node 42") {
		t.Errorf("healthy peer should not be listed as exception: %s", out)
	}
	if strings.Contains(out, "1.2.3.4") {
		t.Errorf("endpoint should have been stripped: %s", out)
	}

	// --all shows every peer in the table. The fake daemon serves a single
	// connection, so spin up a fresh one for the second invocation.
	sd2 := newStreamDaemon(t)
	sd2.useDaemonNoRegistry(t)
	sd2.onJSON(tdCmdInfo, tdCmdInfoOK, payload)
	outAll := captureStdout(t, func() {
		withText(func() { cmdPeers([]string{"--all"}) })
	})
	if !strings.Contains(outAll, "42") || !strings.Contains(outAll, "99") {
		t.Errorf("--all missing peer IDs: %s", outAll)
	}
	if !strings.Contains(outAll, "relay") || !strings.Contains(outAll, "direct") {
		t.Errorf("--all missing path types: %s", outAll)
	}
}

func TestCmdPeersJSONR4(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	payload := `{
		"node_id": 1, "address": "0:0000.0000.0001",
		"uptime_secs": 0, "connections": 0, "ports": 0, "peers": 1,
		"bytes_sent": 0, "bytes_recv": 0, "pkts_sent": 0, "pkts_recv": 0,
		"peer_list": [{"node_id": 5, "encrypted": true, "authenticated": true, "relay": false}]
	}`
	sd.onJSON(tdCmdInfo, tdCmdInfoOK, payload)
	out := captureStdout(t, func() {
		withJSON(func() { cmdPeers(nil) })
	})
	if !strings.Contains(out, `"total":1`) {
		t.Errorf("%s", out)
	}
}

func TestCmdPeersSearch(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	payload := `{
		"node_id": 1, "address": "0:0000.0000.0001",
		"uptime_secs": 0, "connections": 0, "ports": 0, "peers": 2,
		"bytes_sent": 0, "bytes_recv": 0, "pkts_sent": 0, "pkts_recv": 0,
		"peer_list": [
			{"node_id": 42, "encrypted": false, "authenticated": false, "relay": false},
			{"node_id": 99, "encrypted": false, "authenticated": false, "relay": false}
		]
	}`
	sd.onJSON(tdCmdInfo, tdCmdInfoOK, payload)
	out := captureStdout(t, func() {
		withText(func() { cmdPeers([]string{"--search", "42"}) })
	})
	if !strings.Contains(out, "42") {
		t.Errorf("missing matched peer: %s", out)
	}
	if strings.Contains(out, " 99 ") {
		t.Errorf("unmatched peer should be filtered: %s", out)
	}
}

func TestCmdPeersEmptyWithSearch(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	payload := `{
		"node_id": 1, "address": "0:0000.0000.0001",
		"uptime_secs": 0, "connections": 0, "ports": 0, "peers": 0,
		"bytes_sent": 0, "bytes_recv": 0, "pkts_sent": 0, "pkts_recv": 0,
		"peer_list": []
	}`
	sd.onJSON(tdCmdInfo, tdCmdInfoOK, payload)
	out := captureStdout(t, func() {
		withText(func() { cmdPeers([]string{"--search", "missing"}) })
	})
	if !strings.Contains(out, `no peers matching "missing"`) {
		t.Errorf("missing search-not-found banner: %s", out)
	}
}

// ---- cmdConnections ------------------------------------------------------

func TestCmdConnectionsWithList(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	payload := `{
		"node_id": 1, "address": "0:0000.0000.0001",
		"uptime_secs": 0, "connections": 1, "ports": 0, "peers": 0,
		"bytes_sent": 0, "bytes_recv": 0, "pkts_sent": 0, "pkts_recv": 0,
		"conn_list": [{
			"id": 1, "local_port": 1000, "remote_addr": "addr",
			"remote_port": 2000, "state": "ESTAB",
			"cong_win": 1024, "in_flight": 512, "srtt_ms": 10.0,
			"unacked": 0, "ooo_buf": 0, "peer_recv_win": 8192, "recv_win": 8192,
			"bytes_sent": 100, "bytes_recv": 200, "segs_sent": 10, "segs_recv": 10,
			"retransmits": 0, "fast_retx": 0, "sack_recv": 0, "sack_sent": 0, "dup_acks": 0
		}]
	}`
	sd.onJSON(tdCmdInfo, tdCmdInfoOK, payload)
	out := captureStdout(t, func() {
		withText(func() { cmdConnections() })
	})
	if !strings.Contains(out, "Active connections: 1") {
		t.Errorf("missing banner: %s", out)
	}
	if !strings.Contains(out, "ESTAB") {
		t.Errorf("missing state: %s", out)
	}
}

func TestCmdConnectionsEmptyText(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	payload := `{
		"node_id": 1, "address": "0:0000.0000.0001",
		"uptime_secs": 0, "connections": 0, "ports": 0, "peers": 0,
		"bytes_sent": 0, "bytes_recv": 0, "pkts_sent": 0, "pkts_recv": 0,
		"conn_list": []
	}`
	sd.onJSON(tdCmdInfo, tdCmdInfoOK, payload)
	out := captureStdout(t, func() {
		withText(func() { cmdConnections() })
	})
	if !strings.Contains(out, "no active connections") {
		t.Errorf("missing empty banner: %s", out)
	}
}

func TestCmdConnectionsJSONR4(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	payload := `{
		"node_id": 1, "address": "0:0000.0000.0001",
		"uptime_secs": 0, "connections": 0, "ports": 0, "peers": 0,
		"bytes_sent": 0, "bytes_recv": 0, "pkts_sent": 0, "pkts_recv": 0,
		"conn_list": []
	}`
	sd.onJSON(tdCmdInfo, tdCmdInfoOK, payload)
	out := captureStdout(t, func() {
		withJSON(func() { cmdConnections() })
	})
	if !strings.Contains(out, `"total":0`) {
		t.Errorf("%s", out)
	}
}

// ---- cmdTrust ------------------------------------------------------------

func TestCmdTrustWithPeers(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	// Override Handshake handler to return TrustedPeers result.
	sd.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{
		"trusted": [
			{"node_id": 42, "mutual": true, "network": 5, "approved_at": 1700000000},
			{"node_id": 99, "mutual": false, "network": 0, "approved_at": 1700000100}
		]
	}`)
	out := captureStdout(t, func() {
		withText(func() { cmdTrust(nil) })
	})
	if !strings.Contains(out, "node 42") || !strings.Contains(out, "node 99") {
		t.Errorf("missing peer IDs: %s", out)
	}
	if !strings.Contains(out, "Trusted peers — 2") {
		t.Errorf("missing header: %s", out)
	}
	// node 99 is mutual=false → tagged one-way; node 42 is mutual → untagged.
	if !strings.Contains(out, "one-way") {
		t.Errorf("missing one-way tag for asymmetric peer: %s", out)
	}
	// Newest first: 99 (1700000100) before 42 (1700000000).
	if strings.Index(out, "node 99") > strings.Index(out, "node 42") {
		t.Errorf("not sorted newest-first: %s", out)
	}
}

func TestCmdTrustEmptyR4(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{"trusted":[]}`)
	out := captureStdout(t, func() {
		withText(func() { cmdTrust(nil) })
	})
	if !strings.Contains(out, "no trusted peers") {
		t.Errorf("%s", out)
	}
}

func TestCmdTrustJSON(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{"trusted":[]}`)
	out := captureStdout(t, func() {
		withJSON(func() { cmdTrust(nil) })
	})
	if !strings.Contains(out, `"trusted":[]`) {
		t.Errorf("%s", out)
	}
	if !strings.Contains(out, `"total":0`) {
		t.Errorf("missing total: %s", out)
	}
}

// ---- cmdPending ----------------------------------------------------------

func TestCmdPendingEmptyR4(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{"pending":[]}`)
	out := captureStdout(t, func() {
		withText(func() { cmdPending() })
	})
	if !strings.Contains(out, "no pending handshake") {
		t.Errorf("%s", out)
	}
}

func TestCmdPendingWithRequests(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{
		"pending": [
			{"node_id": 42, "justification": "need data exchange", "received_at": 1700000000}
		]
	}`)
	out := captureStdout(t, func() {
		withText(func() { cmdPending() })
	})
	if !strings.Contains(out, "42") || !strings.Contains(out, "need data exchange") {
		t.Errorf("%s", out)
	}
}

// ---- cmdNetworkList ------------------------------------------------------

func TestCmdNetworkListEmptyR4(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{"networks":[]}`)
	out := captureStdout(t, func() {
		withText(func() { cmdNetworkList() })
	})
	if !strings.Contains(out, "no networks") {
		t.Errorf("%s", out)
	}
}

func TestCmdNetworkListWithEntriesR4(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{
		"networks": [
			{"id": 5, "name": "main", "join_rule": "open", "members": 10},
			{"id": 7, "name": "test", "join_rule": "invite", "members": [1, 2, 3]}
		]
	}`)
	out := captureStdout(t, func() {
		withText(func() { cmdNetworkList() })
	})
	if !strings.Contains(out, "main") || !strings.Contains(out, "test") {
		t.Errorf("%s", out)
	}
}

func TestCmdNetworkListJSON(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{"networks":[]}`)
	out := captureStdout(t, func() {
		withJSON(func() { cmdNetworkList() })
	})
	if !strings.Contains(out, `"networks":[]`) {
		t.Errorf("%s", out)
	}
}

// ---- cmdNetworkMembers --------------------------------------------------

func TestCmdNetworkMembersEmptyR4(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{"nodes":[]}`)
	out := captureStdout(t, func() {
		withText(func() { cmdNetworkMembers([]string{"5"}) })
	})
	if !strings.Contains(out, "no members") {
		t.Errorf("%s", out)
	}
}

func TestCmdNetworkMembersText(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{
		"nodes": [
			{"node_id": 42, "hostname": "alice", "version": "v1.2.3", "public": true},
			{"node_id": 99, "hostname": "", "version": "", "public": false}
		]
	}`)
	out := captureStdout(t, func() {
		withText(func() { cmdNetworkMembers([]string{"5"}) })
	})
	if !strings.Contains(out, "alice") {
		t.Errorf("%s", out)
	}
	if !strings.Contains(out, "public") || !strings.Contains(out, "private") {
		t.Errorf("missing visibility: %s", out)
	}
}

// ---- cmdNetworkLeave -----------------------------------------------------

func TestCmdNetworkLeaveText(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{"left": true}`)
	out := captureStdout(t, func() {
		withText(func() { cmdNetworkLeave([]string{"5"}) })
	})
	if !strings.Contains(out, "left network 5") {
		t.Errorf("%s", out)
	}
}

// ---- cmdNetworkAccept / cmdNetworkReject --------------------------------

func TestCmdNetworkAcceptText(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{"accepted": true}`)
	out := captureStdout(t, func() {
		withText(func() { cmdNetworkAccept([]string{"5"}) })
	})
	if !strings.Contains(out, "accepted invite to network 5") {
		t.Errorf("%s", out)
	}
}

func TestCmdNetworkRejectText(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{"rejected": true}`)
	out := captureStdout(t, func() {
		withText(func() { cmdNetworkReject([]string{"5"}) })
	})
	if !strings.Contains(out, "rejected invite to network 5") {
		t.Errorf("%s", out)
	}
}

// ---- cmdNetworkInvites ---------------------------------------------------

func TestCmdNetworkInvitesEmptyR4(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{"invites": []}`)
	out := captureStdout(t, func() {
		withText(func() { cmdNetworkInvites() })
	})
	if !strings.Contains(out, "no pending invites") {
		t.Errorf("%s", out)
	}
}

// ---- cmdNetworkInvite (numeric node ID — skips hostname resolve) -------

func TestCmdNetworkInviteText(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{"invited": true}`)
	out := captureStdout(t, func() {
		withText(func() { cmdNetworkInvite([]string{"5", "42"}) })
	})
	if !strings.Contains(out, "invited node 42 to network 5") {
		t.Errorf("%s", out)
	}
}

// ---- cmdApprove / cmdReject / cmdUntrust (numeric node ID) ------------

func TestCmdApproveText(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{"approved": true}`)
	out := captureStdout(t, func() {
		withText(func() { cmdApprove([]string{"42"}) })
	})
	if !strings.Contains(out, "trust established with node 42") {
		t.Errorf("%s", out)
	}
}

func TestCmdRejectText(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{"rejected": true}`)
	out := captureStdout(t, func() {
		withText(func() { cmdReject([]string{"42", "spam"}) })
	})
	if !strings.Contains(out, "handshake from node 42 rejected") {
		t.Errorf("%s", out)
	}
}

func TestCmdUntrustText(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{"revoked": true}`)
	out := captureStdout(t, func() {
		withText(func() { cmdUntrust([]string{"42"}) })
	})
	_ = out
}

// ---- cmdHandshake (numeric ID — skips hostname resolve, hits Handshake) -

func TestCmdHandshakeNumericTextNew(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{"status": "request_sent"}`)
	out := captureStdout(t, func() {
		captureStderr(t, func() {
			withText(func() {
				cmdHandshake([]string{"42", "for testing"})
			})
		})
	})
	if !strings.Contains(out, "handshake request sent to node 42") {
		t.Errorf("missing banner: %s", out)
	}
}

func TestCmdHandshakeNumericAlreadyTrusted(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{"status": "already_trusted"}`)
	out := captureStdout(t, func() {
		captureStderr(t, func() {
			withText(func() {
				cmdHandshake([]string{"42"})
			})
		})
	})
	if !strings.Contains(out, "already trusted with node 42") {
		t.Errorf("%s", out)
	}
}

func TestCmdHandshakeAddressArg(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{"status": "request_sent"}`)
	captureStdout(t, func() {
		captureStderr(t, func() {
			withText(func() {
				cmdHandshake([]string{"0:0000.0000.002A"})
			})
		})
	})
}

func TestCmdNetworkInvitesWithInvites(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	sd.onJSON(tdCmdNetwork, tdCmdNetworkOK, `{
		"invites": [
			{"network_id": 5, "inviter_id": 42, "timestamp": "2026-01-01T00:00:00Z"}
		]
	}`)
	out := captureStdout(t, func() {
		withText(func() { cmdNetworkInvites() })
	})
	if !strings.Contains(out, "42") {
		t.Errorf("%s", out)
	}
}

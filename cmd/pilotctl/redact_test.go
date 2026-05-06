// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"
)

// TestRedactPeerEndpointsRemovesIPFields pins the privacy guarantee on
// the pilotctl side: peer real_addr / endpoint / lan_addrs / public_addr
// are stripped from any response before display, recursively. Aggregate
// counters (peers, encrypted_peers) and identity fields (node_id,
// hostname, address) survive — the redaction is targeted at IP-bearing
// keys only.
func TestRedactPeerEndpointsRemovesIPFields(t *testing.T) {
	resp := map[string]interface{}{
		"node_id":         42,
		"address":         "0:0000.0000.002A",
		"hostname":        "agent-test",
		"endpoint":        "203.0.113.5:4000",             // must go
		"real_addr":       "203.0.113.5:4000",             // must go
		"public_addr":     "203.0.113.5:4000",             // must go
		"lan_addrs":       []interface{}{"10.0.0.5:4000"}, // must go
		"observed_addr":   "203.0.113.5:4000",             // must go
		"stun_addr":       "203.0.113.5:4000",             // must go
		"peers":           7,
		"encrypted_peers": 7,
		"peer_list": []interface{}{
			map[string]interface{}{
				"node_id":   10,
				"endpoint":  "198.51.100.10:4000",
				"real_addr": "198.51.100.10:4000",
				"encrypted": true,
			},
			map[string]interface{}{
				"node_id":   11,
				"endpoint":  "198.51.100.11:4000",
				"encrypted": false,
			},
		},
		"data": map[string]interface{}{
			"node": map[string]interface{}{
				"node_id":  99,
				"endpoint": "192.0.2.99:4000", // nested under data.node
				"hostname": "deep",
			},
		},
	}

	redactPeerEndpoints(resp)

	// Top-level redacted
	for _, k := range []string{"endpoint", "real_addr", "public_addr", "lan_addrs", "observed_addr", "stun_addr"} {
		if _, ok := resp[k]; ok {
			t.Errorf("top-level %q should be redacted", k)
		}
	}
	// Top-level identity + counters preserved
	if resp["node_id"] != 42 {
		t.Errorf("node_id should be preserved")
	}
	if resp["hostname"] != "agent-test" {
		t.Errorf("hostname should be preserved")
	}
	if resp["peers"] != 7 || resp["encrypted_peers"] != 7 {
		t.Errorf("counters should be preserved")
	}

	// Per-peer entries: endpoint stripped, identity + flags kept
	pl := resp["peer_list"].([]interface{})
	if len(pl) != 2 {
		t.Fatalf("peer_list length changed: %d", len(pl))
	}
	for i, p := range pl {
		peer := p.(map[string]interface{})
		if _, ok := peer["endpoint"]; ok {
			t.Errorf("peer %d endpoint should be redacted", i)
		}
		if _, ok := peer["real_addr"]; ok {
			t.Errorf("peer %d real_addr should be redacted", i)
		}
		if _, ok := peer["node_id"]; !ok {
			t.Errorf("peer %d node_id should be preserved", i)
		}
	}

	// Recursion into data.node
	deep := resp["data"].(map[string]interface{})["node"].(map[string]interface{})
	if _, ok := deep["endpoint"]; ok {
		t.Errorf("nested data.node.endpoint should be redacted")
	}
	if deep["hostname"] != "deep" {
		t.Errorf("nested hostname should be preserved")
	}
}

// TestRedactPeerEndpointsHandlesNonMap ensures the helper is safe to
// call on nil, slices, and primitives without panic.
func TestRedactPeerEndpointsHandlesNonMap(t *testing.T) {
	redactPeerEndpoints(nil)
	redactPeerEndpoints("string")
	redactPeerEndpoints(42)
	redactPeerEndpoints([]interface{}{1, "two", nil})
	// no assertions — just must not panic
}

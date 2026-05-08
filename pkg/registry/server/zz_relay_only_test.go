// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

// seedNodeWithRelayOnly inserts a node directly into server state,
// optionally marked as RelayOnly. Bypasses handleRegister so tests can
// exercise the resolve/lookup path without setting up a full daemon.
func seedNodeWithRelayOnly(t *testing.T, s *Server, nodeID uint32, relayOnly bool) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pkB64 := base64.StdEncoding.EncodeToString(pub)

	s.mu.Lock()
	n := &NodeInfo{
		ID:        nodeID,
		Owner:     fmt.Sprintf("relay-test-%d", nodeID),
		PublicKey: pub,
		RealAddr:  fmt.Sprintf("203.0.113.%d:9000", nodeID%250+1), // RFC5737 documentation IP — never appears in real traffic
		Networks:  []uint16{0},
		Public:    true,
		LANAddrs:  []string{fmt.Sprintf("10.0.0.%d", nodeID%250+1)},
		RelayOnly: relayOnly,
	}
	n.SetLastSeen(time.Now())
	s.nodes[nodeID] = n
	s.pubKeyIdx[pkB64] = nodeID
	s.networks[0].Members = append(s.networks[0].Members, nodeID)
	if s.nextNode <= nodeID {
		s.nextNode = nodeID + 1
	}
	s.mu.Unlock()
	return pub
}

// TestRelayOnlyResolveSubstitutesBeacon confirms task 32's central
// invariant: peers calling resolve on a RelayOnly node receive the
// beacon's address instead of the node's real_addr.
func TestRelayOnlyResolveSubstitutesBeacon(t *testing.T) {
	t.Parallel()
	const beaconAddr = "127.0.0.10:9001"
	s := newTestServer(t, "")
	s.beaconAddr = beaconAddr

	// Two nodes: A (requester, normal) and B (target, RelayOnly).
	_ = seedNodeWithRelayOnly(t, s, 100, false)
	_ = seedNodeWithRelayOnly(t, s, 200, true)

	// Strip A's pubkey so admin-token auth path is taken (avoids needing
	// to sign the request properly in this test).
	s.SetAdminToken("admin")
	s.mu.Lock()
	s.nodes[100].PublicKey = nil
	s.mu.Unlock()
	s.trust.RestorePairs([]string{"100:200"})

	resp, err := s.directory.HandleResolve(map[string]interface{}{
		"node_id":      float64(200),
		"requester_id": float64(100),
		"admin_token":  "admin",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	gotAddr, _ := resp["real_addr"].(string)
	if gotAddr != beaconAddr {
		t.Fatalf("real_addr = %q, want beacon %q (RelayOnly node should not leak its IP)", gotAddr, beaconAddr)
	}
	if got, _ := resp["relay_only"].(bool); !got {
		t.Fatalf("relay_only hint missing — new daemons need this to skip direct retries")
	}
	if _, hasLAN := resp["lan_addrs"]; hasLAN {
		t.Fatalf("lan_addrs should be stripped for RelayOnly nodes (LAN addresses leak the IP too)")
	}
}

// TestRelayOnlyResolveNormalNodeUnchanged confirms normal nodes still
// have their real_addr returned — back-compat for the bulk of the fleet
// while task 32 ramps up.
func TestRelayOnlyResolveNormalNodeUnchanged(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.beaconAddr = "127.0.0.10:9001"

	seedNodeWithRelayOnly(t, s, 300, false)
	seedNodeWithRelayOnly(t, s, 400, false)

	s.SetAdminToken("admin")
	s.mu.Lock()
	s.nodes[300].PublicKey = nil // admin-token auth path
	s.mu.Unlock()
	s.trust.RestorePairs([]string{"300:400"})

	resp, err := s.directory.HandleResolve(map[string]interface{}{
		"node_id":      float64(400),
		"requester_id": float64(300),
		"admin_token":  "admin",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	gotAddr, _ := resp["real_addr"].(string)
	if gotAddr == "" || gotAddr == s.beaconAddr {
		t.Fatalf("real_addr should be the node's own addr, not blank or beacon; got %q", gotAddr)
	}
	if _, hasHint := resp["relay_only"]; hasHint {
		t.Fatalf("relay_only hint should NOT appear for non-RelayOnly nodes")
	}
}

// TestRelayOnlyLookupSubstitutesBeacon: same substitution behavior on
// the public lookup path (not just resolve).
func TestRelayOnlyLookupSubstitutesBeacon(t *testing.T) {
	t.Parallel()
	const beaconAddr = "127.0.0.10:9001"
	s := newTestServer(t, "")
	s.beaconAddr = beaconAddr

	seedNodeWithRelayOnly(t, s, 500, true)

	resp, err := s.directory.HandleLookup(map[string]interface{}{
		"node_id": float64(500),
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	gotAddr, _ := resp["real_addr"].(string)
	if gotAddr != beaconAddr {
		t.Fatalf("lookup real_addr = %q, want beacon %q", gotAddr, beaconAddr)
	}
	gotEndpoint, _ := resp["endpoint"].(string)
	if gotEndpoint != beaconAddr {
		t.Fatalf("lookup endpoint = %q, want beacon %q", gotEndpoint, beaconAddr)
	}
	if got, _ := resp["relay_only"].(bool); !got {
		t.Fatalf("lookup missing relay_only hint")
	}
}

// TestRelayOnlyRegistrationStoresFlag confirms that a daemon registering
// with relay_only=true has the flag persisted on its NodeInfo and that
// subsequent registrations can toggle it.
func TestRelayOnlyRegistrationStoresFlag(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.beaconAddr = "127.0.0.10:9001"

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pkB64 := base64.StdEncoding.EncodeToString(pub)

	// Register with relay_only=true
	resp, err := s.handleRegister(map[string]interface{}{
		"public_key":  pkB64,
		"listen_addr": "10.0.0.1:9000",
		"owner":       "relay-test",
		"relay_only":  true,
	}, "10.0.0.1:9000")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID, _ := resp["node_id"].(uint32)
	if nodeID == 0 {
		// fallback for json conversion
		if v, ok := resp["node_id"].(float64); ok {
			nodeID = uint32(v)
		}
	}
	if nodeID == 0 {
		t.Fatalf("no node_id in response")
	}

	s.mu.RLock()
	gotRelay := s.nodes[nodeID].RelayOnly
	s.mu.RUnlock()
	if !gotRelay {
		t.Fatalf("RelayOnly not stored after registration")
	}

	// Re-register with relay_only=false (operator toggling the flag).
	if _, err := s.handleRegister(map[string]interface{}{
		"public_key":  pkB64,
		"listen_addr": "10.0.0.1:9000",
		"owner":       "relay-test",
		"relay_only":  false,
	}, "10.0.0.1:9000"); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	s.mu.RLock()
	gotRelay = s.nodes[nodeID].RelayOnly
	s.mu.RUnlock()
	if gotRelay {
		t.Fatalf("RelayOnly should toggle off when daemon re-registers without the flag")
	}
}

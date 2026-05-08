// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"sync"
	"testing"
	"time"
)

// stubCacheEntry installs a sentinel cache entry under the given netID so
// tests can assert whether handlers invalidate it.
func stubCacheEntry(t *testing.T, s *Server, netID uint16) {
	t.Helper()
	c := &listNodesCacheState{
		FullBody: []byte(`{"sentinel":true}`),
		BuiltAt:  time.Now(),
	}
	c.Cond = sync.NewCond(&c.Mu)
	s.listNodesPerNetMu.Lock()
	s.listNodesPerNet[netID] = c
	s.listNodesPerNetMu.Unlock()
}

// hasCacheEntry returns true if a per-network cache state still exists.
func hasCacheEntry(s *Server, netID uint16) bool {
	s.listNodesPerNetMu.Lock()
	defer s.listNodesPerNetMu.Unlock()
	_, ok := s.listNodesPerNet[netID]
	return ok
}

// seedNetworkAndNode installs a network with a single node directly in
// server state. Bypasses the create/register handlers so tests don't have
// to deal with crypto identity. Returns the netID + nodeID.
func seedNetworkAndNode(t *testing.T, s *Server) (uint16, uint32) {
	t.Helper()
	const netID uint16 = 42
	const nodeID uint32 = 1001

	s.mu.Lock()
	defer s.mu.Unlock()
	s.networks[netID] = &NetworkInfo{
		ID:       netID,
		Name:     "test-net",
		JoinRule: "open",
		Members:  []uint32{nodeID},
		MemberRoles: map[uint32]Role{
			nodeID: RoleOwner,
		},
		Created: time.Now(),
	}
	n := &NodeInfo{
		ID:        nodeID,
		Owner:     "test",
		PublicKey: []byte("fake-pk"),
		Networks:  []uint16{netID},
	}
	n.SetLastSeen(time.Now())
	s.nodes[nodeID] = n
	if s.nextNet <= netID {
		s.nextNet = netID + 1
	}
	if s.nextNode <= nodeID {
		s.nextNode = nodeID + 1
	}
	return netID, nodeID
}

// TestInvalidateListNodesCacheForNetworkDropsEntry validates the helper
// itself (used by all mutation paths). Smoke test for the contract.
func TestInvalidateListNodesCacheForNetworkDropsEntry(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	stubCacheEntry(t, s, 42)
	if !hasCacheEntry(s, 42) {
		t.Fatalf("setup: expected cache entry for net 42")
	}
	s.invalidateListNodesCacheForNetwork(42)
	if hasCacheEntry(s, 42) {
		t.Fatalf("cache entry for net 42 should be gone after invalidate")
	}
}

// TestHandleDeleteNetworkInvalidatesCache locks down the rc3 fix: when a
// network is deleted, its cached list_nodes response must be dropped so we
// don't leak orphaned cache memory and don't return zombie data if the same
// netID is reused.
func TestHandleDeleteNetworkInvalidatesCache(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	netID, _ := seedNetworkAndNode(t, s)

	stubCacheEntry(t, s, netID)
	if !hasCacheEntry(s, netID) {
		t.Fatalf("setup: cache entry should exist for net %d", netID)
	}

	if _, err := s.membership.HandleDeleteNetwork(map[string]interface{}{
		"network_id":  float64(netID),
		"admin_token": "ADM",
	}); err != nil {
		t.Fatalf("delete_network: %v", err)
	}

	if hasCacheEntry(s, netID) {
		t.Fatalf("cache entry for net %d should be invalidated after delete_network", netID)
	}
}

// TestHandleJoinNetworkInvalidatesCache pins the existing wiring at
// server.go:3403 so a future refactor can't accidentally drop it.
func TestHandleJoinNetworkInvalidatesCache(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")

	// Pre-existing network with no members; we'll join it.
	const netID uint16 = 50
	const nodeID uint32 = 2001
	s.mu.Lock()
	s.networks[netID] = &NetworkInfo{
		ID:       netID,
		Name:     "join-test",
		JoinRule: "open",
		Members:  []uint32{},
		Created:  time.Now(),
	}
	s.nodes[nodeID] = &NodeInfo{
		ID:        nodeID,
		Owner:     "alice",
		PublicKey: []byte("pk"),
	}
	s.nodes[nodeID].SetLastSeen(time.Now())
	if s.nextNet <= netID {
		s.nextNet = netID + 1
	}
	if s.nextNode <= nodeID {
		s.nextNode = nodeID + 1
	}
	s.mu.Unlock()

	stubCacheEntry(t, s, netID)
	if !hasCacheEntry(s, netID) {
		t.Fatalf("setup: cache should exist for net %d", netID)
	}

	if _, err := s.membership.HandleJoinNetwork(map[string]interface{}{
		"node_id":     float64(nodeID),
		"network_id":  float64(netID),
		"admin_token": "ADM",
	}); err != nil {
		t.Fatalf("join_network: %v", err)
	}

	if hasCacheEntry(s, netID) {
		t.Fatalf("cache entry for net %d should be invalidated after join_network", netID)
	}
}

// TestHandleLeaveNetworkInvalidatesCache pins the wiring at server.go:3493.
func TestHandleLeaveNetworkInvalidatesCache(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	netID, nodeID := seedNetworkAndNode(t, s)

	stubCacheEntry(t, s, netID)
	if !hasCacheEntry(s, netID) {
		t.Fatalf("setup: cache should exist for net %d", netID)
	}

	if _, err := s.membership.HandleLeaveNetwork(map[string]interface{}{
		"node_id":     float64(nodeID),
		"network_id":  float64(netID),
		"admin_token": "ADM",
	}); err != nil {
		t.Fatalf("leave_network: %v", err)
	}

	if hasCacheEntry(s, netID) {
		t.Fatalf("cache entry for net %d should be invalidated after leave_network", netID)
	}
}

// TestConcurrentInvalidateAndPopulateRace exercises the cache map under
// `-race` with simultaneous invalidate + manual populate to catch any
// missing locking on the listNodesPerNet map. Run with `go test -race`.
func TestConcurrentInvalidateAndPopulateRace(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")

	const netID uint16 = 7
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			stubCacheEntry(t, s, netID)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			s.invalidateListNodesCacheForNetwork(netID)
		}
	}()
	wg.Wait()
}

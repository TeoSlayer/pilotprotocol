// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

import (
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// genPubKeyB64 generates a fresh Ed25519 key pair and returns the public key
// base64-encoded (the form accepted by HandleRegister).
func genPubKeyB64(t *testing.T) string {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return crypto.EncodePublicKey(id.PublicKey)
}

// newTestStore creates a minimal Store wired with no-op callbacks for unit testing.
func newTestStore(t *testing.T) *Store {
	t.Helper()

	nodes := make(map[uint32]*NodeInfo)
	pubKeyIdx := make(map[string]uint32)
	ownerIdx := make(map[string]uint32)
	hostnameIdx := make(map[string]uint32)
	nextNode := uint32(1)
	maxNodes := 0
	reapCursor := uint32(0)
	listNodesCache := &ListNodesCacheState{}
	listNodesCache.Cond = sync.NewCond(&listNodesCache.Mu)
	listNodesPerNet := make(map[uint16]*ListNodesCacheState)
	var mu sync.RWMutex
	var shards NodeShards
	var perNetMu sync.Mutex

	cb := Callbacks{
		Save:  func() {},
		Audit: func(action string, attrs ...any) {},
		RecordWALRegister: func(nodeID uint32, owner, pubKeyB64, realAddr, hostname string, lanAddrs []string, version, createdAt string) {
		},
		RecordWALDeregister:           func(nodeID uint32) {},
		InvalidateListNodesCache:      func(netID uint16) {},
		InvalidateAdminListNodesCache: func() {},
		PublishMembershipChanged:      func(netID uint16) {},
		RemoveFromNetworks:            func(nodeID uint32, networks []uint16) []uint16 { return nil },
		ClearInviteInbox:              func(nodeID uint32) {},
		RequireAdminToken: func(msg map[string]interface{}) error {
			return nil
		},
		RequireAdminTokenLocked: func(msg map[string]interface{}) error {
			return nil
		},
		AdminToken: func() string { return "test-admin" },
		VerifyNodeSignature: func(pubKey []byte, adminToken string, msg map[string]interface{}, challenge string) error {
			// Accept admin token bypass; otherwise no-op for unit tests.
			return nil
		},
		IsTrusted:              func(nodeA, nodeB uint32) bool { return false },
		BeaconAddr:             func() string { return "beacon:9001" },
		IncRegistrations:       func() {},
		IncDeregistrations:     func() {},
		IncRequestsTotal:       func(label string) {},
		IncErrorsTotal:         func(label string) {},
		ObserveRequestDuration: func(label string, seconds float64) {},
		Now:                    time.Now,
		AddNodeToBackbone:      func(nodeID uint32) {},
		ScanNetworkMemberships: func(nodeID uint32) []uint16 { return nil },
	}

	return NewStore(
		&mu,
		&shards,
		nodes,
		pubKeyIdx,
		ownerIdx,
		hostnameIdx,
		&nextNode,
		&maxNodes,
		&reapCursor,
		listNodesCache,
		&perNetMu,
		&listNodesPerNet,
		func(netID uint16) (NetworkMemberView, bool) {
			return NetworkMemberView{}, false
		},
		cb,
	)
}

// TestHandleRegisterNewNode verifies that HandleRegister creates a new node.
func TestHandleRegisterNewNode(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	pubKeyB64 := genPubKeyB64(t)

	resp, err := st.HandleRegister(map[string]interface{}{
		"public_key": pubKeyB64,
		"owner":      "alice",
	}, "10.0.0.1:4000", nil, nil)
	if err != nil {
		t.Fatalf("HandleRegister: %v", err)
	}
	if resp["type"] != "register_ok" {
		t.Fatalf("expected register_ok, got %v", resp["type"])
	}
	nodeID, ok := resp["node_id"].(uint32)
	if !ok || nodeID == 0 {
		t.Fatalf("node_id missing or zero in response: %v", resp)
	}

	st.mu.RLock()
	node, exists := st.nodes[nodeID]
	st.mu.RUnlock()
	if !exists {
		t.Fatalf("node %d not found in store after registration", nodeID)
	}
	if node.Owner != "alice" {
		t.Fatalf("expected owner 'alice', got %q", node.Owner)
	}
}

// TestHandleLookupByID verifies that HandleLookup returns a registered node.
func TestHandleLookupByID(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	pubKeyB64 := genPubKeyB64(t)

	regResp, err := st.HandleRegister(map[string]interface{}{
		"public_key": pubKeyB64,
		"owner":      "bob",
	}, "192.168.1.5:4000", nil, nil)
	if err != nil {
		t.Fatalf("HandleRegister: %v", err)
	}
	nodeID := regResp["node_id"].(uint32)

	resp, err := st.HandleLookup(map[string]interface{}{
		"node_id": float64(nodeID),
	})
	if err != nil {
		t.Fatalf("HandleLookup: %v", err)
	}
	if resp["type"] != "lookup_ok" {
		t.Fatalf("expected lookup_ok, got %v", resp["type"])
	}
	gotID, ok := resp["node_id"].(uint32)
	if !ok || gotID != nodeID {
		t.Fatalf("expected node_id %d, got %v", nodeID, resp["node_id"])
	}
}

// TestHandleDeregisterCleansUp verifies that HandleDeregister removes the node
// from the node map and the hostname index.
func TestHandleDeregisterCleansUp(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	pubKeyB64 := genPubKeyB64(t)

	regResp, err := st.HandleRegister(map[string]interface{}{
		"public_key": pubKeyB64,
		"hostname":   "mynode",
	}, "1.2.3.4:5000", nil, nil)
	if err != nil {
		t.Fatalf("HandleRegister: %v", err)
	}
	nodeID := regResp["node_id"].(uint32)

	st.mu.RLock()
	_, nodeExists := st.nodes[nodeID]
	_, hnameExists := st.hostnameIdx["mynode"]
	st.mu.RUnlock()
	if !nodeExists {
		t.Fatalf("expected node %d to exist before deregister", nodeID)
	}
	if !hnameExists {
		t.Fatalf("expected hostname index entry 'mynode' before deregister")
	}

	resp, err := st.HandleDeregister(map[string]interface{}{
		"node_id":     float64(nodeID),
		"admin_token": "test-admin",
	})
	if err != nil {
		t.Fatalf("HandleDeregister: %v", err)
	}
	if resp["type"] != "deregister_ok" {
		t.Fatalf("expected deregister_ok, got %v", resp["type"])
	}

	st.mu.RLock()
	_, nodeExists = st.nodes[nodeID]
	_, hnameExists = st.hostnameIdx["mynode"]
	st.mu.RUnlock()
	if nodeExists {
		t.Fatalf("node %d should be removed after deregister", nodeID)
	}
	if hnameExists {
		t.Fatalf("hostname index entry 'mynode' should be removed after deregister")
	}
}

// TestListNodesCacheInvalidatedOnDeregister verifies that the per-network
// list_nodes cache invalidation callback fires on deregister.
func TestListNodesCacheInvalidatedOnDeregister(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)

	invalidated := []uint16{}
	st.cb.InvalidateListNodesCache = func(netID uint16) {
		invalidated = append(invalidated, netID)
	}

	pubKeyB64 := genPubKeyB64(t)
	regResp, err := st.HandleRegister(map[string]interface{}{
		"public_key": pubKeyB64,
	}, "5.6.7.8:4000", nil, nil)
	if err != nil {
		t.Fatalf("HandleRegister: %v", err)
	}
	nodeID := regResp["node_id"].(uint32)

	_, err = st.HandleDeregister(map[string]interface{}{
		"node_id":     float64(nodeID),
		"admin_token": "test-admin",
	})
	if err != nil {
		t.Fatalf("HandleDeregister: %v", err)
	}

	// InvalidateListNodesCache must be called at least once (for backbone net 0).
	if len(invalidated) == 0 {
		t.Fatalf("expected InvalidateListNodesCache to be called on deregister, got 0 calls")
	}
}

// TestHandleHeartbeatUpdatesLastSeen verifies that a heartbeat updates
// the node's LastSeenNano.
func TestHandleHeartbeatUpdatesLastSeen(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	pubKeyB64 := genPubKeyB64(t)

	regResp, err := st.HandleRegister(map[string]interface{}{
		"public_key": pubKeyB64,
	}, "9.9.9.9:4000", nil, nil)
	if err != nil {
		t.Fatalf("HandleRegister: %v", err)
	}
	nodeID := regResp["node_id"].(uint32)

	st.mu.RLock()
	node := st.nodes[nodeID]
	st.mu.RUnlock()

	beforeNano := node.LastSeenNano.Load()

	time.Sleep(2 * time.Millisecond)

	_, err = st.HandleHeartbeat(map[string]interface{}{
		"node_id":     float64(nodeID),
		"admin_token": "test-admin",
	})
	if err != nil {
		t.Fatalf("HandleHeartbeat: %v", err)
	}

	afterNano := node.LastSeenNano.Load()
	if afterNano <= beforeNano {
		t.Fatalf("expected LastSeenNano to increase: before=%d after=%d", beforeNano, afterNano)
	}
}

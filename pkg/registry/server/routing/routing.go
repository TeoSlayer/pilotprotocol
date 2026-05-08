// SPDX-License-Identifier: AGPL-3.0-or-later

// Package routing implements the beacon-registration and NAT punch-coordination
// handlers extracted from the registry server (R1.4 decomposition).
//
// The package owns the beacon cluster state (registration, TTL-based listing)
// and the punch endpoint lookup.  It exposes a Store that holds the beacon
// map and the PunchBackend interface that the *server.Server satisfies for the
// punch operation.
package routing

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// BeaconTTL is how long a beacon registration is valid without re-register.
const BeaconTTL = 60 * time.Second

type BeaconEntry struct {
	ID       uint32
	Addr     string
	LastSeen time.Time
}

// PunchBackend is satisfied by *server.Server and provides the node address
// lookups that HandlePunch needs.  The interface is intentionally narrow:
// only the three operations the punch handler requires are exposed.
type PunchBackend interface {
	// NodePubKeyAndAdminToken returns false if the node does not exist.
	NodePubKeyAndAdminToken(nodeID uint32) (pubKey []byte, adminToken string, ok bool)

	// VerifyPunchSignature accepts either an Ed25519 signature or an admin-token fallback.
	VerifyPunchSignature(pubKey []byte, adminToken string, msg map[string]interface{}, challenge string) error

	// NodeAddrs returns false for addrA or addrB when the respective node is absent.
	NodeAddrs(nodeA, nodeB uint32) (addrA string, okA bool, addrB string, okB bool)
}

// Store holds the beacon cluster state and implements the three
// beacon/punch routing handlers.
type Store struct {
	mu      sync.RWMutex
	beacons map[uint32]*BeaconEntry
	now     func() time.Time
	backend PunchBackend // may be nil until wired; punch returns error if nil
}

// NewStore creates a Store with a real-time clock.
// backend may be nil if HandlePunch will never be called (e.g. in tests that
// only exercise beacon registration/listing).
func NewStore(backend PunchBackend) *Store {
	return &Store{
		beacons: make(map[uint32]*BeaconEntry),
		now:     time.Now,
		backend: backend,
	}
}

// SetClock replaces the time source (for deterministic testing).
func (st *Store) SetClock(fn func() time.Time) {
	st.now = fn
}

// HandleBeaconRegister registers or refreshes a beacon instance for peer discovery.
func (st *Store) HandleBeaconRegister(msg map[string]interface{}) (map[string]interface{}, error) {
	beaconID := jsonUint32(msg, "beacon_id")
	addr, _ := msg["addr"].(string)

	if beaconID == 0 {
		return nil, fmt.Errorf("beacon_id required")
	}
	if addr == "" {
		return nil, fmt.Errorf("addr required")
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, fmt.Errorf("beacon addr invalid: %w", err)
	}

	st.mu.Lock()
	st.beacons[beaconID] = &BeaconEntry{
		ID:       beaconID,
		Addr:     addr,
		LastSeen: st.now(),
	}
	st.mu.Unlock()

	slog.Debug("beacon registered", "beacon_id", beaconID, "addr", addr)

	return map[string]interface{}{
		"type":      "beacon_register_ok",
		"beacon_id": beaconID,
	}, nil
}

// HandleBeaconList returns all known (non-expired) beacon instances.
func (st *Store) HandleBeaconList() (map[string]interface{}, error) {
	now := st.now()

	st.mu.RLock()
	defer st.mu.RUnlock()

	beacons := make([]map[string]interface{}, 0, len(st.beacons))
	for _, b := range st.beacons {
		if now.Sub(b.LastSeen) > BeaconTTL {
			continue
		}
		beacons = append(beacons, map[string]interface{}{
			"id":   b.ID,
			"addr": b.Addr,
		})
	}

	return map[string]interface{}{
		"type":    "beacon_list_ok",
		"beacons": beacons,
	}, nil
}

func (st *Store) HandlePunch(msg map[string]interface{}) (map[string]interface{}, error) {
	if st.backend == nil {
		return nil, fmt.Errorf("routing: punch backend not wired")
	}

	requesterID := jsonUint32(msg, "requester_id")
	nodeA := jsonUint32(msg, "node_a")
	nodeB := jsonUint32(msg, "node_b")

	// H3 fix: verify requester is a participant.
	if requesterID != nodeA && requesterID != nodeB {
		return nil, fmt.Errorf("punch denied: requester must be participant")
	}

	// Phase 1: fetch pubkey + admin token (read-lock inside backend).
	pubKey, adminToken, ok := st.backend.NodePubKeyAndAdminToken(requesterID)
	if !ok {
		return nil, fmt.Errorf("node %d not found", requesterID)
	}

	// Phase 2: signature verification (CPU-bound, no lock).
	challenge := fmt.Sprintf("punch:%d:%d", nodeA, nodeB)
	if err := st.backend.VerifyPunchSignature(pubKey, adminToken, msg, challenge); err != nil {
		return nil, err
	}

	// Phase 3: node address lookup.
	addrA, okA, addrB, okB := st.backend.NodeAddrs(nodeA, nodeB)
	if !okA {
		return nil, fmt.Errorf("node %d not found", nodeA)
	}
	if !okB {
		return nil, fmt.Errorf("node %d not found", nodeB)
	}

	return map[string]interface{}{
		"type":        "punch_ok",
		"node_a":      nodeA,
		"node_a_addr": addrA,
		"node_b":      nodeB,
		"node_b_addr": addrB,
	}, nil
}

// ReapStale deletes beacons whose LastSeen is older than BeaconTTL.
// Called by the server's background reap loop.
func (st *Store) ReapStale() {
	now := st.now()
	st.mu.Lock()
	defer st.mu.Unlock()
	for id, b := range st.beacons {
		if now.Sub(b.LastSeen) > BeaconTTL {
			slog.Info("reaping stale beacon", "beacon_id", id, "last_seen_ago", now.Sub(b.LastSeen).Round(time.Second))
			delete(st.beacons, id)
		}
	}
}

// --- helpers ---

// jsonUint32 is a local copy of the server-package helper, kept here so the
// routing package has zero dependencies on server internals.
func jsonUint32(msg map[string]interface{}, key string) uint32 {
	if v, ok := msg[key].(float64); ok {
		if v < 0 || v > float64(^uint32(0)) {
			return 0
		}
		return uint32(v)
	}
	return 0
}

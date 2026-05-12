// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"net"
	"sync"
	"time"
)

// nodeShardCount controls how the node-id space is partitioned across
// independent locks. A power of two so the modulo lowers to a bitmask.
// 64 was picked empirically: enough shards that 50k+ concurrent Discovers
// see negligible contention on any single shard, low enough that the
// per-shard map overhead stays trivial.
const nodeShardCount = 64

// nodeShard owns one partition of the node-id space.
type nodeShard struct {
	mu    sync.RWMutex
	nodes map[uint32]*beaconNode
}

// nodeMap is a fixed-size array of nodeShards keyed by nodeID modulo
// nodeShardCount. Replaces the single map+RWMutex in Server that became
// the contention bottleneck under fleet-scale Discover load — every
// Discover/Punch packet used to acquire one global write lock; with
// nodeMap the lock is per-shard so 64 cores can hot-write in parallel.
type nodeMap struct {
	shards [nodeShardCount]*nodeShard
}

func newNodeMap() *nodeMap {
	m := &nodeMap{}
	for i := range m.shards {
		m.shards[i] = &nodeShard{nodes: make(map[uint32]*beaconNode)}
	}
	return m
}

func (m *nodeMap) shardFor(nodeID uint32) *nodeShard {
	return m.shards[nodeID&(nodeShardCount-1)]
}

// Upsert refreshes or inserts a node. maxTotal is the global cap; we
// approximate by capping each shard to maxTotal/nodeShardCount so we
// never have to take all 64 locks. Returns the resulting (post-write)
// state via the inserted/atCapacity flags.
func (m *nodeMap) Upsert(nodeID uint32, addr *net.UDPAddr, now time.Time, maxTotal int) (inserted, atCapacity bool) {
	s := m.shardFor(nodeID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.nodes[nodeID]; ok {
		existing.addr = addr
		existing.lastSeen = now
		return false, false
	}
	if maxTotal > 0 && len(s.nodes) >= maxTotal/nodeShardCount {
		return false, true
	}
	s.nodes[nodeID] = &beaconNode{addr: addr, lastSeen: now}
	return true, false
}

// Get returns the stored node entry or nil. Cheap RLock, no allocation.
func (m *nodeMap) Get(nodeID uint32) *beaconNode {
	s := m.shardFor(nodeID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodes[nodeID]
}

// Has reports whether the node is locally registered.
func (m *nodeMap) Has(nodeID uint32) bool {
	s := m.shardFor(nodeID)
	s.mu.RLock()
	_, ok := s.nodes[nodeID]
	s.mu.RUnlock()
	return ok
}

// Len returns the total number of registered nodes across all shards.
// Cost is O(shardCount) — fine for stats/dashboards, not the hot path.
func (m *nodeMap) Len() int {
	total := 0
	for _, s := range m.shards {
		s.mu.RLock()
		total += len(s.nodes)
		s.mu.RUnlock()
	}
	return total
}

// IDs returns a point-in-time snapshot of every locally registered
// nodeID. Order is undefined. Used by gossip to broadcast our node
// set to peer beacons.
func (m *nodeMap) IDs() []uint32 {
	out := make([]uint32, 0, m.Len())
	for _, s := range m.shards {
		s.mu.RLock()
		for id := range s.nodes {
			out = append(out, id)
		}
		s.mu.RUnlock()
	}
	return out
}

// ReapStale deletes every entry whose lastSeen is strictly before
// threshold. Locks each shard once for the scan; safe to call from a
// timer goroutine while the hot path runs.
func (m *nodeMap) ReapStale(threshold time.Time) int {
	removed := 0
	for _, s := range m.shards {
		s.mu.Lock()
		for id, n := range s.nodes {
			if n.lastSeen.Before(threshold) {
				delete(s.nodes, id)
				removed++
			}
		}
		s.mu.Unlock()
	}
	return removed
}

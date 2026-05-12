// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestNodeMap_ConcurrentUpsert proves the sharded map handles 50k unique
// nodeIDs hammered by many goroutines without losing entries. The pre-shard
// implementation used one RWMutex; this test would still have passed there
// — it's here as a regression guard against future "let's simplify to one
// lock" refactors, since the shape under load is the whole point.
func TestNodeMap_ConcurrentUpsert(t *testing.T) {
	t.Parallel()
	m := newNodeMap()
	const (
		writers       = 64
		nodesPerBatch = 1000
	)
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9001}
	var wg sync.WaitGroup
	var inserted atomic.Int64
	now := time.Now()
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(base uint32) {
			defer wg.Done()
			for i := uint32(0); i < nodesPerBatch; i++ {
				ins, _ := m.Upsert(base*nodesPerBatch+i, addr, now, 0)
				if ins {
					inserted.Add(1)
				}
			}
		}(uint32(w))
	}
	wg.Wait()
	if got, want := int(inserted.Load()), writers*nodesPerBatch; got != want {
		t.Fatalf("inserted=%d want=%d (lost writes)", got, want)
	}
	if got := m.Len(); got != writers*nodesPerBatch {
		t.Fatalf("Len=%d want=%d", got, writers*nodesPerBatch)
	}
}

// TestNodeMap_ReapStale verifies that a stale-threshold sweep removes
// only entries older than the threshold and leaves fresh ones alone.
func TestNodeMap_ReapStale(t *testing.T) {
	t.Parallel()
	m := newNodeMap()
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9001}

	stale := time.Now().Add(-30 * time.Minute)
	fresh := time.Now()
	for i := uint32(0); i < 100; i++ {
		if i%2 == 0 {
			m.Upsert(i, addr, stale, 0)
		} else {
			m.Upsert(i, addr, fresh, 0)
		}
	}
	if got := m.Len(); got != 100 {
		t.Fatalf("pre-reap Len=%d want=100", got)
	}
	threshold := time.Now().Add(-5 * time.Minute)
	removed := m.ReapStale(threshold)
	if removed != 50 {
		t.Fatalf("removed=%d want=50", removed)
	}
	if got := m.Len(); got != 50 {
		t.Fatalf("post-reap Len=%d want=50", got)
	}
}

// TestNodeMap_PerShardCap verifies the approximate per-shard capacity
// enforcement: each shard rejects new inserts past maxTotal/shardCount.
func TestNodeMap_PerShardCap(t *testing.T) {
	t.Parallel()
	m := newNodeMap()
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9001}
	const max = 64 // → 1 entry per shard
	now := time.Now()
	// Fill shard 0 (nodeID%64==0): 0, 64, 128, ...
	if _, atCap := m.Upsert(0, addr, now, max); atCap {
		t.Fatal("first Upsert to empty shard should not be at capacity")
	}
	// Second insert in same shard should hit the per-shard cap.
	if _, atCap := m.Upsert(64, addr, now, max); !atCap {
		t.Fatal("second Upsert to a 1-cap shard should report atCapacity")
	}
	// But a different shard is still empty.
	if _, atCap := m.Upsert(1, addr, now, max); atCap {
		t.Fatal("Upsert to a different empty shard should not be at capacity")
	}
}

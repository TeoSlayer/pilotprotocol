// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// NodeInfo atomic LastSeen
// ---------------------------------------------------------------------------

func TestNodeInfo_AtomicLastSeen(t *testing.T) {
	t.Parallel()
	n := &NodeInfo{}
	now := time.Now()

	// setLastSeen writes both fields
	n.SetLastSeen(now)

	got := n.GetLastSeen()
	if !got.Equal(now) {
		t.Errorf("getLastSeen = %v, want %v", got, now)
	}

	// Direct atomic store (heartbeat path) should also be visible
	later := now.Add(10 * time.Second)
	n.LastSeenNano.Store(later.UnixNano())

	got = n.GetLastSeen()
	if !got.Equal(later) {
		t.Errorf("atomic getLastSeen = %v, want %v", got, later)
	}
}

func TestNodeInfo_GetLastSeen_FallsBackToStructField(t *testing.T) {
	t.Parallel()
	n := &NodeInfo{}
	now := time.Now()

	// Only set the struct field (no atomic), simulating legacy load path
	n.LastSeen = now

	got := n.GetLastSeen()
	if !got.Equal(now) {
		t.Errorf("getLastSeen fallback = %v, want %v", got, now)
	}
}

func TestNodeInfo_AtomicLastSeen_Concurrent(t *testing.T) {
	t.Parallel()
	n := &NodeInfo{}
	base := time.Now()
	n.SetLastSeen(base)

	var wg sync.WaitGroup

	// Simulate concurrent heartbeat updates (atomic store).
	// The final value is whichever goroutine ran last — we just verify
	// no panics/races and the value is one of the written values.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			ts := base.Add(time.Duration(offset) * time.Millisecond)
			n.LastSeenNano.Store(ts.UnixNano())
		}(i)
	}
	wg.Wait()

	// Final value should be at or after the base time
	got := n.GetLastSeen()
	if got.Before(base) {
		t.Errorf("final value %v is before base %v", got, base)
	}
}

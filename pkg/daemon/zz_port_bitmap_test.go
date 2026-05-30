// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// TestAllocEphemeralPort_BitmapMarksAndClears confirms the bitmap allocator's
// round-trip: a newly allocated port shows up as "in use" in the bitmap, and
// RemoveConnection clears it so the next AllocEphemeralPort can hand it back.
//
// Pins the regression vector where the old linear-scan allocator could
// silently hand out the same port twice if the connection had been removed
// from the map but the port hadn't been freed in the (then-implicit) "in use"
// representation. With an explicit bitmap, alloc/free is the only contract.
func TestAllocEphemeralPort_BitmapMarksAndClears(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	addr := protocol.Addr{Network: 0, Node: 1}

	conn := pm.NewConnection(50000, addr, 0)
	pm.mu.RLock()
	w, b := ephBitIndex(50000)
	bit := pm.ephBitmap[w] & (1 << b)
	pm.mu.RUnlock()
	if bit == 0 {
		t.Fatal("NewConnection failed to mark ephemeral port in bitmap")
	}

	pm.RemoveConnection(conn.ID)
	pm.mu.RLock()
	bit = pm.ephBitmap[w] & (1 << b)
	pm.mu.RUnlock()
	if bit != 0 {
		t.Fatal("RemoveConnection failed to clear ephemeral port in bitmap")
	}
}

// TestAllocEphemeralPort_ConcurrentNoCollisions throws many parallel
// AllocEphemeralPort calls at the manager and asserts every returned port is
// unique. The bitmap allocator's write-lock invariant must hold under
// contention — concurrent dials previously serialized behind a 16K-port
// linear scan, and a bug there could have returned the same port twice if
// the lock granularity was wrong.
func TestAllocEphemeralPort_ConcurrentNoCollisions(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()

	const N = 1000
	var (
		mu   sync.Mutex
		seen = make(map[uint16]bool, N)
		dup  uint32
		wg   sync.WaitGroup
	)

	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			port := pm.AllocEphemeralPort()
			if port == 0 {
				return
			}
			mu.Lock()
			if seen[port] {
				atomic.AddUint32(&dup, 1)
			}
			seen[port] = true
			mu.Unlock()
		}()
	}
	wg.Wait()

	if dup != 0 {
		t.Fatalf("AllocEphemeralPort returned %d duplicate(s) under concurrency", dup)
	}
	if len(seen) != N {
		t.Fatalf("expected %d unique allocations, got %d (exhaustion happened too early)", N, len(seen))
	}
}

// TestStaleConnections_SynSentReaped pins the new SYN_SENT timeout behavior.
// A connection sitting in SYN_SENT past SynSentReapDuration must be returned
// by StaleConnections so the idle sweeper can free its ephemeral port. Without
// this, a cold-start dial storm against unreachable peers can pin the entire
// 16K ephemeral pool through the L4 retransmit ladder (~30 s+).
func TestStaleConnections_SynSentReaped(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	addr := protocol.Addr{Network: 0, Node: 7}

	fresh := pm.NewConnection(50001, addr, 1234)
	fresh.Mu.Lock()
	fresh.State = StateSynSent
	fresh.LastActivity = time.Now()
	fresh.Mu.Unlock()

	stuck := pm.NewConnection(50002, addr, 1234)
	stuck.Mu.Lock()
	stuck.State = StateSynSent
	stuck.LastActivity = time.Now().Add(-(SynSentReapDuration + time.Second))
	stuck.Mu.Unlock()

	got := pm.StaleConnections(10 * time.Second)
	var sawStuck, sawFresh bool
	for _, c := range got {
		if c.ID == stuck.ID {
			sawStuck = true
		}
		if c.ID == fresh.ID {
			sawFresh = true
		}
	}
	if !sawStuck {
		t.Errorf("StaleConnections did not return the stale SYN_SENT conn (id=%d)", stuck.ID)
	}
	if sawFresh {
		t.Errorf("StaleConnections returned a SYN_SENT conn within the reap window (id=%d) — should NOT be reaped", fresh.ID)
	}
}

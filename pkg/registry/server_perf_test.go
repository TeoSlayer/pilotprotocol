package registry

import (
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// logSampler
// ---------------------------------------------------------------------------

func TestLogSampler_FirstOccurrenceAlwaysLogs(t *testing.T) {
	t.Parallel()
	ls := newLogSampler(1000)
	ok, count := ls.shouldLog("some-key")
	if !ok {
		t.Fatal("first occurrence should always log")
	}
	if count != 1 {
		t.Errorf("first occurrence count = %d, want 1", count)
	}
}

func TestLogSampler_SuppressesIntermediate(t *testing.T) {
	t.Parallel()
	ls := newLogSampler(100)

	// First call logs
	ok, _ := ls.shouldLog("key")
	if !ok {
		t.Fatal("first call should log")
	}

	// Calls 2-99 should be suppressed
	for i := 2; i < 100; i++ {
		ok, _ = ls.shouldLog("key")
		if ok {
			t.Fatalf("call %d should be suppressed", i)
		}
	}

	// Call 100 should log again (count reached interval)
	ok, count := ls.shouldLog("key")
	if !ok {
		t.Fatal("call at interval should log")
	}
	if count != 100 {
		t.Errorf("interval count = %d, want 100", count)
	}
}

func TestLogSampler_MaxKeysCapBypasses(t *testing.T) {
	t.Parallel()
	ls := newLogSampler(1000)
	ls.maxSamplerKeys = 5

	// Fill up the map with 5 distinct keys
	for i := 0; i < 5; i++ {
		ls.shouldLog(string(rune('a' + i)))
	}

	// 6th key should bypass sampling and always log
	ok, count := ls.shouldLog("overflow-key")
	if !ok {
		t.Fatal("over-cap key should always log")
	}
	if count != 0 {
		t.Errorf("over-cap count = %d, want 0 (bypass)", count)
	}
}

func TestLogSampler_CleanupResetsMap(t *testing.T) {
	t.Parallel()
	ls := newLogSampler(100)
	ls.shouldLog("key")
	ls.shouldLog("key")

	ls.cleanup()

	// After cleanup, first call should log again (fresh count)
	ok, count := ls.shouldLog("key")
	if !ok {
		t.Fatal("post-cleanup first call should log")
	}
	if count != 1 {
		t.Errorf("post-cleanup count = %d, want 1", count)
	}
}

func TestLogSampler_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	ls := newLogSampler(100)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				ls.shouldLog("concurrent-key")
			}
		}()
	}
	wg.Wait()
	// No panic = pass (race detector catches data races)
}

// ---------------------------------------------------------------------------
// NodeInfo atomic LastSeen
// ---------------------------------------------------------------------------

func TestNodeInfo_AtomicLastSeen(t *testing.T) {
	t.Parallel()
	n := &NodeInfo{}
	now := time.Now()

	// setLastSeen writes both fields
	n.setLastSeen(now)

	got := n.getLastSeen()
	if !got.Equal(now) {
		t.Errorf("getLastSeen = %v, want %v", got, now)
	}

	// Direct atomic store (heartbeat path) should also be visible
	later := now.Add(10 * time.Second)
	n.lastSeenNano.Store(later.UnixNano())

	got = n.getLastSeen()
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

	got := n.getLastSeen()
	if !got.Equal(now) {
		t.Errorf("getLastSeen fallback = %v, want %v", got, now)
	}
}

func TestNodeInfo_AtomicLastSeen_Concurrent(t *testing.T) {
	t.Parallel()
	n := &NodeInfo{}
	base := time.Now()
	n.setLastSeen(base)

	var wg sync.WaitGroup

	// Simulate concurrent heartbeat updates (atomic store).
	// The final value is whichever goroutine ran last — we just verify
	// no panics/races and the value is one of the written values.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			ts := base.Add(time.Duration(offset) * time.Millisecond)
			n.lastSeenNano.Store(ts.UnixNano())
		}(i)
	}
	wg.Wait()

	// Final value should be at or after the base time
	got := n.getLastSeen()
	if got.Before(base) {
		t.Errorf("final value %v is before base %v", got, base)
	}
}

// ---------------------------------------------------------------------------
// OperationRateLimiter single-mutex
// ---------------------------------------------------------------------------

func TestOperationRateLimiter_AllowUnregisteredCategory(t *testing.T) {
	t.Parallel()
	orl := NewOperationRateLimiter()
	orl.AddCategory("resolve", 10, time.Minute)

	// Unregistered category should always be allowed
	if !orl.Allow("unknown-category", "1.2.3.4") {
		t.Error("unregistered category should allow")
	}
}

func TestOperationRateLimiter_EnforceLimit(t *testing.T) {
	t.Parallel()
	orl := NewOperationRateLimiter()
	orl.AddCategory("resolve", 5, time.Minute)

	for i := 0; i < 5; i++ {
		if !orl.Allow("resolve", "10.0.0.1") {
			t.Fatalf("request %d should be allowed (within limit)", i+1)
		}
	}
	if orl.Allow("resolve", "10.0.0.1") {
		t.Error("request 6 should be rate-limited")
	}
}

func TestOperationRateLimiter_ConcurrentAllow(t *testing.T) {
	t.Parallel()
	orl := NewOperationRateLimiter()
	orl.AddCategory("resolve", 10000, time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				orl.Allow("resolve", "10.0.0.1")
			}
		}()
	}
	wg.Wait()
	// No panic = pass
}

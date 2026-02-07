package tests

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"web4/pkg/registry"
)

// testClock provides a controllable time source for rate limiter tests.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Now()}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestRateLimiterBasicAllowDeny(t *testing.T) {
	t.Parallel()

	// 5 requests per 1-second window
	rl := registry.NewRateLimiter(5, time.Second)

	ip := "192.168.1.1"

	// First 5 requests should all be allowed
	for i := 0; i < 5; i++ {
		if !rl.Allow(ip) {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	// 6th request should be denied (bucket exhausted)
	if rl.Allow(ip) {
		t.Fatal("6th request should be denied (rate limit exceeded)")
	}
}

func TestRateLimiterTokenRefill(t *testing.T) {
	t.Parallel()

	clk := newTestClock()
	rl := registry.NewRateLimiter(10, 100*time.Millisecond)
	rl.SetClock(clk.Now)

	ip := "10.0.0.1"

	// Exhaust all tokens
	for i := 0; i < 10; i++ {
		if !rl.Allow(ip) {
			t.Fatalf("request %d should be allowed during initial burst", i+1)
		}
	}

	// Verify exhausted
	if rl.Allow(ip) {
		t.Fatal("should be denied after exhaustion")
	}

	// Advance clock past one full window (tokens fully refill)
	clk.Advance(110 * time.Millisecond)

	// Should be allowed again after refill
	if !rl.Allow(ip) {
		t.Fatal("should be allowed after full window refill")
	}
}

func TestRateLimiterPartialRefill(t *testing.T) {
	t.Parallel()

	clk := newTestClock()
	rl := registry.NewRateLimiter(10, 100*time.Millisecond)
	rl.SetClock(clk.Now)

	ip := "10.0.0.2"

	// Exhaust all tokens
	for i := 0; i < 10; i++ {
		rl.Allow(ip)
	}

	// Advance clock by exactly 50% of the window (= 5 tokens refilled)
	clk.Advance(50 * time.Millisecond)

	// Should get exactly 5 tokens back
	allowed := 0
	for i := 0; i < 10; i++ {
		if rl.Allow(ip) {
			allowed++
		}
	}

	if allowed != 5 {
		t.Fatalf("expected 5 tokens after half-window refill, got %d", allowed)
	}
}

func TestRateLimiterCleanup(t *testing.T) {
	t.Parallel()

	clk := newTestClock()
	rl := registry.NewRateLimiter(5, 50*time.Millisecond)
	rl.SetClock(clk.Now)

	// Create entries for two IPs
	rl.Allow("stale-ip")
	rl.Allow("fresh-ip")

	// Advance clock past cleanup threshold (2 * 50ms = 100ms)
	clk.Advance(110 * time.Millisecond)

	// Touch fresh-ip so it stays alive
	rl.Allow("fresh-ip")

	// Run cleanup — stale-ip should be removed, fresh-ip should remain
	rl.Cleanup()

	if rl.HasBucket("stale-ip") {
		t.Fatal("stale-ip should have been cleaned up")
	}
	if !rl.HasBucket("fresh-ip") {
		t.Fatal("fresh-ip should still exist after cleanup")
	}
}

func TestRateLimiterCleanupKeepsRecent(t *testing.T) {
	t.Parallel()

	rl := registry.NewRateLimiter(5, time.Second)

	// Create entries for several IPs
	for i := 0; i < 10; i++ {
		rl.Allow(fmt.Sprintf("ip-%d", i))
	}

	// Run cleanup immediately — all entries are fresh, none should be removed
	rl.Cleanup()

	if rl.BucketCount() != 10 {
		t.Fatalf("expected 10 buckets after cleanup (all fresh), got %d", rl.BucketCount())
	}
}

func TestRateLimiterMultipleIPs(t *testing.T) {
	t.Parallel()

	// 3 requests per second per IP
	rl := registry.NewRateLimiter(3, time.Second)

	ipA := "1.1.1.1"
	ipB := "2.2.2.2"

	// Exhaust IP A
	for i := 0; i < 3; i++ {
		if !rl.Allow(ipA) {
			t.Fatalf("ipA request %d should be allowed", i+1)
		}
	}

	// IP A is now exhausted
	if rl.Allow(ipA) {
		t.Fatal("ipA should be denied after exhaustion")
	}

	// IP B should still have its full budget
	for i := 0; i < 3; i++ {
		if !rl.Allow(ipB) {
			t.Fatalf("ipB request %d should be allowed (independent bucket)", i+1)
		}
	}

	// Now IP B is also exhausted
	if rl.Allow(ipB) {
		t.Fatal("ipB should be denied after exhaustion")
	}
}

func TestRateLimiterBoundaryExactLimit(t *testing.T) {
	t.Parallel()

	// Rate of exactly 1 request per second
	rl := registry.NewRateLimiter(1, time.Second)

	ip := "boundary-ip"

	// First request: allowed (creates bucket with tokens = rate-1 = 0)
	if !rl.Allow(ip) {
		t.Fatal("first request should always be allowed")
	}

	// Second request: denied (0 tokens left, negligible time elapsed)
	if rl.Allow(ip) {
		t.Fatal("second request should be denied with rate=1")
	}
}

func TestRateLimiterTokenCap(t *testing.T) {
	t.Parallel()

	clk := newTestClock()
	rl := registry.NewRateLimiter(5, 50*time.Millisecond)
	rl.SetClock(clk.Now)

	ip := "cap-test"

	// Use 1 token
	rl.Allow(ip)

	// Advance clock by 3 full windows (tokens should cap at rate=5, not grow unbounded)
	clk.Advance(160 * time.Millisecond)

	// Count how many requests are allowed
	allowed := 0
	for i := 0; i < 10; i++ {
		if rl.Allow(ip) {
			allowed++
		}
	}

	// Should be capped at 5 (the rate), not more
	if allowed != 5 {
		t.Fatalf("expected exactly 5 allowed (token cap), got %d", allowed)
	}
}

func TestRateLimiterNewIPAlwaysAllowed(t *testing.T) {
	t.Parallel()

	rl := registry.NewRateLimiter(5, time.Second)

	// Each new IP gets its first request allowed
	for i := 0; i < 100; i++ {
		ip := fmt.Sprintf("new-ip-%d", i)
		if !rl.Allow(ip) {
			t.Fatalf("first request from %s should be allowed", ip)
		}
	}
}

func TestRateLimiterHighRate(t *testing.T) {
	t.Parallel()

	// High rate: 1000 requests per second
	rl := registry.NewRateLimiter(1000, time.Second)

	ip := "high-rate"

	allowed := 0
	for i := 0; i < 1500; i++ {
		if rl.Allow(ip) {
			allowed++
		}
	}

	if allowed != 1000 {
		t.Fatalf("expected exactly 1000 allowed with rate=1000, got %d", allowed)
	}
}

func TestRateLimiterConcurrent(t *testing.T) {
	t.Parallel()

	// 100 requests per second — accessed concurrently
	rl := registry.NewRateLimiter(100, time.Second)

	ip := "concurrent-ip"

	done := make(chan bool, 200)
	for i := 0; i < 200; i++ {
		go func() {
			done <- rl.Allow(ip)
		}()
	}

	allowed := 0
	for i := 0; i < 200; i++ {
		if <-done {
			allowed++
		}
	}

	// Exactly 100 should be allowed (all goroutines fire nearly simultaneously)
	if allowed != 100 {
		t.Fatalf("expected exactly 100 allowed under concurrent access, got %d", allowed)
	}
}

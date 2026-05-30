// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"sync"
	"testing"
	"time"
)

// TestKxRateLimiterBasics verifies that allowKxFromSource correctly accepts
// frames within the per-source-IP budget and rejects excess frames.
func TestKxRateLimiterBasics(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()

	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}

	// First perSourceKxLimit frames should be allowed.
	for i := 0; i < perSourceKxLimit; i++ {
		if !tm.allowKxFromSource(addr) {
			t.Fatalf("frame %d should have been allowed within budget", i+1)
		}
	}

	// Next frame should be rejected (budget exhausted).
	if tm.allowKxFromSource(addr) {
		t.Fatal("frame after budget exhaustion should have been rejected")
	}

	// Different source IP should have its own budget.
	addr2 := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 54321}
	if !tm.allowKxFromSource(addr2) {
		t.Fatal("different source IP should have its own fresh budget")
	}
}

// TestKxRateLimiterRefill verifies that the token bucket refills over time.
func TestKxRateLimiterRefill(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 9999}

	// Exhaust the budget.
	for i := 0; i < perSourceKxLimit; i++ {
		tm.allowKxFromSource(addr)
	}
	if tm.allowKxFromSource(addr) {
		t.Fatal("budget should be exhausted")
	}

	// Wait just over 1 second to guarantee at least 1 token refill.
	time.Sleep(time.Duration(1.05 * float64(time.Second)))

	if !tm.allowKxFromSource(addr) {
		t.Fatal("should have refilled at least 1 token")
	}
}

// TestKxRateLimiterNilAddr verifies that nil addr bypasses the check
// (same convention as relay-delivered frames with unknown beacon).
func TestKxRateLimiterNilAddr(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if !tm.allowKxFromSource(nil) {
		t.Fatal("nil addr should always be allowed")
	}
}

// TestKxRateLimiterConcurrent verifies the rate limiter is safe under
// concurrent access from multiple goroutines.
func TestKxRateLimiterConcurrent(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	var wg sync.WaitGroup
	const concurrency = 32

	// Fire concurrent requests from different IPs simultaneously.
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ip := net.IPv4(10, 0, 0, byte(n%256))
			addr := &net.UDPAddr{IP: ip, Port: 10000 + n}
			for j := 0; j < perSourceKxLimit; j++ {
				tm.allowKxFromSource(addr)
			}
			// Should be blocked now.
			if tm.allowKxFromSource(addr) {
				t.Errorf("goroutine %d: should be rate-limited after budget", n)
			}
		}(i)
	}
	wg.Wait()
}

// TestKxRateLimiterMaxEntries verifies the map cap is enforced.
func TestKxRateLimiterMaxEntries(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()

	// Fill beyond capacity — use /16 subnets to generate unique IPs.
	for i := 0; i < maxPerSrcKxEntries+100; i++ {
		addr := &net.UDPAddr{
			IP:   net.IPv4(byte(i>>8), byte(i&0xff), 0, 1),
			Port: 10000,
		}
		tm.allowKxFromSource(addr)
	}

	// Verify the map didn't grow unboundedly.
	tm.kxRateLimMu.Lock()
	size := len(tm.kxRateLim)
	tm.kxRateLimMu.Unlock()
	if size > maxPerSrcKxEntries+10 {
		t.Fatalf("map grew to %d entries, want ≤ %d", size, maxPerSrcKxEntries+10)
	}
}

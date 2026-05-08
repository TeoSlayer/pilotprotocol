// SPDX-License-Identifier: AGPL-3.0-or-later

package registry

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// --- hashOwner -----------------------------------------------------------

func TestHashOwnerEmptyReturnsEmpty(t *testing.T) {
	if got := hashOwner(""); got != "" {
		t.Fatalf("hashOwner(\"\") = %q, want \"\"", got)
	}
}

func TestHashOwnerDeterministic(t *testing.T) {
	a := hashOwner("teodor@pilotprotocol.network")
	b := hashOwner("teodor@pilotprotocol.network")
	if a != b {
		t.Fatalf("non-deterministic: %q vs %q", a, b)
	}
}

func TestHashOwnerFormat(t *testing.T) {
	h := hashOwner("anyone")
	if !strings.HasPrefix(h, "sha256:") {
		t.Fatalf("missing prefix: %q", h)
	}
	// 4 bytes hex = 8 chars after "sha256:"
	if len(h) != len("sha256:")+8 {
		t.Fatalf("expected truncated 4-byte hex, got %q (len=%d)", h, len(h))
	}
	hex := h[len("sha256:"):]
	for _, r := range hex {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Fatalf("non-hex char %q in %q", r, h)
		}
	}
}

func TestHashOwnerDistinguishesInputs(t *testing.T) {
	a := hashOwner("alice@example.com")
	b := hashOwner("bob@example.com")
	if a == b {
		t.Fatalf("different owners hashed to same value: %q", a)
	}
}

// --- NewRateLimiter defaults ---------------------------------------------

func TestNewRateLimiterInitialState(t *testing.T) {
	rl := NewRateLimiter(5, time.Second, 100)
	if rl == nil {
		t.Fatal("nil RateLimiter")
	}
	if rl.rate != 5 {
		t.Fatalf("rate: %d", rl.rate)
	}
	if rl.window != time.Second {
		t.Fatalf("window: %v", rl.window)
	}
	if rl.maxBuckets != 100 {
		t.Fatalf("maxBuckets: %d", rl.maxBuckets)
	}
	if rl.now == nil {
		t.Fatal("now func not wired")
	}
	if rl.BucketCount() != 0 {
		t.Fatalf("initial BucketCount: %d", rl.BucketCount())
	}
	// Default clock should be time.Now — returns approximately current time.
	now := rl.now()
	if time.Since(now) > 2*time.Second {
		t.Fatalf("default clock looks wrong, returned %v", now)
	}
}

// --- SetClock -------------------------------------------------------------

func TestSetClockOverridesTimeSource(t *testing.T) {
	rl := NewRateLimiter(3, time.Second, 0)
	fixed := time.Unix(1_700_000_000, 0)
	rl.SetClock(func() time.Time { return fixed })

	rl.mu.Lock()
	got := rl.now()
	rl.mu.Unlock()
	if !got.Equal(fixed) {
		t.Fatalf("SetClock didn't apply: %v vs %v", got, fixed)
	}
}

// --- Allow: first-hit bucket creation + decrement ------------------------

func TestAllowFirstRequestCreatesBucketAndConsumes(t *testing.T) {
	rl := NewRateLimiter(5, time.Second, 0)
	if !rl.Allow("1.2.3.4") {
		t.Fatal("first request should be allowed")
	}
	if !rl.HasBucket("1.2.3.4") {
		t.Fatal("bucket not created")
	}
	if rl.BucketCount() != 1 {
		t.Fatalf("BucketCount: %d", rl.BucketCount())
	}
}

func TestAllowMultipleIPsCreateSeparateBuckets(t *testing.T) {
	rl := NewRateLimiter(2, time.Second, 0)
	for _, ip := range []string{"a", "b", "c"} {
		if !rl.Allow(ip) {
			t.Fatalf("Allow(%q) denied on first hit", ip)
		}
	}
	if rl.BucketCount() != 3 {
		t.Fatalf("BucketCount: %d", rl.BucketCount())
	}
}

// --- Allow: exhausts rate within window ----------------------------------

func TestAllowExhaustsRateWithinWindow(t *testing.T) {
	// Freeze time so no tokens refill.
	t0 := time.Unix(1_700_000_000, 0)
	rl := NewRateLimiter(3, time.Second, 0)
	rl.SetClock(func() time.Time { return t0 })

	// First call creates bucket with tokens=rate-1=2. Two more calls deplete.
	// Then the 4th call returns false.
	for i := 0; i < 3; i++ {
		if !rl.Allow("ip") {
			t.Fatalf("Allow #%d should be true (rate=3)", i+1)
		}
	}
	if rl.Allow("ip") {
		t.Fatal("Allow #4 should be denied with rate=3 and no time advancement")
	}
}

// --- Allow: tokens refill as time advances -------------------------------

func TestAllowRefillsProportionalToElapsedTime(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	var now time.Time
	rl := NewRateLimiter(10, time.Second, 0)
	rl.SetClock(func() time.Time { return now })

	now = t0
	// Drain the bucket fully (first call gives rate-1 tokens, then 9 more).
	for i := 0; i < 10; i++ {
		if !rl.Allow("ip") {
			t.Fatalf("drain %d denied", i)
		}
	}
	if rl.Allow("ip") {
		t.Fatal("should be denied after drain, same timestamp")
	}

	// Advance 500ms: refill should be rate * 0.5 = 5 tokens. Allow 5 more.
	now = t0.Add(500 * time.Millisecond)
	for i := 0; i < 5; i++ {
		if !rl.Allow("ip") {
			t.Fatalf("refill call %d should succeed (500ms elapsed = 5 tokens)", i)
		}
	}
	// 6th call should fail — refilled 5, just used 5.
	if rl.Allow("ip") {
		t.Fatal("should be denied after using refilled tokens")
	}
}

func TestAllowTokenCapAtRate(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	var now time.Time
	rl := NewRateLimiter(5, time.Second, 0)
	rl.SetClock(func() time.Time { return now })

	now = t0
	if !rl.Allow("ip") {
		t.Fatal("first allow failed")
	}
	// Advance 10 seconds — refill would be rate*10 = 50 but must cap at rate=5.
	now = t0.Add(10 * time.Second)
	for i := 0; i < 5; i++ {
		if !rl.Allow("ip") {
			t.Fatalf("post-cap allow %d denied", i)
		}
	}
	// 6th call should be denied, proving the cap at b.tokens = float64(rl.rate).
	if rl.Allow("ip") {
		t.Fatal("token cap broken — should deny 6th call after capped refill")
	}
}

// --- Allow: maxBuckets eviction branch -----------------------------------

func TestAllowEvictsStaleBucketsWhenAtCapacity(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	var now time.Time
	rl := NewRateLimiter(2, time.Second, 3) // maxBuckets=3
	rl.SetClock(func() time.Time { return now })

	now = t0
	rl.Allow("a")
	rl.Allow("b")
	rl.Allow("c")
	if rl.BucketCount() != 3 {
		t.Fatalf("BucketCount pre-eviction: %d", rl.BucketCount())
	}

	// Advance past 2*window so all existing buckets are "stale".
	now = t0.Add(5 * time.Second)

	// New IP "d" — at-capacity branch fires; stale a/b/c evicted; d created.
	if !rl.Allow("d") {
		t.Fatal("Allow(d) should succeed after stale eviction")
	}
	if !rl.HasBucket("d") {
		t.Fatal("bucket d should exist")
	}
	// All of a/b/c evicted; only d remains.
	if rl.BucketCount() != 1 {
		t.Fatalf("BucketCount after stale eviction: %d, want 1", rl.BucketCount())
	}
}

func TestAllowRejectsWhenFullAndNoneStale(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	rl := NewRateLimiter(2, time.Second, 3)
	rl.SetClock(func() time.Time { return t0 }) // time never advances

	rl.Allow("a")
	rl.Allow("b")
	rl.Allow("c")
	// Now at capacity with all fresh — new IP "d" should be rejected (hard).
	if rl.Allow("d") {
		t.Fatal("Allow(d) should be hard-rejected when full with no stale buckets")
	}
	if rl.HasBucket("d") {
		t.Fatal("bucket d must NOT be created on hard reject")
	}
	if rl.BucketCount() != 3 {
		t.Fatalf("BucketCount should stay at 3, got %d", rl.BucketCount())
	}
}

// --- Cleanup --------------------------------------------------------------

func TestCleanupRemovesStaleBuckets(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	var now time.Time
	rl := NewRateLimiter(5, time.Second, 0)
	rl.SetClock(func() time.Time { return now })

	now = t0
	rl.Allow("old1")
	rl.Allow("old2")

	// Advance past 2*window — both are stale.
	now = t0.Add(5 * time.Second)
	rl.Allow("fresh") // this bumps lastFill for "fresh" to 5s mark

	rl.Cleanup()

	if rl.HasBucket("old1") || rl.HasBucket("old2") {
		t.Fatal("stale buckets should have been evicted")
	}
	if !rl.HasBucket("fresh") {
		t.Fatal("fresh bucket evicted wrongly")
	}
}

func TestCleanupNoopWhenAllFresh(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	rl := NewRateLimiter(5, time.Second, 0)
	rl.SetClock(func() time.Time { return t0 })

	rl.Allow("a")
	rl.Allow("b")
	rl.Cleanup()
	if rl.BucketCount() != 2 {
		t.Fatalf("Cleanup should not evict fresh buckets, got BucketCount=%d", rl.BucketCount())
	}
}

// --- Concurrent Allow is race-safe --------------------------------------

func TestAllowConcurrentRaceSafe(t *testing.T) {
	rl := NewRateLimiter(1000, time.Second, 0)
	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				rl.Allow(ip)
			}
		}(string(rune('a' + g%10)))
	}
	wg.Wait()
	// Just a race-detector probe — any crash is a fail. Bucket count should be 10.
	if rl.BucketCount() != 10 {
		t.Fatalf("expected 10 distinct-IP buckets, got %d", rl.BucketCount())
	}
}

// --- directory_sync.go: strField / boolField -----------------------------

func TestStrFieldAbsentReturnsEmpty(t *testing.T) {
	if got := strField(nil, "x"); got != "" {
		t.Fatalf("nil map: %q", got)
	}
	if got := strField(map[string]interface{}{}, "missing"); got != "" {
		t.Fatalf("missing key: %q", got)
	}
}

func TestStrFieldPresentReturnsString(t *testing.T) {
	m := map[string]interface{}{"name": "alice"}
	if got := strField(m, "name"); got != "alice" {
		t.Fatalf("got %q", got)
	}
}

func TestStrFieldWrongTypeReturnsEmpty(t *testing.T) {
	m := map[string]interface{}{"port": 8080, "ok": true}
	if got := strField(m, "port"); got != "" {
		t.Fatalf("int cast should fall through to zero value, got %q", got)
	}
	if got := strField(m, "ok"); got != "" {
		t.Fatalf("bool cast should fall through to zero value, got %q", got)
	}
}

func TestBoolFieldAbsentReturnsFalse(t *testing.T) {
	if boolField(nil, "x") {
		t.Fatal("nil map → false expected")
	}
	if boolField(map[string]interface{}{}, "missing") {
		t.Fatal("missing key → false expected")
	}
}

func TestBoolFieldPresentReturnsBool(t *testing.T) {
	m := map[string]interface{}{"enabled": true, "disabled": false}
	if !boolField(m, "enabled") {
		t.Fatal("true value not returned")
	}
	if boolField(m, "disabled") {
		t.Fatal("false value not returned")
	}
}

func TestBoolFieldWrongTypeReturnsFalse(t *testing.T) {
	m := map[string]interface{}{"s": "true", "n": 1}
	if boolField(m, "s") {
		t.Fatal("string \"true\" should NOT decode as bool=true (type assertion fails)")
	}
	if boolField(m, "n") {
		t.Fatal("int 1 should NOT decode as bool=true")
	}
}

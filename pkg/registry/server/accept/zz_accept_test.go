// SPDX-License-Identifier: AGPL-3.0-or-later

package accept

import (
	"crypto/tls"
	"sync"
	"testing"
	"time"
)

// ── RateLimiter tests ─────────────────────────────────────────────────────────

func TestRateLimiterAllow(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(3, time.Second, 0)
	for i := 0; i < 3; i++ {
		if !rl.Allow("192.0.2.1") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestRateLimiterDeny(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(2, time.Second, 0)

	// Exhaust the bucket
	rl.Allow("192.0.2.1")
	rl.Allow("192.0.2.1")

	// Next request should be denied
	if rl.Allow("192.0.2.1") {
		t.Fatal("expected rate limiter to deny request after bucket exhausted")
	}
}

func TestRateLimiterRefillAfterWindow(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Now()
	rl := NewRateLimiter(2, time.Second, 0)
	rl.SetClock(func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	})

	rl.Allow("10.0.0.1")
	rl.Allow("10.0.0.1")
	if rl.Allow("10.0.0.1") {
		t.Fatal("should be denied when bucket empty")
	}

	// Advance time by one full window so tokens refill
	mu.Lock()
	now = now.Add(time.Second)
	mu.Unlock()

	if !rl.Allow("10.0.0.1") {
		t.Fatal("should be allowed after window elapsed")
	}
}

func TestRateLimiterMaxBucketsRejectsNew(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(5, time.Second, 2) // max 2 IPs
	rl.Allow("10.0.0.1")
	rl.Allow("10.0.0.2")
	// Third distinct IP must be rejected (at capacity, no stale entries to evict)
	if rl.Allow("10.0.0.3") {
		t.Fatal("expected new IP to be rejected when at maxBuckets capacity")
	}
}

func TestRateLimiterCleanup(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Now()
	rl := NewRateLimiter(5, 100*time.Millisecond, 0)
	rl.SetClock(func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	})

	rl.Allow("10.0.0.1")

	if rl.BucketCount() != 1 {
		t.Fatalf("expected 1 bucket, got %d", rl.BucketCount())
	}

	// Advance past 2× window so the bucket is stale
	mu.Lock()
	now = now.Add(300 * time.Millisecond)
	mu.Unlock()

	rl.Cleanup()
	if rl.BucketCount() != 0 {
		t.Fatalf("expected 0 buckets after cleanup, got %d", rl.BucketCount())
	}
}

// ── TLS / self-signed cert tests ──────────────────────────────────────────────

func TestGenerateSelfSignedCert(t *testing.T) {
	t.Parallel()
	cert, err := GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert() error: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected at least one DER certificate block")
	}
}

func TestAcceptorSetTLSSelfSigned(t *testing.T) {
	t.Parallel()
	a := NewAcceptor(1000, nil) // dispatcher not needed for TLS config test
	if err := a.SetTLS("", ""); err != nil {
		t.Fatalf("SetTLS(self-signed) error: %v", err)
	}
	if a.TLSConfig() == nil {
		t.Fatal("expected non-nil TLS config after SetTLS")
	}
	if len(a.TLSConfig().Certificates) == 0 {
		t.Fatal("expected at least one certificate in TLS config")
	}
}

func TestAcceptorSetTLSStateTransition(t *testing.T) {
	t.Parallel()
	// Confirm that an Acceptor starts with nil TLS config and transitions
	// to non-nil after SetTLS("", "") (self-signed path).
	_ = func() tls.Certificate { c, _ := GenerateSelfSignedCert(); return c }

	a := NewAcceptor(100, nil)
	if a.TLSConfig() != nil {
		t.Fatal("expected nil TLS config before SetTLS")
	}
	if err := a.SetTLS("", ""); err != nil {
		t.Fatalf("SetTLS: %v", err)
	}
	if a.TLSConfig() == nil {
		t.Fatal("expected non-nil TLS config after SetTLS")
	}
	if len(a.TLSConfig().Certificates) == 0 {
		t.Fatal("TLS config must contain at least one certificate")
	}
}

// ── SanitizeListenAddr tests ──────────────────────────────────────────────────

func TestSanitizeListenAddr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		remote   string
		client   string
		expected string
	}{
		{"1.2.3.4:50000", "1.2.3.4:8080", "1.2.3.4:8080"},
		{"1.2.3.4:50000", "", "1.2.3.4:50000"},
		{"1.2.3.4:50000", "9.9.9.9:9000", "1.2.3.4:9000"}, // IP is sanitized, port kept
		{"bad-addr", "1.2.3.4:8080", "bad-addr"},
	}
	for _, c := range cases {
		got := SanitizeListenAddr(c.remote, c.client)
		if got != c.expected {
			t.Errorf("SanitizeListenAddr(%q, %q) = %q, want %q",
				c.remote, c.client, got, c.expected)
		}
	}
}

// ── logSampler tests ──────────────────────────────────────────────────────────

func TestLogSamplerFirstOccurrenceAlwaysLogs(t *testing.T) {
	t.Parallel()
	ls := newLogSampler(10)
	ok, count := ls.shouldLog("key1")
	if !ok {
		t.Fatal("first occurrence should always log")
	}
	if count != 1 {
		t.Fatalf("expected count=1 on first occurrence, got %d", count)
	}
}

func TestLogSamplerSuppressesIntermediateOccurrences(t *testing.T) {
	t.Parallel()
	ls := newLogSampler(5)
	ls.shouldLog("key") // 1st — logged
	for i := 0; i < 3; i++ {
		ok, _ := ls.shouldLog("key")
		if ok {
			t.Fatalf("occurrence %d should be suppressed", i+2)
		}
	}
	// 5th occurrence hits the interval
	ok, _ := ls.shouldLog("key")
	if !ok {
		t.Fatal("5th occurrence (interval hit) should log")
	}
}

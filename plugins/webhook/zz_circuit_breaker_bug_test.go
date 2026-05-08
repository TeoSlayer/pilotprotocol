// SPDX-License-Identifier: AGPL-3.0-or-later

package webhook

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestWebhookHasNoCircuitBreakerForDeadURL reproduces the
// "every event burns full retry budget against a dead receiver" bug.
//
// Symptom: a webhook URL that is consistently returning 5xx (or
// timing out) gets the FULL retry budget (MaxRetries=3 attempts with
// exponential backoff) per event, forever. With 1024-slot queue + a
// 1 s initial backoff, each dead-server attempt blocks the dispatcher
// goroutine for ~3 s; ~340 events fill the queue, then events drop
// silently. Meanwhile we have made ~1024 × 3 = 3072 HTTP attempts
// against a known-dead URL — wasting CPU, outbound bandwidth, and
// (if the receiver is on the same network) potentially the receiver's
// incoming connection budget.
//
// FIXED (v1.9.1): post() now short-circuits when the breaker is
// open. After CircuitOpenThreshold (5) consecutive total failures,
// every subsequent event hits the breaker check at the top of post()
// and increments CircuitSkips instead of attempting HTTP. The first
// event after circuitCooldown elapses is the probe; success closes
// the breaker.
func TestWebhookHasNoCircuitBreakerForDeadURL(t *testing.T) {
	t.Parallel()
	var calls atomic.Uint32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(500)
	}))
	defer srv.Close()

	wc := NewClient(srv.URL, func() uint32 { return 1 },
		WithRetryBackoff(1*time.Millisecond),
		WithHTTPTimeout(50*time.Millisecond),
		WithCircuitCooldown(10*time.Second))
	defer wc.Close()

	const numEvents = 20
	for i := 0; i < numEvents; i++ {
		wc.Emit("dead-url", i)
	}
	wc.Close() // drain — synchronous wait for dispatcher

	got := calls.Load()
	skips := wc.CircuitSkips()

	// FIXED: ~5 events × 3 retries = 15 POSTs needed to reach the
	// open-threshold; subsequent 15 events short-circuit. Allow some
	// slack — the 5th event might land mid-retry and the next event
	// might still squeeze a probe in.
	maxExpected := uint32(CircuitOpenThreshold*MaxRetries + MaxRetries)
	if got > maxExpected {
		t.Errorf("circuit breaker did not curb POSTs: server got %d, expected <= %d (open=%d × max_retries=%d + slack=%d)",
			got, maxExpected, CircuitOpenThreshold, MaxRetries, MaxRetries)
	}
	if skips == 0 {
		t.Errorf("expected CircuitSkips > 0 after breaker opened; got 0")
	}
	if int(skips)+int(got/MaxRetries) < numEvents-2 {
		t.Errorf("skips (%d) + posts/retries (%d) does not account for ~%d events emitted",
			skips, got/MaxRetries, numEvents)
	}
}

// TestWebhookCircuitClosesOnSuccessAfterCooldown pins the recovery
// half: once the receiver is healthy again and the cooldown has
// elapsed, the very next event probes; on 2xx the breaker resets
// (consecutiveFailures back to 0) and subsequent events flow without
// short-circuiting.
func TestWebhookCircuitClosesOnSuccessAfterCooldown(t *testing.T) {
	t.Parallel()
	var calls atomic.Uint32
	var healthy atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if healthy.Load() {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(500)
	}))
	defer srv.Close()

	wc := NewClient(srv.URL, func() uint32 { return 1 },
		WithRetryBackoff(1*time.Millisecond),
		WithHTTPTimeout(50*time.Millisecond),
		WithCircuitCooldown(50*time.Millisecond))
	defer wc.Close()

	// Phase 1: open the breaker by failing 5+ events.
	for i := 0; i < CircuitOpenThreshold+1; i++ {
		wc.Emit("phase1", i)
	}
	// Wait for the dispatcher to chew through them. Each event takes
	// ~3ms (3 attempts × 1ms backoff). Add slack for goroutine wake.
	time.Sleep(100 * time.Millisecond)
	if wc.circuitOpenUntilNano.Load() == 0 {
		t.Fatalf("expected breaker open after %d failures", CircuitOpenThreshold+1)
	}
	postsBeforeRecovery := calls.Load()

	// Phase 2: receiver recovers; cooldown elapses; next event probes.
	healthy.Store(true)
	time.Sleep(80 * time.Millisecond) // cooldown 50ms + buffer
	wc.Emit("probe", nil)
	wc.Close() // drain

	if wc.circuitOpenUntilNano.Load() != 0 {
		t.Errorf("breaker did not close after successful probe; openUntilNano=%d", wc.circuitOpenUntilNano.Load())
	}
	if wc.consecutiveFailures.Load() != 0 {
		t.Errorf("consecutiveFailures did not reset after success; got %d", wc.consecutiveFailures.Load())
	}
	postsAfterRecovery := calls.Load() - postsBeforeRecovery
	if postsAfterRecovery == 0 {
		t.Errorf("probe event was short-circuited instead of attempted; postsAfterRecovery=0")
	}
}

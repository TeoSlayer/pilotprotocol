// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

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
// timing out) gets the FULL retry budget (webhookMaxRetries=3
// attempts with exponential backoff) per event, forever. With
// 1024-slot queue + a 1 s initial backoff, each dead-server attempt
// blocks the dispatcher goroutine for ~3 s; ~340 events fill the
// queue, then events drop silently. Meanwhile we have made ~1024
// × 3 = 3072 HTTP attempts against a known-dead URL — wasting CPU,
// outbound bandwidth, and (if the receiver is on the same network)
// potentially the receiver's incoming connection budget.
//
// Replication (this test): a 500-returning httptest.Server, 20
// events fired with 1 ms backoff. Without a circuit breaker, the
// server receives 20 × 3 = 60 POSTs. After GREEN, the breaker
// opens after webhookCircuitOpenThreshold (5) consecutive total
// failures and short-circuits every subsequent Emit until the
// cooldown elapses — server should receive ~5 × 3 = 15 POSTs and
// the rest of the events get CircuitSkips++ instead.
//
// What the v1.9.1 fix should change:
//   - Track consecutiveFailures (atomic.Uint32). Each post() that
//     exhausts its retry budget without success increments;
//     each success resets to 0.
//   - When consecutiveFailures >= webhookCircuitOpenThreshold,
//     set circuitOpenUntilNano = now + circuitCooldown.
//   - At the start of post(), if now < circuitOpenUntilNano,
//     skip the HTTP attempt and increment circuitSkips.
//   - On a probe attempt after cooldown that succeeds, reset
//     consecutiveFailures and clear circuitOpenUntilNano.
//
// This test pins the CURRENT (buggy) behavior: server receives the
// full 60 POSTs with no circuit breaker. After GREEN, the assertion
// flips: server receives <= ~20 POSTs and CircuitSkips > 0.
func TestWebhookHasNoCircuitBreakerForDeadURL(t *testing.T) {
	var calls atomic.Uint32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(500)
	}))
	defer srv.Close()

	wc := NewWebhookClient(srv.URL, func() uint32 { return 1 },
		WithRetryBackoff(1*time.Millisecond),
		WithHTTPTimeout(50*time.Millisecond))
	defer wc.Close()

	const numEvents = 20
	for i := 0; i < numEvents; i++ {
		wc.Emit("dead-url", i)
	}
	wc.Close() // drain — synchronous wait for dispatcher

	got := calls.Load()
	skips := wc.CircuitSkips()

	// CURRENT: every event hits webhookMaxRetries (3); no circuit
	// breaker. 20 × 3 = 60 POSTs.
	if got < uint32(numEvents*webhookMaxRetries-2) {
		t.Fatalf("BUG NOT REPRODUCED: server got %d POSTs (expected ~%d for full retry budget); circuit breaker may already exist — flip to GREEN",
			got, numEvents*webhookMaxRetries)
	}
	if skips != 0 {
		t.Fatalf("BUG NOT REPRODUCED: CircuitSkips=%d (stub should be 0); GREEN flips this", skips)
	}
}

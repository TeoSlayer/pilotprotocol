package tests

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
)

// --- regression guards and edge cases ---

// TestWebhookEventIDStartsAtOne verifies that the first emitted event has ID 1,
// not 0. Off-by-one regression guard.
func TestWebhookEventIDStartsAtOne(t *testing.T) {
	t.Parallel()
	var got atomic.Uint64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev daemon.WebhookEvent
		json.Unmarshal(body, &ev)
		got.Store(ev.EventID)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wc := daemon.NewWebhookClient(srv.URL, func() uint32 { return 1 })
	wc.Emit("first.event", nil)
	wc.Close()

	if id := got.Load(); id != 1 {
		t.Fatalf("first event ID: got %d, want 1", id)
	}
}

// TestWebhookRetryMaxThreeAttempts verifies that an all-500 server receives
// exactly 3 POST attempts (no more, no less). Regression guard for infinite
// retry loop or wrong max-retry constant.
func TestWebhookRetryMaxThreeAttempts(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(500)
	}))
	defer srv.Close()

	wc := daemon.NewWebhookClient(srv.URL, func() uint32 { return 1 },
		daemon.WithRetryBackoff(10*time.Millisecond))
	wc.Emit("always-fail", nil)
	wc.Close()

	got := int(attempts.Load())
	if got != 3 {
		t.Fatalf("expected exactly 3 attempts on all-500 server, got %d", got)
	}
}

// TestWebhookConcurrentEmitUniqueIDs verifies that concurrent Emit calls from
// multiple goroutines produce unique, non-zero event IDs. Race detector will
// catch any unsafe access.
func TestWebhookConcurrentEmitUniqueIDs(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	ids := make(map[uint64]bool)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev daemon.WebhookEvent
		json.Unmarshal(body, &ev)
		mu.Lock()
		ids[ev.EventID] = true
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wc := daemon.NewWebhookClient(srv.URL, func() uint32 { return 1 })

	const goroutines = 20
	const eventsEach = 5
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < eventsEach; i++ {
				wc.Emit("concurrent.event", nil)
			}
		}()
	}
	wg.Wait()
	wc.Close()

	mu.Lock()
	defer mu.Unlock()

	total := goroutines * eventsEach
	if len(ids) != total {
		t.Fatalf("expected %d unique event IDs, got %d (duplicates present)", total, len(ids))
	}
	for id := range ids {
		if id == 0 {
			t.Fatal("event ID 0 found — IDs must start at 1")
		}
	}
}

// TestWebhookEventDataPreserved verifies that structured data in an event
// survives the JSON encode/decode round-trip intact.
func TestWebhookEventDataPreserved(t *testing.T) {
	t.Parallel()

	type payload struct {
		Key   string `json:"key"`
		Value int    `json:"value"`
	}

	received := make(chan map[string]interface{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var raw map[string]interface{}
		json.Unmarshal(body, &raw)
		received <- raw
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wc := daemon.NewWebhookClient(srv.URL, func() uint32 { return 42 })
	wc.Emit("data.test", payload{Key: "hello", Value: 99})
	wc.Close()

	select {
	case raw := <-received:
		data, ok := raw["data"].(map[string]interface{})
		if !ok {
			t.Fatalf("data field missing or wrong type: %v", raw["data"])
		}
		if data["key"] != "hello" {
			t.Errorf("key: got %v, want hello", data["key"])
		}
		if int(data["value"].(float64)) != 99 {
			t.Errorf("value: got %v, want 99", data["value"])
		}
		if nodeID := uint32(raw["node_id"].(float64)); nodeID != 42 {
			t.Errorf("node_id: got %d, want 42", nodeID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for webhook event")
	}
}

// TestWebhookStressHighVolume emits a large burst of events and verifies that
// delivered + dropped == total emitted (no events silently lost or double-counted).
func TestWebhookStressHighVolume(t *testing.T) {
	t.Parallel()

	var delivered atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wc := daemon.NewWebhookClient(srv.URL, func() uint32 { return 1 })

	const total = 5000
	for i := 0; i < total; i++ {
		wc.Emit("stress.event", nil)
	}
	wc.Close()

	got := delivered.Load() + int64(wc.Dropped())
	// Allow ±1 because the first event may be in-flight when Close() drains
	if got < total-1 || got > total {
		t.Fatalf("delivered(%d) + dropped(%d) = %d, want ~%d", delivered.Load(), wc.Dropped(), got, total)
	}
}

// TestWebhookDroppedCounterAccurate verifies that at least 1 event is counted
// as dropped when the queue overflows while the worker is blocked by a slow server.
func TestWebhookDroppedCounterAccurate(t *testing.T) {
	t.Parallel()

	ready := make(chan struct{})
	var blockOnce sync.Once
	block := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Signal that first request arrived, then block
		select {
		case <-ready:
		default:
			close(ready)
		}
		<-block
		w.WriteHeader(200)
	}))
	defer srv.Close()
	defer blockOnce.Do(func() { close(block) })

	wc := daemon.NewWebhookClient(srv.URL, func() uint32 { return 1 },
		daemon.WithHTTPTimeout(200*time.Millisecond),
		daemon.WithRetryBackoff(10*time.Millisecond))

	// Emit the first event to get the worker goroutine into the blocked HTTP request
	wc.Emit("trigger", nil)

	// Wait until the worker is actually blocked in the server
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for worker to start sending")
	}

	// Now fill the 1024-item queue completely and add more to force drops
	for i := 0; i < 1026; i++ {
		wc.Emit("fill.exact", nil)
	}
	time.Sleep(10 * time.Millisecond)

	dropped := wc.Dropped()
	if dropped == 0 {
		t.Fatal("expected at least 1 dropped event when queue is overfull")
	}
	t.Logf("dropped %d events", dropped)

	blockOnce.Do(func() { close(block) }) // unblock server so queued events drain with 200 OK
	wc.Close()
}

// TestWebhookNilEmitAfterClose verifies that emitting after Close is a no-op
// and does not panic or increment dropped counter.
func TestWebhookNilEmitAfterClose(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wc := daemon.NewWebhookClient(srv.URL, func() uint32 { return 1 })
	wc.Close()

	// Should not panic, should not increment dropped
	wc.Emit("post-close", nil)
	wc.Emit("post-close-2", map[string]interface{}{"x": 1})

	if wc.Dropped() != 0 {
		t.Fatalf("emit after close should not increment dropped counter, got %d", wc.Dropped())
	}
}

// TestWebhookIDsSequentialNoGaps verifies that IDs 1..N are all present
// with no gaps when events are delivered in order.
func TestWebhookIDsSequentialNoGaps(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var ids []uint64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev daemon.WebhookEvent
		json.Unmarshal(body, &ev)
		mu.Lock()
		ids = append(ids, ev.EventID)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	const n = 50
	wc := daemon.NewWebhookClient(srv.URL, func() uint32 { return 1 })
	for i := 0; i < n; i++ {
		wc.Emit("seq.event", nil)
	}
	wc.Close()

	mu.Lock()
	defer mu.Unlock()

	if len(ids) != n {
		t.Fatalf("expected %d events, got %d", n, len(ids))
	}
	seen := make(map[uint64]bool, n)
	for _, id := range ids {
		seen[id] = true
	}
	for i := uint64(1); i <= n; i++ {
		if !seen[i] {
			t.Errorf("missing event ID %d (gap in sequence)", i)
		}
	}
}

func TestWebhookEventIDMonotonic(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var events []daemon.WebhookEvent

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev daemon.WebhookEvent
		json.Unmarshal(body, &ev)
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wc := daemon.NewWebhookClient(srv.URL, func() uint32 { return 1 })
	for i := 0; i < 10; i++ {
		wc.Emit("test.event", nil)
	}
	wc.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 10 {
		t.Fatalf("expected 10 events, got %d", len(events))
	}
	for i, ev := range events {
		expected := uint64(i + 1)
		if ev.EventID != expected {
			t.Errorf("event %d: expected ID %d, got %d", i, expected, ev.EventID)
		}
	}
}

func TestWebhookRetryOn5xx(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n <= 2 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wc := daemon.NewWebhookClient(srv.URL, func() uint32 { return 1 },
		daemon.WithRetryBackoff(10*time.Millisecond))
	wc.Emit("retry.test", nil)
	wc.Close()

	got := int(attempts.Load())
	if got != 3 {
		t.Fatalf("expected 3 attempts (2 failures + 1 success), got %d", got)
	}
}

func TestWebhookNoRetryOn4xx(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(400)
	}))
	defer srv.Close()

	wc := daemon.NewWebhookClient(srv.URL, func() uint32 { return 1 })
	wc.Emit("noretry.test", nil)
	wc.Close()

	got := int(attempts.Load())
	if got != 1 {
		t.Fatalf("expected 1 attempt (no retry on 4xx), got %d", got)
	}
}

// TestWebhookBackoffTiming verifies that retry backoff follows the expected
// exponential pattern: ~1s between attempt 1→2, ~2s between attempt 2→3.
func TestWebhookBackoffTiming(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var timestamps []time.Time

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		timestamps = append(timestamps, time.Now())
		mu.Unlock()
		w.WriteHeader(500) // always fail → 3 retries
	}))
	defer srv.Close()

	wc := daemon.NewWebhookClient(srv.URL, func() uint32 { return 1 })
	wc.Emit("backoff.test", nil)
	wc.Close()

	mu.Lock()
	defer mu.Unlock()

	if len(timestamps) != 3 {
		t.Fatalf("expected 3 attempts, got %d", len(timestamps))
	}

	// Backoff: 1s after first failure, 2s after second failure
	// Allow ±500ms tolerance for scheduling jitter
	gap1 := timestamps[1].Sub(timestamps[0])
	gap2 := timestamps[2].Sub(timestamps[1])

	if gap1 < 800*time.Millisecond || gap1 > 1500*time.Millisecond {
		t.Errorf("first backoff gap: got %v, want ~1s", gap1)
	}
	if gap2 < 1800*time.Millisecond || gap2 > 2500*time.Millisecond {
		t.Errorf("second backoff gap: got %v, want ~2s", gap2)
	}
	t.Logf("backoff gaps: %v, %v", gap1, gap2)
}

// TestWebhookConcurrentEmitClose verifies that calling Emit from multiple
// goroutines while Close is called concurrently does not panic or race.
func TestWebhookConcurrentEmitClose(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wc := daemon.NewWebhookClient(srv.URL, func() uint32 { return 1 })

	var wg sync.WaitGroup

	// Spawn goroutines that emit continuously
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				wc.Emit("race.event", nil)
			}
		}()
	}

	// Close concurrently while emitters are running
	time.Sleep(5 * time.Millisecond)
	wc.Close()

	wg.Wait()
	// If we reach here without panic, the test passes
}

// TestWebhookEventOrderPreserved verifies that when the server is fast enough,
// events are delivered in the same order they were emitted (FIFO channel).
func TestWebhookEventOrderPreserved(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var receivedIDs []uint64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev daemon.WebhookEvent
		json.Unmarshal(body, &ev)
		mu.Lock()
		receivedIDs = append(receivedIDs, ev.EventID)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	const n = 100
	wc := daemon.NewWebhookClient(srv.URL, func() uint32 { return 1 })
	for i := 0; i < n; i++ {
		wc.Emit("order.event", nil)
	}
	wc.Close()

	mu.Lock()
	defer mu.Unlock()

	if len(receivedIDs) != n {
		t.Fatalf("expected %d events, got %d", n, len(receivedIDs))
	}
	// Verify strictly increasing order (single-goroutine consumer guarantees FIFO)
	for i := 1; i < len(receivedIDs); i++ {
		if receivedIDs[i] <= receivedIDs[i-1] {
			t.Fatalf("event %d (ID=%d) not after event %d (ID=%d) — order violated",
				i, receivedIDs[i], i-1, receivedIDs[i-1])
		}
	}
}

func TestWebhookDroppedCounter(t *testing.T) {
	t.Parallel()

	// Create a server that blocks forever so the queue fills up
	var blockOnce sync.Once
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // block until test ends
		w.WriteHeader(200)
	}))
	defer srv.Close()
	defer blockOnce.Do(func() { close(block) })

	wc := daemon.NewWebhookClient(srv.URL, func() uint32 { return 1 },
		daemon.WithHTTPTimeout(200*time.Millisecond),
		daemon.WithRetryBackoff(10*time.Millisecond))

	// Fill the 1024-item buffer. The first event will be consumed by the run
	// goroutine and block in post(), so we need 1024+1 more to fill the queue
	// and get one drop.
	for i := 0; i < 1030; i++ {
		wc.Emit("fill.test", nil)
	}

	// Give goroutine time to process
	time.Sleep(50 * time.Millisecond)

	dropped := wc.Dropped()
	if dropped == 0 {
		t.Fatal("expected at least 1 dropped event, got 0")
	}
	t.Logf("dropped %d events as expected", dropped)

	blockOnce.Do(func() { close(block) }) // unblock server so queued events drain with 200 OK
	wc.Close()
}

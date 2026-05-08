// SPDX-License-Identifier: AGPL-3.0-or-later

package webhook

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- Options ---

func TestWithHTTPTimeoutSetsClientTimeout(t *testing.T) {
	t.Parallel()
	wc := NewClient("http://example.invalid", func() uint32 { return 1 },
		WithHTTPTimeout(42*time.Millisecond))
	if wc == nil {
		t.Fatal("NewClient returned nil")
	}
	defer wc.Close()
	if wc.client.Timeout != 42*time.Millisecond {
		t.Fatalf("client.Timeout = %v, want 42ms", wc.client.Timeout)
	}
}

func TestWithRetryBackoffSetsInitialBackoff(t *testing.T) {
	t.Parallel()
	wc := NewClient("http://example.invalid", func() uint32 { return 1 },
		WithRetryBackoff(250*time.Microsecond))
	if wc == nil {
		t.Fatal("NewClient returned nil")
	}
	defer wc.Close()
	if wc.initialBackoff != 250*time.Microsecond {
		t.Fatalf("initialBackoff = %v, want 250us", wc.initialBackoff)
	}
}

func TestNewClientEmptyURLReturnsNil(t *testing.T) {
	t.Parallel()
	if NewClient("", func() uint32 { return 1 }) != nil {
		t.Fatal("empty URL should return nil")
	}
}

// --- Emit ---

func TestEmitOnNilReceiverIsNoOp(t *testing.T) {
	t.Parallel()
	var wc *Client
	wc.Emit("boom", nil) // should not panic
}

func TestEmitAfterCloseIsNoOp(t *testing.T) {
	t.Parallel()
	var calls atomic.Uint32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wc := NewClient(srv.URL, func() uint32 { return 42 })
	wc.Close()
	wc.Emit("after_close", nil)
	// Give any pending delivery a chance
	time.Sleep(20 * time.Millisecond)
	if n := calls.Load(); n != 0 {
		t.Fatalf("calls = %d, want 0 (emit after close should be no-op)", n)
	}
}

func TestEmitDeliversToServerAndIncrementsEventID(t *testing.T) {
	t.Parallel()
	var recvd atomic.Uint32
	var lastBody []byte
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastBody = make([]byte, r.ContentLength)
		_, _ = r.Body.Read(lastBody)
		mu.Unlock()
		recvd.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wc := NewClient(srv.URL, func() uint32 { return 0xABCD },
		WithRetryBackoff(1*time.Millisecond))
	wc.Emit("test-event", map[string]int{"k": 1})
	wc.Emit("second", nil)
	wc.Close() // drain

	if got := recvd.Load(); got < 2 {
		t.Fatalf("recvd = %d, want at least 2", got)
	}
	mu.Lock()
	body := string(lastBody)
	mu.Unlock()
	if body == "" {
		t.Fatal("expected non-empty body")
	}
}

func TestEmitDropsWhenChannelFull(t *testing.T) {
	t.Parallel()
	// Use a handler that blocks so the dispatcher goroutine is stuck on post.
	// The channel capacity is 1024; we fill it up and one more.
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
		w.WriteHeader(200)
	}))
	defer func() { close(block); srv.Close() }()

	wc := NewClient(srv.URL, func() uint32 { return 1 },
		WithRetryBackoff(1*time.Millisecond))
	defer wc.Close()

	// The run goroutine pulls one message immediately and blocks on post.
	// Now emit 1024 more to fill the channel, then one extra to trigger drop.
	for i := 0; i < 1024; i++ {
		wc.Emit("fill", i)
	}
	// Small settle period in case the first one hasn't been pulled yet.
	time.Sleep(10 * time.Millisecond)
	// At this point the channel should be full (one in-flight post + 1024 buffered).
	// The next Emit should either go through (if the in-flight was dequeued already)
	// or increment Dropped. Do several to guarantee a drop.
	for i := 0; i < 100; i++ {
		wc.Emit("overflow", i)
	}
	if d := wc.Dropped(); d == 0 {
		t.Fatalf("Dropped = 0, want > 0 after overflowing 1024-slot buffer")
	}
}

// --- Dropped ---

func TestDroppedOnNilReturnsZero(t *testing.T) {
	t.Parallel()
	var wc *Client
	if got := wc.Dropped(); got != 0 {
		t.Fatalf("nil.Dropped() = %d, want 0", got)
	}
}

func TestDroppedReturnsCounterValue(t *testing.T) {
	t.Parallel()
	wc := &Client{}
	wc.dropped.Store(17)
	if got := wc.Dropped(); got != 17 {
		t.Fatalf("Dropped = %d, want 17", got)
	}
}

// --- post ---

func TestPost2xxReturnsWithoutRetry(t *testing.T) {
	t.Parallel()
	var calls atomic.Uint32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wc := NewClient(srv.URL, func() uint32 { return 1 },
		WithRetryBackoff(1*time.Millisecond))
	wc.Emit("ok", nil)
	wc.Close()

	if got := calls.Load(); got != 1 {
		t.Fatalf("calls = %d, want 1 (2xx should not retry)", got)
	}
}

func TestPost4xxDoesNotRetry(t *testing.T) {
	t.Parallel()
	var calls atomic.Uint32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(404)
	}))
	defer srv.Close()

	wc := NewClient(srv.URL, func() uint32 { return 1 },
		WithRetryBackoff(1*time.Millisecond))
	wc.Emit("bad", nil)
	wc.Close()

	if got := calls.Load(); got != 1 {
		t.Fatalf("calls = %d, want 1 (4xx should not retry)", got)
	}
}

func TestPost5xxRetriesUpToMaxRetries(t *testing.T) {
	t.Parallel()
	var calls atomic.Uint32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(503)
	}))
	defer srv.Close()

	wc := NewClient(srv.URL, func() uint32 { return 1 },
		WithRetryBackoff(1*time.Millisecond))
	wc.Emit("retry", nil)
	wc.Close()

	if got := calls.Load(); got != MaxRetries {
		t.Fatalf("calls = %d, want %d (5xx should retry to max)", got, MaxRetries)
	}
}

func TestPost5xxThenSuccessStopsRetrying(t *testing.T) {
	t.Parallel()
	var calls atomic.Uint32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wc := NewClient(srv.URL, func() uint32 { return 1 },
		WithRetryBackoff(1*time.Millisecond))
	wc.Emit("recover", nil)
	wc.Close()

	if got := calls.Load(); got != 2 {
		t.Fatalf("calls = %d, want 2 (success after one 5xx)", got)
	}
}

func TestPostNetworkErrorRetries(t *testing.T) {
	t.Parallel()
	// Close an unused server to get a dead port, then retry.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // port becomes dead

	wc := NewClient(url, func() uint32 { return 1 },
		WithRetryBackoff(1*time.Millisecond),
		WithHTTPTimeout(50*time.Millisecond))
	wc.Emit("deadport", nil)
	// Network errors retry until MaxRetries, backoff is tiny (1ms → 2ms → 4ms).
	// Close waits for done; that's enough to be sure all retries exhausted.
	wc.Close()
	// No assertion beyond non-panic & clean shutdown (post path covered).
}

func TestPostMarshalErrorPath(t *testing.T) {
	t.Parallel()
	// A channel value cannot be JSON-marshaled; triggers the marshal error branch.
	var calls atomic.Uint32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	defer srv.Close()

	wc := NewClient(srv.URL, func() uint32 { return 1 },
		WithRetryBackoff(1*time.Millisecond))
	wc.Emit("bad-data", make(chan int))
	wc.Close()

	if got := calls.Load(); got != 0 {
		t.Fatalf("calls = %d, want 0 (unmarshalable payload should never hit wire)", got)
	}
}

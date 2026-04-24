// SPDX-License-Identifier: AGPL-3.0-or-later

package registry

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// --- newRegistryWebhook + Close ------------------------------------------

func TestNewRegistryWebhookHasDefaults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wh := newRegistryWebhook(srv.URL)
	defer wh.Close()

	if wh.url != srv.URL {
		t.Fatalf("url: %q", wh.url)
	}
	if cap(wh.ch) != 1024 {
		t.Fatalf("channel buffer: %d", cap(wh.ch))
	}
	if wh.dlqMax != 100 {
		t.Fatalf("dlqMax: %d", wh.dlqMax)
	}
	if wh.initialBackoff != regWebhookInitialBackoff {
		t.Fatalf("initialBackoff: %v", wh.initialBackoff)
	}
}

func TestCloseNilSafe(t *testing.T) {
	var wh *registryWebhook
	wh.Close() // should not panic
}

func TestEmitNilSafe(t *testing.T) {
	var wh *registryWebhook
	wh.Emit("x", nil)
}

func TestDLQNilSafe(t *testing.T) {
	var wh *registryWebhook
	if got := wh.DLQ(); got != nil {
		t.Fatalf("DLQ on nil: %v", got)
	}
}

func TestStatsNilSafe(t *testing.T) {
	var wh *registryWebhook
	d, f, dr := wh.Stats()
	if d != 0 || f != 0 || dr != 0 {
		t.Fatalf("Stats on nil: %d %d %d", d, f, dr)
	}
}

// --- Emit populates event fields and is idempotent after Close ----------

func TestEmitAfterCloseIsNoop(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wh := newRegistryWebhook(srv.URL)
	wh.Close()
	wh.Emit("post-close", nil)
	time.Sleep(50 * time.Millisecond)
	if got := received.Load(); got != 0 {
		t.Fatalf("post-close Emit should not deliver, got %d POSTs", got)
	}
}

// --- Emit drops when queue is full --------------------------------------

func TestEmitDropsWhenQueueFull(t *testing.T) {
	// Construct without the run goroutine so ch fills up and stays full.
	wh := &registryWebhook{
		url:    "unused",
		ch:     make(chan *RegistryWebhookEvent, 2),
		done:   make(chan struct{}),
		closed: make(chan struct{}),
		dlqMax: 100,
	}
	for i := 0; i < 10; i++ {
		wh.Emit("x", nil)
	}
	_, _, dropped := wh.Stats()
	if dropped < 8 {
		t.Fatalf("expected >= 8 dropped, got %d", dropped)
	}
}

// --- post() direct calls: success / 4xx / 5xx retries -------------------

func TestPostDeliversOn2xx(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wh := newRegistryWebhook(srv.URL)
	defer wh.Close()
	wh.initialBackoff = time.Millisecond
	wh.post(&RegistryWebhookEvent{EventID: 1, Action: "ping", Timestamp: time.Now()})

	d, f, _ := wh.Stats()
	if d != 1 || f != 0 {
		t.Fatalf("delivered=%d failed=%d, want 1/0", d, f)
	}
	if hits.Load() != 1 {
		t.Fatalf("server hits: %d", hits.Load())
	}
}

func TestPost4xxAddsToDLQAndStopsImmediately(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(400)
	}))
	defer srv.Close()

	wh := newRegistryWebhook(srv.URL)
	defer wh.Close()
	wh.initialBackoff = time.Millisecond
	wh.post(&RegistryWebhookEvent{EventID: 2, Action: "bad"})

	_, failed, _ := wh.Stats()
	if failed != 1 {
		t.Fatalf("failed: %d", failed)
	}
	if hits.Load() != 1 {
		t.Fatalf("4xx should NOT retry; server hits=%d want 1", hits.Load())
	}
	if got := wh.DLQ(); len(got) != 1 || got[0].EventID != 2 {
		t.Fatalf("DLQ: %+v", got)
	}
}

func TestPost5xxRetriesThenDLQs(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(500)
	}))
	defer srv.Close()

	wh := newRegistryWebhook(srv.URL)
	defer wh.Close()
	wh.initialBackoff = time.Millisecond
	wh.post(&RegistryWebhookEvent{EventID: 3, Action: "server-err"})

	_, failed, _ := wh.Stats()
	if failed != 1 {
		t.Fatalf("failed: %d", failed)
	}
	if hits.Load() != regWebhookMaxRetries {
		t.Fatalf("expected %d attempts, got %d", regWebhookMaxRetries, hits.Load())
	}
	if got := wh.DLQ(); len(got) != 1 {
		t.Fatalf("DLQ size: %d", len(got))
	}
}

func TestPostNetworkFailureRetriesThenDLQs(t *testing.T) {
	// Listener bound then closed → connection refused on every attempt.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	srv.Close()

	wh := newRegistryWebhook(url)
	defer wh.Close()
	wh.initialBackoff = time.Millisecond
	wh.post(&RegistryWebhookEvent{EventID: 4, Action: "refused"})

	_, failed, _ := wh.Stats()
	if failed != 1 {
		t.Fatalf("failed: %d", failed)
	}
	if got := wh.DLQ(); len(got) != 1 {
		t.Fatalf("expected refused event to land in DLQ; got %d", len(got))
	}
}

// --- addToDLQ trim-oldest + DLQ returns copy -----------------------------

func TestAddToDLQTrimsOldestWhenFull(t *testing.T) {
	wh := &registryWebhook{dlqMax: 3}
	for i := 1; i <= 5; i++ {
		wh.addToDLQ(&RegistryWebhookEvent{EventID: uint64(i)})
	}
	got := wh.DLQ()
	if len(got) != 3 {
		t.Fatalf("DLQ size: %d", len(got))
	}
	// Oldest 2 (IDs 1,2) should be dropped; remaining should be 3,4,5 in order.
	for i, want := range []uint64{3, 4, 5} {
		if got[i].EventID != want {
			t.Fatalf("DLQ[%d].EventID = %d, want %d", i, got[i].EventID, want)
		}
	}
}

func TestDLQReturnsCopy(t *testing.T) {
	wh := &registryWebhook{dlqMax: 2}
	wh.addToDLQ(&RegistryWebhookEvent{EventID: 1})
	got := wh.DLQ()
	if len(got) != 1 {
		t.Fatalf("unexpected: %d", len(got))
	}
	got[0] = nil // mutate copy
	again := wh.DLQ()
	if again[0] == nil || again[0].EventID != 1 {
		t.Fatalf("internal DLQ leaked: %v", again)
	}
}

// --- Stats reads atomics --------------------------------------------------

func TestStatsReadsAtomicCounters(t *testing.T) {
	wh := &registryWebhook{}
	wh.delivered.Store(7)
	wh.failed.Store(3)
	wh.dropped.Store(2)
	d, f, dr := wh.Stats()
	if d != 7 || f != 3 || dr != 2 {
		t.Fatalf("stats: %d %d %d", d, f, dr)
	}
}

// --- Emit+run end-to-end (async) -----------------------------------------

func TestEmitAsyncDelivery(t *testing.T) {
	done := make(chan struct{})
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if received.Add(1) == 1 {
			close(done)
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wh := newRegistryWebhook(srv.URL)
	defer wh.Close()
	wh.Emit("hello", map[string]interface{}{"k": "v"})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("async delivery timed out")
	}
	// eventID monotonic
	wh.Emit("two", nil)
	if wh.nextID.Load() < 2 {
		t.Fatalf("nextID: %d", wh.nextID.Load())
	}
}

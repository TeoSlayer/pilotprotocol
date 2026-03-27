package daemon

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// WebhookEvent is the JSON payload POSTed to the webhook endpoint.
type WebhookEvent struct {
	EventID   uint64      `json:"event_id"`
	Event     string      `json:"event"`
	NodeID    uint32      `json:"node_id"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data,omitempty"`
}

// WebhookClient dispatches events asynchronously to an HTTP(S) endpoint.
// If URL is empty, all methods are no-ops (zero overhead when disabled).
type WebhookClient struct {
	url       string
	ch        chan *WebhookEvent
	client    *http.Client
	done      chan struct{}
	nodeID    func() uint32
	closeOnce sync.Once
	closed    chan struct{} // closed when Close is called, guards Emit
	nextID    atomic.Uint64
	dropped   atomic.Uint64
}

// NewWebhookClient creates a webhook dispatcher. If url is empty, returns nil.
func NewWebhookClient(url string, nodeIDFunc func() uint32) *WebhookClient {
	if url == "" {
		return nil
	}
	wc := &WebhookClient{
		url:    url,
		ch:     make(chan *WebhookEvent, 1024),
		client: &http.Client{Timeout: 5 * time.Second},
		done:   make(chan struct{}),
		nodeID: nodeIDFunc,
		closed: make(chan struct{}),
	}
	go wc.run()
	return wc
}

// Emit queues an event for async delivery. Non-blocking; drops if buffer full.
// Safe to call after Close (becomes a no-op).
func (wc *WebhookClient) Emit(event string, data interface{}) {
	if wc == nil {
		return
	}
	select {
	case <-wc.closed:
		return // already closed
	default:
	}
	ev := &WebhookEvent{
		EventID:   wc.nextID.Add(1),
		Event:     event,
		NodeID:    wc.nodeID(),
		Timestamp: time.Now().UTC(),
		Data:      data,
	}
	select {
	case wc.ch <- ev:
	case <-wc.closed:
	default:
		wc.dropped.Add(1)
		slog.Warn("webhook queue full, dropping event", "event", event)
	}
}

// Dropped returns the number of events dropped due to a full queue. Nil-safe.
func (wc *WebhookClient) Dropped() uint64 {
	if wc == nil {
		return 0
	}
	return wc.dropped.Load()
}

// Close drains the queue and stops the background goroutine. Idempotent.
// Waits up to 5 seconds for the queue to drain before abandoning remaining events.
func (wc *WebhookClient) Close() {
	if wc == nil {
		return
	}
	wc.closeOnce.Do(func() {
		close(wc.closed)
		close(wc.ch)
	})
	select {
	case <-wc.done:
	case <-time.After(5 * time.Second):
		slog.Warn("webhook drain timeout, abandoning remaining events")
	}
}

func (wc *WebhookClient) run() {
	defer close(wc.done)
	for ev := range wc.ch {
		wc.post(ev)
	}
}

const (
	webhookMaxRetries    = 3
	webhookInitialBackoff = 1 * time.Second
)

func (wc *WebhookClient) post(ev *WebhookEvent) {
	body, err := json.Marshal(ev)
	if err != nil {
		slog.Warn("webhook marshal error", "event", ev.Event, "error", err)
		return
	}

	backoff := webhookInitialBackoff
	for attempt := 0; attempt < webhookMaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}

		resp, err := wc.client.Post(wc.url, "application/json", bytes.NewReader(body))
		if err != nil {
			slog.Warn("webhook POST failed", "event", ev.Event, "attempt", attempt+1, "error", err)
			continue // network error → retry
		}
		resp.Body.Close()

		if resp.StatusCode < 400 {
			return // success
		}
		if resp.StatusCode < 500 {
			// 4xx — permanent client error, no retry
			slog.Warn("webhook POST client error", "event", ev.Event, "status", resp.StatusCode)
			return
		}
		// 5xx — server error, retry
		slog.Warn("webhook POST server error", "event", ev.Event, "status", resp.StatusCode, "attempt", attempt+1)
	}
}

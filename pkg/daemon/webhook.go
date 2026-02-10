package daemon

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// WebhookEvent is the JSON payload POSTed to the webhook endpoint.
type WebhookEvent struct {
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
		Event:     event,
		NodeID:    wc.nodeID(),
		Timestamp: time.Now().UTC(),
		Data:      data,
	}
	select {
	case wc.ch <- ev:
	case <-wc.closed:
	default:
		slog.Warn("webhook queue full, dropping event", "event", event)
	}
}

// Close drains the queue and stops the background goroutine. Idempotent.
func (wc *WebhookClient) Close() {
	if wc == nil {
		return
	}
	wc.closeOnce.Do(func() {
		close(wc.closed)
		close(wc.ch)
	})
	<-wc.done
}

func (wc *WebhookClient) run() {
	defer close(wc.done)
	for ev := range wc.ch {
		wc.post(ev)
	}
}

func (wc *WebhookClient) post(ev *WebhookEvent) {
	body, err := json.Marshal(ev)
	if err != nil {
		slog.Warn("webhook marshal error", "event", ev.Event, "error", err)
		return
	}
	resp, err := wc.client.Post(wc.url, "application/json", bytes.NewReader(body))
	if err != nil {
		slog.Warn("webhook POST failed", "event", ev.Event, "error", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		slog.Warn("webhook POST error status", "event", ev.Event, "status", resp.StatusCode)
	}
}

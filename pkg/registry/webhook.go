package registry

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// RegistryWebhookEvent is the JSON payload POSTed to webhook endpoints.
type RegistryWebhookEvent struct {
	EventID   uint64                 `json:"event_id"`
	Action    string                 `json:"action"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// registryWebhook dispatches audit events asynchronously to an HTTP(S) endpoint.
type registryWebhook struct {
	url       string
	ch        chan *RegistryWebhookEvent
	client    *http.Client
	done      chan struct{}
	closeOnce sync.Once
	closed    chan struct{}
	nextID    atomic.Uint64
	dropped   atomic.Uint64
	failed    atomic.Uint64
	delivered atomic.Uint64

	// Dead letter queue: stores last N failed events for retry/inspection
	dlqMu  sync.Mutex
	dlq    []*RegistryWebhookEvent
	dlqMax int
}

func newRegistryWebhook(url string) *registryWebhook {
	wh := &registryWebhook{
		url:    url,
		ch:     make(chan *RegistryWebhookEvent, 1024),
		client: &http.Client{Timeout: 5 * time.Second},
		done:   make(chan struct{}),
		closed: make(chan struct{}),
		dlqMax: 100,
	}
	go wh.run()
	return wh
}

// Emit queues an event for async delivery. Non-blocking; drops if buffer full.
func (wh *registryWebhook) Emit(action string, details map[string]interface{}) {
	if wh == nil {
		return
	}
	select {
	case <-wh.closed:
		return
	default:
	}
	ev := &RegistryWebhookEvent{
		EventID:   wh.nextID.Add(1),
		Action:    action,
		Timestamp: time.Now().UTC(),
		Details:   details,
	}
	select {
	case wh.ch <- ev:
	case <-wh.closed:
	default:
		wh.dropped.Add(1)
		slog.Warn("registry webhook queue full, dropping event", "action", action)
	}
}

// Close drains the queue and stops the background goroutine.
func (wh *registryWebhook) Close() {
	if wh == nil {
		return
	}
	wh.closeOnce.Do(func() {
		close(wh.closed)
		close(wh.ch)
	})
	select {
	case <-wh.done:
	case <-time.After(5 * time.Second):
		slog.Warn("registry webhook drain timeout")
	}
}

func (wh *registryWebhook) run() {
	defer close(wh.done)
	for ev := range wh.ch {
		wh.post(ev)
	}
}

const (
	regWebhookMaxRetries     = 3
	regWebhookInitialBackoff = 1 * time.Second
)

func (wh *registryWebhook) post(ev *RegistryWebhookEvent) {
	body, err := json.Marshal(ev)
	if err != nil {
		slog.Warn("registry webhook marshal error", "action", ev.Action, "error", err)
		return
	}

	backoff := regWebhookInitialBackoff
	for attempt := 0; attempt < regWebhookMaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}

		resp, err := wh.client.Post(wh.url, "application/json", bytes.NewReader(body))
		if err != nil {
			slog.Warn("registry webhook POST failed", "action", ev.Action, "attempt", attempt+1, "error", err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 400 {
			wh.delivered.Add(1)
			return
		}
		if resp.StatusCode < 500 {
			slog.Warn("registry webhook client error", "action", ev.Action, "status", resp.StatusCode)
			wh.addToDLQ(ev)
			wh.failed.Add(1)
			return
		}
		slog.Warn("registry webhook server error", "action", ev.Action, "status", resp.StatusCode, "attempt", attempt+1)
	}
	// All retries exhausted — add to dead letter queue
	wh.addToDLQ(ev)
	wh.failed.Add(1)
}

// addToDLQ adds a failed event to the dead letter queue.
func (wh *registryWebhook) addToDLQ(ev *RegistryWebhookEvent) {
	wh.dlqMu.Lock()
	defer wh.dlqMu.Unlock()
	if len(wh.dlq) >= wh.dlqMax {
		wh.dlq = wh.dlq[1:] // drop oldest
	}
	wh.dlq = append(wh.dlq, ev)
}

// DLQ returns the current dead letter queue contents.
func (wh *registryWebhook) DLQ() []*RegistryWebhookEvent {
	if wh == nil {
		return nil
	}
	wh.dlqMu.Lock()
	defer wh.dlqMu.Unlock()
	out := make([]*RegistryWebhookEvent, len(wh.dlq))
	copy(out, wh.dlq)
	return out
}

// Stats returns webhook delivery statistics.
func (wh *registryWebhook) Stats() (delivered, failed, dropped uint64) {
	if wh == nil {
		return 0, 0, 0
	}
	return wh.delivered.Load(), wh.failed.Load(), wh.dropped.Load()
}

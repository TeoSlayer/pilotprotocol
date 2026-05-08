// SPDX-License-Identifier: AGPL-3.0-or-later

// Package webhook provides the audit-event webhook dispatcher for the
// registry server.  It owns the Store type, which holds the outbound
// HTTP dispatcher (with DLQ and retry), and exposes the three wire
// handler methods that the registry dispatch table calls via thin
// Server wrappers.
//
// Fan-out from the event bus is wired by calling Store.Subscribe(bus)
// after construction; the store listens for "audit.entry" events and
// calls Emit on each one so callers no longer need to touch the store
// directly at mutation sites.
package webhook

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/server/events"
)

// Event is the JSON payload POSTed to webhook endpoints.
type Event struct {
	EventID   uint64                 `json:"event_id"`
	Action    string                 `json:"action"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// dispatcher handles async HTTP delivery of a single webhook target.
type dispatcher struct {
	url            string
	ch             chan *Event
	client         *http.Client
	done           chan struct{}
	closeOnce      sync.Once
	closed         chan struct{}
	nextID         atomic.Uint64
	dropped        atomic.Uint64
	failed         atomic.Uint64
	delivered      atomic.Uint64
	initialBackoff time.Duration

	// Dead letter queue: stores last N failed events for retry/inspection
	dlqMu    sync.Mutex
	dlqItems []*Event
	dlqMax   int
}

const (
	MaxRetries     = 3
	InitialBackoff = 1 * time.Second
)

func newDispatcher(url string) *dispatcher {
	d := &dispatcher{
		url:            url,
		ch:             make(chan *Event, 1024),
		client:         &http.Client{Timeout: 5 * time.Second},
		done:           make(chan struct{}),
		closed:         make(chan struct{}),
		dlqMax:         100,
		initialBackoff: InitialBackoff,
	}
	go d.run()
	return d
}

// Emit is non-blocking; events are dropped when the buffer is full.
func (d *dispatcher) Emit(action string, details map[string]interface{}) {
	if d == nil {
		return
	}
	select {
	case <-d.closed:
		return
	default:
	}
	ev := &Event{
		EventID:   d.nextID.Add(1),
		Action:    action,
		Timestamp: time.Now().UTC(),
		Details:   details,
	}
	select {
	case d.ch <- ev:
	case <-d.closed:
	default:
		d.dropped.Add(1)
		slog.Warn("registry webhook queue full, dropping event", "action", action)
	}
}

func (d *dispatcher) Close() {
	if d == nil {
		return
	}
	d.closeOnce.Do(func() {
		close(d.closed)
		close(d.ch)
	})
	select {
	case <-d.done:
	case <-time.After(5 * time.Second):
		slog.Warn("registry webhook drain timeout")
	}
}

func (d *dispatcher) run() {
	defer close(d.done)
	for ev := range d.ch {
		d.post(ev)
	}
}

func (d *dispatcher) post(ev *Event) {
	body, err := json.Marshal(ev)
	if err != nil {
		slog.Warn("registry webhook marshal error", "action", ev.Action, "error", err)
		return
	}

	backoff := d.initialBackoff
	for attempt := 0; attempt < MaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}

		resp, err := d.client.Post(d.url, "application/json", bytes.NewReader(body))
		if err != nil {
			slog.Warn("registry webhook POST failed", "action", ev.Action, "attempt", attempt+1, "error", err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 400 {
			d.delivered.Add(1)
			return
		}
		if resp.StatusCode < 500 {
			slog.Warn("registry webhook client error", "action", ev.Action, "status", resp.StatusCode)
			d.addToDLQ(ev)
			d.failed.Add(1)
			return
		}
		slog.Warn("registry webhook server error", "action", ev.Action, "status", resp.StatusCode, "attempt", attempt+1)
	}
	// All retries exhausted — add to dead letter queue
	d.addToDLQ(ev)
	d.failed.Add(1)
}

func (d *dispatcher) addToDLQ(ev *Event) {
	d.dlqMu.Lock()
	defer d.dlqMu.Unlock()
	if len(d.dlqItems) >= d.dlqMax {
		d.dlqItems = d.dlqItems[1:] // drop oldest
	}
	d.dlqItems = append(d.dlqItems, ev)
}

func (d *dispatcher) getDLQ() []*Event {
	if d == nil {
		return nil
	}
	d.dlqMu.Lock()
	defer d.dlqMu.Unlock()
	out := make([]*Event, len(d.dlqItems))
	copy(out, d.dlqItems)
	return out
}

func (d *dispatcher) stats() (delivered, failed, dropped uint64) {
	if d == nil {
		return 0, 0, 0
	}
	return d.delivered.Load(), d.failed.Load(), d.dropped.Load()
}

// ---------------------------------------------------------------------------
// Store — the public face of this package.
// ---------------------------------------------------------------------------

// Store holds the webhook configuration and dispatcher for the audit-event
// webhook.  A nil *Store is valid and behaves as "no webhook configured".
//
// Typical lifecycle:
//
//	st := webhook.NewStore()
//	st.Subscribe(bus)          // hook into the event bus for automatic fan-out
//	st.SetURL("https://...")   // configure the endpoint (or leave empty)
//	...
//	st.Close()                 // on server shutdown
type Store struct {
	mu   sync.RWMutex
	disp *dispatcher // nil when no URL is configured
}

// NewStore returns an initialised *Store with no webhook URL configured.
func NewStore() *Store {
	return &Store{}
}

// SetURL reconfigures the webhook target URL.  Pass an empty string to
// disable webhook dispatching.  The old dispatcher (if any) is drained
// before the new one starts.
func (st *Store) SetURL(url string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.disp != nil {
		st.disp.Close()
		st.disp = nil
	}
	if url != "" {
		st.disp = newDispatcher(url)
		slog.Info("registry webhook configured", "url", url)
	}
}

// SetInitialBackoff sets the retry backoff. Tests set a short value to avoid
// waiting on retry exhaustion. No-op when no dispatcher is active.
func (st *Store) SetInitialBackoff(d time.Duration) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.disp != nil {
		st.disp.initialBackoff = d
	}
}

// Emit is a no-op when no webhook URL is configured or the store is nil.
func (st *Store) Emit(action string, details map[string]interface{}) {
	if st == nil {
		return
	}
	st.mu.RLock()
	d := st.disp
	st.mu.RUnlock()
	if d != nil {
		d.Emit(action, details)
	}
}

// Subscribe must be called once after construction. The goroutine exits when
// the store is Closed or the bus channel closes.
func (st *Store) Subscribe(bus events.Bus) {
	if bus == nil {
		return
	}
	ch, _ := bus.Subscribe("audit.entry")
	go func() {
		for evt := range ch {
			action, _ := evt.Payload["action"].(string)
			details, _ := evt.Payload["details"].(map[string]interface{})
			st.Emit(action, details)
		}
	}()
}

// Close drains the current dispatcher and releases resources.
func (st *Store) Close() {
	if st == nil {
		return
	}
	st.mu.Lock()
	d := st.disp
	st.disp = nil
	st.mu.Unlock()
	if d != nil {
		d.Close()
	}
}

// ---------------------------------------------------------------------------
// Handler methods — called by thin wrappers on *server.Server.
// ---------------------------------------------------------------------------

// HandleSetWebhook requires admin-token verification by the caller.
// Empty urlStr disables the webhook.
func (st *Store) HandleSetWebhook(urlStr string) map[string]interface{} {
	st.SetURL(urlStr)
	status := "disabled"
	if urlStr != "" {
		status = "enabled"
	}
	return map[string]interface{}{
		"type":   "set_webhook_ok",
		"status": status,
		"url":    urlStr,
	}
}

// HandleGetWebhook requires admin-token verification by the caller.
func (st *Store) HandleGetWebhook() map[string]interface{} {
	st.mu.RLock()
	d := st.disp
	st.mu.RUnlock()

	url := ""
	var delivered, failed, dropped uint64
	dlqLen := 0
	if d != nil {
		url = d.url
		delivered, failed, dropped = d.stats()
		dlqLen = len(d.getDLQ())
	}
	return map[string]interface{}{
		"type":      "get_webhook_ok",
		"enabled":   d != nil,
		"url":       url,
		"delivered": delivered,
		"failed":    failed,
		"dropped":   dropped,
		"dlq_size":  dlqLen,
	}
}

// HandleGetWebhookDLQ requires admin-token verification by the caller.
func (st *Store) HandleGetWebhookDLQ() map[string]interface{} {
	st.mu.RLock()
	d := st.disp
	st.mu.RUnlock()

	var evts []map[string]interface{}
	if d != nil {
		for _, ev := range d.getDLQ() {
			entry := map[string]interface{}{
				"event_id":  ev.EventID,
				"action":    ev.Action,
				"timestamp": ev.Timestamp.Format("2006-01-02T15:04:05Z"),
			}
			if len(ev.Details) > 0 {
				entry["details"] = ev.Details
			}
			evts = append(evts, entry)
		}
	}
	return map[string]interface{}{
		"type":   "get_webhook_dlq_ok",
		"events": evts,
		"count":  len(evts),
	}
}

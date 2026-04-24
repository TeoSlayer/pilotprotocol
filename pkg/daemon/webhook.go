// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/urlvalidate"
)

// webhookURLPath is the file where the last-set webhook URL is persisted so
// that `pilotctl set-webhook` survives daemon restarts and the first emit
// after restart (node.registered / agent.registered) reaches the sink.
func webhookURLPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".pilot", "webhook_url"), nil
}

// loadPersistedWebhookURL reads the previously-saved webhook URL. Returns
// empty string if no file exists or the contents don't pass validation.
func loadPersistedWebhookURL() (string, error) {
	path, err := webhookURLPath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	url := strings.TrimSpace(string(data))
	if url == "" {
		return "", nil
	}
	if err := ValidateWebhookURL(url); err != nil {
		return "", err
	}
	return url, nil
}

// savePersistedWebhookURL writes the URL to ~/.pilot/webhook_url, or deletes
// the file if url is empty.
func savePersistedWebhookURL(url string) error {
	path, err := webhookURLPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if url == "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return os.WriteFile(path, []byte(url), 0600)
}

// ValidateWebhookURL checks that a webhook URL uses http(s) and does not
// target cloud metadata or link-local endpoints (SSRF prevention). Delegates
// to pkg/urlvalidate so pkg/registry can share the same rules without
// importing pkg/daemon.
func ValidateWebhookURL(rawURL string) error {
	return urlvalidate.Validate(rawURL)
}

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
	url            string
	ch             chan *WebhookEvent
	client         *http.Client
	done           chan struct{}
	nodeID         func() uint32
	closeOnce      sync.Once
	closed         chan struct{} // closed when Close is called, guards Emit
	nextID         atomic.Uint64
	dropped        atomic.Uint64
	initialBackoff time.Duration // retry backoff (default 1s)
}

// WebhookOption configures a WebhookClient.
type WebhookOption func(*WebhookClient)

// WithHTTPTimeout sets the HTTP client timeout (default 5s).
func WithHTTPTimeout(d time.Duration) WebhookOption {
	return func(wc *WebhookClient) { wc.client.Timeout = d }
}

// WithRetryBackoff sets the initial retry backoff (default 1s, doubles each retry).
func WithRetryBackoff(d time.Duration) WebhookOption {
	return func(wc *WebhookClient) { wc.initialBackoff = d }
}

// NewWebhookClient creates a webhook dispatcher. If url is empty, returns nil.
func NewWebhookClient(url string, nodeIDFunc func() uint32, opts ...WebhookOption) *WebhookClient {
	if url == "" {
		return nil
	}
	wc := &WebhookClient{
		url:            url,
		ch:             make(chan *WebhookEvent, 1024),
		client:         &http.Client{Timeout: 5 * time.Second},
		done:           make(chan struct{}),
		nodeID:         nodeIDFunc,
		closed:         make(chan struct{}),
		initialBackoff: webhookInitialBackoff,
	}
	for _, opt := range opts {
		opt(wc)
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
	})
	select {
	case <-wc.done:
	case <-time.After(5 * time.Second):
		slog.Warn("webhook drain timeout, abandoning remaining events")
	}
}

func (wc *WebhookClient) run() {
	defer close(wc.done)
	for {
		select {
		case ev := <-wc.ch:
			wc.post(ev)
		case <-wc.closed:
			for {
				select {
				case ev := <-wc.ch:
					wc.post(ev)
				default:
					return
				}
			}
		}
	}
}

const (
	webhookMaxRetries     = 3
	webhookInitialBackoff = 1 * time.Second
)

func (wc *WebhookClient) post(ev *WebhookEvent) {
	body, err := json.Marshal(ev)
	if err != nil {
		slog.Warn("webhook marshal error", "event", ev.Event, "error", err)
		return
	}

	backoff := wc.initialBackoff
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

// SPDX-License-Identifier: AGPL-3.0-or-later

// Package webhook is the L11 plugin that delivers core daemon events
// to an external HTTP(S) endpoint. Subscribes to the daemon's event
// bus through coreapi.Deps.Events and POSTs each event as a JSON
// payload. Owns the HTTP client, retry+circuit-breaker state, and
// the persisted-URL file (~/.pilot/webhook_url) — none of which
// pkg/daemon (L7) is allowed to know about.
//
// Extracted from pkg/daemon/webhook.go in T4.1 (webhook-inversion).
// The daemon publishes; the plugin subscribes — the layered
// architecture's separation of "what happened" (core) from "tell the
// outside world" (plugin).
package webhook

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

// urlPath is the file where the last-set webhook URL is persisted so
// that `pilotctl set-webhook` survives daemon restarts and the first
// emit after restart (node.registered / agent.registered) reaches
// the sink.
func urlPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".pilot", "webhook_url"), nil
}

// LoadPersistedURL reads the previously-saved webhook URL. Returns
// empty string if no file exists or the contents don't pass validation.
func LoadPersistedURL() (string, error) {
	path, err := urlPath()
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
	if err := Validate(url); err != nil {
		return "", err
	}
	return url, nil
}

// SavePersistedURL writes the URL to ~/.pilot/webhook_url, or deletes
// the file if url is empty.
func SavePersistedURL(url string) error {
	path, err := urlPath()
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

// Validate checks that a webhook URL uses http(s) and does not target
// cloud metadata or link-local endpoints (SSRF prevention). Delegates
// to pkg/urlvalidate so other packages can share the same rules
// without importing this plugin.
func Validate(rawURL string) error {
	return urlvalidate.Validate(rawURL)
}

// Event is the JSON payload POSTed to the webhook endpoint.
type Event struct {
	EventID   uint64      `json:"event_id"`
	Event     string      `json:"event"`
	NodeID    uint32      `json:"node_id"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data,omitempty"`
}

// Client dispatches events asynchronously to an HTTP(S) endpoint.
// If URL is empty, all methods are no-ops (zero overhead when disabled).
type Client struct {
	url            string
	ch             chan *Event
	client         *http.Client
	done           chan struct{}
	nodeID         func() uint32
	closeOnce      sync.Once
	closed         chan struct{} // closed when Close is called, guards Emit
	nextID         atomic.Uint64
	dropped        atomic.Uint64
	initialBackoff time.Duration // retry backoff (default 1s)

	// Circuit breaker state. After CircuitOpenThreshold (5)
	// consecutive total failures (each event = up to MaxRetries
	// attempts), the circuit opens for circuitCooldown — every Emit
	// during the cooldown window is short-circuited (no HTTP attempt,
	// CircuitSkips counter incremented). On the first probe after
	// cooldown, success resets state; failure reopens for another
	// cooldown. Without this, a dead webhook URL burns CPU + outbound
	// bandwidth for every event indefinitely.
	consecutiveFailures  atomic.Uint32
	circuitOpenUntilNano atomic.Int64
	circuitSkips         atomic.Uint64
	circuitCooldown      time.Duration // default CircuitCooldown
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPTimeout sets the HTTP client timeout (default 5s).
func WithHTTPTimeout(d time.Duration) Option {
	return func(wc *Client) { wc.client.Timeout = d }
}

// WithRetryBackoff sets the initial retry backoff (default 1s, doubles each retry).
func WithRetryBackoff(d time.Duration) Option {
	return func(wc *Client) { wc.initialBackoff = d }
}

// NewClient creates a webhook dispatcher. If url is empty, returns nil.
func NewClient(url string, nodeIDFunc func() uint32, opts ...Option) *Client {
	if url == "" {
		return nil
	}
	wc := &Client{
		url:             url,
		ch:              make(chan *Event, 1024),
		client:          &http.Client{Timeout: 5 * time.Second},
		done:            make(chan struct{}),
		nodeID:          nodeIDFunc,
		closed:          make(chan struct{}),
		initialBackoff:  InitialBackoff,
		circuitCooldown: CircuitCooldown,
	}
	for _, opt := range opts {
		opt(wc)
	}
	go wc.run()
	return wc
}

// Emit queues an event for async delivery. Non-blocking; drops if buffer full.
// Safe to call after Close (becomes a no-op).
func (wc *Client) Emit(event string, data interface{}) {
	if wc == nil {
		return
	}
	select {
	case <-wc.closed:
		return // already closed
	default:
	}
	ev := &Event{
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
func (wc *Client) Dropped() uint64 {
	if wc == nil {
		return 0
	}
	return wc.dropped.Load()
}

// Close drains the queue and stops the background goroutine. Idempotent.
// Waits up to 5 seconds for the queue to drain before abandoning remaining events.
func (wc *Client) Close() {
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

func (wc *Client) run() {
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

// Tunable circuit-breaker + retry constants.
const (
	MaxRetries           = 3
	InitialBackoff       = 1 * time.Second
	CircuitOpenThreshold = 5
	CircuitCooldown      = 30 * time.Second
)

// WithCircuitCooldown overrides the default 30s circuit-breaker cooldown.
// Tests use a small value to exercise open→probe→reset cycles quickly.
func WithCircuitCooldown(d time.Duration) Option {
	return func(wc *Client) { wc.circuitCooldown = d }
}

// CircuitSkips returns the number of events short-circuited because the
// breaker was open. Nil-safe.
func (wc *Client) CircuitSkips() uint64 {
	if wc == nil {
		return 0
	}
	return wc.circuitSkips.Load()
}

func (wc *Client) post(ev *Event) {
	body, err := json.Marshal(ev)
	if err != nil {
		slog.Warn("webhook marshal error", "event", ev.Event, "error", err)
		return
	}

	// Circuit breaker (v1.9.1): if the breaker is open AND we're still
	// inside the cooldown window, short-circuit. The first event after
	// cooldown elapses is the probe — if it succeeds, breaker resets
	// to closed; if it fails, breaker reopens for another cooldown.
	if openUntil := wc.circuitOpenUntilNano.Load(); openUntil > 0 {
		now := time.Now().UnixNano()
		if now < openUntil {
			wc.circuitSkips.Add(1)
			return
		}
		// Cooldown elapsed — clear and let this event probe. If it
		// fails, the failure path below will reopen the breaker.
		wc.circuitOpenUntilNano.Store(0)
	}

	backoff := wc.initialBackoff
	success := false
	clientErr := false
	for attempt := 0; attempt < MaxRetries; attempt++ {
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
			success = true
			break
		}
		if resp.StatusCode < 500 {
			// 4xx — permanent client error, no retry. Also doesn't
			// trip the circuit: the URL is reachable, the issue is
			// the payload (which the breaker can't fix by waiting).
			slog.Warn("webhook POST client error", "event", ev.Event, "status", resp.StatusCode)
			clientErr = true
			break
		}
		// 5xx — server error, retry
		slog.Warn("webhook POST server error", "event", ev.Event, "status", resp.StatusCode, "attempt", attempt+1)
	}

	if success {
		wc.consecutiveFailures.Store(0)
		return
	}
	if clientErr {
		// Don't count toward breaker — see comment above.
		return
	}
	// All attempts exhausted (network errors or 5xx). Increment counter
	// and open the circuit if we hit the threshold.
	failures := wc.consecutiveFailures.Add(1)
	if failures >= CircuitOpenThreshold {
		cooldown := wc.circuitCooldown
		if cooldown == 0 {
			cooldown = CircuitCooldown
		}
		wc.circuitOpenUntilNano.Store(time.Now().Add(cooldown).UnixNano())
		slog.Warn("webhook circuit breaker opened",
			"consecutive_failures", failures, "cooldown", cooldown.String())
	}
}

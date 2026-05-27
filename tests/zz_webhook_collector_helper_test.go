// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

// webhookCollector is shared test scaffolding for any test that needs
// to assert on emitted webhook events. Lives in a default-tag file so
// non-nightly consumers (zz_fin_ack_test.go, zz_eventstream_broker_parity_test.go,
// zz_syn_trust_gate_test.go) keep resolving after the heavier
// zz_webhook_test.go got tagged //go:build nightly.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/webhook"
)

type webhookCollector struct {
	mu     sync.Mutex
	events []webhook.Event
	server *httptest.Server
}

func newWebhookCollector() *webhookCollector {
	wc := &webhookCollector{}
	wc.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad body", 400)
			return
		}
		var ev webhook.Event
		if err := json.Unmarshal(body, &ev); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		wc.mu.Lock()
		wc.events = append(wc.events, ev)
		wc.mu.Unlock()
		w.WriteHeader(200)
	}))
	return wc
}

func (wc *webhookCollector) URL() string {
	return wc.server.URL
}

func (wc *webhookCollector) Close() {
	wc.server.Close()
}

func (wc *webhookCollector) Events() []webhook.Event {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	cp := make([]webhook.Event, len(wc.events))
	copy(cp, wc.events)
	return cp
}

func (wc *webhookCollector) WaitFor(eventName string, timeout time.Duration) (*webhook.Event, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		wc.mu.Lock()
		for i := range wc.events {
			if wc.events[i].Event == eventName {
				ev := wc.events[i]
				wc.mu.Unlock()
				return &ev, true
			}
		}
		wc.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	return nil, false
}

func (wc *webhookCollector) CountEvent(eventName string) int {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	n := 0
	for _, ev := range wc.events {
		if ev.Event == eventName {
			n++
		}
	}
	return n
}

// WaitForCount polls until at least count events with the given name are received.
func (wc *webhookCollector) WaitForCount(eventName string, count int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if wc.CountEvent(eventName) >= count {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// EventsMatching returns all events with the given name.
func (wc *webhookCollector) EventsMatching(eventName string) []webhook.Event {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	var out []webhook.Event
	for _, ev := range wc.events {
		if ev.Event == eventName {
			out = append(out, ev)
		}
	}
	return out
}

// Avoid unused-symbol vet warning if no test calls testing.T helpers
// from this file directly.
var _ = (*testing.T)(nil)

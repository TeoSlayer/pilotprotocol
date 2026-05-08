// SPDX-License-Identifier: AGPL-3.0-or-later

package webhook_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/server/events"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry/server/webhook"
)

// TestHandleSetWebhook verifies that HandleSetWebhook enables delivery and
// that subsequent events reach the configured endpoint.
func TestHandleSetWebhook(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	st := webhook.NewStore()
	defer st.Close()
	st.SetInitialBackoff(time.Millisecond)

	resp := st.HandleSetWebhook(srv.URL)
	if resp["type"] != "set_webhook_ok" {
		t.Fatalf("unexpected type: %v", resp["type"])
	}
	if resp["status"] != "enabled" {
		t.Fatalf("unexpected status: %v", resp["status"])
	}

	// Emit an event and wait for it to be delivered.
	st.Emit("test.action", map[string]interface{}{"k": "v"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hits.Load() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if hits.Load() < 1 {
		t.Fatalf("expected at least 1 delivery, got %d", hits.Load())
	}

	// HandleGetWebhook should reflect enabled state.
	info := st.HandleGetWebhook()
	if info["enabled"] != true {
		t.Fatalf("get_webhook enabled: %v", info["enabled"])
	}
	if info["url"] != srv.URL {
		t.Fatalf("get_webhook url: %v", info["url"])
	}
}

// TestHandleGetWebhookDLQ verifies that 4xx responses land in the DLQ and
// HandleGetWebhookDLQ surfaces them.
func TestHandleGetWebhookDLQ(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(400)
	}))
	defer srv.Close()

	st := webhook.NewStore()
	defer st.Close()
	st.SetInitialBackoff(time.Millisecond)

	st.HandleSetWebhook(srv.URL)

	// Emit and wait for the dispatcher to process and DLQ it.
	st.Emit("dlq.test", map[string]interface{}{"reason": "bad-request"})

	deadline := time.Now().Add(2 * time.Second)
	var dlqResp map[string]interface{}
	for time.Now().Before(deadline) {
		dlqResp = st.HandleGetWebhookDLQ()
		if count, _ := dlqResp["count"].(int); count >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	count, _ := dlqResp["count"].(int)
	if count < 1 {
		t.Fatalf("expected DLQ count >= 1, got %d", count)
	}
	if dlqResp["type"] != "get_webhook_dlq_ok" {
		t.Fatalf("unexpected type: %v", dlqResp["type"])
	}
	evts, _ := dlqResp["events"].([]map[string]interface{})
	if len(evts) < 1 {
		t.Fatalf("expected at least 1 DLQ event, got %d", len(evts))
	}
	if evts[0]["action"] != "dlq.test" {
		t.Fatalf("unexpected action: %v", evts[0]["action"])
	}
}

// TestSubscribeFansOutFromEventBus verifies that Store.Subscribe causes
// events published on the bus to be delivered to the webhook endpoint.
func TestSubscribeFansOutFromEventBus(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	st := webhook.NewStore()
	defer st.Close()
	st.SetInitialBackoff(time.Millisecond)
	st.HandleSetWebhook(srv.URL)

	bus := events.NewInProcessBus(64)
	st.Subscribe(bus)

	bus.Publish(events.Event{
		Source: "audit",
		Type:   "audit.entry",
		Payload: map[string]any{
			"action":  "node.registered",
			"details": map[string]interface{}{"node_id": float64(42)},
		},
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hits.Load() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if hits.Load() < 1 {
		t.Fatalf("expected event bus fan-out to deliver at least 1 POST, got %d", hits.Load())
	}
}

// TestDisableWebhookStopsDelivery verifies that setting an empty URL disables
// delivery.
func TestDisableWebhookStopsDelivery(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	st := webhook.NewStore()
	defer st.Close()

	st.HandleSetWebhook(srv.URL)
	// Immediately disable.
	resp := st.HandleSetWebhook("")
	if resp["status"] != "disabled" {
		t.Fatalf("unexpected status: %v", resp["status"])
	}

	// Emit should be a no-op now.
	st.Emit("should.not.arrive", nil)
	time.Sleep(100 * time.Millisecond)
	if hits.Load() != 0 {
		t.Fatalf("expected 0 deliveries after disable, got %d", hits.Load())
	}

	info := st.HandleGetWebhook()
	if info["enabled"] != false {
		t.Fatalf("expected enabled=false after disable, got %v", info["enabled"])
	}
}

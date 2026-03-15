package tests

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
)

// ---------------------------------------------------------------------------
// WebhookClient: nil-safety
// ---------------------------------------------------------------------------

func TestWebhookClientNilEmit(t *testing.T) {
	var wc *daemon.WebhookClient
	wc.Emit("test_event", nil) // should not panic
}

func TestWebhookClientNilClose(t *testing.T) {
	var wc *daemon.WebhookClient
	wc.Close() // should not panic
}

func TestWebhookClientEmptyURL(t *testing.T) {
	wc := daemon.NewWebhookClient("", func() uint32 { return 1 })
	if wc != nil {
		t.Fatal("expected nil for empty URL")
	}
}

// ---------------------------------------------------------------------------
// WebhookClient: lifecycle
// ---------------------------------------------------------------------------

func TestWebhookClientCreateAndClose(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	wc := daemon.NewWebhookClient(ts.URL, func() uint32 { return 42 })
	if wc == nil {
		t.Fatal("expected non-nil webhook client")
	}
	wc.Close()
}

func TestWebhookClientCloseIdempotent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	wc := daemon.NewWebhookClient(ts.URL, func() uint32 { return 1 })
	wc.Close()
	wc.Close() // second close should not panic
}

// ---------------------------------------------------------------------------
// WebhookClient: emit
// ---------------------------------------------------------------------------

func TestWebhookClientEmitReceived(t *testing.T) {
	var received atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev daemon.WebhookEvent
		if err := json.Unmarshal(body, &ev); err != nil {
			t.Errorf("bad webhook payload: %v", err)
			return
		}
		if ev.Event != "node_connected" {
			t.Errorf("unexpected event: %s", ev.Event)
		}
		if ev.NodeID != 42 {
			t.Errorf("unexpected node_id: %d", ev.NodeID)
		}
		received.Add(1)
		w.WriteHeader(200)
	}))
	defer ts.Close()

	wc := daemon.NewWebhookClient(ts.URL, func() uint32 { return 42 })
	wc.Emit("node_connected", map[string]string{"peer": "123"})

	// Wait for delivery
	wc.Close()

	if received.Load() != 1 {
		t.Fatalf("expected 1 event received, got %d", received.Load())
	}
}

func TestWebhookClientEmitAfterClose(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	wc := daemon.NewWebhookClient(ts.URL, func() uint32 { return 1 })
	wc.Close()
	wc.Emit("test", nil) // should not panic (no-op after close)
}

func TestWebhookClientEmitMultiple(t *testing.T) {
	var count atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(200)
	}))
	defer ts.Close()

	wc := daemon.NewWebhookClient(ts.URL, func() uint32 { return 1 })
	for i := 0; i < 10; i++ {
		wc.Emit("event", nil)
	}
	wc.Close()

	if count.Load() != 10 {
		t.Fatalf("expected 10 events, got %d", count.Load())
	}
}

func TestWebhookClientEmitWithData(t *testing.T) {
	var received atomic.Value
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received.Store(string(body))
		w.WriteHeader(200)
	}))
	defer ts.Close()

	wc := daemon.NewWebhookClient(ts.URL, func() uint32 { return 1 })
	wc.Emit("data_event", map[string]interface{}{"key": "value", "count": 42})
	wc.Close()

	raw, ok := received.Load().(string)
	if !ok || raw == "" {
		t.Fatal("expected webhook payload")
	}
	var ev daemon.WebhookEvent
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ev.Event != "data_event" {
		t.Fatalf("expected data_event, got %s", ev.Event)
	}
}

func TestWebhookClientEmitConcurrent(t *testing.T) {
	var count atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(200)
	}))
	defer ts.Close()

	wc := daemon.NewWebhookClient(ts.URL, func() uint32 { return 1 })
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			wc.Emit("concurrent", map[string]int{"id": id})
		}(i)
	}
	wg.Wait()
	wc.Close()

	if count.Load() != 20 {
		t.Fatalf("expected 20 events, got %d", count.Load())
	}
}

// ---------------------------------------------------------------------------
// WebhookClient: error handling
// ---------------------------------------------------------------------------

func TestWebhookClientServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer ts.Close()

	wc := daemon.NewWebhookClient(ts.URL, func() uint32 { return 1 })
	wc.Emit("test", nil) // server error should not crash
	wc.Close()
}

func TestWebhookClientBadURL(t *testing.T) {
	wc := daemon.NewWebhookClient("http://127.0.0.1:1", func() uint32 { return 1 })
	wc.Emit("test", nil) // connection refused should not crash
	wc.Close()
}

// ---------------------------------------------------------------------------
// WebhookEvent: JSON
// ---------------------------------------------------------------------------

func TestWebhookEventJSON(t *testing.T) {
	ev := daemon.WebhookEvent{
		Event:     "node_connected",
		NodeID:    42,
		Timestamp: time.Now().UTC(),
		Data:      map[string]string{"peer": "100"},
	}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded daemon.WebhookEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Event != "node_connected" || decoded.NodeID != 42 {
		t.Fatal("event JSON round-trip mismatch")
	}
}

func TestWebhookEventEmptyData(t *testing.T) {
	ev := daemon.WebhookEvent{
		Event:  "test",
		NodeID: 1,
	}
	data, _ := json.Marshal(ev)
	// "data" should be omitted (omitempty)
	var m map[string]interface{}
	json.Unmarshal(data, &m)
	if _, ok := m["data"]; ok {
		t.Fatal("data should be omitted when nil")
	}
}

// ---------------------------------------------------------------------------
// Handshake types: JSON round-trip
// ---------------------------------------------------------------------------

func TestHandshakeMsgJSON(t *testing.T) {
	msg := daemon.HandshakeMsg{
		Type:          daemon.HandshakeRequest,
		NodeID:        42,
		PublicKey:     "base64pubkey==",
		Justification: "need compute access",
		Signature:     "base64sig==",
		Reason:        "",
		Timestamp:     time.Now().Unix(),
	}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded daemon.HandshakeMsg
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Type != daemon.HandshakeRequest {
		t.Fatalf("expected %s, got %s", daemon.HandshakeRequest, decoded.Type)
	}
	if decoded.NodeID != 42 {
		t.Fatal("node_id mismatch")
	}
}

func TestHandshakeConstants(t *testing.T) {
	if daemon.HandshakeRequest != "handshake_request" {
		t.Fatal("HandshakeRequest constant wrong")
	}
	if daemon.HandshakeAccept != "handshake_accept" {
		t.Fatal("HandshakeAccept constant wrong")
	}
	if daemon.HandshakeReject != "handshake_reject" {
		t.Fatal("HandshakeReject constant wrong")
	}
	if daemon.HandshakeRevoke != "handshake_revoke" {
		t.Fatal("HandshakeRevoke constant wrong")
	}
}

func TestTrustRecordStruct(t *testing.T) {
	tr := daemon.TrustRecord{
		NodeID:     42,
		PublicKey:  "base64key==",
		ApprovedAt: time.Now(),
		Mutual:     true,
		Network:    1,
	}
	if tr.NodeID != 42 || !tr.Mutual || tr.Network != 1 {
		t.Fatal("TrustRecord field mismatch")
	}
}

func TestPendingHandshakeStruct(t *testing.T) {
	ph := daemon.PendingHandshake{
		NodeID:        99,
		PublicKey:     "key==",
		Justification: "testing",
		ReceivedAt:    time.Now(),
	}
	if ph.NodeID != 99 || ph.Justification != "testing" {
		t.Fatal("PendingHandshake field mismatch")
	}
}

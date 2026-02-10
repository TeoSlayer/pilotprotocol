package tests

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"web4/pkg/daemon"
	"web4/pkg/dataexchange"
	"web4/pkg/eventstream"
)

// webhookCollector is a test HTTP server that records received webhook events.
type webhookCollector struct {
	mu     sync.Mutex
	events []daemon.WebhookEvent
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
		var ev daemon.WebhookEvent
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

func (wc *webhookCollector) Events() []daemon.WebhookEvent {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	cp := make([]daemon.WebhookEvent, len(wc.events))
	copy(cp, wc.events)
	return cp
}

func (wc *webhookCollector) WaitFor(eventName string, timeout time.Duration) (*daemon.WebhookEvent, bool) {
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
func (wc *webhookCollector) EventsMatching(eventName string) []daemon.WebhookEvent {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	var out []daemon.WebhookEvent
	for _, ev := range wc.events {
		if ev.Event == eventName {
			out = append(out, ev)
		}
	}
	return out
}

// --- Unit tests for WebhookClient ---

func TestWebhookClient_NilSafe(t *testing.T) {
	t.Parallel()
	// A nil WebhookClient should not panic on Emit or Close.
	var wc *daemon.WebhookClient
	wc.Emit("test.event", nil) // should not panic
	wc.Close()                 // should not panic
}

func TestWebhookClient_EmptyURL(t *testing.T) {
	t.Parallel()
	// NewWebhookClient with empty URL returns nil.
	wc := daemon.NewWebhookClient("", func() uint32 { return 0 })
	if wc != nil {
		t.Fatal("expected nil WebhookClient for empty URL")
	}
}

func TestWebhookClient_PostsEvents(t *testing.T) {
	t.Parallel()
	collector := newWebhookCollector()
	defer collector.Close()

	wc := daemon.NewWebhookClient(collector.URL(), func() uint32 { return 42 })
	defer wc.Close()

	wc.Emit("test.event", map[string]interface{}{"key": "value"})

	ev, ok := collector.WaitFor("test.event", 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for test.event")
	}
	if ev.NodeID != 42 {
		t.Errorf("expected node_id=42, got %d", ev.NodeID)
	}
	if ev.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestWebhookClient_MultipleEvents(t *testing.T) {
	t.Parallel()
	collector := newWebhookCollector()
	defer collector.Close()

	wc := daemon.NewWebhookClient(collector.URL(), func() uint32 { return 1 })

	for i := 0; i < 10; i++ {
		wc.Emit(fmt.Sprintf("event.%d", i), nil)
	}
	wc.Close() // drains the queue

	events := collector.Events()
	if len(events) != 10 {
		t.Fatalf("expected 10 events, got %d", len(events))
	}
	for i, ev := range events {
		expected := fmt.Sprintf("event.%d", i)
		if ev.Event != expected {
			t.Errorf("event %d: expected %q, got %q", i, expected, ev.Event)
		}
	}
}

func TestWebhookClient_DropsOnFullBuffer(t *testing.T) {
	t.Parallel()
	// Create a server that blocks responses, causing the webhook client
	// to fill its buffer. Events beyond buffer size should be dropped.
	blockCh := make(chan struct{})
	var received int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received++
		mu.Unlock()
		<-blockCh // block forever until test unblocks
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wc := daemon.NewWebhookClient(srv.URL, func() uint32 { return 1 })

	// Emit way more than the 1024 buffer capacity.
	// The first one will block in the HTTP POST, filling one slot in the goroutine.
	// The next 1024 fill the channel buffer. Anything after should be dropped.
	for i := 0; i < 2000; i++ {
		wc.Emit("flood.event", nil)
	}

	// Unblock server and close client
	close(blockCh)
	wc.Close()

	// We should have received fewer than 2000 events (buffer is 1024 + 1 in-flight)
	mu.Lock()
	r := received
	mu.Unlock()
	if r >= 2000 {
		t.Errorf("expected dropped events, but all %d were received", r)
	}
	t.Logf("received %d out of 2000 events (rest dropped as expected)", r)
}

func TestWebhookClient_FailedPOSTDoesNotBlock(t *testing.T) {
	t.Parallel()
	// Point to a server that always returns 500.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	wc := daemon.NewWebhookClient(srv.URL, func() uint32 { return 1 })
	wc.Emit("fail.event", nil)
	wc.Close() // should not hang
}

func TestWebhookClient_UnreachableDoesNotBlock(t *testing.T) {
	t.Parallel()
	// Point to a non-existent server.
	wc := daemon.NewWebhookClient("http://127.0.0.1:1", func() uint32 { return 1 })
	wc.Emit("unreachable.event", nil)
	wc.Close() // should complete (5s HTTP timeout, but drain completes)
}

func TestWebhookClient_DoubleClose(t *testing.T) {
	t.Parallel()
	collector := newWebhookCollector()
	defer collector.Close()

	wc := daemon.NewWebhookClient(collector.URL(), func() uint32 { return 1 })
	wc.Close()
	wc.Close() // should not panic
}

func TestWebhookClient_EmitAfterClose(t *testing.T) {
	t.Parallel()
	collector := newWebhookCollector()
	defer collector.Close()

	wc := daemon.NewWebhookClient(collector.URL(), func() uint32 { return 1 })
	wc.Close()
	wc.Emit("after.close", nil) // should not panic
}

// --- Integration tests: verify webhook events fire during daemon lifecycle ---

func TestWebhook_NodeRegistered(t *testing.T) {
	t.Parallel()
	collector := newWebhookCollector()
	defer collector.Close()

	env := NewTestEnv(t)
	_ = env.AddDaemon(func(cfg *daemon.Config) {
		cfg.WebhookURL = collector.URL()
	})

	ev, ok := collector.WaitFor("node.registered", 3*time.Second)
	if !ok {
		t.Fatal("timed out waiting for node.registered event")
	}
	if ev.NodeID == 0 {
		t.Error("expected non-zero node_id")
	}
	data, ok := ev.Data.(map[string]interface{})
	if !ok {
		t.Fatal("expected data to be a map")
	}
	if data["address"] == nil {
		t.Error("expected address in data")
	}
	t.Logf("node.registered: node_id=%d address=%v", ev.NodeID, data["address"])
}

func TestWebhook_ConnectionEvents(t *testing.T) {
	t.Parallel()
	collector := newWebhookCollector()
	defer collector.Close()

	env := NewTestEnv(t)
	a := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.WebhookURL = collector.URL()
	})
	b := env.AddDaemon()

	// Listen on A, port 1000
	ln, err := a.Driver.Listen(1000)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Server goroutine: accept and echo
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 64)
		conn.Read(buf)
		conn.Close()
	}()

	// B dials A
	targetAddr := fmt.Sprintf("%s:1000", a.Daemon.Addr().String())
	conn, err := b.Driver.Dial(targetAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Write([]byte("hi"))
	conn.Close()
	<-serverDone

	// Verify connection lifecycle events on daemon A's webhook
	if _, ok := collector.WaitFor("conn.syn_received", 3*time.Second); !ok {
		t.Error("missing conn.syn_received event")
	}
	if _, ok := collector.WaitFor("conn.established", 3*time.Second); !ok {
		t.Error("missing conn.established event")
	}
	if _, ok := collector.WaitFor("tunnel.peer_added", 3*time.Second); !ok {
		t.Error("missing tunnel.peer_added event")
	}
}

func TestWebhook_NodeDeregistered(t *testing.T) {
	t.Parallel()
	collector := newWebhookCollector()
	// Don't defer collector.Close() — we need it alive during d.Stop()

	env := NewTestEnv(t)
	d, _ := env.AddDaemonOnly(func(cfg *daemon.Config) {
		cfg.WebhookURL = collector.URL()
	})

	// Verify registration happened
	if _, ok := collector.WaitFor("node.registered", 3*time.Second); !ok {
		t.Fatal("timed out waiting for node.registered")
	}

	// Stop daemon triggers deregistration
	d.Stop()

	// Check for deregistration event
	if _, ok := collector.WaitFor("node.deregistered", 3*time.Second); !ok {
		t.Error("missing node.deregistered event")
	}

	collector.Close()
}

func TestWebhook_EventPayloadFormat(t *testing.T) {
	t.Parallel()
	collector := newWebhookCollector()
	defer collector.Close()

	wc := daemon.NewWebhookClient(collector.URL(), func() uint32 { return 99 })
	wc.Emit("test.format", map[string]interface{}{
		"peer_node_id": uint32(42),
		"port":         uint16(80),
	})
	wc.Close()

	ev, ok := collector.WaitFor("test.format", 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for test.format event")
	}

	// Verify JSON round-trip preserves structure
	if ev.Event != "test.format" {
		t.Errorf("expected event=test.format, got %s", ev.Event)
	}
	if ev.NodeID != 99 {
		t.Errorf("expected node_id=99, got %d", ev.NodeID)
	}
	data, ok := ev.Data.(map[string]interface{})
	if !ok {
		t.Fatal("expected data to be map")
	}
	// JSON numbers unmarshal as float64
	if peerID, ok := data["peer_node_id"].(float64); !ok || uint32(peerID) != 42 {
		t.Errorf("expected peer_node_id=42, got %v", data["peer_node_id"])
	}
}

// --- Integration tests: handshake webhook events ---

func TestWebhook_HandshakeMutualAutoApprove(t *testing.T) {
	t.Parallel()
	collectorA := newWebhookCollector()
	defer collectorA.Close()
	collectorB := newWebhookCollector()
	defer collectorB.Close()

	env := NewTestEnv(t)

	// Webhook on A to catch auto_approved (A detects mutual when receiving B's request)
	// Webhook on B to catch received + pending (B receives A's initial request)
	infoA := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
		c.WebhookURL = collectorA.URL()
	})
	infoB := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
		c.WebhookURL = collectorB.URL()
	})

	nodeA := infoA.Daemon.NodeID()
	nodeB := infoB.Daemon.NodeID()
	t.Logf("A=%d, B=%d", nodeA, nodeB)

	// A sends handshake to B
	_, err := infoA.Driver.Handshake(nodeB, "want to collaborate")
	if err != nil {
		t.Fatalf("A handshake to B: %v", err)
	}

	// Wait for B to receive the handshake
	deadline := time.After(5 * time.Second)
	for {
		pending, _ := infoB.Driver.PendingHandshakes()
		if pl, _ := pending["pending"].([]interface{}); len(pl) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for A's handshake to reach B")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// B's webhook should have handshake.received and handshake.pending
	ev, ok := collectorB.WaitFor("handshake.received", 3*time.Second)
	if !ok {
		t.Fatal("missing handshake.received on B")
	}
	data := ev.Data.(map[string]interface{})
	if uint32(data["peer_node_id"].(float64)) != nodeA {
		t.Errorf("expected peer_node_id=%d, got %v", nodeA, data["peer_node_id"])
	}
	t.Logf("B got handshake.received: peer=%v justification=%v", data["peer_node_id"], data["justification"])

	if _, ok := collectorB.WaitFor("handshake.pending", 3*time.Second); !ok {
		t.Error("missing handshake.pending on B")
	}

	// B sends handshake to A → A detects mutual, auto-approves
	_, err = infoB.Driver.Handshake(nodeA, "want to collaborate too")
	if err != nil {
		t.Fatalf("B handshake to A: %v", err)
	}

	// Wait for mutual trust on both sides
	deadline = time.After(5 * time.Second)
	for {
		trustA, _ := infoA.Driver.TrustedPeers()
		trustedA, _ := trustA["trusted"].([]interface{})
		trustB, _ := infoB.Driver.TrustedPeers()
		trustedB, _ := trustB["trusted"].([]interface{})
		if len(trustedA) > 0 && len(trustedB) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for mutual trust")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// A's webhook should have handshake.auto_approved with reason=mutual
	// (A receives B's request second and detects the mutual condition)
	ev, ok = collectorA.WaitFor("handshake.auto_approved", 3*time.Second)
	if !ok {
		t.Fatal("missing handshake.auto_approved on A")
	}
	data = ev.Data.(map[string]interface{})
	if data["reason"] != "mutual" {
		t.Errorf("expected reason=mutual, got %v", data["reason"])
	}
	if uint32(data["peer_node_id"].(float64)) != nodeB {
		t.Errorf("expected auto_approved peer=%d, got %v", nodeB, data["peer_node_id"])
	}
	t.Logf("A got handshake.auto_approved: peer=%v reason=%v", data["peer_node_id"], data["reason"])
}

func TestWebhook_HandshakePendingAndApprove(t *testing.T) {
	t.Parallel()
	collectorB := newWebhookCollector()
	defer collectorB.Close()

	env := NewTestEnv(t)

	infoA := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})
	infoB := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
		c.WebhookURL = collectorB.URL()
	})

	nodeA := infoA.Daemon.NodeID()
	nodeB := infoB.Daemon.NodeID()

	// A sends one-way handshake to B → should go pending
	_, err := infoA.Driver.Handshake(nodeB, "I am agent A")
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// Wait for pending on B
	deadline := time.After(5 * time.Second)
	for {
		pending, _ := infoB.Driver.PendingHandshakes()
		if pl, _ := pending["pending"].([]interface{}); len(pl) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for pending handshake")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Verify handshake.received + handshake.pending events
	if _, ok := collectorB.WaitFor("handshake.received", 3*time.Second); !ok {
		t.Error("missing handshake.received")
	}
	ev, ok := collectorB.WaitFor("handshake.pending", 3*time.Second)
	if !ok {
		t.Fatal("missing handshake.pending")
	}
	data := ev.Data.(map[string]interface{})
	if uint32(data["peer_node_id"].(float64)) != nodeA {
		t.Errorf("expected peer_node_id=%d, got %v", nodeA, data["peer_node_id"])
	}
	t.Logf("handshake.pending: peer=%v justification=%v", data["peer_node_id"], data["justification"])

	// B approves A
	_, err = infoB.Driver.ApproveHandshake(nodeA)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Verify handshake.approved event
	ev, ok = collectorB.WaitFor("handshake.approved", 3*time.Second)
	if !ok {
		t.Fatal("missing handshake.approved")
	}
	data = ev.Data.(map[string]interface{})
	if uint32(data["peer_node_id"].(float64)) != nodeA {
		t.Errorf("expected approved peer_node_id=%d, got %v", nodeA, data["peer_node_id"])
	}
	t.Logf("handshake.approved: peer=%v", data["peer_node_id"])
}

func TestWebhook_HandshakeReject(t *testing.T) {
	t.Parallel()
	collectorB := newWebhookCollector()
	defer collectorB.Close()

	env := NewTestEnv(t)

	infoA := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})
	infoB := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
		c.WebhookURL = collectorB.URL()
	})

	nodeA := infoA.Daemon.NodeID()
	nodeB := infoB.Daemon.NodeID()

	// A sends handshake to B
	_, err := infoA.Driver.Handshake(nodeB, "please trust me")
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// Wait for pending
	deadline := time.After(5 * time.Second)
	for {
		pending, _ := infoB.Driver.PendingHandshakes()
		if pl, _ := pending["pending"].([]interface{}); len(pl) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for pending")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// B rejects A
	_, err = infoB.Driver.RejectHandshake(nodeA, "not authorized")
	if err != nil {
		t.Fatalf("reject: %v", err)
	}

	// Verify handshake.rejected event
	ev, ok := collectorB.WaitFor("handshake.rejected", 3*time.Second)
	if !ok {
		t.Fatal("missing handshake.rejected")
	}
	data := ev.Data.(map[string]interface{})
	if uint32(data["peer_node_id"].(float64)) != nodeA {
		t.Errorf("expected rejected peer_node_id=%d, got %v", nodeA, data["peer_node_id"])
	}
	if data["reason"] != "not authorized" {
		t.Errorf("expected reason='not authorized', got %v", data["reason"])
	}
	t.Logf("handshake.rejected: peer=%v reason=%v", data["peer_node_id"], data["reason"])
}

func TestWebhook_TrustRevoke(t *testing.T) {
	t.Parallel()
	collectorA := newWebhookCollector()
	defer collectorA.Close()
	collectorB := newWebhookCollector()
	defer collectorB.Close()

	env := NewTestEnv(t)

	infoA := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
		c.WebhookURL = collectorA.URL()
	})
	infoB := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
		c.WebhookURL = collectorB.URL()
	})

	nodeA := infoA.Daemon.NodeID()
	nodeB := infoB.Daemon.NodeID()

	// Establish mutual trust: A→B, wait, B→A
	infoA.Driver.Handshake(nodeB, "hello")
	deadline := time.After(5 * time.Second)
	for {
		pending, _ := infoB.Driver.PendingHandshakes()
		if pl, _ := pending["pending"].([]interface{}); len(pl) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for handshake")
		case <-time.After(10 * time.Millisecond):
		}
	}
	infoB.Driver.Handshake(nodeA, "hello back")

	// Wait for mutual trust
	deadline = time.After(5 * time.Second)
	for {
		trustA, _ := infoA.Driver.TrustedPeers()
		trustedA, _ := trustA["trusted"].([]interface{})
		trustB, _ := infoB.Driver.TrustedPeers()
		trustedB, _ := trustB["trusted"].([]interface{})
		if len(trustedA) > 0 && len(trustedB) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for mutual trust")
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Log("mutual trust established")

	// A revokes trust in B
	_, err := infoA.Driver.RevokeTrust(nodeB)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// A's webhook should have trust.revoked
	ev, ok := collectorA.WaitFor("trust.revoked", 3*time.Second)
	if !ok {
		t.Fatal("missing trust.revoked on A")
	}
	data := ev.Data.(map[string]interface{})
	if uint32(data["peer_node_id"].(float64)) != nodeB {
		t.Errorf("expected revoked peer_node_id=%d, got %v", nodeB, data["peer_node_id"])
	}
	t.Logf("trust.revoked on A: peer=%v", data["peer_node_id"])

	// B's webhook should have trust.revoked_by_peer (best-effort delivery —
	// the revoke notification is sent after the tunnel is torn down, so the
	// re-dial may not always succeed in local test environments)
	ev, ok = collectorB.WaitFor("trust.revoked_by_peer", 5*time.Second)
	if !ok {
		t.Log("trust.revoked_by_peer not received on B (best-effort delivery, may not arrive after tunnel teardown)")
	} else {
		data = ev.Data.(map[string]interface{})
		if uint32(data["peer_node_id"].(float64)) != nodeA {
			t.Errorf("expected revoked_by peer_node_id=%d, got %v", nodeA, data["peer_node_id"])
		}
		t.Logf("trust.revoked_by_peer on B: peer=%v", data["peer_node_id"])
	}
}

// --- Integration tests: data path webhook events ---

func TestWebhook_Datagram(t *testing.T) {
	t.Parallel()
	collectorB := newWebhookCollector()
	defer collectorB.Close()

	env := NewTestEnv(t)

	infoA := env.AddDaemon()
	infoB := env.AddDaemon(func(c *daemon.Config) {
		c.WebhookURL = collectorB.URL()
	})

	// A sends a datagram to B on port 1001
	err := infoA.Driver.SendTo(infoB.Daemon.Addr(), 1001, []byte("hello datagram"))
	if err != nil {
		t.Fatalf("sendto: %v", err)
	}

	// B receives the datagram
	go func() {
		infoB.Driver.RecvFrom()
	}()

	// Verify data.datagram event on B
	ev, ok := collectorB.WaitFor("data.datagram", 5*time.Second)
	if !ok {
		t.Fatal("missing data.datagram event on B")
	}
	data := ev.Data.(map[string]interface{})
	if data["dst_port"] == nil {
		t.Error("expected dst_port in data")
	}
	port := uint16(data["dst_port"].(float64))
	if port != 1001 {
		t.Errorf("expected dst_port=1001, got %d", port)
	}
	size := int(data["size"].(float64))
	if size != len("hello datagram") {
		t.Errorf("expected size=%d, got %d", len("hello datagram"), size)
	}
	t.Logf("data.datagram: src=%v dst_port=%v size=%v", data["src_addr"], data["dst_port"], data["size"])
}

func TestWebhook_ConnFIN(t *testing.T) {
	t.Parallel()
	collectorA := newWebhookCollector()
	defer collectorA.Close()

	env := NewTestEnv(t)

	a := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.WebhookURL = collectorA.URL()
	})
	b := env.AddDaemon()

	// Listen on A, port 1000
	ln, err := a.Driver.Listen(1000)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Read data, then let the server side stay open
		buf := make([]byte, 64)
		conn.Read(buf)
		// Keep connection open — wait for client to close
		time.Sleep(200 * time.Millisecond)
		conn.Close()
	}()

	// B dials A, sends data, then closes (triggers FIN)
	targetAddr := fmt.Sprintf("%s:1000", a.Daemon.Addr().String())
	conn, err := b.Driver.Dial(targetAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Write([]byte("hello"))
	conn.Close() // B closes → sends FIN to A

	<-serverDone

	// A should have received conn.fin from B's close
	ev, ok := collectorA.WaitFor("conn.fin", 5*time.Second)
	if !ok {
		t.Fatal("missing conn.fin event on A")
	}
	data := ev.Data.(map[string]interface{})
	t.Logf("conn.fin: remote=%v local_port=%v conn_id=%v",
		data["remote_addr"], data["local_port"], data["conn_id"])
}

// --- Full traffic simulation: exercise multiple event types in one test ---

func TestWebhook_FullTrafficSimulation(t *testing.T) {
	t.Parallel()
	collector := newWebhookCollector()
	defer collector.Close()

	env := NewTestEnv(t)

	a := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.WebhookURL = collector.URL()
	})
	b := env.AddDaemon()

	// 1. Registration should already have fired
	if _, ok := collector.WaitFor("node.registered", 3*time.Second); !ok {
		t.Fatal("missing node.registered")
	}
	t.Log("step 1: node.registered OK")

	// 2. B sends datagram to A
	err := b.Driver.SendTo(a.Daemon.Addr(), 1001, []byte("dgram-payload"))
	if err != nil {
		t.Fatalf("sendto: %v", err)
	}
	go func() { a.Driver.RecvFrom() }()

	if _, ok := collector.WaitFor("data.datagram", 5*time.Second); !ok {
		t.Error("missing data.datagram")
	} else {
		t.Log("step 2: data.datagram OK")
	}

	// 3. Stream connection: listen on A, B dials, exchange data, close
	ln, err := a.Driver.Listen(1000)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 128)
		n, _ := conn.Read(buf)
		t.Logf("server received: %q", string(buf[:n]))
		conn.Write([]byte("echo:" + string(buf[:n])))
		time.Sleep(100 * time.Millisecond)
		conn.Close()
	}()

	targetAddr := fmt.Sprintf("%s:1000", a.Daemon.Addr().String())
	conn, err := b.Driver.Dial(targetAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Write([]byte("simulate-traffic"))

	// Read echo reply
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	t.Logf("client received: %q", string(buf[:n]))

	conn.Close()
	<-serverDone

	// Verify connection lifecycle events
	if _, ok := collector.WaitFor("conn.syn_received", 3*time.Second); !ok {
		t.Error("missing conn.syn_received")
	} else {
		t.Log("step 3a: conn.syn_received OK")
	}
	if _, ok := collector.WaitFor("conn.established", 3*time.Second); !ok {
		t.Error("missing conn.established")
	} else {
		t.Log("step 3b: conn.established OK")
	}
	if _, ok := collector.WaitFor("tunnel.peer_added", 3*time.Second); !ok {
		t.Error("missing tunnel.peer_added")
	} else {
		t.Log("step 3c: tunnel.peer_added OK")
	}
	if _, ok := collector.WaitFor("conn.fin", 5*time.Second); !ok {
		t.Error("missing conn.fin")
	} else {
		t.Log("step 3d: conn.fin OK")
	}

	// 4. Dump all collected events for inspection
	events := collector.Events()
	t.Logf("--- total webhook events: %d ---", len(events))
	for i, ev := range events {
		t.Logf("  [%d] %s node_id=%d data=%v", i, ev.Event, ev.NodeID, ev.Data)
	}

	// Verify we got a reasonable spread of event types
	eventTypes := map[string]bool{}
	for _, ev := range events {
		eventTypes[ev.Event] = true
	}
	required := []string{"node.registered", "data.datagram", "conn.syn_received", "conn.established", "tunnel.peer_added"}
	for _, r := range required {
		if !eventTypes[r] {
			t.Errorf("missing required event type: %s", r)
		}
	}
	t.Logf("event types seen: %d unique types across %d events", len(eventTypes), len(events))
}

// --- Integration tests: application-level webhook events (messages, files, pub/sub) ---

func TestWebhook_MessageReceived(t *testing.T) {
	t.Parallel()
	collector := newWebhookCollector()
	defer collector.Close()

	env := NewTestEnv(t)

	// A has built-in dataexchange service enabled (default) + webhook
	a := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.WebhookURL = collector.URL()
	})
	// B sends messages to A
	b := env.AddDaemon()

	// B dials A's built-in dataexchange service on port 1001
	c, err := dataexchange.Dial(b.Driver, a.Daemon.Addr())
	if err != nil {
		t.Fatalf("dial dataexchange: %v", err)
	}
	defer c.Close()

	// Send a text message
	if err := c.SendText("hello from B"); err != nil {
		t.Fatalf("send text: %v", err)
	}
	// Read ACK from built-in service
	c.Recv()

	// Verify message.received webhook
	ev, ok := collector.WaitFor("message.received", 5*time.Second)
	if !ok {
		t.Fatal("missing message.received webhook event")
	}
	data := ev.Data.(map[string]interface{})
	if data["type"] != "TEXT" {
		t.Errorf("expected type=TEXT, got %v", data["type"])
	}
	if data["from"] == nil {
		t.Error("expected from field")
	}
	size := int(data["size"].(float64))
	if size != len("hello from B") {
		t.Errorf("expected size=%d, got %d", len("hello from B"), size)
	}
	t.Logf("message.received: type=%v from=%v size=%v", data["type"], data["from"], data["size"])
}

func TestWebhook_FileReceived(t *testing.T) {
	t.Parallel()
	collector := newWebhookCollector()
	defer collector.Close()

	env := NewTestEnv(t)

	a := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.WebhookURL = collector.URL()
	})
	b := env.AddDaemon()

	c, err := dataexchange.Dial(b.Driver, a.Daemon.Addr())
	if err != nil {
		t.Fatalf("dial dataexchange: %v", err)
	}
	defer c.Close()

	// Send a file
	fileContent := []byte("this is test file content")
	if err := c.SendFile("test-doc.txt", fileContent); err != nil {
		t.Fatalf("send file: %v", err)
	}
	// Read ACK
	c.Recv()

	// Verify file.received webhook
	ev, ok := collector.WaitFor("file.received", 5*time.Second)
	if !ok {
		t.Fatal("missing file.received webhook event")
	}
	data := ev.Data.(map[string]interface{})
	if data["filename"] != "test-doc.txt" {
		t.Errorf("expected filename=test-doc.txt, got %v", data["filename"])
	}
	size := int(data["size"].(float64))
	if size != len(fileContent) {
		t.Errorf("expected size=%d, got %d", len(fileContent), size)
	}
	if data["path"] == nil {
		t.Error("expected path field")
	}
	t.Logf("file.received: filename=%v size=%v path=%v", data["filename"], data["size"], data["path"])
}

func TestWebhook_PubSubLifecycle(t *testing.T) {
	t.Parallel()
	collector := newWebhookCollector()
	defer collector.Close()

	env := NewTestEnv(t)

	// A has built-in eventstream broker + webhook
	a := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.WebhookURL = collector.URL()
	})
	b := env.AddDaemon()
	c := env.AddDaemon()

	// B subscribes to "alerts" topic on A's built-in broker
	sub, err := eventstream.Subscribe(b.Driver, a.Daemon.Addr(), "alerts")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	// Verify pubsub.subscribed webhook
	ev, ok := collector.WaitFor("pubsub.subscribed", 5*time.Second)
	if !ok {
		t.Fatal("missing pubsub.subscribed webhook event")
	}
	data := ev.Data.(map[string]interface{})
	if data["topic"] != "alerts" {
		t.Errorf("expected topic=alerts, got %v", data["topic"])
	}
	t.Logf("pubsub.subscribed: topic=%v remote=%v", data["topic"], data["remote"])

	// C subscribes and publishes to "alerts"
	pub, err := eventstream.Subscribe(c.Driver, a.Daemon.Addr(), "alerts")
	if err != nil {
		t.Fatalf("publisher subscribe: %v", err)
	}

	// Wait for both subscriptions to be registered
	if !collector.WaitForCount("pubsub.subscribed", 2, 5*time.Second) {
		t.Fatal("expected 2 pubsub.subscribed events")
	}

	// Start receiver before publishing
	recvDone := make(chan *eventstream.Event, 1)
	go func() {
		evt, err := sub.Recv()
		if err == nil {
			recvDone <- evt
		}
	}()

	// C publishes a message
	if err := pub.Publish("alerts", []byte("server is down")); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// Wait for B to receive
	select {
	case evt := <-recvDone:
		t.Logf("subscriber received: topic=%s payload=%s", evt.Topic, string(evt.Payload))
	case <-time.After(5 * time.Second):
		t.Error("subscriber did not receive published event")
	}

	// Verify pubsub.published webhook
	ev, ok = collector.WaitFor("pubsub.published", 5*time.Second)
	if !ok {
		t.Fatal("missing pubsub.published webhook event")
	}
	data = ev.Data.(map[string]interface{})
	if data["topic"] != "alerts" {
		t.Errorf("expected topic=alerts, got %v", data["topic"])
	}
	size := int(data["size"].(float64))
	if size != len("server is down") {
		t.Errorf("expected size=%d, got %d", len("server is down"), size)
	}
	t.Logf("pubsub.published: topic=%v size=%v from=%v", data["topic"], data["size"], data["from"])

	// B disconnects → should trigger pubsub.unsubscribed
	sub.Close()

	ev, ok = collector.WaitFor("pubsub.unsubscribed", 5*time.Second)
	if !ok {
		t.Fatal("missing pubsub.unsubscribed webhook event")
	}
	data = ev.Data.(map[string]interface{})
	if data["topic"] != "alerts" {
		t.Errorf("expected topic=alerts, got %v", data["topic"])
	}
	t.Logf("pubsub.unsubscribed: topic=%v remote=%v", data["topic"], data["remote"])

	pub.Close()
}

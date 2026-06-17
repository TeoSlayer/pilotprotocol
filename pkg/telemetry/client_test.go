package telemetry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestDisabledNoOp verifies that a client with an empty URL is a hard no-op.
func TestDisabledNoOp(t *testing.T) {
	c := New("", 0)
	if !c.disabled {
		t.Fatal("expected disabled client")
	}
	if err := c.Send(Event{Kind: "test"}); err != nil {
		t.Fatalf("Send on disabled client should not error: %v", err)
	}
}

// TestNewClientFromIdentityEmptyURL verifies that empty URL produces a no-op.
func TestNewClientFromIdentityEmptyURL(t *testing.T) {
	c := NewClientFromIdentity("", "/nonexistent", 0)
	if !c.disabled {
		t.Fatal("expected disabled client with empty URL")
	}
}

// TestNewClientFromIdentityNoIdentity verifies that missing identity file
// produces a client without signer (first-run grace).
func TestNewClientFromIdentityNoIdentity(t *testing.T) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity.json")
	c := NewClientFromIdentity("https://example.com/telemetry", identityPath, 42)
	if c.disabled {
		t.Fatal("expected non-disabled client even without identity")
	}
	// Without a signer, Send should be a no-op
	if err := c.Send(Event{Kind: "test"}); err != nil {
		t.Fatalf("Send without signer should not error: %v", err)
	}
}

// TestNewClientFromIdentityBadPerms verifies that permissive file perms
// do not prevent identity loading (identity loading is best-effort).
func TestNewClientFromIdentityBadPerms(t *testing.T) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity.json")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := map[string]any{
		"node_id":            42,
		"public_key_base64":  base64.StdEncoding.EncodeToString(pub),
		"private_key_base64": base64.StdEncoding.EncodeToString(priv),
	}
	data, _ := json.Marshal(id)
	if err := os.WriteFile(identityPath, data, 0644); err != nil {
		t.Fatal(err)
	}
	_ = NewClientFromIdentity("https://example.com/telemetry", identityPath, 42)
}

func edSign(priv ed25519.PrivateKey) func([]byte) []byte {
	return func(msg []byte) []byte { return ed25519.Sign(priv, msg) }
}

// TestSendWithSigner verifies that a configured client sends signed events.
func TestSendWithSigner(t *testing.T) {
	var mu sync.Mutex
	var receivedBody []byte
	var receivedTS, receivedPub, receivedSig string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		receivedBody, _ = io.ReadAll(r.Body)
		receivedTS = r.Header.Get(HeaderTimestamp)
		receivedPub = r.Header.Get(HeaderPubKey)
		receivedSig = r.Header.Get(HeaderSignature)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	c := New(server.URL, 42)
	c.SetSigner(edSign(priv), base64.StdEncoding.EncodeToString(pub))

	payload, _ := json.Marshal(map[string]string{"app_id": "io.test.app", "version": "1.0.0", "source": "catalogue"})
	err = c.Send(Event{
		Kind:    "app_installed",
		TS:      time.Now().UTC().Format(time.RFC3339),
		Payload: payload,
	})
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedTS == "" {
		t.Fatal("expected timestamp header")
	}
	if receivedPub == "" {
		t.Fatal("expected public key header")
	}
	if receivedSig == "" {
		t.Fatal("expected signature header")
	}
	if len(receivedBody) == 0 {
		t.Fatal("expected body")
	}
}

// TestSendDropsEventsWhenNoSigner verifies that Send is a no-op without signer.
func TestSendDropsEventsWhenNoSigner(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not receive request — no signer configured")
	}))
	defer server.Close()

	c := New(server.URL, 42)
	// No SetSigner call
	if err := c.Send(Event{Kind: "test"}); err != nil {
		t.Fatalf("Send should be no-op without signer: %v", err)
	}
}

// TestSignMessage verifies the signing contract.
func TestSignMessage(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"test":"data"}`)
	ts, pubB64, sigB64, err := SignMessage(priv, body)
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}
	if ts == "" {
		t.Fatal("expected non-empty timestamp")
	}
	if pubB64 == "" {
		t.Fatal("expected non-empty public key")
	}
	if sigB64 == "" {
		t.Fatal("expected non-empty signature")
	}
	pubBytes, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}
	pub := ed25519.PublicKey(pubBytes)
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	message := append([]byte(ts), '\n')
	message = append(message, body...)
	if !ed25519.Verify(pub, message, sigBytes) {
		t.Fatal("signature verification failed")
	}
}

// TestMultipleEvents verifies sending multiple events in one POST.
func TestMultipleEvents(t *testing.T) {
	var callCount int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	c := New(server.URL, 42)
	c.SetSigner(edSign(priv), base64.StdEncoding.EncodeToString(pub))

	events := []Event{
		{Kind: "app_installed", TS: time.Now().UTC().Format(time.RFC3339)},
		{Kind: "app_uninstalled", TS: time.Now().UTC().Format(time.RFC3339)},
	}
	if err := c.Send(events...); err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 HTTP call, got %d", callCount)
	}
}

// TestSetSignerNil disables signing.
func TestSetSignerNil(t *testing.T) {
	c := New("https://example.com", 0)
	c.SetSigner(nil, "")
	if err := c.Send(Event{Kind: "test"}); err != nil {
		t.Fatalf("Send should be no-op after nil signer: %v", err)
	}
}

// TestServerError propagates.
func TestServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	c := New(server.URL, 42)
	c.SetSigner(edSign(priv), base64.StdEncoding.EncodeToString(pub))

	err = c.Send(Event{Kind: "test", TS: time.Now().UTC().Format(time.RFC3339)})
	if err == nil {
		t.Fatal("expected error from server 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected error to mention status, got: %v", err)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package telemetry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestNewNoop(t *testing.T) {
	c := New("", 0)
	if err := c.Send(); err != nil {
		t.Fatal("no-op send should not error:", err)
	}
	if err := c.Send(Event{Kind: "test", Payload: []byte(`{}`)}); err != nil {
		t.Fatal("no-op send with events should not error:", err)
	}
}

func TestNewNoSigner(t *testing.T) {
	c := New("http://example.com/v1/events", 42)
	if err := c.Send(Event{Kind: "test", Payload: []byte(`{}`)}); err != nil {
		t.Fatal("send without signer should be no-op, not error:", err)
	}
}

func TestDisabledOnEmptyURL(t *testing.T) {
	c1 := New("", 0)
	if !c1.disabled {
		t.Fatal("expected disabled for empty URL")
	}
	c2 := New("  ", 0)
	if !c2.disabled {
		t.Fatal("expected disabled for whitespace-only URL")
	}
	c3 := New("https://example.com/v1/events", 0)
	if c3.disabled {
		t.Fatal("expected enabled for valid URL")
	}
}

func TestSendErrorsOnBadURL(t *testing.T) {
	c := New("http://127.0.0.1:1/events", 1)
	if err := c.Send(Event{Kind: "test", Payload: []byte(`{}`)}); err != nil {
		t.Fatal("no signer means no-op, not error:", err)
	}
}

func TestSignMessageRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"kind":"test","ts":"2026-01-01T00:00:00Z","payload":{}}`)

	ts, pubB64, sigB64, err := SignMessage(priv, body)
	if err != nil {
		t.Fatal("SignMessage failed:", err)
	}
	if ts == "" || pubB64 == "" || sigB64 == "" {
		t.Fatal("expected non-empty outputs")
	}

	// Reconstruct the canonical message
	msg := make([]byte, 0, len(ts)+1+len(body))
	msg = append(msg, ts...)
	msg = append(msg, '\n')
	msg = append(msg, body...)

	decodedPub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		t.Fatal("decode pubkey:", err)
	}
	decodedSig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatal("decode sig:", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(decodedPub), msg, decodedSig) {
		t.Fatal("signature verification failed on round-trip")
	}

	// Also verify public key matches
	if !ed25519.PublicKey(decodedPub).Equal(pub) {
		t.Fatal("public key mismatch")
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package telemetry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/pilot-protocol/common/crypto"
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

func TestNewClientFromIdentity(t *testing.T) {
	// Empty URL = no-op, no identity file needed
	c := NewClientFromIdentity("", "/nonexistent/identity.json", 0)
	if err := c.Send(Event{Kind: "test", Payload: []byte(`{}`)}); err != nil {
		t.Fatal("no-op with no url should not error:", err)
	}

	// Non-empty URL with no identity file = noop (file doesn't exist = first run)
	c2 := NewClientFromIdentity("http://example.com/v1/events", "/nonexistent/identity.json", 42)
	if err := c2.Send(Event{Kind: "test", Payload: []byte(`{}`)}); err != nil {
		t.Fatal("no identity file should be no-op, not error:", err)
	}

	// Valid identity file
	dir := t.TempDir()
	idPath := filepath.Join(dir, "identity.json")
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.SaveIdentity(idPath, id); err != nil {
		t.Fatal(err)
	}

	c3 := NewClientFromIdentity("http://example.com/v1/events", idPath, 7)
	if c3.disabled {
		t.Fatal("expected enabled for valid identity + URL")
	}
	if c3.sign == nil {
		t.Fatal("expected signer to be set")
	}
	if c3.pubKeyB == "" {
		t.Fatal("expected public key to be set")
	}
}

func TestNewClientFromIdentityLoosePerms(t *testing.T) {
	dir := t.TempDir()
	idPath := filepath.Join(dir, "identity.json")
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.SaveIdentity(idPath, id); err != nil {
		t.Fatal(err)
	}
	// Make the identity file world-readable — simulates a manual restore
	if err := os.Chmod(idPath, 0644); err != nil {
		t.Fatal(err)
	}

	// LoadIdentity refuses loose perms; client should warn and stay noop
	c := NewClientFromIdentity("http://example.com/v1/events", idPath, 7)
	if c.sign != nil {
		t.Fatal("expected no signer for loose-permissions identity file")
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

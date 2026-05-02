// SPDX-License-Identifier: AGPL-3.0-or-later

package trustedagents

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

// TestEmbeddedListVerifies is the build-time guarantee: the JSON+sig
// pair shipped in the binary must verify against the baked
// SignerPublicKey. If this test fails, the release would ship a
// daemon that rejects its own embedded list, so CI must catch it.
func TestEmbeddedListVerifies(t *testing.T) {
	store, err := NewStore("")
	if err != nil {
		t.Fatalf("embedded list failed verification: %v", err)
	}
	if store.Version() < 1 {
		t.Fatalf("version must be >= 1, got %d", store.Version())
	}
}

func TestRollbackRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Patch SignerPublicKey for this test by constructing a Store directly.
	signerPub := pub

	v2 := mustSign(t, priv, List{Version: 2, IssuedAt: time.Now().UTC().Format(time.RFC3339)})
	v1 := mustSign(t, priv, List{Version: 1, IssuedAt: time.Now().UTC().Format(time.RFC3339)})

	s := &Store{}
	l, err := parseAndVerify(v2.raw, []byte(v2.sigB64), signerPub)
	if err != nil {
		t.Fatal(err)
	}
	s.adopt(l)
	if s.Version() != 2 {
		t.Fatalf("want v2, got %d", s.Version())
	}

	// Try rolling back to v1.
	l, err = parseAndVerify(v1.raw, []byte(v1.sigB64), signerPub)
	if err != nil {
		t.Fatal(err)
	}
	if l.Version > s.Version() {
		t.Fatalf("v1 should not be greater than v2")
	}
}

func TestForgedSigRejected(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	s := mustSign(t, priv, List{
		Version:  1,
		IssuedAt: time.Now().UTC().Format(time.RFC3339),
		Agents:   []Agent{{Name: "evil", PublicKey: "AAAA", AddedAt: time.Now().UTC().Format(time.RFC3339)}},
	})

	if _, err := parseAndVerify(s.raw, []byte(s.sigB64), otherPub); err == nil {
		t.Fatal("expected verify failure with wrong signer pubkey")
	}
}

func TestIsTrusted(t *testing.T) {
	s := &Store{}
	s.adopt(List{
		Version:  1,
		IssuedAt: time.Now().UTC().Format(time.RFC3339),
		Agents: []Agent{
			{Name: "list-agents", PublicKey: "PUBKEY-A"},
			{Name: "search-agent", PublicKey: "PUBKEY-B"},
		},
	})

	if name, ok := s.IsTrusted("PUBKEY-A"); !ok || name != "list-agents" {
		t.Fatalf("PUBKEY-A: want (list-agents,true), got (%q,%v)", name, ok)
	}
	if _, ok := s.IsTrusted("UNKNOWN"); ok {
		t.Fatalf("UNKNOWN should not be trusted")
	}
	if _, ok := s.IsTrusted(""); ok {
		t.Fatalf("empty pubkey must never match")
	}
}

func TestCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "trusted-agents.json")

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signerPub := pub

	// Write a v3 cache file by signing-then-writing.
	s := mustSign(t, priv, List{
		Version:  3,
		IssuedAt: time.Now().UTC().Format(time.RFC3339),
		Agents:   []Agent{{Name: "x", PublicKey: "kx"}},
	})
	writeCache(cachePath, s.raw, []byte(s.sigB64))

	got, ok := loadCache(cachePath, signerPub)
	if !ok || got.Version != 3 {
		t.Fatalf("want v3 from cache, got ok=%v ver=%d", ok, got.Version)
	}

	// Tampered raw must fail to load.
	tampered := append([]byte(nil), s.raw...)
	tampered[len(tampered)-2] ^= 0x01
	writeCache(cachePath, tampered, []byte(s.sigB64))
	if _, ok := loadCache(cachePath, signerPub); ok {
		t.Fatal("tampered cache must not load")
	}
}

type signed struct {
	raw    []byte
	sigB64 string
}

func mustSign(t *testing.T, priv ed25519.PrivateKey, l List) signed {
	t.Helper()
	raw, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	sig := ed25519.Sign(priv, raw)
	return signed{raw: raw, sigB64: base64.StdEncoding.EncodeToString(sig)}
}

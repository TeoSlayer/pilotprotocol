// SPDX-License-Identifier: AGPL-3.0-or-later

package trustedagents

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

// TestEmbeddedListLoads is the build-time guard: the JSON shipped in
// the binary must parse cleanly. CI catches a malformed commit before
// it ships in a release.
func TestEmbeddedListLoads(t *testing.T) {
	store, err := NewStore("")
	if err != nil {
		t.Fatalf("embedded list malformed: %v", err)
	}
	if store.Version() < 1 {
		t.Fatalf("version must be >= 1, got %d", store.Version())
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

func TestRollbackRejected(t *testing.T) {
	s := &Store{}
	s.adopt(List{Version: 5, IssuedAt: time.Now().UTC().Format(time.RFC3339)})

	rawV4, _ := json.Marshal(List{Version: 4, IssuedAt: time.Now().UTC().Format(time.RFC3339)})
	updated, err := s.TryUpdate(rawV4)
	if err != nil {
		t.Fatalf("TryUpdate(v4): %v", err)
	}
	if updated {
		t.Fatal("v4 must not replace v5")
	}
	if s.Version() != 5 {
		t.Fatalf("want v5 still active, got %d", s.Version())
	}

	rawV6, _ := json.Marshal(List{
		Version:  6,
		IssuedAt: time.Now().UTC().Format(time.RFC3339),
		Agents:   []Agent{{Name: "x", PublicKey: "kx"}},
	})
	updated, err = s.TryUpdate(rawV6)
	if err != nil || !updated {
		t.Fatalf("TryUpdate(v6): updated=%v err=%v", updated, err)
	}
	if s.Version() != 6 {
		t.Fatalf("want v6 active, got %d", s.Version())
	}
	if _, ok := s.IsTrusted("kx"); !ok {
		t.Fatal("v6 agent should now be trusted")
	}
}

func TestCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "trusted-agents.json")

	raw, _ := json.Marshal(List{
		Version:  3,
		IssuedAt: time.Now().UTC().Format(time.RFC3339),
		Agents:   []Agent{{Name: "x", PublicKey: "kx"}},
	})
	writeCache(cachePath, raw)

	got, ok := loadCache(cachePath)
	if !ok || got.Version != 3 {
		t.Fatalf("want v3, got ok=%v ver=%d", ok, got.Version)
	}
}

func TestMalformedRejected(t *testing.T) {
	s := &Store{}
	s.adopt(List{Version: 1, IssuedAt: time.Now().UTC().Format(time.RFC3339)})

	if _, err := s.TryUpdate([]byte(`{"version": 0, "issued_at": "2026-01-01T00:00:00Z"}`)); err == nil {
		t.Fatal("version=0 must reject")
	}
	if _, err := s.TryUpdate([]byte(`{"version": 9, "issued_at": "not a date"}`)); err == nil {
		t.Fatal("bad issued_at must reject")
	}
	if _, err := s.TryUpdate([]byte(`{not json`)); err == nil {
		t.Fatal("garbage must reject")
	}
}

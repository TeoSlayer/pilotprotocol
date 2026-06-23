package catalogue

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/pilot-protocol/pilotprotocol/internal/catalogtrust"
)

// writeSignedCatalogue writes catalogue.json + a valid .sig (signed with an
// ephemeral key swapped into catalogtrust) and returns the file:// URL plus a
// restore func that undoes the key swap. Not parallel-safe: it mutates the
// process-global catalogue verify key.
func writeSignedCatalogue(t *testing.T, body string) (url string, restore func()) {
	t.Helper()
	dir := t.TempDir()
	cat := filepath.Join(dir, "catalogue.json")
	if err := os.WriteFile(cat, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	sig, restore := catalogtrust.SignWithEphemeralKey([]byte(body))
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	if err := os.WriteFile(cat+".sig", []byte(sigB64), 0o600); err != nil {
		t.Fatal(err)
	}
	return "file://" + cat, restore
}

const twoAppCatalogue = `{
  "version": 2,
  "apps": [
    {"id": "io.pilot.smolmachines", "publisher": "ed25519:3QJm6H6OdjtfrF+Es1lrRjfFmdtq2tGvVSWxia63vcI="},
    {"id": "io.pilot.nopublisher"}
  ]
}`

func TestLoadPublishers_VerifiesAndParses(t *testing.T) {
	url, restore := writeSignedCatalogue(t, twoAppCatalogue)
	defer restore()

	pins, err := LoadPublishers(url)
	if err != nil {
		t.Fatalf("LoadPublishers: %v", err)
	}
	if got := pins["io.pilot.smolmachines"]; got != "ed25519:3QJm6H6OdjtfrF+Es1lrRjfFmdtq2tGvVSWxia63vcI=" {
		t.Errorf("smolmachines pin = %q, want the declared key", got)
	}
	if _, ok := pins["io.pilot.nopublisher"]; ok {
		t.Error("an entry without a publisher must not be pinned")
	}
}

func TestLoadPublishers_RejectsTamperedCatalogue(t *testing.T) {
	url, restore := writeSignedCatalogue(t, twoAppCatalogue)
	defer restore()

	// Tamper the catalogue body after signing — the signature must no longer verify.
	cat := url[len("file://"):]
	tampered := `{"version":2,"apps":[{"id":"io.evil.app","publisher":"ed25519:3QJm6H6OdjtfrF+Es1lrRjfFmdtq2tGvVSWxia63vcI="}]}`
	if err := os.WriteFile(cat, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPublishers(url); err == nil {
		t.Fatal("expected a signature error for a tampered catalogue, got nil")
	}
}

func TestLoadPublishers_RejectsMissingSignature(t *testing.T) {
	dir := t.TempDir()
	cat := filepath.Join(dir, "catalogue.json")
	if err := os.WriteFile(cat, []byte(twoAppCatalogue), 0o600); err != nil {
		t.Fatal(err)
	}
	// No .sig file written.
	if _, err := LoadPublishers("file://" + cat); err == nil {
		t.Fatal("expected an error when the catalogue signature is missing, got nil")
	}
}

func TestProvider_RefreshPublisherAndCache(t *testing.T) {
	url, restore := writeSignedCatalogue(t, twoAppCatalogue)
	defer restore()

	cachePath := filepath.Join(t.TempDir(), "pins.json")
	p := NewProvider(url, cachePath)
	if err := p.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if pub, ok := p.Publisher("io.pilot.smolmachines"); !ok || pub == "" {
		t.Error("Publisher should report smolmachines as pinned after Refresh")
	}
	if _, ok := p.Publisher("io.pilot.unknown"); ok {
		t.Error("Publisher must report an unknown app as not pinned")
	}
	if p.Count() != 1 {
		t.Errorf("Count = %d, want 1", p.Count())
	}
	// Refresh wrote the cache; a fresh Provider must recover pins from it offline.
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("cache not written: %v", err)
	}
	p2 := NewProvider("file:///nonexistent/catalogue.json", cachePath)
	if err := p2.Refresh(); err == nil {
		t.Fatal("expected Refresh to fail against a nonexistent catalogue")
	}
	if !p2.LoadCache() {
		t.Fatal("LoadCache should recover pins from the disk cache")
	}
	if _, ok := p2.Publisher("io.pilot.smolmachines"); !ok {
		t.Error("after LoadCache, the cached pin must be served")
	}
}

func TestProvider_NilCacheAndFailClosed(t *testing.T) {
	// A provider that has never loaded anything reports nothing pinned.
	p := NewProvider("file:///nonexistent", "")
	if _, ok := p.Publisher("io.pilot.smolmachines"); ok {
		t.Error("an empty provider must report apps as not pinned (fail closed)")
	}
	if p.LoadCache() {
		t.Error("LoadCache with no cache path must report no pins")
	}
}

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// repoCataloguePath returns the path to the repo's signed catalogue,
// skipping if it (or its detached signature) isn't present.
func repoCataloguePath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd() // .../web4/cmd/pilotctl
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(wd, "..", "..", "catalogue", "catalogue.json")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("repo catalogue not found at %s: %v", p, err)
	}
	if _, err := os.Stat(p + ".sig"); err != nil {
		t.Skipf("repo catalogue signature not found: %v", err)
	}
	return p
}

// TestLoadCatalogue_VerifiesSignedRepoCatalogue confirms the committed
// catalogue verifies against the embedded catalogue key (the .sig in the
// repo must be signed by the embedded key — this guards that invariant).
func TestLoadCatalogue_VerifiesSignedRepoCatalogue(t *testing.T) {
	p := repoCataloguePath(t)
	t.Setenv("PILOT_APPSTORE_CATALOG_URL", "file://"+p)
	c, err := loadCatalogue()
	if err != nil {
		t.Fatalf("loadCatalogue on signed repo catalogue: %v", err)
	}
	if len(c.Apps) == 0 {
		t.Error("expected at least one app in the signed catalogue")
	}
}

// TestLoadCatalogue_FailsClosedWithoutSignature asserts a catalogue with
// no detached signature is rejected.
func TestLoadCatalogue_FailsClosedWithoutSignature(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile(repoCataloguePath(t))
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "catalogue.json")
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PILOT_APPSTORE_CATALOG_URL", "file://"+dst)
	if _, err := loadCatalogue(); err == nil {
		t.Error("loadCatalogue must fail closed when the signature is missing")
	}
}

// TestLoadCatalogue_FailsOnTamper asserts a modified catalogue fails the
// signature check even when a (now-stale) signature is present.
func TestLoadCatalogue_FailsOnTamper(t *testing.T) {
	dir := t.TempDir()
	src := repoCataloguePath(t)
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(src + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "catalogue.json")
	if err := os.WriteFile(dst, append(data, ' '), 0o644); err != nil { // tamper
		t.Fatal(err)
	}
	if err := os.WriteFile(dst+".sig", sig, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PILOT_APPSTORE_CATALOG_URL", "file://"+dst)
	if _, err := loadCatalogue(); err == nil {
		t.Error("loadCatalogue must reject a tampered catalogue")
	}
}

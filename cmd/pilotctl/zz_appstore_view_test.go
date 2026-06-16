// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/internal/catalogtrust"
)

// stageCatalogue writes a catalogue.json to a tempdir, signs it with an
// ephemeral catalogue key (whose public half is swapped into the embedded
// trust anchor for the duration of the test), writes the detached
// <catalogue>.sig, and points PILOT_APPSTORE_CATALOG_URL at it via file://.
//
// loadCatalogue verifies fail-closed against the embedded key, so the
// fixture MUST carry a valid signature — staging an unsigned fixture would
// (correctly) be rejected. Signing with a per-test key, rather than
// disabling the gate, keeps these tests exercising the real verification
// path against a valid signature. The original embedded key is restored via
// t.Cleanup so tests stay isolated.
func stageCatalogue(t *testing.T, catJSON string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "catalogue.json")
	if err := os.WriteFile(p, []byte(catJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	sig, restore := catalogtrust.SignWithEphemeralKey([]byte(catJSON))
	t.Cleanup(restore)
	if err := os.WriteFile(p+".sig", []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PILOT_APPSTORE_CATALOG_URL", "file://"+p)
}

// stageMetadata writes a metadata.json to a tempdir and returns its
// file:// URL plus the sha256 a catalogue entry must pin.
func stageMetadata(t *testing.T, mdJSON string) (url, sha string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "metadata.json")
	if err := os.WriteFile(p, []byte(mdJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(mdJSON))
	return "file://" + p, hex.EncodeToString(sum[:])
}

// installFake plants a sha-matching manifest + binary under root/id, the
// same layout the installer produces, so gatherInstalledFacts sees a
// "stopped, integrity OK" app.
func installFake(t *testing.T, root, id string) {
	t.Helper()
	appDir := filepath.Join(root, id)
	if err := os.MkdirAll(filepath.Join(appDir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(appDir, "bin", "app")
	if err := os.WriteFile(binPath, []byte("fake-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	binSHA := sha256File(binPath)
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"), validManifestJSON(id, binSHA), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadCatalogueVersions(t *testing.T) {
	cases := []struct {
		name    string
		version int
		wantErr bool
	}{
		{"v1 accepted", 1, false},
		{"v2 accepted", 2, false},
		{"v3 rejected", 3, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stageCatalogue(t, `{"version":`+itoa(tc.version)+`,"updated_at":"x","apps":[]}`)
			_, err := loadCatalogue()
			if tc.wantErr != (err != nil) {
				t.Fatalf("version %d: err=%v wantErr=%v", tc.version, err, tc.wantErr)
			}
		})
	}
}

// TestLoadCatalogueV1BackwardCompat confirms a pure v1 entry (no v2
// fields) still decodes and the new struct fields are simply empty.
func TestLoadCatalogueV1BackwardCompat(t *testing.T) {
	stageCatalogue(t, `{"version":1,"updated_at":"x","apps":[
		{"id":"io.old.app","version":"0.1.0","description":"old","bundle_url":"https://x/y.tgz","bundle_sha256":"abc"}]}`)
	c, err := loadCatalogue()
	if err != nil {
		t.Fatal(err)
	}
	e := c.Apps[0]
	if e.ID != "io.old.app" || e.Description != "old" {
		t.Fatalf("v1 core fields wrong: %+v", e)
	}
	if e.DisplayName != "" || e.MetadataURL != "" || len(e.Categories) != 0 || e.BundleSize != 0 {
		t.Fatalf("v2 fields should be zero on a v1 entry: %+v", e)
	}
}

func TestLoadAppMetadata(t *testing.T) {
	md := `{"schema_version":1,"id":"io.test.md","display_name":"MD","license":"MIT"}`
	url, sha := stageMetadata(t, md)

	t.Run("pinned + correct sha parses", func(t *testing.T) {
		m, err := loadAppMetadata(catalogueEntry{ID: "io.test.md", MetadataURL: url, MetadataSHA: sha})
		if err != nil {
			t.Fatal(err)
		}
		if m == nil || m.DisplayName != "MD" || m.License != "MIT" {
			t.Fatalf("bad parse: %+v", m)
		}
	})

	t.Run("sha mismatch is a hard error", func(t *testing.T) {
		_, err := loadAppMetadata(catalogueEntry{ID: "io.test.md", MetadataURL: url, MetadataSHA: "deadbeef"})
		if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
			t.Fatalf("want sha mismatch error, got %v", err)
		}
	})

	t.Run("no url means no detail, not an error", func(t *testing.T) {
		m, err := loadAppMetadata(catalogueEntry{ID: "io.test.md"})
		if err != nil || m != nil {
			t.Fatalf("want (nil,nil), got (%v,%v)", m, err)
		}
	})

	t.Run("id mismatch rejected", func(t *testing.T) {
		_, err := loadAppMetadata(catalogueEntry{ID: "io.other", MetadataURL: url, MetadataSHA: sha})
		if err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("want id-mismatch error, got %v", err)
		}
	})
}

// TestBuildAppViewReportMerge checks band precedence: detail doc overrides
// the index teaser, and real on-disk size + manifest methods layer on top.
func TestBuildAppViewReportMerge(t *testing.T) {
	entry := &catalogueEntry{
		ID: "io.merge.app", Version: "2.0.0", Description: "teaser desc",
		Vendor: "TeaserVendor", License: "TEASER", BundleSize: 999,
		MetadataURL: "file:///x", MetadataSHA: "abc",
	}
	meta := &appMetadata{
		ID: "io.merge.app", DescriptionMD: "full description",
		Vendor:  &mdVendor{Name: "RealVendor"},
		License: "MIT",
		Methods: []mdMethod{{Name: "a.one", Summary: "first"}},
		Size:    &mdSize{InstalledBytes: 5000},
	}
	facts := &installedAppFacts{
		Installed: true, AppVersion: "2.0.0", State: "ready", IntegrityOK: true,
		InstalledBytes: 42, Methods: []string{"a.one", "a.two"},
	}

	r := buildAppViewReport("io.merge.app", entry, meta, facts)
	if r.Description != "full description" {
		t.Errorf("detail desc should override teaser, got %q", r.Description)
	}
	if r.Vendor == nil || r.Vendor.Name != "RealVendor" {
		t.Errorf("detail vendor should override teaser, got %+v", r.Vendor)
	}
	if r.License != "MIT" {
		t.Errorf("detail license should override teaser, got %q", r.License)
	}
	if r.InstalledBytes != 42 {
		t.Errorf("real on-disk size should win, got %d", r.InstalledBytes)
	}
	if len(r.Methods) != 1 { // metadata methods present → no manifest fallback
		t.Errorf("metadata methods should be kept, got %d", len(r.Methods))
	}
	if !r.DetailVerified {
		t.Error("DetailVerified should be true when entry is pinned")
	}
	wantSources := "catalogue,metadata,local-manifest"
	if strings.Join(r.Sources, ",") != wantSources {
		t.Errorf("sources = %v, want %s", r.Sources, wantSources)
	}
}

// TestBuildAppViewReportSideloaded: installed but absent from catalogue —
// methods fall back to the manifest's exposes.
func TestBuildAppViewReportSideloaded(t *testing.T) {
	facts := &installedAppFacts{Installed: true, Methods: []string{"x.a", "x.b"}}
	r := buildAppViewReport("io.side.app", nil, nil, facts)
	if r.InCatalogue {
		t.Error("InCatalogue should be false")
	}
	if len(r.Methods) != 2 || r.Methods[0].Name != "x.a" {
		t.Errorf("methods should fall back to manifest exposes, got %+v", r.Methods)
	}
	if strings.Join(r.Sources, ",") != "local-manifest" {
		t.Errorf("sources = %v", r.Sources)
	}
}

func TestGatherInstalledFacts(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)

	if f := gatherInstalledFacts("io.absent.app"); f != nil {
		t.Errorf("absent app should yield nil, got %+v", f)
	}

	installFake(t, root, "io.present.app")
	f := gatherInstalledFacts("io.present.app")
	if f == nil || !f.Installed || !f.IntegrityOK || f.State != "stopped" {
		t.Fatalf("present app facts wrong: %+v", f)
	}
}

// TestCmdAppStoreViewJSON drives the full command in JSON mode for a
// catalogue+metadata+installed app and asserts the merged report.
func TestCmdAppStoreViewJSON(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	installFake(t, root, "io.view.app")

	md := `{"schema_version":1,"id":"io.view.app","display_name":"Viewer",` +
		`"description_md":"the full thing","license":"Apache-2.0",` +
		`"changelog":[{"version":"1.0.0","date":"2026-06-01","notes":["first"]}]}`
	url, sha := stageMetadata(t, md)
	stageCatalogue(t, `{"version":2,"updated_at":"x","apps":[
		{"id":"io.view.app","version":"1.0.0","description":"teaser",
		 "bundle_url":"https://x/y.tgz","bundle_sha256":"abc",
		 "vendor":"Acme","bundle_size":1234,
		 "metadata_url":"`+url+`","metadata_sha256":"`+sha+`"}]}`)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	out := captureStdout(t, func() { cmdAppStoreView([]string{"io.view.app"}) })
	var r appViewReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if r.ID != "io.view.app" || r.DisplayName != "Viewer" {
		t.Errorf("id/name wrong: %+v", r)
	}
	if r.Description != "the full thing" {
		t.Errorf("description should come from metadata, got %q", r.Description)
	}
	if !r.InCatalogue || !r.DetailVerified {
		t.Errorf("InCatalogue/DetailVerified should be true: %+v", r)
	}
	if r.Install == nil || !r.Install.IntegrityOK {
		t.Errorf("install band missing or not verified: %+v", r.Install)
	}
	if len(r.Changelog) != 1 || r.Changelog[0].Version != "1.0.0" {
		t.Errorf("changelog wrong: %+v", r.Changelog)
	}
	if !sliceHas(r.Sources, "catalogue") || !sliceHas(r.Sources, "metadata") || !sliceHas(r.Sources, "local-manifest") {
		t.Errorf("sources incomplete: %v", r.Sources)
	}
}

// itoa avoids pulling strconv into the test for one tiny conversion.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

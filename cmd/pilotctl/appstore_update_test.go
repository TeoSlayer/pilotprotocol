package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSemverCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"1.2.0", "1.1.9", 1},
		{"2.0.0", "1.9.9", 1},
		{"1.2", "1.2.0", 0},        // missing component == 0
		{"1.2.3-rc.1", "1.2.3", 0}, // prerelease ignored in the core compare
		{"0.10.0", "0.9.0", 1},     // numeric, not lexical
	}
	for _, c := range cases {
		if got := semverCompare(c.a, c.b); got != c.want {
			t.Errorf("semverCompare(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestScanInstalledApps(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)

	writeApp := func(id, ver string) {
		d := filepath.Join(root, id)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		mf := `{"id":"` + id + `","app_version":"` + ver + `","manifest_version":1,` +
			`"binary":{"path":"bin/x","sha256":"` + hex64 + `"},"exposes":["x.help"],` +
			`"protection":"shareable","store":{"publisher":"ed25519:AAA"}}`
		if err := os.WriteFile(filepath.Join(d, "manifest.json"), []byte(mf), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeApp("io.pilot.alpha", "1.0.0")
	writeApp("io.pilot.beta", "0.3.1")
	// a junk dir without a manifest is skipped
	_ = os.MkdirAll(filepath.Join(root, "junk"), 0o755)

	apps, err := scanInstalledApps()
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 2 {
		t.Fatalf("got %d apps, want 2: %+v", len(apps), apps)
	}
	if apps[0].ID != "io.pilot.alpha" || apps[0].AppVersion != "1.0.0" {
		t.Errorf("unexpected first app: %+v", apps[0])
	}
}

const hex64 = "0000000000000000000000000000000000000000000000000000000000000000"

func TestOutdatedReason(t *testing.T) {
	cases := []struct {
		name                                       string
		instVer, catVer, instSHA, catSHA, expected string
	}{
		{"newer version", "1.0.0", "1.1.0", "aaa", "bbb", "version"},
		{"newer version even if sha same", "1.0.0", "1.1.0", "aaa", "aaa", "version"},
		{"same version, bundle rebuilt", "0.1.3", "0.1.3", "aaa", "bbb", "rebuilt"},
		{"same version, same bundle → up to date", "0.1.3", "0.1.3", "aaa", "aaa", ""},
		{"same version, no recorded sha (pre-feature) → up to date", "0.1.3", "0.1.3", "", "bbb", ""},
		{"same version, catalogue sha unknown → up to date", "0.1.3", "0.1.3", "aaa", "", ""},
		{"older installed than catalogue is 'version'", "2.0.0", "2.0.1", "aaa", "bbb", "version"},
		{"installed newer than catalogue → not outdated", "1.2.0", "1.1.0", "aaa", "bbb", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := outdatedReason(c.instVer, c.catVer, c.instSHA, c.catSHA); got != c.expected {
				t.Fatalf("outdatedReason(inst=%s,cat=%s,iSHA=%s,cSHA=%s)=%q want %q",
					c.instVer, c.catVer, c.instSHA, c.catSHA, got, c.expected)
			}
		})
	}
}

// The aegis case, concretely: a same-version republish MUST be flagged as
// rebuilt so `upgrade --all` picks up the fixed bundle without a version bump.
func TestOutdatedReasonCatchesSameVersionRepublish(t *testing.T) {
	if outdatedReason("0.1.3", "0.1.3", "ae40da40oldsha", "c8416c11newsha") != "rebuilt" {
		t.Fatal("a rebuilt same-version bundle must be flagged 'rebuilt' (the aegis argv-fix case)")
	}
}

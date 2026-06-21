package main

import (
	"runtime"
	"strings"
	"testing"
)

// v1/v2 entry (no Bundles map) falls back to the single top-level bundle_url.
func TestResolveBundle_LegacySinglePlatform(t *testing.T) {
	e := catalogueEntry{ID: "io.pilot.x", BundleURL: "https://h/x.tar.gz", BundleSHA: "abc"}
	url, sha, err := e.resolveBundle()
	if err != nil || url != "https://h/x.tar.gz" || sha != "abc" {
		t.Fatalf("legacy fallback: url=%q sha=%q err=%v", url, sha, err)
	}
}

// v3 entry picks the host's os/arch from the Bundles map.
func TestResolveBundle_PicksHostPlatform(t *testing.T) {
	host := runtime.GOOS + "/" + runtime.GOARCH
	e := catalogueEntry{
		ID:        "io.pilot.x",
		BundleURL: "https://h/x-linux-amd64.tar.gz", // primary, should be ignored on non-linux/amd64 hosts when host has its own
		BundleSHA: "primary",
		Bundles: map[string]bundleVariant{
			host:           {BundleURL: "https://h/host.tar.gz", BundleSHA: "hostsha"},
			"plan9/risatx": {BundleURL: "https://h/other.tar.gz", BundleSHA: "x"},
		},
	}
	url, sha, err := e.resolveBundle()
	if err != nil || url != "https://h/host.tar.gz" || sha != "hostsha" {
		t.Fatalf("host pick: url=%q sha=%q err=%v", url, sha, err)
	}
}

// v3 entry that omits the host platform errors (no silent broken install),
// and lists what IS available.
func TestResolveBundle_MissingHostPlatformErrors(t *testing.T) {
	e := catalogueEntry{
		ID:        "io.pilot.x",
		BundleURL: "https://h/x.tar.gz",
		BundleSHA: "abc",
		Bundles: map[string]bundleVariant{
			"plan9/risatx": {BundleURL: "https://h/other.tar.gz", BundleSHA: "x"},
		},
	}
	_, _, err := e.resolveBundle()
	if err == nil {
		t.Fatal("expected error for unsupported host platform")
	}
	if !strings.Contains(err.Error(), "plan9/risatx") {
		t.Fatalf("error should list available platforms, got: %v", err)
	}
}

// canonicalPlatform folds every ecosystem naming convention to os/arch.
func TestCanonicalPlatform(t *testing.T) {
	cases := map[string]string{
		"darwin/arm64":   "darwin/arm64",
		"macos-arm64":    "darwin/arm64",
		"macos-arm":      "darwin/arm64",
		"aarch64-darwin": "darwin/arm64",
		"macos/silicon":  "darwin/arm64",
		"darwin/amd64":   "darwin/amd64",
		"macos-x86_64":   "darwin/amd64",
		"macos-intel":    "darwin/amd64",
		"linux/amd64":    "linux/amd64",
		"linux-x86_64":   "linux/amd64",
		"linux/arm64":    "linux/arm64",
		"aarch64-linux":  "linux/arm64",
	}
	for in, want := range cases {
		if got := canonicalPlatform(in); got != want {
			t.Errorf("canonicalPlatform(%q) = %q, want %q", in, got, want)
		}
	}
}

// A v3 entry keyed by the org "macos-arm64" convention still resolves on a
// darwin/arm64 host (the openclaw-agent bug: silicon nodes couldn't find the
// silicon bundle because the key wasn't the exact Go string).
func TestResolveBundle_AliasKeyResolves(t *testing.T) {
	host := runtime.GOOS + "/" + runtime.GOARCH
	// Build a map keyed by org-convention names for the current host.
	alias := map[string]string{
		"darwin/arm64": "macos-arm64",
		"darwin/amd64": "macos-x86_64",
		"linux/amd64":  "linux-x86_64",
		"linux/arm64":  "linux-arm64",
	}[host]
	if alias == "" {
		t.Skipf("no alias mapping for host %s", host)
	}
	e := catalogueEntry{
		ID:      "io.pilot.x",
		Bundles: map[string]bundleVariant{alias: {BundleURL: "https://h/host.tar.gz", BundleSHA: "hostsha"}},
	}
	url, sha, err := e.resolveBundle()
	if err != nil || url != "https://h/host.tar.gz" || sha != "hostsha" {
		t.Fatalf("alias key %q should resolve on host %s: url=%q sha=%q err=%v", alias, host, url, sha, err)
	}
}

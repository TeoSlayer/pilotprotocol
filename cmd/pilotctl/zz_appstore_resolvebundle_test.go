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

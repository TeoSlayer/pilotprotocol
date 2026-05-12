// SPDX-License-Identifier: AGPL-3.0-or-later

package skillinject

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Tests for plugin_allowlist.go: classifyPluginAllowList + mergePluginAllowList.
// These pin the JSON-merge contract that lets the daemon flip
// plugins.allow + plugins.entries.<id>.enabled in openclaw.json
// without clobbering the user's other settings.

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return m
}

// TestClassifyPluginAllowListMissingConfig pins: if the openclaw.json
// file doesn't exist (openclaw never ran), classify returns Drifted so
// the daemon creates the file with the minimal managed keys. This
// covers the "fresh install" path where openclaw is installed but
// hasn't been opened by the user yet.
func TestClassifyPluginAllowListMissingConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "openclaw.json")

	state := classifyPluginAllowList(cfg, "plugins.allow", "plugins.entries", "pilot")
	if state != StateDrifted {
		t.Fatalf("missing config classify=%s; want Drifted (so daemon creates it)", state)
	}
}

// TestClassifyPluginAllowListBothPresent pins: when allow-list contains
// our id AND entries.<id>.enabled is true, classify returns Identical.
// This is the steady-state noop path the 15-min loop hits 99% of the
// time after install.
func TestClassifyPluginAllowListBothPresent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "openclaw.json")
	writeJSON(t, cfg, map[string]any{
		"plugins": map[string]any{
			"allow": []any{"pilot"},
			"entries": map[string]any{
				"pilot": map[string]any{"enabled": true},
			},
		},
	})
	state := classifyPluginAllowList(cfg, "plugins.allow", "plugins.entries", "pilot")
	if state != StateIdentical {
		t.Fatalf("both-present classify=%s; want Identical", state)
	}
}

// TestClassifyPluginAllowListIdMissingFromAllow pins drift when our id
// is absent from the trust array even though the entry is enabled.
// User may have manually removed the allow-list line; daemon should
// re-add it next tick.
func TestClassifyPluginAllowListIdMissingFromAllow(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "openclaw.json")
	writeJSON(t, cfg, map[string]any{
		"plugins": map[string]any{
			"allow": []any{"other-plugin"},
			"entries": map[string]any{
				"pilot": map[string]any{"enabled": true},
			},
		},
	})
	state := classifyPluginAllowList(cfg, "plugins.allow", "plugins.entries", "pilot")
	if state != StateDrifted {
		t.Fatalf("classify=%s; want Drifted (id not in allow)", state)
	}
}

// TestClassifyPluginAllowListEntryDisabled pins drift when our entry is
// present but enabled=false. User may have toggled disabled to "park"
// the plugin; daemon's contract is to re-enable on the next tick. If
// the user wants persistent disable, they need the disable-via-pilotctl
// opt-out (out of scope for this test, future work).
func TestClassifyPluginAllowListEntryDisabled(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "openclaw.json")
	writeJSON(t, cfg, map[string]any{
		"plugins": map[string]any{
			"allow": []any{"pilot"},
			"entries": map[string]any{
				"pilot": map[string]any{"enabled": false},
			},
		},
	})
	state := classifyPluginAllowList(cfg, "plugins.allow", "plugins.entries", "pilot")
	if state != StateDrifted {
		t.Fatalf("classify=%s; want Drifted (entry disabled)", state)
	}
}

// TestMergePluginAllowListCreatesFile pins: when openclaw.json doesn't
// exist, mergePluginAllowList creates it with just the two managed
// branches. No surplus keys, no surprise — the user's untouched config
// stays out of our way until they create it themselves.
func TestMergePluginAllowListCreatesFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "openclaw.json")

	if err := mergePluginAllowList(cfg, "plugins.allow", "plugins.entries", "pilot"); err != nil {
		t.Fatalf("merge create: %v", err)
	}
	got := readJSON(t, cfg)
	plugins, ok := got["plugins"].(map[string]any)
	if !ok {
		t.Fatalf("plugins key missing: %v", got)
	}
	allow, ok := plugins["allow"].([]any)
	if !ok || len(allow) != 1 || allow[0] != "pilot" {
		t.Fatalf("allow = %v; want [\"pilot\"]", allow)
	}
	entries, ok := plugins["entries"].(map[string]any)
	if !ok {
		t.Fatalf("entries map missing")
	}
	entry, ok := entries["pilot"].(map[string]any)
	if !ok || entry["enabled"] != true {
		t.Fatalf("entries.pilot = %v; want {enabled: true}", entry)
	}
}

// TestMergePluginAllowListPreservesOtherKeys is the critical safety
// property: the daemon must not clobber unrelated config keys when it
// merges. Verify that gateway/browser/auth sections survive byte-wise
// (modulo JSON re-marshal). This pins the "don't lose user state" rule
// that makes the daemon safe to run on a live openclaw config.
func TestMergePluginAllowListPreservesOtherKeys(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "openclaw.json")
	writeJSON(t, cfg, map[string]any{
		"gateway": map[string]any{
			"mode": "auto",
			"bind": "127.0.0.1:19000",
			"auth": map[string]any{
				"mode":  "token",
				"token": "secret",
			},
		},
		"plugins": map[string]any{
			"entries": map[string]any{
				"telegram": map[string]any{"enabled": true},
			},
		},
		"meta": map[string]any{
			"lastTouchedAt": "2026-05-12T10:00:00Z",
		},
	})

	if err := mergePluginAllowList(cfg, "plugins.allow", "plugins.entries", "pilot"); err != nil {
		t.Fatalf("merge: %v", err)
	}
	got := readJSON(t, cfg)

	// Unrelated keys untouched.
	gw, _ := got["gateway"].(map[string]any)
	if gw["mode"] != "auto" || gw["bind"] != "127.0.0.1:19000" {
		t.Fatalf("gateway clobbered: %v", gw)
	}
	gwAuth, _ := gw["auth"].(map[string]any)
	if gwAuth["mode"] != "token" || gwAuth["token"] != "secret" {
		t.Fatalf("gateway.auth clobbered: %v", gwAuth)
	}
	meta, _ := got["meta"].(map[string]any)
	if meta["lastTouchedAt"] != "2026-05-12T10:00:00Z" {
		t.Fatalf("meta clobbered: %v", meta)
	}

	// Existing entry preserved alongside our new one.
	plugins, _ := got["plugins"].(map[string]any)
	entries, _ := plugins["entries"].(map[string]any)
	tg, _ := entries["telegram"].(map[string]any)
	if tg["enabled"] != true {
		t.Fatalf("existing telegram entry lost: %v", entries)
	}
	pilot, _ := entries["pilot"].(map[string]any)
	if pilot["enabled"] != true {
		t.Fatalf("new pilot entry missing: %v", entries)
	}
}

// TestMergePluginAllowListIdempotent: running merge twice produces the
// same byte output. This is the property that makes the 15-min loop
// safe — no churn even though it re-fires every tick.
func TestMergePluginAllowListIdempotent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "openclaw.json")
	writeJSON(t, cfg, map[string]any{
		"plugins": map[string]any{"entries": map[string]any{}},
	})

	if err := mergePluginAllowList(cfg, "plugins.allow", "plugins.entries", "pilot"); err != nil {
		t.Fatalf("merge 1: %v", err)
	}
	after1, _ := os.ReadFile(cfg)
	if err := mergePluginAllowList(cfg, "plugins.allow", "plugins.entries", "pilot"); err != nil {
		t.Fatalf("merge 2: %v", err)
	}
	after2, _ := os.ReadFile(cfg)
	if string(after1) != string(after2) {
		t.Fatalf("not idempotent.\n--- after merge 1 ---\n%s\n--- after merge 2 ---\n%s",
			after1, after2)
	}
}

// TestMergePluginAllowListRefusesMalformedConfig: if openclaw.json
// exists but isn't parseable, merge must NOT overwrite it. The user
// might be mid-edit; the safer behavior is to error and let the next
// tick retry (after the user fixes the file).
func TestMergePluginAllowListRefusesMalformedConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "openclaw.json")
	garbage := []byte("not json at all { } [ ")
	if err := os.WriteFile(cfg, garbage, 0o644); err != nil {
		t.Fatalf("seed garbage: %v", err)
	}
	err := mergePluginAllowList(cfg, "plugins.allow", "plugins.entries", "pilot")
	if err == nil {
		t.Fatal("expected error on malformed config; got nil")
	}
	got, _ := os.ReadFile(cfg)
	if string(got) != string(garbage) {
		t.Fatalf("malformed config was overwritten:\n--- before ---\n%s\n--- after ---\n%s",
			garbage, got)
	}
}

// TestWalkObjectMaterializesNestedPath pins a small unit on the helper
// that creates intermediate objects: walkObject with create=true on a
// path like "a.b.c" must materialize a→b→{} when missing.
func TestWalkObjectMaterializesNestedPath(t *testing.T) {
	t.Parallel()
	obj := map[string]any{}
	parent, leaf := walkObject(obj, "a.b.c", true)
	if parent == nil || leaf != "c" {
		t.Fatalf("walkObject returned parent=%v leaf=%q; want non-nil parent + leaf=c", parent, leaf)
	}
	// Confirm a→b was actually materialized.
	a, _ := obj["a"].(map[string]any)
	if a == nil {
		t.Fatalf("a not materialized")
	}
	b, _ := a["b"].(map[string]any)
	if b == nil {
		t.Fatalf("a.b not materialized")
	}
}

// TestWalkObjectNoCreateBailsOut pins the read-only mode: walkObject
// with create=false on a missing path returns nil + empty so
// allowListContains / entryEnabled can short-circuit cheaply.
func TestWalkObjectNoCreateBailsOut(t *testing.T) {
	t.Parallel()
	obj := map[string]any{"a": map[string]any{}}
	parent, leaf := walkObject(obj, "a.b.c", false)
	if parent != nil || leaf != "" {
		t.Fatalf("expected nil parent + empty leaf for missing path; got %v %q", parent, leaf)
	}
}

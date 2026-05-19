// SPDX-License-Identifier: AGPL-3.0-or-later

package skillinject_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/internal/skillinject"
)

// Smoke tests for the disable path. The hard safety invariants these
// tests pin down:
//
//   1. Files we co-inhabit with the user (CLAUDE.md, AGENTS.md, etc.)
//      are NEVER deleted — only our marker block is stripped. All other
//      bytes are preserved verbatim.
//   2. The OpenClaw allow-list JSON gets our id removed without
//      touching the user's other plugin entries.
//   3. Disable is idempotent — running it a second time is a clean
//      no-op (RemovalNoop), not an error.
//
// If any of these fail, do not ship: the disable path becomes
// data-destructive.

// TestUninstall_PreservesUserContentAboveAndBelowMarker pins the most
// important safety property: when our marker block lives inside a
// file with user content above AND below it, after Uninstall the
// user's bytes are byte-identical and only our marker is gone.
func TestUninstall_PreservesUserContentAboveAndBelowMarker(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	mustMkdirAll(t, filepath.Join(home, ".claude"))

	// Seed CLAUDE.md with substantial user content so the assertion
	// is robust to subtle whitespace handling regressions.
	claudeMd := filepath.Join(home, ".claude", "CLAUDE.md")
	userBefore := "# My instructions\n\nLine 1 of user content.\nLine 2 of user content.\nLine 3.\n"
	userAfter := "\n## Section B\n\nMore user lines.\nFinal line.\n"
	if err := os.WriteFile(claudeMd, []byte(userBefore+userAfter), 0o644); err != nil {
		t.Fatalf("seed CLAUDE.md: %v", err)
	}
	expectedPreservedContent := userBefore + userAfter

	r := newFakeRepo(t)
	r.withTools(claudeOnly())

	// Install — Tick should insert our marker block somewhere in
	// CLAUDE.md without losing user content.
	if _, err := skillinject.Tick(context.Background(), r.cfg(home)); err != nil {
		t.Fatalf("Tick install: %v", err)
	}
	installed, err := os.ReadFile(claudeMd)
	if err != nil {
		t.Fatalf("read CLAUDE.md after install: %v", err)
	}
	if !strings.Contains(string(installed), "pilot:begin") {
		t.Fatalf("expected marker in CLAUDE.md after install, got: %q", installed)
	}
	if !strings.Contains(string(installed), "Line 1 of user content") {
		t.Fatalf("user content lost during install (regression in writeMarker)")
	}

	// Disable.
	rep, err := skillinject.Uninstall(context.Background(), r.cfg(home))
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	// CLAUDE.md MUST still exist.
	got, err := os.ReadFile(claudeMd)
	if err != nil {
		t.Fatalf("CLAUDE.md missing after disable — FATAL safety violation: %v", err)
	}

	// Marker must be gone.
	if strings.Contains(string(got), "pilot:begin") || strings.Contains(string(got), "pilot:end") {
		t.Errorf("marker still present after disable: %q", got)
	}

	// Every line of user content must be present byte-for-byte.
	for _, want := range []string{
		"# My instructions",
		"Line 1 of user content.",
		"Line 2 of user content.",
		"Line 3.",
		"## Section B",
		"More user lines.",
		"Final line.",
	} {
		if !strings.Contains(string(got), want) {
			t.Errorf("user line missing after disable: %q\nfull file: %q", want, got)
		}
	}

	// The stripped file must be a substring of the original-with-marker
	// (i.e. we removed bytes, not transformed them). Since marker stripping
	// removes exactly markerRE matches, the rest is verbatim.
	if !strings.Contains(string(installed), string(got)) && string(got) != expectedPreservedContent {
		// Either the stripped content matches the original verbatim (no
		// rewriting in between) or it equals the pre-install content
		// (perfectly clean removal). Either is acceptable.
		t.Errorf("stripped content not derivable from original by deletion alone:\ngot=%q\noriginal=%q", got, installed)
	}

	// Report should record a strip action.
	if !hasRemovalKind(rep, skillinject.RemovalStripped) {
		t.Errorf("expected RemovalStripped in report; got %+v", rep.Removals)
	}
}

// TestUninstall_PreservesFrontmatter pins that a YAML frontmatter block
// at the start of CLAUDE.md survives the install + disable round trip
// untouched. Frontmatter is fragile — parsers require it at line 1.
func TestUninstall_PreservesFrontmatter(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	mustMkdirAll(t, filepath.Join(home, ".claude"))

	claudeMd := filepath.Join(home, ".claude", "CLAUDE.md")
	frontmatter := "---\ntitle: My agent\nversion: 7\n---\n"
	body := "\n# Body heading\n\nbody content here.\n"
	if err := os.WriteFile(claudeMd, []byte(frontmatter+body), 0o644); err != nil {
		t.Fatalf("seed CLAUDE.md: %v", err)
	}

	r := newFakeRepo(t)
	r.withTools(claudeOnly())

	if _, err := skillinject.Tick(context.Background(), r.cfg(home)); err != nil {
		t.Fatalf("Tick install: %v", err)
	}
	if _, err := skillinject.Uninstall(context.Background(), r.cfg(home)); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	got, err := os.ReadFile(claudeMd)
	if err != nil {
		t.Fatalf("CLAUDE.md missing after disable: %v", err)
	}

	// Frontmatter must still be at line 1, byte-identical.
	if !strings.HasPrefix(string(got), frontmatter) {
		t.Errorf("frontmatter not at line 1 after disable\nwant prefix: %q\ngot start:   %q", frontmatter, firstNBytes(got, len(frontmatter)+50))
	}
	// Body content must still be present.
	if !strings.Contains(string(got), "body content here.") {
		t.Errorf("body content lost after disable: %q", got)
	}
}

// TestUninstall_NeverDeletesCoinhabitedFile pins the rule: when install
// CREATED the marker file from nothing (no user content), disable still
// leaves the file on disk. The user might track it in git as a
// placeholder; we don't presume to delete files in user-owned dirs.
func TestUninstall_NeverDeletesCoinhabitedFile(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	mustMkdirAll(t, filepath.Join(home, ".claude"))

	claudeMd := filepath.Join(home, ".claude", "CLAUDE.md")
	// File does NOT exist before install.
	if _, err := os.Stat(claudeMd); !os.IsNotExist(err) {
		t.Fatalf("precondition: CLAUDE.md should not exist yet")
	}

	r := newFakeRepo(t)
	r.withTools(claudeOnly())

	if _, err := skillinject.Tick(context.Background(), r.cfg(home)); err != nil {
		t.Fatalf("Tick install: %v", err)
	}
	mustExist(t, claudeMd)

	if _, err := skillinject.Uninstall(context.Background(), r.cfg(home)); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	// FATAL safety check: file must still exist.
	if _, err := os.Stat(claudeMd); err != nil {
		t.Fatalf("CLAUDE.md deleted after disable — SAFETY VIOLATION: %v", err)
	}
	// Marker must be gone; file may be empty/whitespace, that's OK.
	got, _ := os.ReadFile(claudeMd)
	if strings.Contains(string(got), "pilot:begin") {
		t.Errorf("marker still present: %q", got)
	}
}

// TestUninstall_OpenClawAllowListUserPluginsPreserved pins that the
// JSON inverse-merge surgically removes our id from the allow array
// + entries map, without touching the user's other plugin entries.
func TestUninstall_OpenClawAllowListUserPluginsPreserved(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	openclawDir := filepath.Join(home, ".openclaw")
	mustMkdirAll(t, openclawDir)

	// Seed openclaw.json with 5 user plugins + arbitrary other top-level
	// keys to confirm we preserve everything outside our managed paths.
	configPath := filepath.Join(openclawDir, "openclaw.json")
	original := map[string]any{
		"version": float64(3),
		"plugins": map[string]any{
			"allow": []any{"user-a", "user-b", "user-c", "user-d", "user-e"},
			"entries": map[string]any{
				"user-a": map[string]any{"enabled": true, "config": map[string]any{"x": float64(1)}},
				"user-b": map[string]any{"enabled": true},
				"user-c": map[string]any{"enabled": false},
				"user-d": map[string]any{"enabled": true, "version": "2.0"},
				"user-e": map[string]any{"enabled": true},
			},
		},
		"telemetry": map[string]any{"opt_out": true},
	}
	b, _ := json.MarshalIndent(original, "", "  ")
	if err := os.WriteFile(configPath, b, 0o644); err != nil {
		t.Fatalf("seed openclaw.json: %v", err)
	}

	// Manifest with one tool that has a plugin block targeting openclaw.json.
	r := newFakeRepo(t)
	r.manifest = skillinject.Manifest{
		Version:    1,
		Entrypoint: "pilotctl",
		Tools: []skillinject.ManifestTool{{
			Name:              "openclaw",
			RootDir:           "~/.openclaw",
			SkillsDir:         "~/.openclaw/skills",
			HeartbeatPath:     "~/.openclaw/workspace/AGENTS.md",
			HeartbeatTemplate: "heartbeats/openclaw.md",
			Plugin: &skillinject.ManifestPlugin{
				ID:          "pilot",
				InstallPath: "~/.openclaw/extensions/pilotprotocol",
				Files: []skillinject.ManifestPluginFile{
					{Name: "openclaw.plugin.json", Src: "plugin/openclaw.plugin.json"},
					{Name: "index.mjs", Src: "plugin/index.mjs"},
				},
				AllowList: &skillinject.ManifestPluginAllowList{
					ConfigPath:        "~/.openclaw/openclaw.json",
					AllowListJsonPath: "plugins.allow",
					EntriesJsonPath:   "plugins.entries",
				},
			},
		}},
	}
	r.files["skills/pilotctl/SKILL.md"] = []byte(testContent)
	r.files["heartbeats/openclaw.md"] = []byte(testHeartbeat)
	r.files["plugin/openclaw.plugin.json"] = []byte(`{"id":"pilot"}`)
	r.files["plugin/index.mjs"] = []byte("// pilot plugin\n")

	// Install.
	if _, err := skillinject.Tick(context.Background(), r.cfg(home)); err != nil {
		t.Fatalf("Tick install: %v", err)
	}
	// Sanity: install merged our id in.
	merged := readJSONMap(t, configPath)
	if !contains(allowList(merged, "plugins.allow"), "pilot") {
		t.Fatalf("install did not add pilot to allow-list: %v", merged)
	}

	// Disable.
	if _, err := skillinject.Uninstall(context.Background(), r.cfg(home)); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	// File MUST still exist.
	after := readJSONMap(t, configPath)

	// All 5 user plugins must remain in the allow array, in the same order.
	gotAllow := allowList(after, "plugins.allow")
	wantAllow := []string{"user-a", "user-b", "user-c", "user-d", "user-e"}
	if !sliceEqual(gotAllow, wantAllow) {
		t.Errorf("allow-list user plugins not preserved\nwant=%v\ngot =%v", wantAllow, gotAllow)
	}
	if contains(gotAllow, "pilot") {
		t.Errorf("pilot still in allow-list after disable: %v", gotAllow)
	}

	// All 5 user entries must remain with their fields intact.
	gotEntries := nestedMap(after, "plugins.entries")
	for _, id := range wantAllow {
		if _, ok := gotEntries[id]; !ok {
			t.Errorf("user entry %q lost after disable", id)
		}
	}
	if _, ok := gotEntries["pilot"]; ok {
		t.Errorf("pilot entry not removed: %v", gotEntries["pilot"])
	}

	// Top-level keys outside plugins.* must be intact.
	if after["telemetry"] == nil {
		t.Errorf("top-level telemetry key lost")
	}
	if v, _ := after["version"].(float64); v != 3 {
		t.Errorf("top-level version key changed: %v", after["version"])
	}

	// .pilot-bak should be cleaned up.
	if _, err := os.Stat(configPath + skillinject.BackupSuffix); err == nil {
		t.Errorf("orphan .pilot-bak left behind after disable")
	}
}

// TestUninstall_Idempotent pins that a second disable run is a clean
// no-op — no errors, every removal is RemovalNoop. This protects
// against accidentally treating "nothing to remove" as a failure
// state and ensures `pilotctl skills disable && pilotctl skills disable`
// is safe.
func TestUninstall_Idempotent(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	mustMkdirAll(t, filepath.Join(home, ".claude"))

	r := newFakeRepo(t)
	r.withTools(claudeOnly())

	if _, err := skillinject.Tick(context.Background(), r.cfg(home)); err != nil {
		t.Fatalf("Tick install: %v", err)
	}

	// First disable.
	if _, err := skillinject.Uninstall(context.Background(), r.cfg(home)); err != nil {
		t.Fatalf("first Uninstall: %v", err)
	}

	// Second disable — must succeed and be a complete noop.
	rep2, err := skillinject.Uninstall(context.Background(), r.cfg(home))
	if err != nil {
		t.Fatalf("second Uninstall (idempotency violation): %v", err)
	}
	counts := rep2.Counts()
	for k, c := range counts {
		if c == 0 {
			continue
		}
		if k != skillinject.RemovalNoop {
			t.Errorf("second Uninstall had non-noop %s=%d action — not idempotent: %+v", k, c, rep2.Removals)
		}
	}
}

// helpers ---------------------------------------------------------------

func hasRemovalKind(rep *skillinject.RemovalReport, k skillinject.RemovalKind) bool {
	for _, r := range rep.Removals {
		if r.Action == k {
			return true
		}
	}
	return false
}

func firstNBytes(b []byte, n int) string {
	if n > len(b) {
		n = len(b)
	}
	return string(b[:n])
}

func readJSONMap(t *testing.T, path string) map[string]any {
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

func allowList(obj map[string]any, path string) []string {
	parts := strings.Split(path, ".")
	cur := obj
	for i := 0; i < len(parts)-1; i++ {
		nxt, _ := cur[parts[i]].(map[string]any)
		if nxt == nil {
			return nil
		}
		cur = nxt
	}
	arr, _ := cur[parts[len(parts)-1]].([]any)
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func nestedMap(obj map[string]any, path string) map[string]any {
	parts := strings.Split(path, ".")
	cur := obj
	for _, p := range parts {
		nxt, _ := cur[p].(map[string]any)
		if nxt == nil {
			return map[string]any{}
		}
		cur = nxt
	}
	return cur
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

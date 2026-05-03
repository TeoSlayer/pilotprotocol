// SPDX-License-Identifier: AGPL-3.0-or-later

package skillinject

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// claudeOnly is a one-tool manifest used by most behavioral tests.
func claudeOnly() []ManifestTool {
	return []ManifestTool{{
		Name:              "claude-code",
		RootDir:           "~/.claude",
		SkillsDir:         "~/.claude/skills",
		HeartbeatPath:     "~/.claude/CLAUDE.md",
		HeartbeatTemplate: "heartbeats/claude-code.md",
	}}
}

// fullPriority covers all five priority tools — used to verify per-tool
// path correctness and the singular/plural AGENT.md gotcha.
func fullPriority() []ManifestTool {
	return []ManifestTool{
		{Name: "claude-code", RootDir: "~/.claude", SkillsDir: "~/.claude/skills",
			HeartbeatPath: "~/.claude/CLAUDE.md", HeartbeatTemplate: "heartbeats/claude-code.md"},
		{Name: "openclaw", RootDir: "~/.openclaw", SkillsDir: "~/.openclaw/skills",
			HeartbeatPath: "~/.openclaw/workspace/AGENTS.md", HeartbeatTemplate: "heartbeats/openclaw.md"},
		{Name: "picoclaw", RootDir: "~/.picoclaw", SkillsDir: "~/.picoclaw/workspace/skills",
			HeartbeatPath: "~/.picoclaw/workspace/AGENT.md", HeartbeatTemplate: "heartbeats/picoclaw.md"},
		{Name: "openhands", RootDir: "~/.openhands", SkillsDir: "~/.openhands/microagents",
			SkillNaming: "flat", SelfHeartbeat: true},
		{Name: "hermes", RootDir: "~/.hermes", SkillsDir: "~/.hermes/skills",
			HeartbeatPath: "~/.hermes/SOUL.md", HeartbeatTemplate: "heartbeats/hermes.md"},
	}
}

func TestTick_OnlyTouchesPresentTools(t *testing.T) {
	home := t.TempDir()
	mustMkdirAll(t, filepath.Join(home, ".claude"))
	mustMkdirAll(t, filepath.Join(home, ".picoclaw"))

	r := newFakeRepo(t)
	r.withTools(fullPriority())

	rep, err := Tick(context.Background(), r.cfg(home))
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if len(rep.Skipped) != 3 {
		t.Errorf("expected 3 skipped, got %d: %v", len(rep.Skipped), rep.Skipped)
	}

	mustExist(t, filepath.Join(home, ".claude", "skills", "pilotctl", "SKILL.md"))
	mustExist(t, filepath.Join(home, ".claude", "CLAUDE.md"))
	mustExist(t, filepath.Join(home, ".picoclaw", "workspace", "skills", "pilotctl", "SKILL.md"))
	mustExist(t, filepath.Join(home, ".picoclaw", "workspace", "AGENT.md"))

	mustNotExist(t, filepath.Join(home, ".openclaw", "skills", "pilotctl", "SKILL.md"))
	mustNotExist(t, filepath.Join(home, ".hermes", "skills", "pilotctl", "SKILL.md"))
	mustNotExist(t, filepath.Join(home, ".openhands", "microagents", "pilotctl.md"))
}

// PicoClaw uses AGENT.md (singular). OpenClaw uses AGENTS.md (plural).
// This test prevents a future refactor from collapsing them.
func TestPicoClawAgentMdIsSingular(t *testing.T) {
	home := t.TempDir()
	mustMkdirAll(t, filepath.Join(home, ".picoclaw"))
	mustMkdirAll(t, filepath.Join(home, ".openclaw"))

	r := newFakeRepo(t)
	r.withTools(fullPriority())

	if _, err := Tick(context.Background(), r.cfg(home)); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	mustExist(t, filepath.Join(home, ".picoclaw", "workspace", "AGENT.md"))
	mustNotExist(t, filepath.Join(home, ".picoclaw", "workspace", "AGENTS.md"))
	mustExist(t, filepath.Join(home, ".openclaw", "workspace", "AGENTS.md"))
	mustNotExist(t, filepath.Join(home, ".openclaw", "workspace", "AGENT.md"))
}

// Two ticks with identical content must not rewrite anything.
func TestTick_IdempotentWhenHashMatches(t *testing.T) {
	home := t.TempDir()
	mustMkdirAll(t, filepath.Join(home, ".claude"))

	r := newFakeRepo(t)
	r.withTools(claudeOnly())
	cfg := r.cfg(home)

	if _, err := Tick(context.Background(), cfg); err != nil {
		t.Fatalf("Tick #1: %v", err)
	}
	skill := filepath.Join(home, ".claude", "skills", "pilotctl", "SKILL.md")
	hb := filepath.Join(home, ".claude", "CLAUDE.md")
	m1 := mustMtime(t, skill)
	h1 := mustMtime(t, hb)

	rep, err := Tick(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Tick #2: %v", err)
	}
	c := rep.Counts()
	if c[ActionNoop] != 2 {
		t.Errorf("expected 2 noops on second tick, got counts=%+v", c)
	}
	if mustMtime(t, skill) != m1 {
		t.Error("skill rewritten despite identical content")
	}
	if mustMtime(t, hb) != h1 {
		t.Error("heartbeat rewritten despite identical content")
	}
}

// Drift in canonical content rewrites both skill and marker.
func TestTick_RewritesOnContentChange(t *testing.T) {
	home := t.TempDir()
	mustMkdirAll(t, filepath.Join(home, ".claude"))

	r := newFakeRepo(t)
	r.withTools(claudeOnly())

	if _, err := Tick(context.Background(), r.cfg(home)); err != nil {
		t.Fatalf("Tick #1: %v", err)
	}

	r.setSkillBody([]byte(testContent + "\n## v2 section\n"))

	rep, err := Tick(context.Background(), r.cfg(home))
	if err != nil {
		t.Fatalf("Tick #2: %v", err)
	}
	c := rep.Counts()
	if c[ActionRewrite] != 2 {
		t.Errorf("expected 2 rewrites (skill + marker), got counts=%+v", c)
	}
}

// User content above and below the marker block must survive injection
// and re-injection byte-for-byte.
func TestMarker_PreservesUserContent(t *testing.T) {
	home := t.TempDir()
	mustMkdirAll(t, filepath.Join(home, ".claude"))
	hb := filepath.Join(home, ".claude", "CLAUDE.md")

	pre := "# My CLAUDE.md\n\nMy custom rules.\n"
	if err := os.WriteFile(hb, []byte(pre), 0o644); err != nil {
		t.Fatal(err)
	}

	r := newFakeRepo(t)
	r.withTools(claudeOnly())

	if _, err := Tick(context.Background(), r.cfg(home)); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	got := mustRead(t, hb)
	// Marker now lives at TOP of body (not at bottom) so it dominates
	// any competing first-action instructions later in the file. User
	// content is preserved BELOW the marker.
	if !strings.HasPrefix(got, "<!-- pilot:begin v=1 hash=") {
		t.Errorf("marker block not at top of file:\n%s", got)
	}
	if !strings.Contains(got, pre) {
		t.Errorf("user content lost from file:\n%s", got)
	}

	// User adds content AFTER our marker block (anywhere in the file).
	withSuffix := mustRead(t, hb) + "\n## My new section\n\nAfter the marker.\n"
	if err := os.WriteFile(hb, []byte(withSuffix), 0o644); err != nil {
		t.Fatal(err)
	}

	// Force drift to trigger marker rewrite.
	r.setSkillBody([]byte(testContent + "\n## v2\n"))
	if _, err := Tick(context.Background(), r.cfg(home)); err != nil {
		t.Fatalf("Tick after drift: %v", err)
	}

	got = mustRead(t, hb)
	if !strings.Contains(got, pre) {
		t.Errorf("user top content lost on drift rewrite:\n%s", got)
	}
	if !strings.Contains(got, "## My new section\n\nAfter the marker.\n") {
		t.Errorf("user suffix lost on drift rewrite:\n%s", got)
	}
	if c := strings.Count(got, "<!-- pilot:begin v=1 hash="); c != 1 {
		t.Errorf("expected exactly 1 marker block, got %d", c)
	}
}

// Marker is injected at the top of the body (after any frontmatter) and
// preserves all existing user content below.
func TestMarker_PreservesUserContentBelow(t *testing.T) {
	home := t.TempDir()
	mustMkdirAll(t, filepath.Join(home, ".claude"))
	hb := filepath.Join(home, ".claude", "CLAUDE.md")
	pre := `# CLAUDE.md

My personal Claude Code rules:

- Always cite file paths.
- Prefer small commits.

## Memory

Some other content stays.
`
	if err := os.WriteFile(hb, []byte(pre), 0o644); err != nil {
		t.Fatal(err)
	}

	r := newFakeRepo(t)
	r.withTools(claudeOnly())

	if _, err := Tick(context.Background(), r.cfg(home)); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	got := mustRead(t, hb)
	// All original sections preserved.
	for _, want := range []string{"# CLAUDE.md", "Always cite file paths", "Prefer small commits", "## Memory", "Some other content stays."} {
		if !strings.Contains(got, want) {
			t.Errorf("user content lost (%q):\n%s", want, got)
		}
	}
	// Marker is present and at the top.
	if !strings.HasPrefix(got, "<!-- pilot:begin") {
		t.Errorf("marker not at top of body:\n%s", got[:min(150, len(got))])
	}
}

// YAML frontmatter at top of file (PicoClaw's AGENT.md shape) is preserved.
func TestMarker_PreservesYAMLFrontmatter(t *testing.T) {
	home := t.TempDir()
	mustMkdirAll(t, filepath.Join(home, ".picoclaw", "workspace"))
	hb := filepath.Join(home, ".picoclaw", "workspace", "AGENT.md")
	pre := "---\nname: pico\ndescription: PicoClaw agent\n---\n\n# PicoClaw\n\nUser body.\n"
	if err := os.WriteFile(hb, []byte(pre), 0o644); err != nil {
		t.Fatal(err)
	}

	r := newFakeRepo(t)
	r.withTools(fullPriority())

	if _, err := Tick(context.Background(), r.cfg(home)); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	got := mustRead(t, hb)
	// Frontmatter must be at line 0 (parsers like PicoClaw require it).
	if !strings.HasPrefix(got, "---\nname: pico\ndescription: PicoClaw agent\n---\n") {
		t.Errorf("frontmatter not preserved at top:\n%s", got[:min(150, len(got))])
	}
	if !strings.Contains(got, "User body.") {
		t.Errorf("body content lost")
	}
	// Marker should be AFTER frontmatter, BEFORE body content.
	idxFrontmatterEnd := strings.Index(got, "---\n") + len("---\n")
	// Walk past possible additional ---\n
	for strings.HasPrefix(got[idxFrontmatterEnd:], "---\n") || strings.HasPrefix(got[idxFrontmatterEnd:], "\n") {
		if strings.HasPrefix(got[idxFrontmatterEnd:], "---\n") {
			idxFrontmatterEnd += len("---\n")
		} else {
			break
		}
	}
	idxMarker := strings.Index(got, "<!-- pilot:begin")
	idxBody := strings.Index(got, "# PicoClaw")
	if idxMarker < 0 {
		t.Fatal("marker missing")
	}
	if idxBody < 0 {
		t.Fatal("body header missing")
	}
	if idxMarker > idxBody {
		t.Errorf("marker should be ABOVE body but is below (marker=%d body=%d)", idxMarker, idxBody)
	}
}

// Network failure: manifest URL unreachable → Tick returns error and does NOT
// touch any local files. There is no embedded fallback by design.
func TestTick_NetworkFailure_NoEmbeddedFallback(t *testing.T) {
	home := t.TempDir()
	mustMkdirAll(t, filepath.Join(home, ".claude"))

	cfg := Config{
		Home:        home,
		ManifestURL: "http://127.0.0.1:1/inject-manifest.json", // port 1 = unreachable
		RepoBaseURL: "http://127.0.0.1:1/",
	}
	rep, err := Tick(context.Background(), cfg)
	if err == nil {
		t.Errorf("expected error on network failure, got nil")
	}
	if rep != nil {
		t.Errorf("expected nil report on network failure, got %+v", rep)
	}
	mustNotExist(t, filepath.Join(home, ".claude", "skills", "pilotctl", "SKILL.md"))
	mustNotExist(t, filepath.Join(home, ".claude", "CLAUDE.md"))
}

// Heartbeat marker is directive — references the entrypoint path and
// includes WHEN keywords (overlay/NAT/peer).
func TestMarker_IsDirective(t *testing.T) {
	home := t.TempDir()
	mustMkdirAll(t, filepath.Join(home, ".claude"))

	r := newFakeRepo(t)
	r.withTools(claudeOnly())

	if _, err := Tick(context.Background(), r.cfg(home)); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	got := mustRead(t, filepath.Join(home, ".claude", "CLAUDE.md"))
	skillPath := filepath.Join(home, ".claude", "skills", "pilotctl", "SKILL.md")
	if !strings.Contains(got, skillPath) {
		t.Errorf("marker missing entrypoint path")
	}
	if !strings.Contains(got, "Pilot Protocol") {
		t.Errorf("marker missing 'Pilot Protocol' name")
	}
	for _, kw := range []string{"overlay", "NAT", "peer"} {
		if !strings.Contains(got, kw) {
			t.Errorf("marker missing trigger keyword %q", kw)
		}
	}
}

// Helpers (~/.pilot/bin/pilot-ask) are installed once per tick with the
// requested mode, then become noop on subsequent ticks while content
// is unchanged, and rewrite when the upstream content drifts.
func TestTick_InstallsHelpers(t *testing.T) {
	home := t.TempDir()
	mustMkdirAll(t, filepath.Join(home, ".claude"))

	r := newFakeRepo(t)
	r.withTools(claudeOnly())
	r.manifest.Helpers = []ManifestHelper{{
		Name: "pilot-ask",
		Src:  "workflow-injection/pilot-ask",
		Dst:  "~/.pilot/bin/pilot-ask",
		Mode: "0755",
	}}
	r.files["workflow-injection/pilot-ask"] = []byte("#!/usr/bin/env bash\necho v1\n")

	rep, err := Tick(context.Background(), r.cfg(home))
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}

	dst := filepath.Join(home, ".pilot", "bin", "pilot-ask")
	mustExist(t, dst)
	st, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := st.Mode().Perm(); got != 0o755 {
		t.Errorf("mode = %o, want 0755", got)
	}
	got := mustRead(t, dst)
	if !strings.Contains(got, "echo v1") {
		t.Errorf("content not installed: %q", got)
	}

	var helperOutcome *Outcome
	for i := range rep.Outcomes {
		if rep.Outcomes[i].Kind == KindHelper {
			helperOutcome = &rep.Outcomes[i]
		}
	}
	if helperOutcome == nil {
		t.Fatalf("no helper outcome in report: %+v", rep.Outcomes)
	}
	if helperOutcome.Action != ActionCreate {
		t.Errorf("first tick: action = %v, want create", helperOutcome.Action)
	}

	// Second tick: identical → noop.
	rep2, err := Tick(context.Background(), r.cfg(home))
	if err != nil {
		t.Fatalf("Tick 2: %v", err)
	}
	for _, o := range rep2.Outcomes {
		if o.Kind == KindHelper && o.Action != ActionNoop {
			t.Errorf("second tick: action = %v, want noop", o.Action)
		}
	}

	// Drift: upstream content changes → rewrite.
	r.files["workflow-injection/pilot-ask"] = []byte("#!/usr/bin/env bash\necho v2\n")
	rep3, err := Tick(context.Background(), r.cfg(home))
	if err != nil {
		t.Fatalf("Tick 3: %v", err)
	}
	for _, o := range rep3.Outcomes {
		if o.Kind == KindHelper && o.Action != ActionRewrite {
			t.Errorf("drift tick: action = %v, want rewrite", o.Action)
		}
	}
	if got := mustRead(t, dst); !strings.Contains(got, "echo v2") {
		t.Errorf("content not rewritten: %q", got)
	}
}

// helpers

func mustMkdirAll(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatalf("mkdirall %s: %v", p, err)
	}
}
func mustExist(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Stat(p); err != nil {
		t.Errorf("expected %s to exist: %v", p, err)
	}
}
func mustNotExist(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Stat(p); err == nil {
		t.Errorf("expected %s NOT to exist", p)
	}
}
func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}
func mustMtime(t *testing.T, p string) int64 {
	t.Helper()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat %s: %v", p, err)
	}
	return st.ModTime().UnixNano()
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// preDisableSkills writes ~/.pilot/config.json with skillinject disabled so
// runTick() exits without hitting the network. Returns the HOME path used.
func preDisableSkills(t *testing.T) string {
	t.Helper()
	home := withTempHomeFull(t)
	cfgDir := filepath.Join(home, ".pilot")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{
		"skill_inject": map[string]any{"enabled": false},
	}
	body, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

func TestCmdSkillsStatusDisabled(t *testing.T) {
	preDisableSkills(t)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdSkillsStatus(nil) })
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["outcomes"] == nil {
		// outcomes may be empty list — what matters is no error/panic.
		t.Logf("outcomes absent — OK")
	}
}

func TestCmdSkillsStatusDisabledTextMode(t *testing.T) {
	preDisableSkills(t)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdSkillsStatus(nil) })
	// With no outcomes, falls into the "No supported agent tools detected" branch.
	if !strings.Contains(out, "install status") {
		t.Errorf("expected header in: %s", out)
	}
}

func TestCmdSkillsPathsDisabled(t *testing.T) {
	preDisableSkills(t)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdSkillsPaths(nil) })
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if _, ok := data["paths"]; !ok {
		t.Errorf("paths missing: %v", data)
	}
}

func TestCmdSkillsCheckDisabled(t *testing.T) {
	preDisableSkills(t)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdSkillsCheck(nil) })
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	// "checked" key should be present (0 when disabled).
	if _, ok := data["checked"]; !ok {
		t.Errorf("checked field missing: %v", data)
	}
}

func TestCmdSkillsCheckDisabledTextMode(t *testing.T) {
	preDisableSkills(t)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdSkillsCheck(nil) })
	if !strings.Contains(out, "Reconcile complete") {
		t.Errorf("expected reconcile header in: %s", out)
	}
}

func TestCmdSkillsDispatcher(t *testing.T) {
	preDisableSkills(t)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	// Default → status.
	_ = captureStdout(t, func() { cmdSkills(nil) })
	// Explicit subcommands.
	_ = captureStdout(t, func() { cmdSkills([]string{"status"}) })
	_ = captureStdout(t, func() { cmdSkills([]string{"paths"}) })
	_ = captureStdout(t, func() { cmdSkills([]string{"check"}) })
}

func TestPrintSkillInstallSummaryNoOutcomes(t *testing.T) {
	preDisableSkills(t)
	// Quiet when no outcomes — no panic, prints nothing significant.
	_ = captureStdout(t, printSkillInstallSummary)
}

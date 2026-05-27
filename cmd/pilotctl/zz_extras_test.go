// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCmdAppStoreAuditSinceFilter(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	appID := "io.test.since"
	appDir := filepath.Join(root, appID)
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// One old line (well past --since cutoff) and one recent line.
	now := time.Now().UTC()
	oldTime := now.Add(-2 * time.Hour).Format(time.RFC3339Nano)
	newTime := now.Add(-5 * time.Minute).Format(time.RFC3339Nano)
	body := `{"at":"` + oldTime + `","app":"io.test.since","event":"spawn","pid":1}` + "\n" +
		`{"at":"` + newTime + `","app":"io.test.since","event":"spawn","pid":2}` + "\n"
	if err := os.WriteFile(filepath.Join(appDir, "supervisor.log"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	// --since 30m should keep only the new entry.
	out := captureStdout(t, func() {
		cmdAppStoreAudit([]string{appID, "--since", "30m"})
	})
	var lines []auditLine
	if err := json.Unmarshal([]byte(out), &lines); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if len(lines) != 1 {
		t.Errorf("got %d lines, want 1: %+v", len(lines), lines)
	}
	if len(lines) > 0 && lines[0].PID != 2 {
		t.Errorf("expected new entry (pid=2), got %d", lines[0].PID)
	}
}

func TestCmdAppStoreAuditMultiFilter(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	appID := "io.test.multi"
	appDir := filepath.Join(root, appID)
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339Nano)
	body := `{"at":"` + now + `","app":"io.test.multi","event":"spawn","pid":1}` + "\n" +
		`{"at":"` + now + `","app":"io.test.multi","event":"exit","pid":1}` + "\n" +
		`{"at":"` + now + `","app":"io.test.multi","event":"spawn","pid":2}` + "\n"
	if err := os.WriteFile(filepath.Join(appDir, "supervisor.log"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	// All three filters together.
	out := captureStdout(t, func() {
		cmdAppStoreAudit([]string{appID, "--since", "1h", "--event", "spawn", "--tail", "1"})
	})
	var lines []auditLine
	if err := json.Unmarshal([]byte(out), &lines); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if len(lines) != 1 {
		t.Errorf("got %d lines, want 1 (last spawn)", len(lines))
	}
}

func TestCmdAppStoreActionsShortFlags(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	writePilotctlAudit(root, pilotctlAuditEvent{Event: "installed", AppID: "a"})
	writePilotctlAudit(root, pilotctlAuditEvent{Event: "uninstalled", AppID: "a"})

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	// Short flags should work the same as long ones.
	out := captureStdout(t, func() {
		cmdAppStoreActions([]string{"-e", "installed", "-n", "1"})
	})
	var lines []pilotctlAuditEvent
	if err := json.Unmarshal([]byte(out), &lines); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if len(lines) != 1 || lines[0].Event != "installed" {
		t.Errorf("got %+v", lines)
	}
}

func TestCmdAppStoreCapsOverLimit(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	appID := "io.test.over"
	dir := filepath.Join(root, appID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	mf := `{
		"id": "` + appID + `",
		"app_version": "1.0.0",
		"manifest_version": 1,
		"binary": {"runtime": "go", "path": "bin/app", "sha256": ""},
		"grants": [
			{"cap": "key.sign", "target": "x402-auth",
			 "if": {"kind": "cap", "params": {"asset": "USDC", "per": "hour", "limit": 10}}}
		],
		"store": {"publisher": "ed25519:test", "signature": "sig"}
	}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(mf), 0o600); err != nil {
		t.Fatal(err)
	}
	// Spend record exceeds the limit — exercises Remaining < 0 reporting.
	in := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339Nano)
	body := `{"at":"` + in + `","asset":"USDC","amount":50}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "cap-state.jsonl"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	out := captureStdout(t, func() { cmdAppStoreCaps([]string{appID}) })
	var reports []capUsageReport
	if err := json.Unmarshal([]byte(out), &reports); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if len(reports) != 1 {
		t.Fatalf("got %d, want 1", len(reports))
	}
	if reports[0].Remaining >= 0 {
		t.Errorf("expected negative Remaining, got %d", reports[0].Remaining)
	}
	if reports[0].Used != 50 {
		t.Errorf("Used = %d", reports[0].Used)
	}
}

func TestCmdAppStoreStatusInvalidManifest(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	appID := "io.test.invalid"
	appDir := filepath.Join(root, appID)
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Minimal manifest fails Validate (no grants, weak publisher).
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"),
		minimalManifestJSON(appID, nil), 0o600); err != nil {
		t.Fatal(err)
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdAppStoreStatus([]string{appID}) })
	var rpt appStatusReport
	if err := json.Unmarshal([]byte(out), &rpt); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rpt.ManifestValid {
		t.Error("expected ManifestValid=false for minimal manifest")
	}
	if len(rpt.ManifestErrors) == 0 {
		t.Error("expected ManifestErrors to be populated")
	}
}

func TestCmdAppStoreStatusInvalidManifestTextMode(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	appID := "io.test.invalid.text"
	appDir := filepath.Join(root, appID)
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"),
		minimalManifestJSON(appID, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdAppStoreStatus([]string{appID}) })
	// Text mode prints the invalid-manifest branch.
	for _, frag := range []string{"manifest:", "INVALID"} {
		if !contains(out, frag) {
			t.Errorf("expected %q in: %s", frag, out)
		}
	}
}

func TestSHA256FileLargerThanBuffer(t *testing.T) {
	t.Parallel()
	// Exercise io.Copy path with a > 32KB input so the chunked branch fires.
	dir := t.TempDir()
	path := filepath.Join(dir, "big")
	body := make([]byte, 200*1024)
	for i := range body {
		body[i] = byte(i % 251)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	got := sha256File(path)
	if len(got) != 64 {
		t.Errorf("expected 64-hex digest, got %q (len=%d)", got, len(got))
	}
}

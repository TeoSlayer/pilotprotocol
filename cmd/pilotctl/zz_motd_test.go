// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/pilotprotocol/internal/motd"
)

// withMOTD saves and restores the package-global banner/json state so these
// tests don't leak into the rest of the (non-parallel) package suite.
func withMOTD(t *testing.T, msg string, asJSON bool, fn func()) {
	t.Helper()
	origMsg, origJSON := importantUpdate, jsonOutput
	importantUpdate, jsonOutput = msg, asJSON
	defer func() { importantUpdate, jsonOutput = origMsg, origJSON }()
	fn()
}

func TestLoadMOTDFromMirror(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// configDir() resolves to $HOME/.pilot — write the mirror the daemon
	// would have produced for today, then confirm loadMOTD picks it up.
	now := time.Now()
	if err := motd.WriteMirror(motdMirrorPath(), motd.Message{Date: motd.DayKey(now), Text: "overlay maintenance 22:00 UTC"}, now); err != nil {
		t.Fatalf("seed mirror: %v", err)
	}

	importantUpdate = ""
	loadMOTD()
	if importantUpdate != "overlay maintenance 22:00 UTC" {
		t.Fatalf("importantUpdate = %q, want the seeded message", importantUpdate)
	}

	// Clear it (empty motd) — loadMOTD must yield no banner.
	if err := motd.WriteMirror(motdMirrorPath(), motd.Message{}, now); err != nil {
		t.Fatalf("clear mirror: %v", err)
	}
	importantUpdate = ""
	loadMOTD()
	if importantUpdate != "" {
		t.Fatalf("importantUpdate = %q, want empty after clear", importantUpdate)
	}
}

func TestPrintMOTDBannerTextMode(t *testing.T) {
	withMOTD(t, "scheduled maintenance", false, func() {
		out := captureStdout(t, printMOTDBanner)
		if !strings.Contains(out, "Message of the day: scheduled maintenance") {
			t.Fatalf("banner missing from output: %q", out)
		}
	})
}

func TestPrintMOTDBannerSuppressedInJSON(t *testing.T) {
	withMOTD(t, "scheduled maintenance", true, func() {
		out := captureStdout(t, printMOTDBanner)
		if out != "" {
			t.Fatalf("expected no text banner in JSON mode, got %q", out)
		}
	})
}

func TestPrintMOTDBannerEmpty(t *testing.T) {
	withMOTD(t, "", false, func() {
		out := captureStdout(t, printMOTDBanner)
		if out != "" {
			t.Fatalf("expected no banner with no message, got %q", out)
		}
	})
}

func TestOutputJSONCarriesImportantUpdate(t *testing.T) {
	withMOTD(t, "read this first", true, func() {
		out := captureStdout(t, func() { output(map[string]interface{}{"ok": true}) })
		var env map[string]interface{}
		if err := json.Unmarshal([]byte(out), &env); err != nil {
			t.Fatalf("unmarshal %q: %v", out, err)
		}
		if env["important_update"] != "read this first" {
			t.Fatalf("important_update = %v, want the message", env["important_update"])
		}
	})
}

func TestOutputJSONOmitsImportantUpdateWhenEmpty(t *testing.T) {
	withMOTD(t, "", true, func() {
		out := captureStdout(t, func() { output(map[string]interface{}{"ok": true}) })
		var env map[string]interface{}
		if err := json.Unmarshal([]byte(out), &env); err != nil {
			t.Fatalf("unmarshal %q: %v", out, err)
		}
		if _, present := env["important_update"]; present {
			t.Fatalf("important_update should be absent when there is no message: %q", out)
		}
	})
}

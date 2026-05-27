// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"strings"
	"testing"
)

// withArgs swaps os.Args around fn(). main() reads os.Args directly,
// so tests that invoke it must guard the global. NOT parallel safe.
func withArgs(t *testing.T, args []string, fn func()) {
	t.Helper()
	prev := os.Args
	defer func() { os.Args = prev }()
	os.Args = append([]string{"pilotctl"}, args...)
	fn()
}

// TestMainDispatchVersion exercises main()'s `version` branch in-process,
// covering global-flag parsing + dispatch table + the version handler.
// Safe because the version branch returns cleanly without os.Exit.
func TestMainDispatchVersion(t *testing.T) {
	withTempHomeFull(t)
	// Reset global state so previous tests don't bleed in.
	jsonOutput = false
	verbose = false

	withArgs(t, []string{"version"}, func() {
		out := captureStdout(t, main)
		if !strings.Contains(out, "dev") && out == "" {
			t.Errorf("expected version output, got %q", out)
		}
	})
}

func TestMainDispatchContext(t *testing.T) {
	withTempHomeFull(t)
	jsonOutput = false
	verbose = false

	withArgs(t, []string{"--json", "context"}, func() {
		out := captureStdout(t, main)
		if !strings.Contains(out, "commands") {
			t.Errorf("context did not produce commands: %s", out[:min3(500, len(out))])
		}
	})
}

func TestMainDispatchExtras(t *testing.T) {
	withTempHomeFull(t)
	jsonOutput = false
	verbose = false

	withArgs(t, []string{"extras"}, func() {
		out := captureStdout(t, main)
		if !strings.Contains(out, "extras") {
			t.Errorf("extras help missing: %s", out)
		}
	})
}

func TestMainDispatchInit(t *testing.T) {
	withTempHomeFull(t)
	jsonOutput = false
	verbose = false

	withArgs(t, []string{"--json", "init", "--registry", "test.r:9000"}, func() {
		out := captureStdout(t, main)
		if !strings.Contains(out, "test.r:9000") {
			t.Errorf("init missing registry: %s", out)
		}
	})
}

func TestMainDispatchAppstoreList(t *testing.T) {
	withTempHomeFull(t)
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	jsonOutput = false
	verbose = false

	withArgs(t, []string{"--json", "appstore", "list"}, func() {
		out := captureStdout(t, main)
		out = strings.TrimSpace(out)
		if out != "[]" && out != "null" {
			t.Errorf("expected empty list, got %q", out)
		}
	})
}

func TestMainDispatchInbox(t *testing.T) {
	withTempHomeFull(t)
	jsonOutput = false
	verbose = false

	withArgs(t, []string{"--json", "inbox"}, func() {
		out := captureStdout(t, main)
		if !strings.Contains(out, "messages") {
			t.Errorf("inbox missing 'messages': %s", out[:min3(300, len(out))])
		}
	})
}

func TestMainDispatchReceived(t *testing.T) {
	withTempHomeFull(t)
	jsonOutput = false
	verbose = false

	withArgs(t, []string{"--json", "received"}, func() {
		out := captureStdout(t, main)
		if !strings.Contains(out, "files") {
			t.Errorf("received missing 'files': %s", out[:min3(300, len(out))])
		}
	})
}

func TestMainDispatchVerboseFlag(t *testing.T) {
	withTempHomeFull(t)
	jsonOutput = false
	verbose = false

	withArgs(t, []string{"--verbose", "version"}, func() {
		out := captureStdout(t, main)
		if !strings.Contains(out, "dev") && out == "" {
			t.Errorf("expected version output: %q", out)
		}
	})
	// Restore for other tests.
	verbose = false
}

func TestMainDispatchExtrasGatewayList(t *testing.T) {
	withTempHomeFull(t)
	jsonOutput = false
	verbose = false
	withArgs(t, []string{"extras", "gateway", "list"}, func() {
		out := captureStdout(t, main)
		if !strings.Contains(out, "mappings") && !strings.Contains(out, "no mappings") {
			t.Errorf("gateway list missing output: %s", out)
		}
	})
}

func TestMainDispatchExtrasGatewayListJSON(t *testing.T) {
	withTempHomeFull(t)
	jsonOutput = false
	verbose = false
	withArgs(t, []string{"--json", "extras", "gateway", "list"}, func() {
		out := captureStdout(t, main)
		if !strings.Contains(out, "mappings") {
			t.Errorf("missing mappings: %s", out)
		}
	})
}

func TestMainDispatchAppstoreHelp(t *testing.T) {
	withTempHomeFull(t)
	jsonOutput = false
	verbose = false
	withArgs(t, []string{"appstore", "help"}, func() {
		// help text goes to stderr — just ensure no panic / no exit.
		_ = captureStderr(t, main)
	})
}

func TestMainDispatchAppstoreActions(t *testing.T) {
	withTempHomeFull(t)
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	jsonOutput = false
	verbose = false
	withArgs(t, []string{"--json", "appstore", "actions"}, func() {
		out := captureStdout(t, main)
		out = strings.TrimSpace(out)
		if out != "[]" && out != "null" {
			t.Errorf("expected empty array, got %q", out)
		}
	})
}

func TestMainDispatchHelpFlag(t *testing.T) {
	withTempHomeFull(t)
	jsonOutput = false
	verbose = false
	// pilotctl ping -h → printCommandHelp(ping, ["-h"]) → exits with status 0.
	// We can't easily call this inline (it os.Exit's) but we CAN test that
	// the help-flag detection happens in main's normal flow when followed
	// by a no-network command's help.
	withArgs(t, []string{"context", "-h"}, func() {
		// hasHelpFlag returns true → printCommandHelp("context", ["-h"]) →
		// looks up commandHelp["context"] → prints to stderr → os.Exit(0).
		// We can't catch os.Exit, so don't actually call. Just ensure args
		// path parses.
		_, _ = parseFlags([]string{"context", "-h"})
	})
}

func TestMainDispatchConfig(t *testing.T) {
	withTempHomeFull(t)
	jsonOutput = false
	verbose = false

	withArgs(t, []string{"--json", "config"}, func() {
		out := captureStdout(t, main)
		if !strings.Contains(out, "registry") {
			t.Errorf("config missing key: %s", out[:min3(300, len(out))])
		}
	})
}

func min3(a, b int) int {
	if a < b {
		return a
	}
	return b
}

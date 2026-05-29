// SPDX-License-Identifier: AGPL-3.0-or-later

package logging_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/pilot-protocol/common/logging"
)

func TestSetupWriterJSONFormat(t *testing.T) {
	// Cannot run in parallel because this mutates the package-global default logger.
	saved := slog.Default()
	defer slog.SetDefault(saved)

	var buf bytes.Buffer
	logging.SetupWriter(&buf, "info", "json")
	slog.Info("hello", "k", "v")

	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatal("no output emitted")
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, line)
	}
	if m["msg"] != "hello" {
		t.Errorf("msg = %v, want hello", m["msg"])
	}
	if m["k"] != "v" {
		t.Errorf("attr k = %v, want v", m["k"])
	}
	if m["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", m["level"])
	}
}

func TestSetupWriterTextFormat(t *testing.T) {
	saved := slog.Default()
	defer slog.SetDefault(saved)

	var buf bytes.Buffer
	logging.SetupWriter(&buf, "info", "text")
	slog.Info("hello", "k", "v")

	out := buf.String()
	if out == "" {
		t.Fatal("no output")
	}
	// text format output should NOT parse as JSON
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &map[string]interface{}{}); err == nil {
		t.Fatalf("text output unexpectedly parsed as JSON: %s", out)
	}
	if !strings.Contains(out, "hello") || !strings.Contains(out, "k=v") {
		t.Errorf("missing expected content: %s", out)
	}
}

func TestSetupWriterDefaultFormatIsText(t *testing.T) {
	saved := slog.Default()
	defer slog.SetDefault(saved)

	var buf bytes.Buffer
	logging.SetupWriter(&buf, "info", "unknown-format")
	slog.Info("msg")

	out := strings.TrimSpace(buf.String())
	// default (unknown format) → text handler, not JSON
	if strings.HasPrefix(out, "{") {
		t.Fatalf("unknown format should default to text, got JSON: %s", out)
	}
}

func TestSetupWriterLevelsGateOutput(t *testing.T) {
	cases := []struct {
		level     string
		wantDebug bool
		wantInfo  bool
		wantWarn  bool
		wantError bool
	}{
		{"debug", true, true, true, true},
		{"info", false, true, true, true},
		{"warn", false, false, true, true},
		{"warning", false, false, true, true},
		{"error", false, false, false, true},
		{"unknown", false, true, true, true}, // default → info
	}
	for _, tc := range cases {
		t.Run(tc.level, func(t *testing.T) {
			saved := slog.Default()
			defer slog.SetDefault(saved)

			var buf bytes.Buffer
			logging.SetupWriter(&buf, tc.level, "text")

			slog.Debug("D")
			slog.Info("I")
			slog.Warn("W")
			slog.Error("E")

			out := buf.String()
			if strings.Contains(out, "\"D\"") != tc.wantDebug && strings.Contains(out, "D") != tc.wantDebug {
				hasD := strings.Contains(out, "msg=D")
				if hasD != tc.wantDebug {
					t.Errorf("debug output present=%v, want=%v\n%s", hasD, tc.wantDebug, out)
				}
			}
			hasInfo := strings.Contains(out, "msg=I")
			if hasInfo != tc.wantInfo {
				t.Errorf("info output present=%v, want=%v\n%s", hasInfo, tc.wantInfo, out)
			}
			hasWarn := strings.Contains(out, "msg=W")
			if hasWarn != tc.wantWarn {
				t.Errorf("warn output present=%v, want=%v\n%s", hasWarn, tc.wantWarn, out)
			}
			hasError := strings.Contains(out, "msg=E")
			if hasError != tc.wantError {
				t.Errorf("error output present=%v, want=%v\n%s", hasError, tc.wantError, out)
			}
		})
	}
}

func TestSetupCaseInsensitive(t *testing.T) {
	saved := slog.Default()
	defer slog.SetDefault(saved)

	var buf bytes.Buffer
	logging.SetupWriter(&buf, "DEBUG", "JSON")
	slog.Debug("dbg-msg")
	line := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(line, "{") {
		t.Fatalf("uppercase JSON should produce JSON, got: %s", line)
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if m["level"] != "DEBUG" {
		t.Errorf("level = %v, want DEBUG", m["level"])
	}
}

func TestSetupUsesStderrByDefault(t *testing.T) {
	// Smoke test: Setup() picks the stderr path. We don't capture stderr (too
	// invasive) but we verify the call doesn't panic and leaves slog.Default
	// non-nil.
	saved := slog.Default()
	defer slog.SetDefault(saved)

	logging.Setup("info", "text")
	if slog.Default() == nil {
		t.Fatal("slog.Default() is nil after Setup")
	}
}

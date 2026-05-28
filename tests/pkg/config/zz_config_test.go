// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/pilot-protocol/common/config"
)

func TestLoadValidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	body := `{"log_level":"debug","port":8080,"verbose":true}`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg["log_level"] != "debug" {
		t.Errorf("log_level = %v, want debug", cfg["log_level"])
	}
	if cfg["port"].(float64) != 8080 {
		t.Errorf("port = %v, want 8080", cfg["port"])
	}
	if cfg["verbose"] != true {
		t.Errorf("verbose = %v, want true", cfg["verbose"])
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := config.Load("/nonexistent/path/cfg.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected parse error")
	}
}

// ApplyToFlags tests must serialize because flag package has global state.
// We use a dedicated FlagSet per test, but package-level flag.Visit reads
// flag.CommandLine — so we temporarily swap it.
func withFreshCommandLine(t *testing.T) *flag.FlagSet {
	t.Helper()
	saved := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
	t.Cleanup(func() { flag.CommandLine = saved })
	return flag.CommandLine
}

func TestApplyToFlagsSetsUnsetFlags(t *testing.T) {
	fs := withFreshCommandLine(t)
	var level string
	var port int
	var verbose bool
	fs.StringVar(&level, "log-level", "info", "")
	fs.IntVar(&port, "port", 9000, "")
	fs.BoolVar(&verbose, "verbose", false, "")

	// Parse with no args so nothing is explicitly set
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	cfg := map[string]interface{}{
		"log-level": "debug",
		"port":      float64(8080),
		"verbose":   true,
	}
	config.ApplyToFlags(cfg)

	if level != "debug" {
		t.Errorf("log-level = %q, want debug", level)
	}
	if port != 8080 {
		t.Errorf("port = %d, want 8080", port)
	}
	if verbose != true {
		t.Errorf("verbose = %v, want true", verbose)
	}
}

func TestApplyToFlagsPreservesExplicitlySetFlags(t *testing.T) {
	fs := withFreshCommandLine(t)
	var level string
	fs.StringVar(&level, "log-level", "info", "")

	// Explicitly set on the command line — config must NOT override.
	if err := fs.Parse([]string{"-log-level=warn"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	cfg := map[string]interface{}{"log-level": "debug"}
	config.ApplyToFlags(cfg)

	if level != "warn" {
		t.Errorf("log-level = %q, want warn (explicit flag must win over config)", level)
	}
}

func TestApplyToFlagsUnderscoreVariantMatches(t *testing.T) {
	fs := withFreshCommandLine(t)
	var level string
	fs.StringVar(&level, "log-level", "info", "")
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}

	// Config uses underscore; flag uses hyphen. ApplyToFlags should match them.
	cfg := map[string]interface{}{"log_level": "debug"}
	config.ApplyToFlags(cfg)

	if level != "debug" {
		t.Errorf("log-level = %q, want debug (underscore→hyphen match)", level)
	}
}

func TestApplyToFlagsHyphenVariantTakesPrecedenceOverUnderscore(t *testing.T) {
	fs := withFreshCommandLine(t)
	var level string
	fs.StringVar(&level, "log-level", "info", "")
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}

	// If both keys present, the exact flag-name match (log-level) must win.
	cfg := map[string]interface{}{
		"log-level": "debug",
		"log_level": "warn",
	}
	config.ApplyToFlags(cfg)

	if level != "debug" {
		t.Errorf("log-level = %q, want debug (exact match wins)", level)
	}
}

func TestApplyToFlagsIgnoresUnknownKeys(t *testing.T) {
	fs := withFreshCommandLine(t)
	var level string
	fs.StringVar(&level, "log-level", "info", "")
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	config.ApplyToFlags(map[string]interface{}{"unrelated-flag": "xyz"})
	if level != "info" {
		t.Errorf("log-level changed unexpectedly: %q", level)
	}
}

func TestApplyToFlagsSkipsUnsupportedTypes(t *testing.T) {
	fs := withFreshCommandLine(t)
	var level string
	fs.StringVar(&level, "log-level", "info", "")
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	// Nested map / array — should be silently skipped (not panic)
	config.ApplyToFlags(map[string]interface{}{
		"log-level": map[string]interface{}{"nested": "value"},
	})
	if level != "info" {
		t.Errorf("log-level changed from nested map: %q (unsupported type should skip)", level)
	}
}

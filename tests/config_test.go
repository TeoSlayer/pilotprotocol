package tests

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/config"
)

// NOTE: These tests modify the global flag.CommandLine and cannot use t.Parallel().

func TestConfigLoadAndApply(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.json")
	os.WriteFile(cfgPath, []byte(`{
		"addr": ":8080",
		"log-level": "debug",
		"encrypt": true,
		"count": 42
	}`), 0644)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg["addr"] != ":8080" {
		t.Fatalf("got addr=%v, want :8080", cfg["addr"])
	}

	// Set up a fresh flag set to test ApplyToFlags
	oldCommandLine := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
	defer func() { flag.CommandLine = oldCommandLine }()

	addr := flag.String("addr", ":9000", "")
	logLevel := flag.String("log-level", "info", "")
	encrypt := flag.Bool("encrypt", false, "")
	flag.Parse() // no args, nothing explicitly set

	config.ApplyToFlags(cfg)

	if *addr != ":8080" {
		t.Errorf("addr = %q, want %q", *addr, ":8080")
	}
	if *logLevel != "debug" {
		t.Errorf("log-level = %q, want %q", *logLevel, "debug")
	}
	if !*encrypt {
		t.Errorf("encrypt = false, want true")
	}
}

func TestConfigExplicitFlagOverridesConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.json")
	os.WriteFile(cfgPath, []byte(`{"addr": ":8080"}`), 0644)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	oldCommandLine := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
	defer func() { flag.CommandLine = oldCommandLine }()

	addr := flag.String("addr", ":9000", "")
	flag.CommandLine.Parse([]string{"-addr", ":7777"}) // explicitly set

	config.ApplyToFlags(cfg)

	if *addr != ":7777" {
		t.Errorf("addr = %q, want %q (explicit flag should win)", *addr, ":7777")
	}
}

func TestConfigUnderscoreVariant(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.json")
	os.WriteFile(cfgPath, []byte(`{"log_level": "warn"}`), 0644)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	oldCommandLine := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
	defer func() { flag.CommandLine = oldCommandLine }()

	logLevel := flag.String("log-level", "info", "")
	flag.Parse()

	config.ApplyToFlags(cfg)

	if *logLevel != "warn" {
		t.Errorf("log-level = %q, want %q (underscore key should match)", *logLevel, "warn")
	}
}

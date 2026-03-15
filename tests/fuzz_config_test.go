package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/config"
)

// ---------------------------------------------------------------------------
// config.Load
// ---------------------------------------------------------------------------

func TestConfigLoadValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	data := map[string]interface{}{
		"registry-addr": "localhost:9000",
		"beacon-addr":   "localhost:9001",
		"encrypt":       true,
		"log-level":     "debug",
	}
	b, _ := json.Marshal(data)
	os.WriteFile(path, b, 0600)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg["registry-addr"] != "localhost:9000" {
		t.Fatal("registry-addr mismatch")
	}
	if cfg["encrypt"] != true {
		t.Fatal("encrypt mismatch")
	}
}

func TestConfigLoadNonExistent(t *testing.T) {
	_, err := config.Load("/nonexistent/path/config.json")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestConfigLoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte("not json"), 0600)

	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestConfigLoadEmptyObject(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte("{}"), 0600)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg) != 0 {
		t.Fatalf("expected empty config, got %d keys", len(cfg))
	}
}

func TestConfigLoadNestedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := `{"key": {"nested": "value"}, "num": 42}`
	os.WriteFile(path, []byte(data), 0600)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Nested values are map[string]interface{}
	nested, ok := cfg["key"].(map[string]interface{})
	if !ok {
		t.Fatal("expected nested map")
	}
	if nested["nested"] != "value" {
		t.Fatal("nested value mismatch")
	}
	// JSON numbers are float64
	if cfg["num"] != float64(42) {
		t.Fatal("number should be float64")
	}
}

func TestConfigLoadEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(""), 0600)

	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestConfigLoadArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`[1,2,3]`), 0600)

	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for JSON array (not object)")
	}
}

func TestConfigLoadNullValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{"key": null}`), 0600)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg["key"] != nil {
		t.Fatal("null should decode as nil")
	}
}

func TestConfigLoadBooleanValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{"encrypt": true, "public": false}`), 0600)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg["encrypt"] != true {
		t.Fatal("true mismatch")
	}
	if cfg["public"] != false {
		t.Fatal("false mismatch")
	}
}

func FuzzConfigLoad(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"key":"value"}`))
	f.Add([]byte(`not json`))
	f.Add([]byte{})
	f.Add([]byte(`{"a": 1, "b": true, "c": null, "d": "str"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		os.WriteFile(path, data, 0600)
		_, _ = config.Load(path)
	})
}

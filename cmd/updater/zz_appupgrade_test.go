package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAutoUpdateEnabledGate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auto-update.json")
	// absent → off
	if autoUpdateEnabled(p) {
		t.Fatal("absent state file must read as disabled")
	}
	// empty path → off
	if autoUpdateEnabled("") {
		t.Fatal("empty state path must read as disabled")
	}
	// malformed → off (fail safe)
	_ = os.WriteFile(p, []byte("{not json"), 0o600)
	if autoUpdateEnabled(p) {
		t.Fatal("malformed state file must read as disabled")
	}
	// explicitly disabled
	_ = os.WriteFile(p, []byte(`{"enabled":false}`), 0o600)
	if autoUpdateEnabled(p) {
		t.Fatal("enabled:false must read as disabled")
	}
	// enabled
	_ = os.WriteFile(p, []byte(`{"enabled":true}`), 0o600)
	if !autoUpdateEnabled(p) {
		t.Fatal("enabled:true must read as enabled")
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"testing"
)

// TestAutoUpdateControl pins the enable/disable/default-off control surface.
func TestAutoUpdateControl(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // configDir() -> $HOME/.pilot

	if autoUpdateEnabled() {
		t.Fatal("auto-update must be OFF by default (no state file)")
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	_ = captureStdout(t, func() { cmdAutoUpdateSet(true) })
	if !autoUpdateEnabled() {
		t.Fatal("enable did not persist")
	}
	if _, err := os.Stat(autoUpdateStatePath()); err != nil {
		t.Fatalf("state file not written: %v", err)
	}

	_ = captureStdout(t, func() { cmdAutoUpdateSet(false) })
	if autoUpdateEnabled() {
		t.Fatal("disable did not persist")
	}
}

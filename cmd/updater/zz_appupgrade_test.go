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

// TestAppAutoUpgradeOptOut pins the PILOT_APP_UPDATE_OPT_OUT gate: app auto-upgrade is
// ON by default, off when the operator opts out, and back on when they opt in
// again. PILOT_UPDATER_NO_APP_UPGRADE is honored as a back-compat alias.
func TestAppAutoUpgradeOptOut(t *testing.T) {
	// Default: both unset → enabled.
	t.Setenv("PILOT_APP_UPDATE_OPT_OUT", "")
	t.Setenv("PILOT_UPDATER_NO_APP_UPGRADE", "")
	if !appAutoUpgradeEnabled() {
		t.Fatal("default (both env vars unset) must enable app auto-upgrade")
	}

	// Opt out via PILOT_APP_UPDATE_OPT_OUT (each truthy spelling).
	for _, v := range []string{"true", "1", "yes", "on", "TRUE"} {
		t.Setenv("PILOT_APP_UPDATE_OPT_OUT", v)
		if appAutoUpgradeEnabled() {
			t.Errorf("PILOT_APP_UPDATE_OPT_OUT=%q must disable app auto-upgrade", v)
		}
	}

	// Explicit opt-in values keep it enabled — this is what "switch back on".
	for _, v := range []string{"false", "0", "", "no"} {
		t.Setenv("PILOT_APP_UPDATE_OPT_OUT", v)
		if !appAutoUpgradeEnabled() {
			t.Errorf("PILOT_APP_UPDATE_OPT_OUT=%q must keep app auto-upgrade enabled", v)
		}
	}

	// Back-compat alias still disables.
	t.Setenv("PILOT_APP_UPDATE_OPT_OUT", "false")
	t.Setenv("PILOT_UPDATER_NO_APP_UPGRADE", "1")
	if appAutoUpgradeEnabled() {
		t.Error("legacy PILOT_UPDATER_NO_APP_UPGRADE=1 must still disable app auto-upgrade")
	}
}

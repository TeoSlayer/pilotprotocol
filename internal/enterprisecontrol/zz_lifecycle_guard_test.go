// SPDX-License-Identifier: AGPL-3.0-or-later

package enterprisecontrol

import (
	"path/filepath"
	"testing"

	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
)

// TestLifecycleGuardRejectsReplay pins SECURITY_REVIEW_v1.14 finding M2: an
// authority-signed restart/shutdown command is applied at most once; a replay
// (same or older issue time, or the same id) is rejected, and the record
// survives a process restart.
func TestLifecycleGuardRejectsReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "applied.json")
	rt := &Runtime{lifecycleGuardPath: path}
	cmd := authority.FleetCommand{ID: "cmd-1", IssuedAt: 1000}

	if rt.LifecycleCommandAlreadyApplied(cmd) {
		t.Fatal("fresh command reported as already applied")
	}
	if err := rt.MarkLifecycleCommandApplied(cmd); err != nil {
		t.Fatal(err)
	}
	if !rt.LifecycleCommandAlreadyApplied(cmd) {
		t.Fatal("replay of the same command was NOT rejected")
	}
	if !rt.LifecycleCommandAlreadyApplied(authority.FleetCommand{ID: "cmd-old", IssuedAt: 999}) {
		t.Fatal("older-issue-time command was not rejected")
	}
	if rt.LifecycleCommandAlreadyApplied(authority.FleetCommand{ID: "cmd-2", IssuedAt: 1001}) {
		t.Fatal("a genuinely newer command was wrongly rejected")
	}
	// Survives a restart: a fresh Runtime reading the same persisted guard.
	if restarted := (&Runtime{lifecycleGuardPath: path}); !restarted.LifecycleCommandAlreadyApplied(cmd) {
		t.Fatal("idempotency record did not survive restart")
	}
}

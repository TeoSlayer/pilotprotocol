// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pilot-protocol/app-store/pkg/manifest"
)

// TestProcExecCapabilityAccepted pins that this daemon's pinned app-store knows
// the proc.exec capability. CLI apps ship a proc.exec grant scoped to one
// command; before the app-store bump the daemon validated every manifest with a
// vocabulary that lacked proc.exec and would reject them as "not a known
// capability". This is the regression guard for the bump.
func TestProcExecCapabilityAccepted(t *testing.T) {
	mk := func(grants []any) *manifest.Manifest {
		raw, _ := json.Marshal(map[string]any{
			"id":               "io.pilot.gh",
			"app_version":      "0.1.0",
			"manifest_version": 1,
			"binary":           map[string]any{"runtime": "go", "path": "bin/app", "sha256": strings.Repeat("a", 64)},
			"grants":           grants,
			"protection":       "guarded",
			"store":            map[string]any{"publisher": "ed25519:AAAAB3NzaC1yc2EAAAADAQABAAABAQDXX0000000", "signature": "deadbeef"},
		})
		m, err := manifest.Parse(raw)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return m
	}

	// A CLI app's manifest (proc.exec scoped to the command) must validate.
	ok := mk([]any{
		map[string]any{"cap": "proc.exec", "target": "gh"},
		map[string]any{"cap": "audit.log", "target": "*"},
	})
	if errs := ok.Validate(); len(errs) != 0 {
		t.Fatalf("proc.exec manifest must validate against the pinned app-store: %v", errs)
	}

	// The hardened target still rejects a wildcard ("run anything").
	bad := mk([]any{
		map[string]any{"cap": "proc.exec", "target": "*"},
		map[string]any{"cap": "audit.log", "target": "*"},
	})
	if errs := bad.Validate(); len(errs) == 0 {
		t.Fatal("proc.exec target '*' must be rejected by the pinned app-store (hardened target)")
	}
}

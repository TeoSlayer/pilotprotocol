// SPDX-License-Identifier: AGPL-3.0-or-later

package policy_test

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	registry "github.com/pilot-protocol/common/registry/wire"
	"github.com/pilot-protocol/policy"
)

// TestShippedNetworkBlueprintsLoadAndValidate walks every blueprint JSON
// under configs/networks/ and confirms it parses via LoadBlueprint and
// passes ValidateBlueprint, then checks any expr_policy clause compiles.
//
// This test was previously in pkg/registry but importing pkg/policy
// from pkg/registry violates the layered architecture (registry is L8,
// policy is L11). It now lives at L12 (tests/plugins/policy) where
// importing both registry and the policy plugin is allowed.
func TestShippedNetworkBlueprintsLoadAndValidate(t *testing.T) {
	t.Parallel()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	// tests/plugins/policy/<this_file> → repo root via three ".."
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	configDir := filepath.Join(repoRoot, "..", "configs", "networks") /* sibling pilot-protocol/configs repo */

	matches, err := filepath.Glob(filepath.Join(configDir, "*.json"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) == 0 {
		t.Skipf("no blueprint JSONs found under %s (sibling pilot-protocol/configs not checked out)", configDir)
	}

	for _, path := range matches {
		name := filepath.Base(path)
		t.Run(strings.TrimSuffix(name, ".json"), func(t *testing.T) {
			bp, err := registry.LoadBlueprint(path)
			if err != nil {
				t.Fatalf("LoadBlueprint(%s): %v", name, err)
			}
			if err := registry.ValidateBlueprint(bp); err != nil {
				t.Fatalf("ValidateBlueprint(%s): %v", name, err)
			}
			if bp.Name == "" {
				t.Fatalf("%s: blueprint name is empty after load", name)
			}
			if len(bp.ExprPolicy) > 0 {
				doc, err := policy.Parse([]byte(bp.ExprPolicy))
				if err != nil {
					t.Fatalf("%s: expr_policy parse: %v", name, err)
				}
				if _, err := policy.Compile(doc); err != nil {
					t.Fatalf("%s: expr_policy compile: %v", name, err)
				}
			}
		})
	}
}

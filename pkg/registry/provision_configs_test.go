package registry

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/policy"
)

// TestShippedNetworkBlueprintsLoadAndValidate walks every blueprint JSON under
// configs/networks/ and confirms it parses via LoadBlueprint and passes
// ValidateBlueprint. This catches ship-time regressions (a bad commit hand-
// editing a config JSON, an expr_policy that no longer passes validation,
// etc.) before they reach operators using the provisioning CLI.
func TestShippedNetworkBlueprintsLoadAndValidate(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	configDir := filepath.Join(repoRoot, "configs", "networks")

	matches, err := filepath.Glob(filepath.Join(configDir, "*.json"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("no blueprint JSONs found under %s", configDir)
	}

	for _, path := range matches {
		name := filepath.Base(path)
		t.Run(strings.TrimSuffix(name, ".json"), func(t *testing.T) {
			bp, err := LoadBlueprint(path)
			if err != nil {
				t.Fatalf("LoadBlueprint(%s): %v", name, err)
			}
			if err := ValidateBlueprint(bp); err != nil {
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

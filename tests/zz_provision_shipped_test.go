// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestProvisionEveryShippedBlueprint round-trips each configs/networks/*.json
// through the real Server.ApplyBlueprint path via the registry client wire
// protocol. pkg/registry/provision_configs_test.go covers parse + policy
// compile; this goes one step further and actually provisions each blueprint
// against a live in-process registry, then verifies the network appears in
// ListNetworks and can be deprovisioned via DeleteNetwork. That catches
// regressions in findOrCreateNetwork, applyBlueprintPolicy,
// applyBlueprintExprPolicy, and storeRBACPreAssignments that the
// parse-only test cannot see.
func TestProvisionEveryShippedBlueprint(t *testing.T) {
	t.Parallel()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..")
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
			t.Parallel()
			rc, _, cleanup := startTestRegistryWithAdmin(t)
			defer cleanup()

			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			var bp map[string]interface{}
			if err := json.Unmarshal(raw, &bp); err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}

			resp, err := rc.ProvisionNetwork(bp, TestAdminToken)
			if err != nil {
				t.Fatalf("ProvisionNetwork(%s): %v", name, err)
			}
			if got, _ := resp["type"].(string); got != "provision_network_ok" {
				t.Fatalf("%s: expected type=provision_network_ok, got %q (resp=%+v)", name, got, resp)
			}
			netIDFloat, ok := resp["network_id"].(float64)
			if !ok || netIDFloat == 0 {
				t.Fatalf("%s: missing/zero network_id in response: %+v", name, resp)
			}
			netID := uint16(netIDFloat)
			if respName, _ := resp["name"].(string); respName == "" {
				t.Fatalf("%s: empty name in response", name)
			}
			if created, _ := resp["created"].(bool); !created {
				t.Fatalf("%s: first provision should report created=true", name)
			}

			// Re-apply: should be idempotent and report created=false.
			resp2, err := rc.ProvisionNetwork(bp, TestAdminToken)
			if err != nil {
				t.Fatalf("re-ProvisionNetwork(%s): %v", name, err)
			}
			if created, _ := resp2["created"].(bool); created {
				t.Fatalf("%s: second provision should report created=false", name)
			}

			// Network should be listed.
			listResp, err := rc.ListNetworks()
			if err != nil {
				t.Fatalf("%s: ListNetworks: %v", name, err)
			}
			nets, _ := listResp["networks"].([]interface{})
			found := false
			for _, n := range nets {
				nm, _ := n.(map[string]interface{})
				if uint16(nm["id"].(float64)) == netID {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("%s: network %d missing from ListNetworks", name, netID)
			}

			// Deprovision round-trip.
			if _, err := rc.DeleteNetwork(netID, TestAdminToken); err != nil {
				t.Fatalf("%s: DeleteNetwork(%d): %v", name, netID, err)
			}
		})
	}
}

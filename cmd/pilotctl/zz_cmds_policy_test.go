// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// IPC sub-command bytes for managed/policy — re-declared local so tests
// don't reach into pkg/driver's unexported identifiers. Must match
// pkg/driver/ipc.go.
const (
	tdCmdManaged   byte = 0x23
	tdCmdManagedOK byte = 0x24
)

// --- managed ---

func TestCmdManagedStatusJSON(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdManaged, tdCmdManagedOK, `{"network_id": 5, "peers": 3, "active": true}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdManagedStatus([]string{"--net", "5"}) })
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["network_id"].(float64) != 5 {
		t.Errorf("network_id = %v", data["network_id"])
	}
}

func TestCmdManagedCycleHuman(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdManaged, tdCmdManagedOK, `{"pruned": 2, "filled": 4, "peers": 5}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() {
		cmdManagedCycle([]string{"--net", "5", "--force"})
	})
	for _, want := range []string{"cycle complete", "pruned=2", "filled=4", "peers=5"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q: %s", want, out)
		}
	}
}

func TestCmdManagedReconcileHuman(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdManaged, tdCmdManagedOK, `{"network_id": 5, "peers": 7}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() {
		cmdManagedReconcile([]string{"--net", "5"})
	})
	if !strings.Contains(out, "reconciled") || !strings.Contains(out, "peers=7") {
		t.Errorf("missing reconciled/peers: %s", out)
	}
}

// --- policy ---

func TestCmdPolicyGet(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdManaged, tdCmdManagedOK, `{"network_id": 7, "policy": {"version": "1"}}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdPolicyGet([]string{"--net", "7"}) })
	if !strings.Contains(out, "policy") {
		t.Errorf("expected policy in: %s", out)
	}
}

func TestCmdPolicyValidateInlineHuman(t *testing.T) {
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	policy := `{
		"version": 1,
		"rules": [
			{"name": "demo", "on": "connect", "match": "true", "actions": [{"type": "allow"}]}
		]
	}`
	out := captureStdout(t, func() {
		cmdPolicyValidate([]string{"--inline", policy})
	})
	if !strings.Contains(out, "valid policy") {
		t.Errorf("expected 'valid policy' in: %s", out)
	}
}

func TestCmdPolicyValidateInlineJSON(t *testing.T) {
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	policy := `{
		"version": 1,
		"rules": [
			{"name": "demo", "on": "connect", "match": "true", "actions": [{"type": "allow"}]}
		]
	}`
	out := captureStdout(t, func() {
		cmdPolicyValidate([]string{"--inline", policy})
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["valid"] != true {
		t.Errorf("valid = %v", data["valid"])
	}
}

func TestCmdPolicyValidateFromFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "pol.json")
	policy := `{
		"version": 1,
		"rules": [
			{"name": "demo", "on": "connect", "match": "true", "actions": [{"type": "allow"}]}
		]
	}`
	if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() {
		cmdPolicyValidate([]string{"--file", path})
	})
	if !strings.Contains(out, "valid policy") {
		t.Errorf("expected 'valid policy' in: %s", out)
	}
}

func TestCmdPolicyTestEvalEvent(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "pol.json")
	policy := `{
		"version": 1,
		"rules": [
			{"name": "allow-all", "on": "connect", "match": "true", "actions": [{"type": "allow"}]}
		]
	}`
	if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() {
		cmdPolicyTest([]string{
			"--file", path,
			"--event", `{"type":"connect","peer":1}`,
		})
	})
	if !strings.Contains(out, "event type: connect") {
		t.Errorf("expected event report in: %s", out)
	}
}

func TestCmdPolicyTestJSON(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "pol.json")
	policy := `{
		"version": 1,
		"rules": [
			{"name": "allow-all", "on": "connect", "match": "true", "actions": [{"type": "allow"}]}
		]
	}`
	if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() {
		cmdPolicyTest([]string{
			"--file", path,
			"--event", `{"type":"connect"}`,
		})
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if _, ok := data["directives"]; !ok {
		t.Errorf("directives missing: %s", out)
	}
}

// --- member-tags ---

func TestCmdMemberTagsGetSingleNode(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdManaged, tdCmdManagedOK, `{"tags": ["alpha","beta"]}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() {
		cmdMemberTagsGet([]string{"--net", "5", "--node", "42"})
	})
	for _, want := range []string{"Node 42 in network 5", "alpha", "beta"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q: %s", want, out)
		}
	}
}

func TestCmdMemberTagsGetNoTagsForNode(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdManaged, tdCmdManagedOK, `{}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() {
		cmdMemberTagsGet([]string{"--net", "5", "--node", "42"})
	})
	if !strings.Contains(out, "(no tags)") {
		t.Errorf("expected '(no tags)' in: %s", out)
	}
}

func TestCmdMemberTagsGetAllMembers(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdManaged, tdCmdManagedOK,
		`{"members": {"7": ["alpha"], "8": ["beta"]}}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() {
		cmdMemberTagsGet([]string{"--net", "5"})
	})
	if !strings.Contains(out, "node 7") || !strings.Contains(out, "node 8") {
		t.Errorf("expected per-node lines: %s", out)
	}
}

func TestCmdMemberTagsSetDaemonPath(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdManaged, tdCmdManagedOK, `{"ok": true}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() {
		cmdMemberTagsSet([]string{"--net", "5", "--node", "42", "--tags", "alpha,beta"})
	})
	if !strings.Contains(out, "Member tags set for node 42 in network 5") {
		t.Errorf("missing confirmation: %s", out)
	}
}

// --- helpers ---

func TestCountEventTypesFromCompiledPolicy(t *testing.T) {
	// Compile a tiny policy with one connect rule so countEventTypes has
	// at least one populated entry. Going through cmdPolicyValidate keeps
	// the test honest — countEventTypes panics on a nil CompiledPolicy.
	pol := `{
		"version": 1,
		"rules": [
			{"name": "demo", "on": "connect", "match": "true", "actions": [{"type": "allow"}]}
		]
	}`
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() {
		cmdPolicyValidate([]string{"--inline", pol})
	})
	if !strings.Contains(out, "connect") {
		t.Errorf("expected connect event surfaced, got: %s", out)
	}
}

func TestDirectiveTypeNameUnknown(t *testing.T) {
	if got := directiveTypeName(99); got != "unknown" {
		t.Errorf("got %q", got)
	}
}

func TestResolveNetworkNodeArgNumeric(t *testing.T) {
	if got := resolveNetworkNodeArg("12345"); got != 12345 {
		t.Errorf("got %d", got)
	}
}

func TestResolveNetworkNodeArgAddress(t *testing.T) {
	if got := resolveNetworkNodeArg("0:0000.0000.000F"); got != 0xF {
		t.Errorf("got %d", got)
	}
}

func TestParseNodeIDHappy(t *testing.T) {
	if got := parseNodeID("100"); got != 100 {
		t.Errorf("got %d", got)
	}
	if got := parseNodeID("0"); got != 0 {
		t.Errorf("got %d", got)
	}
}

func TestParseUint16Happy(t *testing.T) {
	if got := parseUint16("1234", "port"); got != 1234 {
		t.Errorf("got %d", got)
	}
	if got := parseUint16("65535", "port"); got != 65535 {
		t.Errorf("got %d", got)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCmdVerifyStatusNotVerified: registry returns no badge for our node →
// status not_verified with a how-to-verify hint.
func TestCmdVerifyStatusNotVerified(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("lookup", map[string]interface{}{"node_id": float64(99), "address": "0:0000.0000.0063"})
	useRegistry(t, r)

	out := captureStdout(t, func() {
		withJSON(func() { cmdVerify([]string{"status", "--node", "99"}) })
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	data, _ := env["data"].(map[string]interface{})
	if v, _ := data["verified"].(bool); v {
		t.Errorf("verified=true, want false; out=%s", out)
	}
	if data["status"] != "not_verified" {
		t.Errorf("status=%v, want not_verified", data["status"])
	}
	if _, ok := data["how_to_verify"]; !ok {
		t.Error("missing how_to_verify hint when unverified")
	}
}

// TestCmdVerifyStatusBadgePresentUnvalidated: registry serves a badge but the
// build's issuer keyring is the all-zero placeholder, so offline verification
// fails closed → status badge_present_unvalidated, verified=false, provider
// still surfaced. Proves we do NOT trust the registry's word for "verified".
func TestCmdVerifyStatusBadgePresentUnvalidated(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("lookup", map[string]interface{}{
		"node_id":               float64(99),
		"badge":                 "pilotbadge:v1:99:github:1781827200:0:bdg-v1:",
		"badge_sig":             "ZmFrZQ==",
		"verification_provider": "github",
		"verified_at":           "2026-06-19T00:00:00Z",
	})
	useRegistry(t, r)

	out := captureStdout(t, func() {
		withJSON(func() { cmdVerify([]string{"status", "--node", "99"}) })
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	data, _ := env["data"].(map[string]interface{})
	if v, _ := data["verified"].(bool); v {
		t.Errorf("verified=true with placeholder issuer key (should fail closed); out=%s", out)
	}
	if data["status"] != "badge_present_unvalidated" {
		t.Errorf("status=%v, want badge_present_unvalidated", data["status"])
	}
	if data["provider"] != "github" {
		t.Errorf("provider=%v, want github", data["provider"])
	}
}

// TestCmdVerifyStatusHumanHint: human (non-JSON) output for an unverified node
// shows a clear headline plus the verify how-to.
func TestCmdVerifyStatusHumanHint(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("lookup", map[string]interface{}{"node_id": float64(99)})
	useRegistry(t, r)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdVerify([]string{"status", "--node", "99"}) })
	if !strings.Contains(out, "Not verified") || !strings.Contains(out, "pilot-verify verify") {
		t.Errorf("human hint missing expected text:\n%s", out)
	}
}

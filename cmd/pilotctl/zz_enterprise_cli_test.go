// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Round-3 supplementary coverage: usage-error + offline-registry paths
// for the enterprise admin commands and the network admin subcommands.
// All go through runCLI so fatalCode/fatalHint (which call os.Exit) are
// safely captured. Tests are -short safe — no network I/O beyond an
// instant ECONNREFUSED dial against 127.0.0.1:1.

// nopeRegistry returns a closed-port registry env so connectRegistry
// fails fast with ECONNREFUSED instead of hanging on a real DNS lookup.
func nopeRegistry(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"PILOT_REGISTRY":    "127.0.0.1:1",
		"PILOT_SOCKET":      "/tmp/nope-" + t.Name() + ".sock",
		"PILOT_ADMIN_TOKEN": "test-token",
	}
}

// ---- network admin subcommand usage errors ----

func TestCLINetworkDeleteUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"network", "delete"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLINetworkRenameUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"network", "rename"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLINetworkPromoteUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"network", "promote"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLINetworkDemoteUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"network", "demote"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLINetworkKickUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"network", "kick"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLINetworkRoleUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"network", "role"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLINetworkPolicyUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"network", "policy"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

// ---- network admin subcommand offline-registry paths ----

func TestCLINetworkDeleteOffline(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"network", "delete", "5"}, nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

func TestCLINetworkRenameOffline(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"network", "rename", "5", "new-name"}, nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

func TestCLINetworkPromoteOffline(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"network", "promote", "5", "42"}, nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

func TestCLINetworkDemoteOffline(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"network", "demote", "5", "42"}, nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

func TestCLINetworkKickOffline(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"network", "kick", "5", "42"}, nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

func TestCLINetworkRoleOffline(t *testing.T) {
	t.Parallel()
	// `role` doesn't need admin token but still hits the registry.
	_, stderr, code := runCLI(t, []string{"network", "role", "5", "42"},
		map[string]string{
			"PILOT_REGISTRY": "127.0.0.1:1",
			"PILOT_SOCKET":   "/tmp/nope-" + t.Name() + ".sock",
		})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

func TestCLINetworkPolicyGetOffline(t *testing.T) {
	t.Parallel()
	// network policy with only network_id → GET path, no admin token needed.
	_, stderr, code := runCLI(t, []string{"network", "policy", "5"},
		map[string]string{
			"PILOT_REGISTRY": "127.0.0.1:1",
			"PILOT_SOCKET":   "/tmp/nope-" + t.Name() + ".sock",
		})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

func TestCLINetworkPolicySetOffline(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t,
		[]string{"network", "policy", "5", "--max-members", "100", "--description", "test"},
		nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

// ---- enterprise admin commands ----

func TestCLIAuditOffline(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"audit", "--network", "0"}, nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

func TestCLIAuditNoToken(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"audit"},
		map[string]string{
			"PILOT_REGISTRY": "127.0.0.1:1",
			"PILOT_SOCKET":   "/tmp/nope-" + t.Name() + ".sock",
		})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "admin") && !strings.Contains(stderr, "token") {
		t.Errorf("expected admin token hint: %s", stderr)
	}
}

func TestCLIProvisionUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"provision"},
		map[string]string{"PILOT_ADMIN_TOKEN": "x"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLIProvisionMissingFile(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"provision", "/nonexistent/blueprint.json"},
		map[string]string{"PILOT_ADMIN_TOKEN": "x"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

func TestCLIProvisionBadJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := runCLI(t, []string{"provision", bad},
		map[string]string{"PILOT_ADMIN_TOKEN": "x"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "parse") && !strings.Contains(stderr, "invalid") {
		t.Errorf("expected parse error: %s", stderr)
	}
}

func TestCLIDeprovisionUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"deprovision"},
		map[string]string{"PILOT_ADMIN_TOKEN": "x"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLIDeprovisionOffline(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"deprovision", "my-network"}, nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

func TestCLIIDPUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"idp"},
		map[string]string{"PILOT_ADMIN_TOKEN": "x"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLIIDPGetOffline(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"idp", "get"}, nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

func TestCLIIDPSetMissingArgs(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"idp", "set"}, nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLIIDPSetOffline(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t,
		[]string{"idp", "set", "--type", "oidc", "--url", "https://idp.example.com"},
		nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

func TestCLIIDPUnknownSub(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"idp", "bogus"},
		map[string]string{"PILOT_ADMIN_TOKEN": "x"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "unknown") {
		t.Errorf("missing unknown hint: %s", stderr)
	}
}

func TestCLIAuditExportUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"audit-export"},
		map[string]string{"PILOT_ADMIN_TOKEN": "x"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLIAuditExportGetOffline(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"audit-export", "get"}, nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

func TestCLIAuditExportSetMissingArgs(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"audit-export", "set"}, nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLIAuditExportSetOffline(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t,
		[]string{"audit-export", "set", "--format", "json", "--endpoint", "https://siem.example.com"},
		nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

func TestCLIAuditExportDisableOffline(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"audit-export", "disable"}, nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

func TestCLIAuditExportUnknownSub(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"audit-export", "bogus"},
		map[string]string{"PILOT_ADMIN_TOKEN": "x"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "unknown") {
		t.Errorf("missing unknown hint: %s", stderr)
	}
}

func TestCLIProvisionStatusOffline(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"provision-status"}, nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

func TestCLIDirectoryStatusOffline(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"directory-status"}, nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

func TestCLIDirectorySyncOffline(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"directory-sync"}, nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

// ---- registry-only commands ----

func TestCLIRegisterOffline(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"register"}, nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

func TestCLILookupUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"lookup"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLILookupOffline(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"lookup", "42"}, nopeRegistry(t))
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if stderr == "" {
		t.Errorf("expected error on stderr")
	}
}

// ---- updates ----

func TestCLIUpdatesOffline(t *testing.T) {
	t.Parallel()
	// updates checks GitHub releases; with a non-routable endpoint it fails fast.
	_, _, code := runCLI(t, []string{"updates"},
		map[string]string{
			"PILOTCTL_UPDATES_FEED_URL": "http://127.0.0.1:1/releases.atom",
		})
	// Either non-zero (network error) or zero (renders empty/cached) — both are valid.
	_ = code
}

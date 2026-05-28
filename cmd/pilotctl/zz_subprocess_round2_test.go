// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// Round-2 subprocess tests target the fatalCode/fatalHint paths in cmd
// dispatch + per-cmd usage validation. Each test re-execs the binary
// via runCLI so os.Exit doesn't take down the test runner.

// --- gateway ---

func TestCLIGatewayStopHints(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"extras", "gateway", "stop"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit (gateway stop is unsupported)")
	}
	if !strings.Contains(stderr, "pilot-gateway") {
		t.Errorf("expected pilot-gateway hint, got: %s", stderr)
	}
}

func TestCLIGatewayUnmapHints(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"extras", "gateway", "unmap", "10.4.0.5"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit (gateway unmap is unsupported)")
	}
	if !strings.Contains(stderr, "pilot-gateway") {
		t.Errorf("expected pilot-gateway hint: %s", stderr)
	}
}

func TestCLIGatewayMapMissingArgs(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"extras", "gateway", "map"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit (missing pilot-addr)")
	}
	if !strings.Contains(stderr, "usage") && !strings.Contains(stderr, "pilot-addr") {
		t.Errorf("expected usage error: %s", stderr)
	}
}

func TestCLIGatewayUnmapMissingArgs(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"extras", "gateway", "unmap"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit (missing local-ip)")
	}
	if !strings.Contains(stderr, "usage") && !strings.Contains(stderr, "local-ip") {
		t.Errorf("expected usage error: %s", stderr)
	}
}

func TestCLIGatewayListEmpty(t *testing.T) {
	t.Parallel()
	stdout, _, code := runCLI(t, []string{"--json", "extras", "gateway", "list"}, nil)
	if code != 0 {
		t.Errorf("exit=%d", code)
	}
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("json: %v", err)
	}
	data := env["data"].(map[string]interface{})
	if data["total"].(float64) != 0 {
		t.Errorf("total = %v", data["total"])
	}
}

// --- usage errors on cmds that require args ---

func TestCLISetHostnameMissingArg(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"extras", "set-hostname"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit for missing hostname")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("expected usage hint: %s", stderr)
	}
}

func TestCLISetTagsMissingArg(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"extras", "set-tags"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("expected usage hint: %s", stderr)
	}
}

func TestCLISetTagsTooMany(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{
		"extras", "set-tags", "a", "b", "c", "d",
	}, nil)
	if code == 0 {
		t.Error("expected non-zero exit (too many tags)")
	}
	if !strings.Contains(stderr, "maximum 3") {
		t.Errorf("expected 'maximum 3' hint: %s", stderr)
	}
}

func TestCLISetWebhookInvalidScheme(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"extras", "set-webhook", "ftp://bad/scheme"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit (bad scheme)")
	}
	if !strings.Contains(stderr, "http") {
		t.Errorf("expected scheme error: %s", stderr)
	}
}

func TestCLINetworkLeaveMissingArg(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"network", "leave"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("expected usage hint: %s", stderr)
	}
}

func TestCLINetworkMembersMissingArg(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"network", "members"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("expected usage hint: %s", stderr)
	}
}

func TestCLINetworkInviteMissingArgs(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"network", "invite"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("expected usage hint: %s", stderr)
	}
}

func TestCLINetworkAcceptMissingArg(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"network", "accept"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("expected usage hint: %s", stderr)
	}
}

func TestCLINetworkRejectMissingArg(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"network", "reject"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("expected usage hint: %s", stderr)
	}
}

func TestCLINetworkCreateMissingName(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"network", "create"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "name") && !strings.Contains(stderr, "usage") {
		t.Errorf("expected usage hint: %s", stderr)
	}
}

func TestCLIPolicyValidateInline(t *testing.T) {
	t.Parallel()
	pol := `{
		"version": 1,
		"rules": [
			{"name": "demo", "on": "connect", "match": "true", "actions": [{"type": "allow"}]}
		]
	}`
	stdout, stderr, code := runCLI(t, []string{
		"--json", "policy", "validate", "--inline", pol,
	}, nil)
	if code != 0 {
		t.Errorf("exit=%d stderr=%s", code, stderr)
	}
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("json: %v\nstdout=%s", err, stdout)
	}
	data := env["data"].(map[string]interface{})
	if data["valid"] != true {
		t.Errorf("valid = %v", data["valid"])
	}
}

func TestCLIPolicyValidateNoFlags(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"policy", "validate"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit (no --file or --inline)")
	}
	if !strings.Contains(stderr, "file") && !strings.Contains(stderr, "inline") {
		t.Errorf("expected --file/--inline hint: %s", stderr)
	}
}

func TestCLIPolicyTestMissingFlags(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"policy", "test"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("expected usage hint: %s", stderr)
	}
}

func TestCLIPolicyGetMissingNet(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"policy", "get"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "--net") && !strings.Contains(stderr, "usage") {
		t.Errorf("expected --net hint: %s", stderr)
	}
}

func TestCLIManagedReconcileMissingNet(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"managed", "reconcile"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "--net") && !strings.Contains(stderr, "usage") {
		t.Errorf("expected --net hint: %s", stderr)
	}
}

func TestCLIManagedCycleNoForce(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"managed", "cycle"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit (missing --force)")
	}
	if !strings.Contains(stderr, "--force") {
		t.Errorf("expected --force hint: %s", stderr)
	}
}

func TestCLIMemberTagsSetMissingArgs(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"member-tags", "set"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("expected usage hint: %s", stderr)
	}
}

func TestCLIMemberTagsGetMissingNet(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"member-tags", "get"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "--net") && !strings.Contains(stderr, "usage") {
		t.Errorf("expected --net hint: %s", stderr)
	}
}

// --- daemon error path: daemon offline ---

func TestCLIInfoNoDaemon(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	_, stderr, code := runCLI(t, []string{"info"}, map[string]string{
		"PILOT_SOCKET": filepath.Join(tmp, "nope.sock"),
	})
	if code == 0 {
		t.Error("expected non-zero exit (daemon offline)")
	}
	if !strings.Contains(stderr, "daemon") {
		t.Errorf("expected 'daemon' in stderr: %s", stderr)
	}
}

func TestCLIHealthNoDaemon(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	_, stderr, code := runCLI(t, []string{"health"}, map[string]string{
		"PILOT_SOCKET": filepath.Join(tmp, "nope.sock"),
	})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "daemon") {
		t.Errorf("expected 'daemon' in stderr: %s", stderr)
	}
}

func TestCLITrustNoDaemon(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	_, stderr, code := runCLI(t, []string{"trust"}, map[string]string{
		"PILOT_SOCKET": filepath.Join(tmp, "nope.sock"),
	})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "daemon") {
		t.Errorf("expected 'daemon' in stderr: %s", stderr)
	}
}

func TestCLIPendingNoDaemon(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	_, stderr, code := runCLI(t, []string{"pending"}, map[string]string{
		"PILOT_SOCKET": filepath.Join(tmp, "nope.sock"),
	})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "daemon") {
		t.Errorf("expected 'daemon' in stderr: %s", stderr)
	}
}

func TestCLIPeersNoDaemon(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	_, stderr, code := runCLI(t, []string{"peers"}, map[string]string{
		"PILOT_SOCKET": filepath.Join(tmp, "nope.sock"),
	})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "daemon") {
		t.Errorf("expected 'daemon' in stderr: %s", stderr)
	}
}

func TestCLIConnectionsNoDaemon(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	_, stderr, code := runCLI(t, []string{"connections"}, map[string]string{
		"PILOT_SOCKET": filepath.Join(tmp, "nope.sock"),
	})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "daemon") {
		t.Errorf("expected 'daemon' in stderr: %s", stderr)
	}
}

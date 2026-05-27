// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFindCompanionBinaryEnvOverride(t *testing.T) {
	t.Setenv("PILOT_DAEMON_BIN", "/usr/local/bin/custom-pilot")
	got, err := findCompanionBinary("pilot-daemon", "PILOT_DAEMON_BIN")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "/usr/local/bin/custom-pilot" {
		t.Errorf("got %q", got)
	}
}

func TestFindCompanionBinarySibling(t *testing.T) {
	// Drop a fake "pilot-daemon" next to the test binary location.
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("no executable path: %v", err)
	}
	// Use a unique companion name to avoid colliding with any real binary.
	name := fmt.Sprintf("companion-%d-test", os.Getpid())
	envVar := "TESTONLY_BIN_X"
	t.Setenv(envVar, "")
	companion := filepath.Join(filepath.Dir(exe), name)
	if err := os.WriteFile(companion, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write companion: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(companion) })

	got, err := findCompanionBinary(name, envVar)
	if err != nil {
		t.Fatalf("expected sibling discovery to succeed, got: %v", err)
	}
	// The function may return the resolved path (EvalSymlinks) — just
	// confirm the basename matches.
	if filepath.Base(got) != name {
		t.Errorf("got %q, want basename %q", got, name)
	}
}

func TestFindCompanionBinaryMissing(t *testing.T) {
	envVar := "TESTONLY_BIN_MISS"
	t.Setenv(envVar, "")
	_, err := findCompanionBinary("pilot-definitely-not-installed-xxxx", envVar)
	if err == nil {
		t.Error("expected error for missing binary, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in: %v", err)
	}
}

func TestLaunchdAgentDomainTarget(t *testing.T) {
	t.Parallel()
	got := launchdAgentDomainTarget("foo.bar.baz")
	wantSuffix := "/foo.bar.baz"
	if !strings.HasSuffix(got, wantSuffix) {
		t.Errorf("got %q, want suffix %q", got, wantSuffix)
	}
	if !strings.HasPrefix(got, "gui/") {
		t.Errorf("got %q, want gui/ prefix", got)
	}
}

func TestLaunchdAgentPlistNonDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("only relevant on non-darwin")
	}
	path, label := launchdAgentPlist()
	if path != "" || label != "" {
		t.Errorf("non-darwin should return empty: %q, %q", path, label)
	}
}

func TestLaunchdAgentPlistDarwinAbsent(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	// Point HOME at a fresh tmp dir where no plist exists.
	t.Setenv("HOME", t.TempDir())
	path, label := launchdAgentPlist()
	if path != "" || label != "" {
		t.Errorf("expected empty for fresh HOME: %q, %q", path, label)
	}
}

func TestLaunchdAgentPlistDarwinPresent(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	plistDir := filepath.Join(tmp, "Library", "LaunchAgents")
	if err := os.MkdirAll(plistDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Use the FIRST known label so it wins the match loop.
	label := launchdAgentLabels[0]
	plistPath := filepath.Join(plistDir, label+".plist")
	if err := os.WriteFile(plistPath, []byte("<plist></plist>"), 0o644); err != nil {
		t.Fatal(err)
	}
	gotPath, gotLabel := launchdAgentPlist()
	if gotPath != plistPath {
		t.Errorf("path = %q, want %q", gotPath, plistPath)
	}
	if gotLabel != label {
		t.Errorf("label = %q, want %q", gotLabel, label)
	}
}

func TestLaunchdAgentLoadedEmptyLabel(t *testing.T) {
	t.Parallel()
	if launchdAgentLoaded("") {
		t.Error("empty label should return false")
	}
}

func TestProcessExistsSelf(t *testing.T) {
	t.Parallel()
	if !processExists(os.Getpid()) {
		t.Error("expected self pid to exist")
	}
}

func TestProcessExistsBogus(t *testing.T) {
	t.Parallel()
	// A huge PID that can't realistically be active. Reserve plenty of
	// headroom over Linux's default pid_max (32768) and macOS (99998).
	if processExists(0x7FFFFFFF - 1) {
		t.Skip("rare race: pid happens to exist")
	}
}

func TestReadPIDMissing(t *testing.T) {
	withTempHomeFull(t)
	if got := readPID(); got != 0 {
		t.Errorf("missing pid file = %d, want 0", got)
	}
}

func TestReadPIDValid(t *testing.T) {
	tmp := withTempHomeFull(t)
	if err := os.MkdirAll(filepath.Join(tmp, ".pilot"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, ".pilot", defaultPIDFile),
		[]byte("4242\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readPID(); got != 4242 {
		t.Errorf("got %d, want 4242", got)
	}
}

func TestDaemonBinaryPathViaEnv(t *testing.T) {
	t.Setenv("PILOT_DAEMON_BIN", "/opt/pilot-daemon-custom")
	got := daemonBinaryPath()
	if got != "/opt/pilot-daemon-custom" {
		t.Errorf("got %q", got)
	}
}

func TestGatewayBinaryPathViaEnv(t *testing.T) {
	t.Setenv("PILOT_GATEWAY_BIN", "/opt/pilot-gateway-custom")
	got := gatewayBinaryPath()
	if got != "/opt/pilot-gateway-custom" {
		t.Errorf("got %q", got)
	}
}

func TestReadPIDInvalid(t *testing.T) {
	tmp := withTempHomeFull(t)
	if err := os.MkdirAll(filepath.Join(tmp, ".pilot"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, ".pilot", defaultPIDFile),
		[]byte("not-a-pid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readPID(); got != 0 {
		t.Errorf("invalid pid file = %d, want 0", got)
	}
}

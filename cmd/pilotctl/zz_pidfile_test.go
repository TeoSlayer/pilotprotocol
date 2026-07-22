// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// TestPidLooksLikeDaemon_RejectsNonDaemonProcesses pins the PID-reuse
// guard: a live process whose executable is NOT a pilot daemon must not
// be treated as one — before this, `daemon stop` would SIGTERM whatever
// process had inherited a recycled PID, and `daemon start` would refuse
// with "already running".
func TestPidLooksLikeDaemon_RejectsNonDaemonProcesses(t *testing.T) {
	if pidLooksLikeDaemon(0) || pidLooksLikeDaemon(-5) {
		t.Fatal("non-positive pids must never look like a daemon")
	}
	// Our own test binary is alive but is not a pilot daemon.
	if pidLooksLikeDaemon(os.Getpid()) {
		t.Fatal("the test process itself must not look like a daemon")
	}
	// A live unrelated child (sleep) — alive, wrong name.
	cmd := exec.Command("sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot spawn sleep: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	// Give the exec a moment so /proc/<pid>/cmdline (linux) is populated.
	time.Sleep(50 * time.Millisecond)
	if pidLooksLikeDaemon(cmd.Process.Pid) {
		t.Fatalf("live 'sleep' process (pid %d) must not look like a daemon", cmd.Process.Pid)
	}
	// A dead PID: reap the child, then check.
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	if pidLooksLikeDaemon(cmd.Process.Pid) {
		t.Fatal("a dead pid must not look like a daemon")
	}
}

// TestReadPID_ZeroPlaceholderIsUnusable pins the poisoned-claim shape:
// the "0\n" placeholder a pre-fix --foreground start left behind must
// read as no-usable-PID (0), which the start path now treats as a stale
// file to remove — NOT as "another start in progress".
func TestReadPID_ZeroPlaceholderIsUnusable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PILOT_HOME", home)
	dir := configDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, content := range []string{"0\n", "", "garbage\n"} {
		if err := os.WriteFile(dir+"/"+defaultPIDFile, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := readPID(); got > 0 {
			t.Fatalf("content %q: readPID = %d, want <= 0", content, got)
		}
	}
	// And a real PID round-trips.
	if err := os.WriteFile(dir+"/"+defaultPIDFile, []byte(strconv.Itoa(12345)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readPID(); got != 12345 {
		t.Fatalf("readPID = %d, want 12345", got)
	}
}

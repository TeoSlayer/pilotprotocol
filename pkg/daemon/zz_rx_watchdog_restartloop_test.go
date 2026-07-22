// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// primeExitLog writes the given exit ages (relative to now) into the
// watchdog exit-log file so a test can drive the restart-loop breaker.
func primeExitLog(t *testing.T, path string, now time.Time, ages ...time.Duration) {
	t.Helper()
	var b strings.Builder
	for _, age := range ages {
		b.WriteString(strconv.FormatInt(now.Add(-age).UnixNano(), 10))
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("prime exit log: %v", err)
	}
}

// TestRxWatchdogRestartLoopBreakerOpens: once rxWedgeLoopMax hard exits
// have already happened within the window, a further wedge withholds the
// exit (restarting isn't clearing it) and keeps the daemon up.
func TestRxWatchdogRestartLoopBreakerOpens(t *testing.T) {
	d := newRxWatchdogTestDaemon(t)
	exitCode := swapExitForTest(t)
	now := time.Now()
	d.config.IdentityPath = filepath.Join(t.TempDir(), "id")
	d.lastRegistryOKNano.Store(now.UnixNano()) // fresh registry: wedge signature

	// rxWedgeLoopMax recent exits already recorded.
	ages := make([]time.Duration, rxWedgeLoopMax)
	for i := range ages {
		ages[i] = time.Duration(i+1) * time.Minute
	}
	primeExitLog(t, rxWedgeExitLogPath(d.config.IdentityPath), now, ages...)

	st := wedgeState(d, now)
	if got := d.rxWatchdogTick(st, now); got != rxActionRestartLoop {
		t.Fatalf("action = %q, want %q (breaker should be open)", got, rxActionRestartLoop)
	}
	if *exitCode != 0 {
		t.Fatalf("breaker open but exit fired (code %d)", *exitCode)
	}
	if st.softAttempts != 0 {
		t.Fatalf("withheld exit must reset softAttempts, got %d", st.softAttempts)
	}
}

// TestRxWatchdogRestartLoopBreakerClosedExitsAndRecords: below the
// threshold the exit still fires, and it is recorded so the respawned
// process sees an incremented count.
func TestRxWatchdogRestartLoopBreakerClosedExitsAndRecords(t *testing.T) {
	d := newRxWatchdogTestDaemon(t)
	exitCode := swapExitForTest(t)
	now := time.Now()
	d.config.IdentityPath = filepath.Join(t.TempDir(), "id")
	d.lastRegistryOKNano.Store(now.UnixNano())

	path := rxWedgeExitLogPath(d.config.IdentityPath)
	// One fewer than the max: this exit is allowed and becomes the max-th.
	ages := make([]time.Duration, rxWedgeLoopMax-1)
	for i := range ages {
		ages[i] = time.Duration(i+1) * time.Minute
	}
	primeExitLog(t, path, now, ages...)

	st := wedgeState(d, now)
	if got := d.rxWatchdogTick(st, now); got != rxActionExit {
		t.Fatalf("action = %q, want %q (breaker should be closed)", got, rxActionExit)
	}
	if *exitCode != rxWedgeExitCode {
		t.Fatalf("exit code = %d, want %d", *exitCode, rxWedgeExitCode)
	}
	// The exit must have been recorded: count is now rxWedgeLoopMax.
	if n := len(recentRxWedgeExits(path, now, rxWedgeLoopWindow)); n != rxWedgeLoopMax {
		t.Fatalf("recorded exits = %d, want %d", n, rxWedgeLoopMax)
	}
}

// TestRxWatchdogRestartLoopIgnoresOldExits: exits older than the window
// do not count, so a daemon that wedged long ago still gets to restart.
func TestRxWatchdogRestartLoopIgnoresOldExits(t *testing.T) {
	d := newRxWatchdogTestDaemon(t)
	exitCode := swapExitForTest(t)
	now := time.Now()
	d.config.IdentityPath = filepath.Join(t.TempDir(), "id")
	d.lastRegistryOKNano.Store(now.UnixNano())

	// rxWedgeLoopMax exits, all OUTSIDE the window.
	ages := make([]time.Duration, rxWedgeLoopMax)
	for i := range ages {
		ages[i] = rxWedgeLoopWindow + time.Duration(i+1)*time.Minute
	}
	primeExitLog(t, rxWedgeExitLogPath(d.config.IdentityPath), now, ages...)

	st := wedgeState(d, now)
	if got := d.rxWatchdogTick(st, now); got != rxActionExit {
		t.Fatalf("action = %q, want %q (stale exits must not open the breaker)", got, rxActionExit)
	}
	if *exitCode != rxWedgeExitCode {
		t.Fatalf("exit should fire when prior exits are outside window")
	}
}

// TestRxWatchdogRestartLoopDisabledWithoutPersistence: an empty identity
// path (no persistence) leaves the breaker off — behaviour is exactly as
// before (exit always allowed).
func TestRxWatchdogRestartLoopDisabledWithoutPersistence(t *testing.T) {
	d := newRxWatchdogTestDaemon(t)
	exitCode := swapExitForTest(t)
	now := time.Now()
	// d.config.IdentityPath stays "".
	d.lastRegistryOKNano.Store(now.UnixNano())

	st := wedgeState(d, now)
	if got := d.rxWatchdogTick(st, now); got != rxActionExit {
		t.Fatalf("action = %q, want %q (no persistence disables the breaker)", got, rxActionExit)
	}
	if *exitCode != rxWedgeExitCode {
		t.Fatalf("exit should fire when persistence is off")
	}
}

// TestRecentRxWedgeExits_WindowAndMalformed pins the sidecar-file parser.
func TestRecentRxWedgeExits_WindowAndMalformed(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "id.rxwedge")
	content := strings.Join([]string{
		strconv.FormatInt(now.Add(-1*time.Minute).UnixNano(), 10), // in window
		"garbage-not-a-number",                                    // skipped
		strconv.FormatInt(now.Add(-3*time.Hour).UnixNano(), 10),   // outside window
		"",                                                        // skipped
		strconv.FormatInt(now.Add(-5*time.Minute).UnixNano(), 10), // in window
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if n := len(recentRxWedgeExits(path, now, rxWedgeLoopWindow)); n != 2 {
		t.Fatalf("recent count = %d, want 2 (2 in-window, 1 stale, 2 junk)", n)
	}
	// Missing file and empty path both yield zero, never error.
	if n := len(recentRxWedgeExits(filepath.Join(t.TempDir(), "nope"), now, rxWedgeLoopWindow)); n != 0 {
		t.Fatalf("missing file should yield 0, got %d", n)
	}
	if n := len(recentRxWedgeExits("", now, rxWedgeLoopWindow)); n != 0 {
		t.Fatalf("empty path should yield 0, got %d", n)
	}
}

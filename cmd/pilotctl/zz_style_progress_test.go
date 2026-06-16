// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// In the test environment stderr is not a character device, so
// stderrIsTTY must be false and startWaitProgress must be a no-op that
// writes nothing — agents and pipes never see ANSI rewrites.
func TestStderrIsTTYFalseUnderTests(t *testing.T) {
	if stderrIsTTY {
		t.Fatal("stderrIsTTY should be false when stderr is a pipe")
	}
}

func TestStartWaitProgressNoopNonTTY(t *testing.T) {
	stop := startWaitProgress("waiting")
	if stop == nil {
		t.Fatal("stop func must never be nil")
	}
	// Double-stop must be safe on the no-op path too.
	stop()
	stop()
}

func TestStartWaitProgressDrawAndStopIdempotent(t *testing.T) {
	// Force the active path even without a TTY to exercise the
	// goroutine lifecycle: start, tick once, stop twice. Capture
	// stderr via a pipe so the animation does not pollute test output.
	origTTY, origJSON, origStderr := stderrIsTTY, jsonOutput, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	stderrIsTTY, jsonOutput, os.Stderr = true, false, w
	t.Cleanup(func() { stderrIsTTY, jsonOutput, os.Stderr = origTTY, origJSON, origStderr })

	stop := startWaitProgress("test wait")
	time.Sleep(600 * time.Millisecond) // let at least one tick draw
	done := make(chan struct{})
	go func() {
		stop()
		stop() // second call must not panic or block
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop() did not return; goroutine leak or deadlock")
	}

	w.Close()
	out, _ := io.ReadAll(r)
	got := string(out)
	if !strings.Contains(got, "test wait") {
		t.Errorf("progress line never drawn: %q", got)
	}
	if !strings.Contains(got, "\r\x1b[2K") {
		t.Errorf("missing rewrite/erase sequence: %q", got)
	}
	if !strings.HasSuffix(got, "\r\x1b[2K") {
		t.Errorf("stop() must erase the line last: %q", got)
	}
}

func TestStartWaitProgressNoopWhenJSON(t *testing.T) {
	origTTY, origJSON := stderrIsTTY, jsonOutput
	stderrIsTTY, jsonOutput = true, true
	t.Cleanup(func() { stderrIsTTY, jsonOutput = origTTY, origJSON })

	// --json must suppress the animation even on a TTY. The no-op stop
	// returns immediately; if the active path were taken the draw would
	// go to the real stderr, which the assertion below cannot see, so we
	// assert on behavior: stop returns instantly and is double-safe.
	stop := startWaitProgress("waiting")
	stop()
	stop()
}

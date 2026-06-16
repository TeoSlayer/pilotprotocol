// SPDX-License-Identifier: AGPL-3.0-or-later

// style.go — ANSI styling for human-facing output.
//
// Rules:
//   - Color only when stdout is a TTY and NO_COLOR / TERM=dumb are unset.
//   - --json output is NEVER styled (agents parse it byte-for-byte).
//   - Piped text output stays plain so grep/awk/cut keep working.
//
// The palette is semantic, not decorative: ok=green, warn=yellow,
// err=red, accent=cyan (ids, hostnames), dim=metadata. Use sparingly —
// a screen that is all color is as unreadable as one with none.

package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// colorEnabled is computed once at startup. Tests capture stdout via a
// pipe, so styling is automatically off there and assertions on plain
// text stay stable.
var colorEnabled = func() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("PILOT_NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}()

func sc(code, s string) string {
	if !colorEnabled {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func sBold(s string) string   { return sc("1", s) }
func sDim(s string) string    { return sc("2", s) }
func sOK(s string) string     { return sc("32", s) }
func sWarn(s string) string   { return sc("33", s) }
func sErr(s string) string    { return sc("31", s) }
func sAccent(s string) string { return sc("36", s) }

// stderrIsTTY mirrors colorEnabled but for os.Stderr. It gates the
// animated wait-progress line: animation (cursor rewrites) only makes
// sense on an interactive terminal, and NO_COLOR / TERM=dumb users have
// asked for plain output, so they get silence instead of a spinner.
var stderrIsTTY = func() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("PILOT_NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}()

// startWaitProgress shows a single self-rewriting stderr line
// ("label… Ns") while a blocking wait is in flight, so commands like
// `send-message --wait` don't sit in 30 s of dead silence. Returns a
// stop func that erases the line and terminates the ticker goroutine.
//
// Safe by construction:
//   - no-op when stderr is not a TTY or --json is set (agents and pipes
//     never see control sequences);
//   - stop() is idempotent (sync.Once), so it can be called on every
//     exit path of a wait without bookkeeping;
//   - stop() blocks until the goroutine has erased the line, so output
//     printed right after stop() never interleaves with the animation.
//
// First draw happens at the first 500 ms tick — sub-500 ms waits finish
// without any flicker.
func startWaitProgress(label string) (stop func()) {
	if !stderrIsTTY || jsonOutput {
		return func() {}
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(finished)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				fmt.Fprint(os.Stderr, "\r\x1b[2K")
				return
			case <-ticker.C:
				elapsed := int(time.Since(start).Seconds())
				fmt.Fprintf(os.Stderr, "\r\x1b[2K%s",
					sDim(fmt.Sprintf("%s… %ds", label, elapsed)))
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(done)
			<-finished
		})
	}
}

// statusDot renders a colored ● for state lines: ok=green, warn=yellow,
// err=red. Falls back to plain symbols when color is off so piped output
// still distinguishes states.
func statusDot(state string) string {
	switch state {
	case "ok":
		if colorEnabled {
			return sOK("●")
		}
		return "●"
	case "warn":
		if colorEnabled {
			return sWarn("●")
		}
		return "◐"
	default:
		if colorEnabled {
			return sErr("●")
		}
		return "○"
	}
}

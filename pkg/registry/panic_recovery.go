// SPDX-License-Identifier: AGPL-3.0-or-later

package registry

import (
	"log/slog"
	"runtime/debug"
	"sync/atomic"
)

// recoveredPanicCount is a process-global counter incremented every time
// recoverHandler swallows a panic. Exposed on /metrics so operators can
// alert on a non-zero rate (panics are bugs and should be visible — they
// just shouldn't crash the process).
var recoveredPanicCount atomic.Uint64

// RecoveredPanicCount returns the total number of panics swallowed by
// recoverHandler since process start. Used by metrics.go for the gauge.
func RecoveredPanicCount() uint64 {
	return recoveredPanicCount.Load()
}

// recoverHandler is the standard panic-recovery shim used at the top of
// every connection-handling goroutine and every background loop. Usage:
//
//   defer recoverHandler("handleConn", nil)
//
// On panic it:
//   1. Recovers (process keeps running)
//   2. Logs at ERROR with the panic value + full goroutine stack trace
//   3. Increments the global recoveredPanicCount metric
//   4. Calls onPanic(count) if non-nil — callers can use this to drop
//      a connection / restart a loop / etc.
//
// recoverHandler must be the OUTERMOST defer in the goroutine: defers
// run LIFO, so other defers (conn.Close, mu.Unlock) run first; we want
// to see them complete before recover so resource cleanup runs even on
// panic.
func recoverHandler(label string, onPanic func(panicCount uint64)) {
	r := recover()
	if r == nil {
		return
	}
	count := recoveredPanicCount.Add(1)
	slog.Error("panic recovered",
		"where", label,
		"panic", r,
		"recovered_total", count,
		"stack", string(debug.Stack()),
	)
	if onPanic != nil {
		// Defensive: a callback that itself panics must not propagate.
		func() {
			defer func() { _ = recover() }()
			onPanic(count)
		}()
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync/atomic"
)

// recoveredPanicCount is a process-global counter incremented every time
// recoverLayer swallows a panic at any layer entry. Exposed via
// RecoveredPanicCount so observability/metrics can alert on a non-zero
// rate — panics are bugs and must be visible — they just must not crash
// the daemon. Mirrors the pattern in pkg/registry/server/panic_recovery.go.
var recoveredPanicCount atomic.Uint64

// RecoveredPanicCount returns the total number of panics swallowed by
// recoverLayer since process start.
func RecoveredPanicCount() uint64 {
	return recoveredPanicCount.Load()
}

// resetRecoveredPanicCountForTest is test-only: lets tests assert that
// THIS run produced exactly N recovered panics without being polluted
// by panics from earlier tests in the same process.
func resetRecoveredPanicCountForTest() {
	recoveredPanicCount.Store(0)
}

// recoverLayer is the standard panic-recovery shim used at every L1-L9
// layer entry point in the daemon. Usage:
//
//	defer recoverLayer("L2", "readLoop", tm.bus, nil)
//
// On panic it:
//  1. Recovers (caller continues / loop body is dropped)
//  2. Logs at ERROR with structured layer/op fields, the panic value,
//     and a full goroutine stack trace
//  3. Increments the global recoveredPanicCount metric
//  4. Publishes a "<layer>.panic" event on the bus (if bus != nil) so
//     observability subscribers (webhook plugin, eventstream broker)
//     see the recovery
//  5. Calls onPanic(r) if non-nil — typical use is per-conn teardown,
//     plugin restart signal, etc.
//
// recoverLayer must be the OUTERMOST defer in the goroutine: defers
// run LIFO, so other defers (conn.Close, mu.Unlock) run first; we want
// to see them complete before recover so resource cleanup runs even on
// panic.
//
// Returns true if a panic was caught — callers wrapping a single loop
// iteration use this to decide whether to continue.
func recoverLayer(layer, op string, bus *inProcessBus, onPanic func(any)) (caught bool) {
	r := recover()
	if r == nil {
		return false
	}
	count := recoveredPanicCount.Add(1)
	slog.Error("layer panic recovered",
		"layer", layer,
		"op", op,
		"panic", r,
		"recovered_total", count,
		"stack", string(debug.Stack()),
	)
	if bus != nil {
		// Defensive: a bus that itself panics during Publish must not
		// propagate. The bus is non-blocking by contract, but a buggy
		// subscriber could inject a panic on the publishing goroutine
		// path in the future.
		func() {
			defer func() { _ = recover() }()
			bus.Publish(layer+".panic", map[string]any{
				"layer":           layer,
				"op":              op,
				"panic":           fmt.Sprintf("%v", r),
				"recovered_total": count,
			})
		}()
	}
	if onPanic != nil {
		// Defensive: onPanic that itself panics must not propagate.
		func() {
			defer func() { _ = recover() }()
			onPanic(r)
		}()
	}
	return true
}

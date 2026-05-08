// SPDX-License-Identifier: AGPL-3.0-or-later

package coreapi

import (
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync/atomic"
)

// pluginRecoveredPanicCount is the L11 counterpart to the daemon's
// internal recoveredPanicCount. Tracks how many panics have been
// caught at plugin entry points (acceptLoop, handleConn, Service.Start
// goroutines). Exposed via PluginRecoveredPanicCount.
var pluginRecoveredPanicCount atomic.Uint64

// PluginRecoveredPanicCount returns the total number of panics
// swallowed by RecoverPlugin since process start.
func PluginRecoveredPanicCount() uint64 {
	return pluginRecoveredPanicCount.Load()
}

// ResetPluginRecoveredPanicCountForTest is test-only.
func ResetPluginRecoveredPanicCountForTest() {
	pluginRecoveredPanicCount.Store(0)
}

// RecoverPlugin is the L11 panic-recovery shim used at the top of
// every plugin entrypoint goroutine: Service.Start helper goroutines,
// acceptLoop, and per-connection handlers. Usage:
//
//	defer coreapi.RecoverPlugin("eventstream", "acceptLoop", events, nil)
//
// On panic it:
//  1. Recovers (caller goroutine continues / loop iteration is dropped)
//  2. Logs at ERROR with structured plugin/op fields, panic value, and
//     full goroutine stack trace
//  3. Increments PluginRecoveredPanicCount
//  4. Publishes a "plugin.<plugin>.panic" event on the bus (if
//     events != nil) so observability subscribers see the recovery
//  5. Calls onPanic(r) if non-nil — typical use is per-conn close,
//     or signaling a future per-plugin supervisor for restart
//
// TODO(03-INVARIANTS.md §8): per-plugin supervisor not yet implemented.
// Today the boundary just survives + logs. A future tier will signal a
// restart of the panicked plugin via the onPanic callback.
//
// This must be the OUTERMOST defer in the goroutine: defers run LIFO,
// so other defers (conn.Close, mu.Unlock, removeSub) run first.
func RecoverPlugin(plugin, op string, events EventBus, onPanic func(any)) {
	r := recover()
	if r == nil {
		return
	}
	count := pluginRecoveredPanicCount.Add(1)
	slog.Error("plugin panic recovered",
		"layer", "L11",
		"plugin", plugin,
		"op", op,
		"panic", r,
		"recovered_total", count,
		"stack", string(debug.Stack()),
	)
	if events != nil {
		// Defensive: a publisher that itself panics must not propagate.
		func() {
			defer func() { _ = recover() }()
			events.Publish("plugin."+plugin+".panic", map[string]any{
				"plugin":          plugin,
				"op":              op,
				"panic":           fmt.Sprintf("%v", r),
				"recovered_total": count,
			})
		}()
	}
	if onPanic != nil {
		func() {
			defer func() { _ = recover() }()
			onPanic(r)
		}()
	}
}

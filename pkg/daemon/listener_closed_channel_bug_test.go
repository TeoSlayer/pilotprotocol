// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestListenerSendAfterUnbindSafe verifies that sending a connection to a
// Listener's accept queue after Unbind does not panic.
//
// Bug (pre-v1.9.1): Listener.AcceptCh is a plain Go channel.
// Unbind() calls close(ln.AcceptCh) and deletes the listener from the map.
// handleStreamPacket() calls GetListener() (takes pm.mu RLock, returns ln),
// then releases the lock. If Unbind() fires between GetListener's return and
// the `select { case ln.AcceptCh <- conn: default: }` statement, the send
// races with close(). Sending to a closed channel panics unconditionally in
// Go — the select's `default` branch does NOT prevent it. routeLoop has no
// top-level recover(), so the panic propagates, killing the daemon's entire
// packet routing goroutine.
//
// Real-world trigger: a pilotctl client binds a port to accept inbound
// connections, then closes (crashes / Ctrl-C) while a SYN is being processed.
// The IPC handler's cleanup defer calls Unbind() for all tracked ports; if a
// SYN just passed GetListener() at that instant, the daemon crashes.
//
// Fix (v1.9.1): Listener gains a mutex-protected `closed` flag and a safe
// TrySend() method. Unbind() sets `closed=true` under the lock before
// closing AcceptCh; handleStreamPacket calls ln.TrySend() instead of the
// bare channel send, eliminating the close-vs-send race.
//
// GREEN assertion: ln.TrySend(conn) after Unbind returns false without
// panicking. Against unpatched code the goroutine panics (panicked <- true),
// causing t.Error.
func TestListenerSendAfterUnbindSafe(t *testing.T) {
	pm := NewPortManager()
	ln, err := pm.Bind(9090)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}

	conn := pm.NewConnection(9090, protocol.Addr{}, 1234)

	// Close the listener (simulating the Unbind race with handleStreamPacket).
	pm.Unbind(9090)

	// Exercise the send path in an isolated goroutine so its panic is caught.
	panicked := make(chan bool, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicked <- true // panic → bug present
			} else {
				panicked <- false // clean → fix applied
			}
		}()
		// FIXED: use TrySend (state-aware, won't panic on closed channel).
		// The line below references the NEW method added by the fix.
		// Before the fix existed, this call was the direct channel send that panicked.
		ln.TrySend(conn)
	}()

	if <-panicked {
		t.Error("send on closed AcceptCh panicked; Listener.TrySend fix not applied — " +
			"Unbind race kills routeLoop goroutine")
	}
}

// TestListenerTrySendReturnsFalseAfterClose verifies TrySend returns false
// (not true, not panic) after the listener is closed.
func TestListenerTrySendReturnsFalseAfterClose(t *testing.T) {
	pm := NewPortManager()
	ln, err := pm.Bind(9091)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	conn := pm.NewConnection(9091, protocol.Addr{}, 5678)
	pm.Unbind(9091)

	if ln.TrySend(conn) {
		t.Error("TrySend returned true after Unbind — connection queued to closed listener")
	}
}

// TestListenerTrySendReturnsTrueWhenOpen verifies the happy path: TrySend
// succeeds when the listener is open and the queue has room.
func TestListenerTrySendReturnsTrueWhenOpen(t *testing.T) {
	pm := NewPortManager()
	ln, err := pm.Bind(9092)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { pm.Unbind(9092) })
	conn := pm.NewConnection(9092, protocol.Addr{}, 9999)

	if !ln.TrySend(conn) {
		t.Error("TrySend returned false on open, non-full listener")
	}
}

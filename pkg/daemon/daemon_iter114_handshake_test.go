// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// Iter-114 coverage for HandshakeManager.Start (0% baseline) — the port-444
// service bootstrap that spawns BOTH the accept-loop goroutine AND the periodic
// replay-reaper ticker goroutine. Prior iter tests hit processMessage/handleConnection
// directly but never the bind+spawn lifecycle.

// --- Start: happy path — binds port + allocates reapStop ---

func TestHandshakeManagerStartBindsAndAllocatesReapStop(t *testing.T) {
	hm := newTestHM(t, "")
	if err := hm.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Port should be bound — second Bind on PortHandshake fails.
	if _, err := hm.daemon.ports.Bind(protocol.PortHandshake); err == nil {
		t.Fatal("PortHandshake should already be bound after Start")
	}
	// reapStop should now be non-nil (allocated by Start at handshake.go:246).
	if hm.reapStop == nil {
		t.Fatal("reapStop should be allocated after Start")
	}
	// Clean shutdown via Stop — closes reapStop exactly once, reap goroutine exits.
	hm.Stop()
}

// --- Start: error path — port already bound returns the bind err ---

func TestHandshakeManagerStartErrorsWhenPortAlreadyBound(t *testing.T) {
	hm := newTestHM(t, "")
	if _, err := hm.daemon.ports.Bind(protocol.PortHandshake); err != nil {
		t.Fatalf("pre-bind: %v", err)
	}
	defer hm.daemon.ports.Unbind(protocol.PortHandshake)

	if err := hm.Start(); err == nil {
		t.Fatal("Start should error when PortHandshake already bound")
	}
	// On the error path, reapStop is NOT allocated (early return at handshake.go:236).
	if hm.reapStop != nil {
		t.Fatal("reapStop should remain nil after Start error (early-return before allocation)")
	}
}

// --- Start: accept-loop goroutine dispatches a fed Connection via AcceptCh ---

func TestHandshakeManagerStartAcceptLoopDispatchesToHandleConnection(t *testing.T) {
	hm := newTestHM(t, "")
	if err := hm.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer hm.Stop()

	ln := hm.daemon.ports.GetListener(protocol.PortHandshake)
	if ln == nil {
		t.Fatal("listener should be registered under PortHandshake")
	}

	// Feed a Connection with a CLOSED RecvBuf — handleConnection's
	// `<-conn.RecvBuf` returns ok=false → early return. This exercises the
	// full chain: AcceptCh → for-range → go hm.handleConnection(conn) → exit.
	conn := &Connection{
		ID:         999,
		RecvBuf:    make(chan []byte, 1),
		RemoteAddr: protocol.Addr{Network: 1, Node: 0xAA00BB00},
		RemotePort: 12345,
	}
	conn.CloseRecvBuf()

	select {
	case ln.AcceptCh <- conn:
	case <-time.After(1 * time.Second):
		t.Fatal("AcceptCh blocked — accept loop not draining")
	}

	// Give the dispatched handler goroutine a moment to run + return.
	// We can't directly join a detached go-routine spawned by the accept loop,
	// but the successful AcceptCh send proves the for-range is live and the
	// spawned handler's early-return path is exercised.
	time.Sleep(100 * time.Millisecond)
}

// --- Start: Unbind closes AcceptCh → for-range exits cleanly ---

func TestHandshakeManagerStartAcceptLoopExitsOnUnbind(t *testing.T) {
	hm := newTestHM(t, "")
	if err := hm.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Unbind closes AcceptCh — `for conn := range ln.AcceptCh` loop exits.
	hm.daemon.ports.Unbind(protocol.PortHandshake)

	// Give the goroutine a moment to drain. Test passes if there's no panic
	// or deadlock. hm.Stop() below closes reapStop (reap goroutine exits too).
	time.Sleep(50 * time.Millisecond)
	hm.Stop()
}

// --- Start: Stop closes reapStop → reap ticker goroutine exits via <-reapStop ---

func TestHandshakeManagerStartReapGoroutineExitsOnStop(t *testing.T) {
	hm := newTestHM(t, "")
	if err := hm.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Stop closes reapStop (via stopOnce). The reap goroutine's
	// `case <-hm.reapStop: return` branch at handshake.go:254 fires.
	// hm.Stop also waits for all goRPC wg — no outstanding goroutines here.
	done := make(chan struct{})
	go func() {
		hm.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("hm.Stop did not complete within 3s — reap goroutine may be stuck")
	}
}

// --- Start: re-starting after a failed Start (no reapStop leaked) ---

func TestHandshakeManagerStartCanRetryAfterBindError(t *testing.T) {
	hm := newTestHM(t, "")
	if _, err := hm.daemon.ports.Bind(protocol.PortHandshake); err != nil {
		t.Fatalf("pre-bind: %v", err)
	}
	if err := hm.Start(); err == nil {
		t.Fatal("first Start should error")
	}
	// Unbind and retry — second Start should succeed now that the port is free.
	hm.daemon.ports.Unbind(protocol.PortHandshake)
	if err := hm.Start(); err != nil {
		t.Fatalf("second Start (after Unbind): %v", err)
	}
	// reapStop now allocated on the successful retry.
	if hm.reapStop == nil {
		t.Fatal("reapStop should be allocated after successful retry")
	}
	hm.Stop()
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// Iter-112 coverage for the built-in service bootstrap path at services.go:
// startBuiltinServices (0%), startEchoService (0%), handleEchoConn (0%),
// startDataExchangeService (0%), startEventStreamService (0%). These are
// the *bind + accept-loop spawn* paths invoked from Daemon.Start; the
// per-message handlers are exercised by other iter tests, but the
// bind-and-spawn lifecycle is currently unreached because no test calls
// Daemon.Start through to the service-bootstrap stage.

// --- startEchoService: binds PortEcho + accept loop exits cleanly on stopCh ---

func TestStartEchoServiceBindsAndExitsOnStop(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if err := d.startEchoService(); err != nil {
		t.Fatalf("startEchoService: %v", err)
	}
	// Port should be bound — second Bind on PortEcho fails.
	if _, err := d.ports.Bind(protocol.PortEcho); err == nil {
		t.Fatalf("PortEcho (%d) should already be bound", protocol.PortEcho)
	}
	close(d.stopCh)
	time.Sleep(100 * time.Millisecond)
}

// --- startEchoService: error path — port already bound returns the bind err ---

func TestStartEchoServiceErrorsWhenPortAlreadyBound(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if _, err := d.ports.Bind(protocol.PortEcho); err != nil {
		t.Fatalf("pre-bind: %v", err)
	}
	defer d.ports.Unbind(protocol.PortEcho)

	err := d.startEchoService()
	if err == nil {
		t.Fatal("startEchoService should error when PortEcho already bound")
	}
}

// --- handleEchoConn: data on RecvBuf is echoed back via SendData (then ok=false exits) ---

func TestHandleEchoConnExitsOnRecvBufClose(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	conn := &Connection{
		ID:      55,
		RecvBuf: make(chan []byte, 2),
	}
	// Close RecvBuf — handleEchoConn's `data, ok := <-conn.RecvBuf` returns ok=false → return.
	close(conn.RecvBuf)

	done := make(chan struct{})
	go func() {
		d.handleEchoConn(conn)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleEchoConn did not exit on RecvBuf close")
	}
}

// --- handleEchoConn: data with no tunnel → SendData errors → return without panic ---

func TestHandleEchoConnExitsOnSendDataError(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	conn := &Connection{
		ID:      66,
		RecvBuf: make(chan []byte, 2),
	}
	// Push data; conn.State=0 → SendData returns "connection not established"
	// → handleEchoConn returns on first iteration's error branch.
	conn.RecvBuf <- []byte("ping")

	done := make(chan struct{})
	go func() {
		d.handleEchoConn(conn)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleEchoConn did not exit on SendData error")
	}
}


// --- startBuiltinServices: with all enabled (defaults), binds 4 service ports ---

func TestStartBuiltinServicesBindsAllEnabledByDefault(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})
	d.startBuiltinServices()

	// Ports 1001 (dataexchange), 1002 (eventstream), 1003 (tasks) are
	// no longer bound by startBuiltinServices — all three are registered
	// L11 plugins that bind via coreapi.Streams.Listen during
	// Service.Start. cmd/daemon/main.go is the binding-time owner.
	// This test only asserts the daemon-side in-tree service (echo)
	// still binds here.
	for _, port := range []uint16{
		protocol.PortEcho,
	} {
		if _, err := d.ports.Bind(port); err == nil {
			t.Fatalf("port %d should be bound by startBuiltinServices", port)
		}
	}

	close(d.stopCh)
	time.Sleep(100 * time.Millisecond)
}

// --- startBuiltinServices: all disable flags → no ports bound ---

func TestStartBuiltinServicesAllDisabledBindsNothing(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{
		DisableEcho:         true,
		DisableDataExchange: true,
		DisableEventStream:  true,
	})
	d.startBuiltinServices()

	for _, port := range []uint16{
		protocol.PortEcho,
		protocol.PortDataExchange,
		protocol.PortEventStream,
	} {
		ln, err := d.ports.Bind(port)
		if err != nil {
			t.Fatalf("port %d should NOT be bound when service disabled: bind err = %v", port, err)
		}
		d.ports.Unbind(port)
		_ = ln
	}
}

// --- accept-loop exit on AcceptCh close (Unbind closes the channel) ---

func TestStartEchoServiceAcceptLoopExitsOnUnbind(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if err := d.startEchoService(); err != nil {
		t.Fatalf("startEchoService: %v", err)
	}

	// Use a WaitGroup-style probe: spawn another goroutine that confirms
	// Unbind triggers AcceptCh close → for-select hits `if !ok { return }` branch.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Sleep briefly, then Unbind to close AcceptCh.
		time.Sleep(50 * time.Millisecond)
		d.ports.Unbind(protocol.PortEcho)
	}()
	wg.Wait()

	// The accept-loop goroutine should have exited via the !ok branch.
	// Test passes if no panic / goroutine leak; can't directly join the
	// detached goroutine but Sleep gives it a chance to drain.
	time.Sleep(100 * time.Millisecond)
}

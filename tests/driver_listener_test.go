package tests

import (
	"net"
	"testing"
	"time"
)

// TestDriverListenAccept tests the full driver Listen → Accept → Read/Write path
// and verifies Listener.Addr, Conn.LocalAddr, Conn.RemoteAddr, pilotAddr.Network.
func TestDriverListenAccept(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	// A listens on a custom port
	const testPort uint16 = 2000
	ln, err := a.Driver.Listen(testPort)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Verify Listener.Addr()
	addr := ln.Addr()
	if addr == nil {
		t.Fatal("Addr() returned nil")
	}
	if addr.Network() != "pilot" {
		t.Errorf("expected network 'pilot', got %q", addr.Network())
	}
	addrStr := addr.String()
	if addrStr == "" {
		t.Error("Addr().String() returned empty")
	}
	t.Logf("Listener addr: %s (network=%s)", addrStr, addr.Network())

	// B dials A on the test port
	connDone := make(chan net.Conn, 1)
	errDone := make(chan error, 1)
	go func() {
		conn, err := b.Driver.DialAddr(a.Daemon.Addr(), testPort)
		if err != nil {
			errDone <- err
			return
		}
		connDone <- conn
	}()

	// A accepts the connection
	acceptDone := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		accepted, err := ln.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		acceptDone <- accepted
	}()

	// Wait for both dial and accept to complete
	var dialConn, acceptConn net.Conn
	select {
	case dialConn = <-connDone:
	case err := <-errDone:
		t.Fatalf("dial: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("dial timed out")
	}

	select {
	case acceptConn = <-acceptDone:
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("accept timed out")
	}

	// Verify conn addresses
	localAddr := acceptConn.LocalAddr()
	if localAddr == nil {
		t.Fatal("LocalAddr() returned nil")
	}
	if localAddr.Network() != "pilot" {
		t.Errorf("expected network 'pilot', got %q", localAddr.Network())
	}
	t.Logf("Accepted conn: local=%s remote=%s", localAddr, acceptConn.RemoteAddr())

	remoteAddr := acceptConn.RemoteAddr()
	if remoteAddr == nil {
		t.Fatal("RemoteAddr() returned nil")
	}
	if remoteAddr.Network() != "pilot" {
		t.Errorf("expected remote network 'pilot', got %q", remoteAddr.Network())
	}

	// Test write/read through accepted connection
	testData := []byte("hello from B")
	if _, err := dialConn.Write(testData); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 256)
	acceptConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := acceptConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "hello from B" {
		t.Errorf("expected 'hello from B', got %q", string(buf[:n]))
	}

	// Clean up
	dialConn.Close()
	acceptConn.Close()
	ln.Close()
}

// TestDriverListenerCloseUnblocksAccept verifies that closing a listener
// unblocks a pending Accept call.
func TestDriverListenerCloseUnblocksAccept(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()

	const testPort uint16 = 2001
	ln, err := a.Driver.Listen(testPort)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		errCh <- err
	}()

	// Brief pause then close listener
	time.Sleep(50 * time.Millisecond)
	ln.Close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Error("expected error from Accept after close, got nil")
		}
		t.Logf("Accept after close: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("Accept did not unblock after Close")
	}
}

// TestDriverConnSetDeadline tests SetDeadline and SetWriteDeadline.
func TestDriverConnSetDeadline(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	// Connect A → B on echo port
	conn, err := a.Driver.DialAddr(b.Daemon.Addr(), 7)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// SetDeadline should not error
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetDeadline: %v", err)
	}

	// SetWriteDeadline should not error (it's a no-op)
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetWriteDeadline: %v", err)
	}

	// SetReadDeadline with expired time should cause Read to timeout
	conn.SetReadDeadline(time.Now().Add(-time.Second))
	buf := make([]byte, 16)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected deadline exceeded error, got nil")
	}
}

// TestTestEnvSocketPath tests the SocketPath utility method.
func TestTestEnvSocketPath(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	path := env.SocketPath("test-service")
	if path == "" {
		t.Fatal("SocketPath returned empty")
	}
	t.Logf("SocketPath: %s", path)
}

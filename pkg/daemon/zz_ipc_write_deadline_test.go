// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/ipcutil"
)

// TestWriteLoopExitsOnWriteDeadline verifies that when a Unix socket peer
// accepts a connection but never reads, the writeLoop eventually times out
// on a blocked write and exits, freeing ipcWrite callers. This is the
// root-cause fix for PILOT-218: without a write deadline, writeLoop blocks
// indefinitely in ipcutil.Write, the sendCh fills, dispatch goroutines
// park in ipcWrite, and the per-conn semaphore exhausts — the daemon appears
// unresponsive even though the process is live.
//
// net.Pipe() ignores SetWriteDeadline, so we use a real Unix socket pair.
func TestWriteLoopExitsOnWriteDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("uses real Unix sockets with deadline-sensitive timing")
	}
	t.Parallel()

	// Keep the path below Darwin's short sockaddr_un.sun_path limit.
	// t.TempDir includes the full test name and can exceed that limit.
	sockPath := shortSockPath(t)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- acceptResult{c, err}
	}()

	client, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Intentionally never read from client — the kernel's Unix socket
	// send buffer will fill and ipcutil.Write will block.

	res := <-accepted
	if res.err != nil {
		client.Close()
		t.Fatalf("accept: %v", res.err)
	}
	server := res.conn

	ic := newIPCConn(server, 0, false)
	defer func() {
		ic.Close()
		client.Close()
	}()

	// Fill sendCh + keep writing until ipcWrite blocks.
	//
	// Each iteration allocates its own message copy in the main
	// goroutine BEFORE spawning the writer — `msg` is reused across
	// iterations, so doing the copy inside the goroutine raced with
	// the next iteration's msg[0] = ... write. Caught by -race on
	// ubuntu-latest in the Architecture-gates job (zz_ipc_write_deadline_test
	// race report 2026-05-29).
	const msgSize = 4096
	msg := make([]byte, msgSize)
	for i := 0; i < ipcSendBuffer+10; i++ {
		msg[0] = byte(i & 0xFF)
		m := make([]byte, msgSize)
		copy(m, msg)
		go func() { ic.ipcWrite(m) }()
	}

	// Give writeLoop time to fill the kernel send buffer.
	time.Sleep(100 * time.Millisecond)

	// writeLoop should be stuck in ipcutil.Write now. Wait for it
	// to hit the write deadline and exit (ipcWriteTimeout = 10s).
	select {
	case <-ic.writeDone:
		// writeLoop exited — deadline worked
	case <-time.After(15 * time.Second):
		select {
		case <-ic.writeDone:
		default:
			t.Fatal("writeLoop did not exit within deadline window")
		}
	}

	// Verify ipcWrite now returns ErrIPCClosed.
	if err := ic.ipcWrite([]byte("should-fail")); err == nil {
		t.Error("ipcWrite on deadline-closed conn should return error")
	}
}

// TestHealthHandlerInlineDispatch verifies the CmdHealth handler
// produces a valid CmdHealthOK reply when invoked directly (the
// inline dispatch path exercised by the handleClient semaphore-bypass).
func TestHealthHandlerInlineDispatch(t *testing.T) {
	t.Parallel()

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ic := newIPCConn(server, 0, false)
	defer ic.Close()

	// Minimal daemon — handleHealth only needs Info().
	d := &Daemon{
		nodeID:      1,
		tunnels:     NewTunnelManager(),
		ports:       NewPortManager(),
		startTime:   time.Now(),
		netPolicies: make(map[uint16][]uint16),
		managed:     make(map[uint16]*ManagedEngine),
	}
	s := NewIPCServer("", d)

	go func() {
		s.handleHealth(ic, 0)
	}()

	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	msg, err := ipcutil.Read(client)
	if err != nil {
		t.Fatalf("ipcutil.Read: %v", err)
	}
	if len(msg) < 1 {
		t.Fatal("reply too short")
	}
	if msg[0] != CmdHealthOK {
		t.Fatalf("reply cmd = 0x%02X, want CmdHealthOK (0x%02X)", msg[0], CmdHealthOK)
	}

	// Verify ipcWrite still works after health check.
	sendPayload := []byte{0xAA, 0xBB}
	go func() { _ = ic.ipcWrite(sendPayload) }()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	msg2, err := ipcutil.Read(client)
	if err != nil {
		t.Fatalf("second ipcutil.Read: %v", err)
	}
	if msg2[0] != sendPayload[0] || msg2[1] != sendPayload[1] {
		t.Errorf("second message corrupted: got %v, want %v", msg2[:2], sendPayload)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/ipcutil"
)

// macOS sun_path is ~104 bytes; Go test temp dirs blow past it. Mint short
// /tmp paths that the test cleans up itself.
var iter108Seq uint64

func shortSockPath(t *testing.T) string {
	t.Helper()
	n := atomic.AddUint64(&iter108Seq, 1)
	p := filepath.Join(os.TempDir(), fmt.Sprintf("p%d-%d.sock", os.Getpid(), n))
	t.Cleanup(func() { _ = os.Remove(p) })
	return p
}

// writeIPCRequest builds a `[cmd][reqID(8)][payload...]` envelope (issue
// #99 wire format) and writes it to the daemon over conn. reqID==0 is
// fine for these tests: the daemon echoes whatever we send and these
// tests check the reply's cmd byte, not the reqID.
func writeIPCRequest(conn net.Conn, cmd byte, payload []byte) error {
	buf := make([]byte, IPCEnvelopeHeaderSize+len(payload))
	buf[0] = cmd
	// reqID stays zero — fine for tests that don't demultiplex.
	copy(buf[IPCEnvelopeHeaderSize:], payload)
	return ipcutil.Write(conn, buf)
}

// readIPCFrame reads one envelope and returns `[cmd][body...]` so the
// caller can index into it the same way it always did.
func readIPCFrame(conn net.Conn) ([]byte, error) {
	msg, err := ipcutil.Read(conn)
	if err != nil {
		return nil, err
	}
	if len(msg) < IPCEnvelopeHeaderSize {
		return nil, fmt.Errorf("ipc reply shorter than envelope header (%d bytes)", len(msg))
	}
	out := make([]byte, 1+len(msg)-IPCEnvelopeHeaderSize)
	out[0] = msg[0]
	copy(out[1:], msg[IPCEnvelopeHeaderSize:])
	return out, nil
}

// Iter-108 coverage for IPCServer.Start (0% baseline), acceptLoop (0%),
// and handleClient (0%) — the Unix-socket lifecycle that drivers use to
// talk to the daemon. Previous IPC tests (daemon_ipc_test.go) exercise
// individual handlers via net.Pipe, but never route through the real
// socket + acceptLoop + handleClient path.

// newIPCTestServer builds a fresh Daemon + IPCServer pair bound to a temp
// socket under t.TempDir(). Cleanup Close()s both — safe to call twice.
func newIPCTestServer(t *testing.T) (*Daemon, *IPCServer, string) {
	t.Helper()
	sockPath := shortSockPath(t)
	d := New(Config{SocketPath: sockPath})
	// d.ipc was created by New with the configured SocketPath.
	s := d.ipc
	t.Cleanup(func() { _ = s.Close() })
	return d, s, sockPath
}

// --- Start: binds socket, chmod 0600, spawns acceptLoop ---

func TestIPCServerStartBindsSocketAndSetsMode(t *testing.T) {
	t.Parallel()
	_, s, sockPath := newIPCTestServer(t)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	// chmod 0600 — owner rw only (proves chmod branch ran)
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("socket mode = %o, want 0600", mode)
	}
	if s.listener == nil {
		t.Fatal("listener not set after Start")
	}
}

// --- Start removes a stale socket file before bind ---

func TestIPCServerStartRemovesStaleSocket(t *testing.T) {
	t.Parallel()
	_, s, sockPath := newIPCTestServer(t)

	// Pre-create a stale socket-path file; Start must os.Remove it before listen.
	if err := os.WriteFile(sockPath, []byte("stale"), 0600); err != nil {
		t.Fatalf("seed stale socket: %v", err)
	}

	if err := s.Start(); err != nil {
		t.Fatalf("Start with stale file: %v", err)
	}
	// After start, it must be a unix socket, not the stale regular file.
	info, _ := os.Stat(sockPath)
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("path is not a unix socket after Start; mode=%v", info.Mode())
	}
}

// --- Start returns error when parent dir does not exist ---

func TestIPCServerStartInvalidPathReturnsError(t *testing.T) {
	t.Parallel()
	d := New(Config{SocketPath: "/nonexistent-dir-xyz/pilot.sock"})
	s := d.ipc
	err := s.Start()
	if err == nil {
		_ = s.Close()
		t.Fatal("Start with invalid path should error")
	}
	if s.listener != nil {
		t.Fatal("listener should not be set on Start failure")
	}
}

// --- acceptLoop: accepts a real client connect, handleClient dispatches ---

func TestIPCServerAcceptLoopDispatchesCommand(t *testing.T) {
	t.Parallel()
	_, s, sockPath := newIPCTestServer(t)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Dial as a driver would. acceptLoop receives it, spawns handleClient.
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send a CmdBind frame (port 4321) → handleClient dispatches to handleBind,
	// which writes CmdBindOK back. This proves the full path:
	// Start → acceptLoop.Accept → go handleClient → ipcutil.Read → dispatch.
	// CmdBind is safe in isolation (no registry needed, unlike CmdHealth).
	if err := writeIPCRequest(conn, CmdBind, []byte{0x10, 0xE1}); err != nil {
		t.Fatalf("write bind: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply, err := readIPCFrame(conn)
	if err != nil {
		t.Fatalf("read bind reply: %v", err)
	}
	if reply[0] != CmdBindOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdBindOK (0x%02X)", reply[0], CmdBindOK)
	}
}

// --- acceptLoop: tracks client in s.clients map while connected ---

func TestIPCServerAcceptLoopRegistersClientInMap(t *testing.T) {
	t.Parallel()
	_, s, sockPath := newIPCTestServer(t)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// acceptLoop → s.mu.Lock → s.clients[ic]=true runs asynchronously after
	// Accept returns. Poll briefly (up to 500ms) for registration.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		n := len(s.clients)
		s.mu.Unlock()
		if n == 1 {
			return // registered — test passes
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("client was not registered in s.clients within 500ms")
}

// --- handleClient: unknown cmd byte → sendError, loop continues ---

func TestIPCServerHandleClientUnknownCmdSendsError(t *testing.T) {
	t.Parallel()
	_, s, sockPath := newIPCTestServer(t)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// 0xFE is not a known command — handleClient's default branch fires.
	if err := writeIPCRequest(conn, 0xFE, nil); err != nil {
		t.Fatalf("write unknown cmd: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply, err := readIPCFrame(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[0] != CmdError {
		t.Fatalf("reply[0] = 0x%02X, want CmdError", reply[0])
	}
}

// --- handleClient: empty payload (len 0) → `if len(msg) < 1` branch continues ---

func TestIPCServerHandleClientEmptyFrameContinuesLoop(t *testing.T) {
	t.Parallel()
	_, s, sockPath := newIPCTestServer(t)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send a frame too short for the envelope header (issue #99 wire
	// format), then a valid CmdBind. If the continue branch works, the
	// second frame still produces a CmdBindOK.
	if err := ipcutil.Write(conn, []byte{0x01, 0x02}); err != nil {
		t.Fatalf("write short frame: %v", err)
	}
	if err := writeIPCRequest(conn, CmdBind, []byte{0x20, 0x01}); err != nil {
		t.Fatalf("write bind: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply, err := readIPCFrame(conn)
	if err != nil {
		t.Fatalf("read bind reply after short: %v", err)
	}
	if reply[0] != CmdBindOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdBindOK (short-frame branch skipped it)", reply[0])
	}
}

// --- handleClient: client disconnect → EOF path → cleanup defer fires ---

func TestIPCServerHandleClientClientDisconnectCleansUp(t *testing.T) {
	t.Parallel()
	_, s, sockPath := newIPCTestServer(t)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Wait for acceptLoop to register the client.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		n := len(s.clients)
		s.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Close client end → handleClient's ipcutil.Read returns io.EOF → defer
	// runs → delete(s.clients, conn). Poll for removal.
	conn.Close()
	deadline = time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		n := len(s.clients)
		s.mu.Unlock()
		if n == 0 {
			return // cleanup happened — test passes
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("client not removed from s.clients within 1s of disconnect")
}

// --- handleClient cleanup: tracked ports are Unbound on disconnect ---

func TestIPCServerHandleClientCleansUpTrackedPorts(t *testing.T) {
	t.Parallel()
	d, s, sockPath := newIPCTestServer(t)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Bind port 1234 through IPC so it gets tracked on the client's ipcConn.
	// CmdBind payload = 2-byte big-endian port number.
	if err := writeIPCRequest(conn, CmdBind, []byte{0x04, 0xD2}); err != nil {
		t.Fatalf("write bind: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply, err := readIPCFrame(conn)
	if err != nil {
		t.Fatalf("read bind reply: %v", err)
	}
	if reply[0] != CmdBindOK {
		t.Fatalf("bind reply[0] = 0x%02X, want CmdBindOK", reply[0])
	}
	// Verify bind actually happened in the port manager.
	if ln := d.ports.GetListener(1234); ln == nil {
		t.Fatal("port 1234 should be bound after CmdBind")
	}

	// Disconnect → defer in handleClient iterates tracked ports → Unbind(1234).
	conn.Close()
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if d.ports.GetListener(1234) == nil {
			return // unbound — cleanup path fired
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("port 1234 was not unbound after client disconnect")
}

// --- acceptLoop exits when listener is closed (Close path) ---

func TestIPCServerCloseStopsAcceptLoopAndRemovesSocket(t *testing.T) {
	t.Parallel()
	_, s, sockPath := newIPCTestServer(t)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Dial so there's one active client; Close should reap it too.
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Give acceptLoop a moment to register the client so Close exercises
	// the "close all active client connections" branch.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		n := len(s.clients)
		s.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Socket file must be removed.
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("socket file still exists after Close; stat err=%v", err)
	}

	// Subsequent dial must fail (acceptLoop returned on listener.Close).
	if c, err := net.Dial("unix", sockPath); err == nil {
		c.Close()
		t.Fatal("dial after Close should fail — acceptLoop should be gone")
	}
}

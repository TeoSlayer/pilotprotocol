// SPDX-License-Identifier: AGPL-3.0-or-later

package driver

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/ipcutil"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// pushFromDaemon writes an unsolicited frame from the fakeDaemon side to
// exercise driver.readLoop dispatch. Waits briefly for the daemon conn to
// be accepted first.
//
// frame must be [cmd][payload...]. pushFromDaemon inserts the 8-byte zero
// reqID after the cmd byte, matching the wire format writePush uses:
// [cmd][reqID=0(8)][payload...]
func pushFromDaemon(t *testing.T, d *fakeDaemon, frame []byte) {
	t.Helper()
	waitFor(t, 2*time.Second, func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.conn != nil
	}, "daemon accept")
	d.mu.Lock()
	conn := d.conn
	d.mu.Unlock()
	// Insert 8-byte zero reqID after cmd byte (if frame has a cmd byte).
	var wire []byte
	if len(frame) > 0 {
		wire = make([]byte, len(frame)+8)
		wire[0] = frame[0]
		// reqID = 0 (already zero from make)
		copy(wire[9:], frame[1:])
	}
	if err := ipcutil.Write(conn, wire); err != nil {
		t.Fatalf("write from daemon: %v", err)
	}
}

// ---------- readLoop dispatch ----------

func TestReadLoopRecvDeliversToRegisteredChannel(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer drv.Close()

	connID := uint32(42)
	ch := drv.ipc.registerRecvCh(connID)

	frame := make([]byte, 1+4+5)
	frame[0] = cmdRecv
	binary.BigEndian.PutUint32(frame[1:5], connID)
	copy(frame[5:], "hello")
	pushFromDaemon(t, d, frame)

	select {
	case data := <-ch:
		if string(data) != "hello" {
			t.Errorf("got %q, want hello", data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no data delivered to recvCh")
	}
}

func TestReadLoopRecvBuffersWhenChannelNotRegistered(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer drv.Close()

	connID := uint32(99)
	frame := make([]byte, 1+4+3)
	frame[0] = cmdRecv
	binary.BigEndian.PutUint32(frame[1:5], connID)
	copy(frame[5:], "buf")
	pushFromDaemon(t, d, frame)

	// Wait for readLoop to process the frame (no recvCh registered yet).
	waitFor(t, 2*time.Second, func() bool {
		drv.ipc.recvMu.Lock()
		defer drv.ipc.recvMu.Unlock()
		return len(drv.ipc.pendRecv[connID]) == 1
	}, "pendRecv buffered")

	// Registering now should drain the buffered data.
	ch := drv.ipc.registerRecvCh(connID)
	select {
	case data := <-ch:
		if string(data) != "buf" {
			t.Errorf("got %q, want buf", data)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("registerRecvCh did not drain pendRecv")
	}
}

func TestReadLoopRecvShortPayloadDropped(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer drv.Close()

	// <4 bytes after cmd byte → dropped.
	pushFromDaemon(t, d, []byte{cmdRecv, 0x01})

	// Sanity: no crash, no data buffered, no recv channels created.
	time.Sleep(50 * time.Millisecond)
	drv.ipc.recvMu.Lock()
	defer drv.ipc.recvMu.Unlock()
	if len(drv.ipc.pendRecv) != 0 {
		t.Errorf("short cmdRecv should not buffer, got %d entries", len(drv.ipc.pendRecv))
	}
}

func TestReadLoopCloseOKClosesRegisteredChannel(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer drv.Close()

	connID := uint32(7)
	ch := drv.ipc.registerRecvCh(connID)

	frame := make([]byte, 1+4)
	frame[0] = cmdCloseOK
	binary.BigEndian.PutUint32(frame[1:], connID)
	pushFromDaemon(t, d, frame)

	select {
	case _, ok := <-ch:
		if ok {
			t.Error("expected channel closed, got value")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("channel not closed")
	}

	drv.ipc.recvMu.Lock()
	_, stillThere := drv.ipc.recvChs[connID]
	drv.ipc.recvMu.Unlock()
	if stillThere {
		t.Error("recvCh entry should be deleted")
	}
}

func TestReadLoopCloseOKShortPayloadDropped(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer drv.Close()

	// payload < 4 — must not panic, must not disturb recvChs.
	connID := uint32(8)
	ch := drv.ipc.registerRecvCh(connID)
	pushFromDaemon(t, d, []byte{cmdCloseOK, 0x00})

	time.Sleep(50 * time.Millisecond)
	select {
	case <-ch:
		t.Error("channel should not close on short CloseOK")
	default:
	}
}

func TestReadLoopRecvFromDeliversDatagram(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer drv.Close()

	srcAddr, err := protocol.ParseAddr("1:0001.AAAA.BBBB")
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 1+protocol.AddrSize+4+5)
	frame[0] = cmdRecvFrom
	srcAddr.MarshalTo(frame, 1)
	binary.BigEndian.PutUint16(frame[1+protocol.AddrSize:], 111)
	binary.BigEndian.PutUint16(frame[1+protocol.AddrSize+2:], 222)
	copy(frame[1+protocol.AddrSize+4:], "ping!")
	pushFromDaemon(t, d, frame)

	dg, err := drv.RecvFrom()
	if err != nil {
		t.Fatalf("RecvFrom: %v", err)
	}
	if dg.SrcPort != 111 || dg.DstPort != 222 || string(dg.Data) != "ping!" {
		t.Errorf("datagram = %+v, data=%q", dg, string(dg.Data))
	}
	if dg.SrcAddr != srcAddr {
		t.Errorf("src addr = %v, want %v", dg.SrcAddr, srcAddr)
	}
}

func TestReadLoopRecvFromShortPayloadDropped(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer drv.Close()

	// AddrSize=6, need +4 for ports — send just 5 bytes payload → drop.
	pushFromDaemon(t, d, append([]byte{cmdRecvFrom}, make([]byte, 5)...))

	// If it were dispatched, it'd land on dgCh. Confirm nothing arrives.
	select {
	case dg := <-drv.ipc.dgCh:
		t.Errorf("unexpected datagram: %+v", dg)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestReadLoopAcceptShortPayloadDropped(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer drv.Close()

	// <2 bytes after cmd byte → dropped.
	pushFromDaemon(t, d, []byte{cmdAccept, 0x01})
	time.Sleep(50 * time.Millisecond) // assertion: no crash
}

func TestReadLoopEmptyFrameContinues(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer drv.Close()

	// Zero-length frame is skipped; readLoop must keep running.
	pushFromDaemon(t, d, []byte{})

	// Follow it with a valid cmdRecvFrom to prove readLoop is still alive.
	srcAddr, err := protocol.ParseAddr("1:0001.CCCC.DDDD")
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 1+protocol.AddrSize+4+2)
	frame[0] = cmdRecvFrom
	srcAddr.MarshalTo(frame, 1)
	copy(frame[1+protocol.AddrSize+4:], "ok")
	pushFromDaemon(t, d, frame)

	if _, err := drv.RecvFrom(); err != nil {
		t.Fatalf("readLoop died after empty frame: %v", err)
	}
}

func TestReadLoopUnknownCmdWithNoHandlerDropped(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer drv.Close()

	// cmd 0xFE not in any handler map — readLoop default branch, no waiter, drop.
	pushFromDaemon(t, d, []byte{0xFE, 0x01, 0x02})

	// Prove readLoop still alive by exchanging Info.
	d.onCmd(cmdInfo, func(_ []byte) [][]byte {
		return [][]byte{jsonOK(cmdInfoOK, `{"ok":true}`)}
	})
	if _, err := drv.Info(); err != nil {
		t.Fatalf("Info after unknown cmd: %v", err)
	}
}

// ---------- Listener.Accept branches ----------

func TestListenerAcceptDeliversConn(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer drv.Close()

	// Bind port 5000.
	d.onCmd(cmdBind, func(frame []byte) [][]byte {
		return [][]byte{{cmdBindOK, frame[1], frame[2]}}
	})
	ln, err := drv.Listen(5000)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	// Push an unsolicited cmdAccept: [port][connID][addr][port]
	remoteAddr, _ := protocol.ParseAddr("1:0002.1111.2222")
	payload := make([]byte, 2+4+protocol.AddrSize+2)
	binary.BigEndian.PutUint16(payload[0:2], 5000)
	binary.BigEndian.PutUint32(payload[2:6], 1234)
	remoteAddr.MarshalTo(payload, 6)
	binary.BigEndian.PutUint16(payload[6+protocol.AddrSize:], 99)
	pushFromDaemon(t, d, append([]byte{cmdAccept}, payload...))

	// Accept should return a Conn with the parsed fields.
	done := make(chan *Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		done <- c.(*Conn)
	}()

	select {
	case c := <-done:
		if c.id != 1234 {
			t.Errorf("conn.id = %d, want 1234", c.id)
		}
		if c.remoteAddr.Port != 99 {
			t.Errorf("remote port = %d, want 99", c.remoteAddr.Port)
		}
		if c.remoteAddr.Addr != remoteAddr {
			t.Errorf("remote addr = %v, want %v", c.remoteAddr.Addr, remoteAddr)
		}
	case err := <-errCh:
		t.Fatalf("Accept: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not complete")
	}
}

func TestListenerAcceptInvalidPayloadReturnsError(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer drv.Close()

	d.onCmd(cmdBind, func(frame []byte) [][]byte {
		return [][]byte{{cmdBindOK, frame[1], frame[2]}}
	})
	ln, err := drv.Listen(5001)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	// cmdAccept with port=5001 but truncated tail.
	pushFromDaemon(t, d, []byte{cmdAccept, 0x13, 0x89, 0x00})

	_, err = ln.Accept()
	if err == nil {
		t.Fatal("expected invalid payload error")
	}
}

func TestListenerAcceptUnblocksOnClose(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer drv.Close()

	d.onCmd(cmdBind, func(frame []byte) [][]byte {
		return [][]byte{{cmdBindOK, frame[1], frame[2]}}
	})
	ln, err := drv.Listen(5002)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		errCh <- err
	}()

	// Give Accept a moment to enter the select, then close.
	time.Sleep(50 * time.Millisecond)
	_ = ln.Close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not unblock on Close")
	}
}

// ---------- ipcClient helpers ----------

func TestUnregisterRecvChRemovesEntry(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer drv.Close()

	connID := uint32(55)
	_ = drv.ipc.registerRecvCh(connID)

	drv.ipc.recvMu.Lock()
	if _, ok := drv.ipc.recvChs[connID]; !ok {
		drv.ipc.recvMu.Unlock()
		t.Fatal("recvCh not present after registerRecvCh")
	}
	drv.ipc.recvMu.Unlock()

	drv.ipc.unregisterRecvCh(connID)

	drv.ipc.recvMu.Lock()
	_, ok := drv.ipc.recvChs[connID]
	drv.ipc.recvMu.Unlock()
	if ok {
		t.Error("recvCh still present after unregisterRecvCh")
	}
}

func TestSendAndWaitTimeoutFires(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer drv.Close()

	// No handler for cmdInfo — daemon accepts the frame and never replies.
	start := time.Now()
	_, err = drv.ipc.sendAndWaitTimeout([]byte{cmdInfo}, cmdInfoOK, 80*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed < 50*time.Millisecond || elapsed > 500*time.Millisecond {
		t.Errorf("unexpected elapsed %v (want ~80ms)", elapsed)
	}
}

func TestSendAndWaitReturnsWhenDaemonDisconnects(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer drv.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := drv.ipc.sendAndWait([]byte{cmdInfo}, cmdInfoOK)
		errCh <- err
	}()

	// Give the request time to enqueue its handler, then yank the daemon.
	time.Sleep(50 * time.Millisecond)
	d.close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error on daemon disconnect")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sendAndWait did not unblock on disconnect")
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"io"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// ---------- pilotAddr ----------

func TestPilotAddrNetworkAndString(t *testing.T) {
	t.Parallel()
	pa := pilotAddr{addr: protocol.Addr{Network: 1, Node: 2}, port: 1234}
	if pa.Network() != "pilot" {
		t.Errorf("Network = %q, want pilot", pa.Network())
	}
	got := pa.String()
	want := protocol.Addr{Network: 1, Node: 2}.String() + ":1234"
	if got != want {
		t.Errorf("String = %q, want %q", got, want)
	}
}

// ---------- connAdapter ----------

func newTestConn() *Connection {
	return &Connection{
		LocalAddr:  protocol.Addr{Network: 1, Node: 10},
		LocalPort:  4000,
		RemoteAddr: protocol.Addr{Network: 1, Node: 20},
		RemotePort: 5000,
		RecvBuf:    make(chan []byte, 4),
	}
}

func TestNewConnAdapterFields(t *testing.T) {
	t.Parallel()
	d := &Daemon{}
	c := newTestConn()
	a := newConnAdapter(d, c)
	if a.daemon != d {
		t.Errorf("daemon not stored")
	}
	if a.conn != c {
		t.Errorf("conn not stored")
	}
	if a.buf != nil {
		t.Errorf("buf should start nil, got len %d", len(a.buf))
	}
}

func TestConnAdapterReadFromRecvBuf(t *testing.T) {
	t.Parallel()
	c := newTestConn()
	a := newConnAdapter(&Daemon{}, c)
	c.RecvBuf <- []byte("hello")
	buf := make([]byte, 5)
	n, err := a.Read(buf)
	if err != nil {
		t.Fatalf("read err: %v", err)
	}
	if n != 5 || string(buf) != "hello" {
		t.Errorf("read got %d %q, want 5 \"hello\"", n, buf[:n])
	}
}

func TestConnAdapterReadShortBufferLeaveLeftover(t *testing.T) {
	t.Parallel()
	c := newTestConn()
	a := newConnAdapter(&Daemon{}, c)
	c.RecvBuf <- []byte("hello world")
	buf := make([]byte, 5)
	n, err := a.Read(buf)
	if err != nil || n != 5 || string(buf) != "hello" {
		t.Fatalf("first read got %d %q err=%v", n, buf[:n], err)
	}
	// Next call drains leftover (without blocking on channel)
	buf2 := make([]byte, 6)
	n, err = a.Read(buf2)
	if err != nil {
		t.Fatalf("leftover read err: %v", err)
	}
	if n != 6 || string(buf2) != " world" {
		t.Errorf("leftover got %d %q, want 6 \" world\"", n, buf2[:n])
	}
	if len(a.buf) != 0 {
		t.Errorf("after full drain, buf len = %d, want 0", len(a.buf))
	}
}

func TestConnAdapterReadEOFWhenRecvBufClosed(t *testing.T) {
	t.Parallel()
	c := newTestConn()
	a := newConnAdapter(&Daemon{}, c)
	c.CloseRecvBuf()
	buf := make([]byte, 4)
	n, err := a.Read(buf)
	if err != io.EOF {
		t.Errorf("err = %v, want io.EOF", err)
	}
	if n != 0 {
		t.Errorf("n = %d, want 0", n)
	}
}

func TestConnAdapterLocalAndRemoteAddr(t *testing.T) {
	t.Parallel()
	c := newTestConn()
	a := newConnAdapter(&Daemon{}, c)
	la, ok := a.LocalAddr().(pilotAddr)
	if !ok {
		t.Fatalf("LocalAddr is %T, want pilotAddr", a.LocalAddr())
	}
	if la.addr != c.LocalAddr || la.port != c.LocalPort {
		t.Errorf("LocalAddr = %+v, want addr=%v port=%d", la, c.LocalAddr, c.LocalPort)
	}
	ra, ok := a.RemoteAddr().(pilotAddr)
	if !ok {
		t.Fatalf("RemoteAddr is %T, want pilotAddr", a.RemoteAddr())
	}
	if ra.addr != c.RemoteAddr || ra.port != c.RemotePort {
		t.Errorf("RemoteAddr = %+v, want addr=%v port=%d", ra, c.RemoteAddr, c.RemotePort)
	}
}

func TestConnAdapterDeadlineSettersAreNoops(t *testing.T) {
	t.Parallel()
	a := newConnAdapter(&Daemon{}, newTestConn())
	now := time.Now().Add(time.Hour)
	if err := a.SetDeadline(now); err != nil {
		t.Errorf("SetDeadline: %v", err)
	}
	if err := a.SetReadDeadline(now); err != nil {
		t.Errorf("SetReadDeadline: %v", err)
	}
	if err := a.SetWriteDeadline(now); err != nil {
		t.Errorf("SetWriteDeadline: %v", err)
	}
}

// saveReceivedFile / saveInboxMessage tests removed: extracted to plugins/dataexchange (T3.2).
// Task file disk I/O tests removed: extracted to internal/tasksfiles (T3.2).

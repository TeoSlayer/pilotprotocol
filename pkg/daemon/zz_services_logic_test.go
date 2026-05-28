// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"io"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// --- pilotAddr ---

func TestPilotAddrNetworkReturnsConstant(t *testing.T) {
	t.Parallel()
	a := pilotAddr{addr: protocol.Addr{Network: 7, Node: 0xBEEF}, port: 1234}
	if a.Network() != "pilot" {
		t.Fatalf("Network = %q, want 'pilot'", a.Network())
	}
}

func TestPilotAddrStringFormatsAddressAndPort(t *testing.T) {
	t.Parallel()
	a := pilotAddr{addr: protocol.Addr{Network: 7, Node: 0xBEEF}, port: 1234}
	got := a.String()
	want := a.addr.String() + ":1234"
	if got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
}

// --- connAdapter ---

func TestConnAdapterSetDeadlineAllNoOps(t *testing.T) {
	t.Parallel()
	a := &connAdapter{}
	if err := a.SetDeadline(time.Now()); err != nil {
		t.Fatalf("SetDeadline = %v, want nil", err)
	}
	if err := a.SetReadDeadline(time.Now()); err != nil {
		t.Fatalf("SetReadDeadline = %v, want nil", err)
	}
	if err := a.SetWriteDeadline(time.Now()); err != nil {
		t.Fatalf("SetWriteDeadline = %v, want nil", err)
	}
}

func TestConnAdapterLocalAddrAndRemoteAddrUseConnFields(t *testing.T) {
	t.Parallel()
	c := &Connection{
		LocalAddr:  protocol.Addr{Network: 1, Node: 0x11},
		LocalPort:  100,
		RemoteAddr: protocol.Addr{Network: 2, Node: 0x22},
		RemotePort: 200,
	}
	a := newConnAdapter(nil, c)

	local, ok := a.LocalAddr().(pilotAddr)
	if !ok {
		t.Fatal("LocalAddr should be pilotAddr")
	}
	if local.port != 100 {
		t.Fatalf("local.port = %d, want 100", local.port)
	}
	remote, ok := a.RemoteAddr().(pilotAddr)
	if !ok {
		t.Fatal("RemoteAddr should be pilotAddr")
	}
	if remote.port != 200 {
		t.Fatalf("remote.port = %d, want 200", remote.port)
	}
}

func TestConnAdapterReadDelivRecvBufData(t *testing.T) {
	t.Parallel()
	c := &Connection{RecvBuf: make(chan []byte, 2)}
	a := newConnAdapter(nil, c)
	c.RecvBuf <- []byte("hello")

	buf := make([]byte, 10)
	n, err := a.Read(buf)
	if err != nil {
		t.Fatalf("Read err = %v", err)
	}
	if n != 5 || string(buf[:n]) != "hello" {
		t.Fatalf("Read = %q (n=%d), want 'hello'", buf[:n], n)
	}
}

func TestConnAdapterReadPartialCopyBuffersRemainder(t *testing.T) {
	t.Parallel()
	c := &Connection{RecvBuf: make(chan []byte, 2)}
	a := newConnAdapter(nil, c)
	c.RecvBuf <- []byte("hello-world")

	// Tiny buffer — only 5 bytes can be read
	buf := make([]byte, 5)
	n, err := a.Read(buf)
	if err != nil {
		t.Fatalf("Read err = %v", err)
	}
	if n != 5 || string(buf[:n]) != "hello" {
		t.Fatalf("first Read = %q, want 'hello'", buf[:n])
	}
	// Second Read should drain the leftover buffer WITHOUT pulling from RecvBuf
	buf2 := make([]byte, 10)
	n, err = a.Read(buf2)
	if err != nil {
		t.Fatalf("second Read err = %v", err)
	}
	if string(buf2[:n]) != "-world" {
		t.Fatalf("leftover Read = %q, want '-world'", buf2[:n])
	}
}

func TestConnAdapterReadReturnsEOFWhenRecvBufClosed(t *testing.T) {
	t.Parallel()
	c := &Connection{RecvBuf: make(chan []byte, 1)}
	a := newConnAdapter(nil, c)
	close(c.RecvBuf)

	buf := make([]byte, 10)
	n, err := a.Read(buf)
	if err != io.EOF {
		t.Fatalf("Read err = %v, want io.EOF", err)
	}
	if n != 0 {
		t.Fatalf("Read n = %d, want 0", n)
	}
}

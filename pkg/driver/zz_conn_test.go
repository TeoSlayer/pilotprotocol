// SPDX-License-Identifier: AGPL-3.0-or-later

package driver

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// ---------------------------------------------------------------------------
// pilotAddr — net.Addr implementation
// ---------------------------------------------------------------------------

func TestPilotAddrNetwork(t *testing.T) {
	t.Parallel()
	a := pilotAddr(protocol.SocketAddr{Port: 80})
	if got := a.Network(); got != "pilot" {
		t.Errorf("Network() = %q, want %q", got, "pilot")
	}
}

func TestPilotAddrString(t *testing.T) {
	t.Parallel()
	addr, _ := protocol.ParseAddr("1:0001.0002.0003")
	a := pilotAddr(protocol.SocketAddr{Addr: addr, Port: 7})
	got := a.String()
	want := protocol.SocketAddr{Addr: addr, Port: 7}.String()
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// Conn — read leftover and deadline behaviour exercise the in-memory
// branches that don't require live IPC.
// ---------------------------------------------------------------------------

func TestConnReadDrainsLeftover(t *testing.T) {
	t.Parallel()
	c := &Conn{
		recvBuf:    []byte("hello world"),
		recvCh:     make(chan []byte),
		deadlineCh: make(chan struct{}),
	}
	got := make([]byte, 5)
	n, err := c.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 || string(got) != "hello" {
		t.Fatalf("first read: n=%d got=%q", n, got)
	}
	// Second read drains the rest of the leftover (no IPC needed).
	got2 := make([]byte, 6)
	n2, err := c.Read(got2)
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 6 || string(got2) != " world" {
		t.Fatalf("second read: n=%d got=%q", n2, got2)
	}
}

func TestConnReadDeadlineAlreadyPassed(t *testing.T) {
	t.Parallel()
	c := &Conn{
		recvCh:       make(chan []byte),
		deadlineCh:   make(chan struct{}),
		readDeadline: time.Now().Add(-time.Second), // already in past
	}
	_, err := c.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("got %v, want ErrDeadlineExceeded", err)
	}
}

func TestConnReadEOFOnClosedRecvCh(t *testing.T) {
	t.Parallel()
	ch := make(chan []byte)
	close(ch)
	c := &Conn{
		recvCh:     ch,
		deadlineCh: make(chan struct{}),
	}
	_, err := c.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Errorf("got %v, want io.EOF", err)
	}
}

func TestConnReadDelivers(t *testing.T) {
	t.Parallel()
	ch := make(chan []byte, 1)
	ch <- []byte("xy")
	c := &Conn{
		recvCh:     ch,
		deadlineCh: make(chan struct{}),
	}
	buf := make([]byte, 2)
	n, err := c.Read(buf)
	if err != nil || n != 2 || string(buf) != "xy" {
		t.Fatalf("got n=%d err=%v buf=%q", n, err, buf)
	}
}

func TestConnReadStoresLeftoverWhenBufferTooSmall(t *testing.T) {
	t.Parallel()
	ch := make(chan []byte, 1)
	ch <- []byte("12345")
	c := &Conn{
		recvCh:     ch,
		deadlineCh: make(chan struct{}),
	}
	buf := make([]byte, 2)
	n, err := c.Read(buf)
	if err != nil || n != 2 || string(buf) != "12" {
		t.Fatalf("first read got n=%d err=%v buf=%q", n, err, buf)
	}
	// Remaining 3 bytes should be in recvBuf
	rest := make([]byte, 3)
	n2, err := c.Read(rest)
	if err != nil || n2 != 3 || string(rest) != "345" {
		t.Fatalf("leftover read got n=%d err=%v buf=%q", n2, err, rest)
	}
}

func TestConnReadTimerExpires(t *testing.T) {
	t.Parallel()
	c := &Conn{
		recvCh:       make(chan []byte),
		deadlineCh:   make(chan struct{}),
		readDeadline: time.Now().Add(20 * time.Millisecond),
	}
	start := time.Now()
	_, err := c.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("got %v, want ErrDeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Errorf("returned too early: %v", elapsed)
	}
}

func TestSetReadDeadlineUnblocksReader(t *testing.T) {
	t.Parallel()
	c := &Conn{
		recvCh:     make(chan []byte),
		deadlineCh: make(chan struct{}),
	}
	done := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		done <- err
	}()
	// Give Read a moment to enter the select.
	time.Sleep(10 * time.Millisecond)
	c.SetReadDeadline(time.Now().Add(time.Hour)) // closes the old deadlineCh
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("got %v, want ErrDeadlineExceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not unblock after SetReadDeadline")
	}
}

func TestSetDeadlineDelegatesToRead(t *testing.T) {
	t.Parallel()
	c := &Conn{
		recvCh:     make(chan []byte),
		deadlineCh: make(chan struct{}),
	}
	dl := time.Now().Add(time.Hour)
	if err := c.SetDeadline(dl); err != nil {
		t.Fatal(err)
	}
	if !c.readDeadline.Equal(dl) {
		t.Errorf("readDeadline = %v, want %v", c.readDeadline, dl)
	}
}

func TestSetWriteDeadlineNoop(t *testing.T) {
	t.Parallel()
	c := &Conn{}
	if err := c.SetWriteDeadline(time.Now()); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestConnAddrs(t *testing.T) {
	t.Parallel()
	addr, _ := protocol.ParseAddr("1:0001.0002.0003")
	c := &Conn{
		localAddr:  protocol.SocketAddr{Port: 80},
		remoteAddr: protocol.SocketAddr{Addr: addr, Port: 7},
	}
	if c.LocalAddr().Network() != "pilot" {
		t.Errorf("LocalAddr().Network() unexpected")
	}
	if c.RemoteAddr().Network() != "pilot" {
		t.Errorf("RemoteAddr().Network() unexpected")
	}
}

// ---------------------------------------------------------------------------
// Listener — Accept payload parsing and Close behavior
// ---------------------------------------------------------------------------

func TestListenerCloseUnblocksAccept(t *testing.T) {
	t.Parallel()
	l := &Listener{
		port:     80,
		acceptCh: make(chan []byte),
		done:     make(chan struct{}),
	}
	type r struct{ err error }
	ch := make(chan r, 1)
	go func() {
		_, err := l.Accept()
		ch <- r{err}
	}()
	time.Sleep(10 * time.Millisecond)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-ch:
		if got.err == nil {
			t.Fatal("expected error after close")
		}
	case <-time.After(time.Second):
		t.Fatal("Accept did not unblock after Close")
	}
}

func TestListenerAcceptOnAlreadyClosed(t *testing.T) {
	t.Parallel()
	l := &Listener{
		port:     80,
		acceptCh: make(chan []byte),
		done:     make(chan struct{}),
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := l.Accept()
	if err == nil {
		t.Fatal("expected closed error")
	}
}

func TestListenerCloseIdempotent(t *testing.T) {
	t.Parallel()
	l := &Listener{
		port:     80,
		acceptCh: make(chan []byte),
		done:     make(chan struct{}),
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	// Second Close must not panic on closed channel
	if err := l.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestListenerAddr(t *testing.T) {
	t.Parallel()
	l := &Listener{port: 8080}
	a := l.Addr()
	if a.Network() != "pilot" {
		t.Errorf("Network() = %q", a.Network())
	}
}

func TestListenerAcceptInvalidPayload(t *testing.T) {
	t.Parallel()
	l := &Listener{
		port:     80,
		acceptCh: make(chan []byte, 1),
		done:     make(chan struct{}),
	}
	l.acceptCh <- []byte{0x01, 0x02} // way too short
	_, err := l.Accept()
	if err == nil {
		t.Fatal("expected invalid-payload error")
	}
}

// satisfy unused import detector if SDK isn't otherwise used here
var _ net.Listener = (*Listener)(nil)

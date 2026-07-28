// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"errors"
	"net"
	"testing"
	"time"
)

// newTestConnAdapter builds a connAdapter over a bare Connection with a
// RecvBuf nobody ever writes to — the exact shape of a peer that opens a
// stream, sends nothing, and stalls.
func newTestConnAdapter() *connAdapter {
	c := &Connection{
		RecvBuf: make(chan []byte, RecvBufSize),
	}
	return &connAdapter{conn: c}
}

// TestConnAdapterReadDeadlineFires is the regression guard for the leak
// that OOM-killed the 431-agent service fleet on 2026-07-28.
//
// connAdapter.SetReadDeadline used to be a stub returning nil without
// storing anything, so Read blocked on <-RecvBuf forever. A stalled peer
// pinned its handler goroutine plus the whole Connection (512-slot
// RecvBuf + 256-slot SendBuf + goroutine stacks, ~43 KiB) until the
// process died. Against that stub this test hangs until the deadline
// arrives and then fails on the nil error.
func TestConnAdapterReadDeadlineFires(t *testing.T) {
	a := newTestConnAdapter()

	if err := a.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, err := a.Read(buf)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Read returned nil error — deadline did not fire (stub regression)")
		}
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("expected a net.Error with Timeout()==true, got %T: %v", err, err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("Read blocked %v — far past the 100ms deadline", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Read never returned — deadline is not enforced; this is the fleet-killing leak")
	}
}

// TestConnAdapterZeroDeadlineBlocks pins the documented default: with no
// deadline set, Read keeps its historical block-forever behaviour, and a
// zero time clears a previously-set deadline.
func TestConnAdapterZeroDeadlineBlocks(t *testing.T) {
	a := newTestConnAdapter()

	if err := a.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := a.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clearing SetReadDeadline: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, err := a.Read(buf)
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("Read returned %v — a cleared deadline must not time out", err)
	case <-time.After(300 * time.Millisecond):
		// Correct: still blocked with no deadline armed.
	}
}

// TestConnAdapterReadDeliversBeforeDeadline guards the other direction —
// arming a deadline must not break normal reads.
func TestConnAdapterReadDeliversBeforeDeadline(t *testing.T) {
	a := newTestConnAdapter()
	a.conn.RecvBuf <- []byte("hello")

	if err := a.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	buf := make([]byte, 64)
	n, err := a.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := string(buf[:n]); got != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

// TestConnAdapterAlreadyExpiredDeadline covers the boundary where the
// deadline is already in the past when Read is entered.
func TestConnAdapterAlreadyExpiredDeadline(t *testing.T) {
	a := newTestConnAdapter()

	if err := a.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	buf := make([]byte, 64)
	if _, err := a.Read(buf); err == nil {
		t.Fatal("Read with an already-expired deadline must not block or succeed")
	}
}

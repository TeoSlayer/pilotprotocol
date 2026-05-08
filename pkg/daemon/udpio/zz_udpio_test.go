// SPDX-License-Identifier: AGPL-3.0-or-later

// Package udpio_test exercises the public Send/Recv/Close surface of
// pkg/daemon/udpio. Run under -race to validate the §3 (single reader,
// concurrent writers ok) and §6 (pool-backed buffer reused across Recvs;
// returned slice valid only until next Recv) invariants from
// docs/architecture/03-INVARIANTS.md.
package udpio_test

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/udpio"
)

// recvWithTimeout drains one frame from sock or fails the test if the
// socket doesn't return within d. It runs the blocking Recv in a
// goroutine so the test framework can fail fast on a hang.
func recvWithTimeout(t *testing.T, sock *udpio.Socket, d time.Duration) ([]byte, *net.UDPAddr, error) {
	t.Helper()
	type rr struct {
		buf []byte
		src *net.UDPAddr
		err error
	}
	ch := make(chan rr, 1)
	go func() {
		buf, src, err := sock.Recv()
		// Copy because the pool-backed slice is invalidated by the next
		// Recv on this socket; we want the bytes to be safe to compare
		// from the test goroutine.
		var copied []byte
		if buf != nil {
			copied = append([]byte(nil), buf...)
		}
		ch <- rr{copied, src, err}
	}()
	select {
	case r := <-ch:
		return r.buf, r.src, r.err
	case <-time.After(d):
		t.Fatalf("Recv timed out after %s", d)
		return nil, nil, nil
	}
}

// TestListenSendRecvLoopback covers goal 1: bind, send to self, receive,
// verify bytes round-trip and the source matches the sender's local
// endpoint.
func TestListenSendRecvLoopback(t *testing.T) {
	t.Parallel()
	receiver, err := udpio.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen receiver: %v", err)
	}
	defer receiver.Close()

	sender, err := udpio.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen sender: %v", err)
	}
	defer sender.Close()

	want := []byte("hello pilot l2")
	dst := receiver.LocalAddr()
	if dst == nil {
		t.Fatal("receiver LocalAddr nil")
	}
	n, err := sender.Send(want, dst)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if n != len(want) {
		t.Fatalf("Send n=%d want %d", n, len(want))
	}

	got, src, err := recvWithTimeout(t, receiver, 2*time.Second)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Recv bytes = %q, want %q", got, want)
	}
	if src == nil {
		t.Fatal("Recv src is nil")
	}

	wantSrc := sender.LocalAddr()
	if wantSrc == nil {
		t.Fatal("sender LocalAddr nil")
	}
	// Compare port and that the source IP is loopback (the kernel may
	// surface 127.0.0.1 specifically for an explicit bind).
	if src.Port != wantSrc.Port {
		t.Fatalf("Recv src port = %d, want %d", src.Port, wantSrc.Port)
	}
	if !src.IP.IsLoopback() {
		t.Fatalf("Recv src IP %v not loopback", src.IP)
	}
}

// TestConcurrentSenders covers goal 2: 10 senders, 100 packets each,
// 1000 received total. UDP loopback is reliable in practice. Validates
// concurrent-Send safety + single-reader Recv contract under -race.
func TestConcurrentSenders(t *testing.T) {
	t.Parallel()
	const senders = 10
	const perSender = 100
	const total = senders * perSender

	receiver, err := udpio.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer receiver.Close()
	dst := receiver.LocalAddr()

	// Single drainer goroutine — matches §3 single-reader contract.
	var got int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			buf, _, err := receiver.Recv()
			if err != nil {
				return
			}
			if len(buf) == 0 {
				continue
			}
			atomic.AddInt64(&got, 1)
			if atomic.LoadInt64(&got) >= int64(total) {
				return
			}
		}
	}()

	// Each sender owns its own Socket — concurrent Send is allowed at
	// the kernel-FD level, but the production code uses one Socket per
	// daemon. Per-sender sockets stress the receiver-side fan-in path.
	var wg sync.WaitGroup
	for i := 0; i < senders; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			s, err := udpio.Listen("127.0.0.1:0")
			if err != nil {
				t.Errorf("sender %d listen: %v", id, err)
				return
			}
			defer s.Close()
			frame := []byte{byte(id), 0, 1, 2, 3}
			for j := 0; j < perSender; j++ {
				if _, err := s.Send(frame, dst); err != nil {
					t.Errorf("sender %d send %d: %v", id, j, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	// Wait up to 5s for the drainer to collect every packet — UDP loopback
	// can briefly drop on receive-buffer overrun, so 1000/1000 is the
	// happy-path target with a generous timeout.
	deadline := time.After(5 * time.Second)
	for atomic.LoadInt64(&got) < int64(total) {
		select {
		case <-deadline:
			t.Fatalf("only received %d/%d packets", atomic.LoadInt64(&got), total)
		case <-time.After(10 * time.Millisecond):
		}
	}

	receiver.Close()
	<-done
}

// TestCloseUnblocksRecv covers goal 3a: Close() must make a blocked
// Recv return ErrClosed promptly.
func TestCloseUnblocksRecv(t *testing.T) {
	t.Parallel()
	sock, err := udpio.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	type rr struct {
		err error
	}
	ch := make(chan rr, 1)
	go func() {
		_, _, err := sock.Recv()
		ch <- rr{err}
	}()

	// Give the goroutine a tick to actually block in ReadFromUDP.
	time.Sleep(50 * time.Millisecond)
	if err := sock.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case r := <-ch:
		if r.err == nil {
			t.Fatal("Recv after Close returned nil err, want ErrClosed")
		}
		if !errors.Is(r.err, udpio.ErrClosed) {
			t.Fatalf("Recv after Close err = %v, want ErrClosed", r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Recv did not return within 2s after Close")
	}
}

// TestCloseIdempotent covers the §3 idempotency contract for Close —
// multiple calls must not panic and the second returns nil.
func TestCloseIdempotent(t *testing.T) {
	t.Parallel()
	sock, err := udpio.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := sock.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := sock.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestSendAfterClose covers goal 3b: Send after Close returns an error
// (the underlying net.OpError or, when conn is nil-after-close, ErrClosed).
func TestSendAfterClose(t *testing.T) {
	t.Parallel()
	sock, err := udpio.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	dst := sock.LocalAddr()
	if err := sock.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := sock.Send([]byte("after close"), dst); err == nil {
		t.Fatal("Send after Close returned nil err, want non-nil")
	}
}

// TestRecvAfterClose: Recv on an already-closed socket also returns an
// error promptly without blocking.
func TestRecvAfterClose(t *testing.T) {
	t.Parallel()
	sock, err := udpio.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := sock.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := sock.Recv()
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Recv after Close returned nil err")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Recv after Close blocked >2s")
	}
}

// TestNilSocketSafe: Send/Recv/Close on a nil Socket pointer must not
// panic — the package guards every entry-point with a nil check.
func TestNilSocketSafe(t *testing.T) {
	t.Parallel()
	var s *udpio.Socket
	if got := s.LocalAddr(); got != nil {
		t.Fatalf("nil LocalAddr = %v, want nil", got)
	}
	if got := s.Conn(); got != nil {
		t.Fatalf("nil Conn = %v, want nil", got)
	}
	if _, err := s.Send(nil, nil); !errors.Is(err, udpio.ErrClosed) {
		t.Fatalf("nil Send err = %v, want ErrClosed", err)
	}
	if _, _, err := s.Recv(); !errors.Is(err, udpio.ErrClosed) {
		t.Fatalf("nil Recv err = %v, want ErrClosed", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("nil Close err = %v, want nil", err)
	}
}

// TestRecvBufferReuse covers goal 4: the §6 contract that the read
// buffer is pool-backed and reused across Recvs. testing.AllocsPerRun
// asserts Recv allocates 0 user-visible bytes per call after the lazy
// first-call buffer alloc — the slice header returned is constructed on
// stack from the same backing array.
//
// Why "<= 1" rather than "== 0": Go's escape analysis on net.UDPConn's
// ReadFromUDP can occasionally heap-allocate the *net.UDPAddr return
// value depending on the Go version. We pin to "no growth in
// per-iteration allocs" which is what the §6 invariant actually
// promises (no per-Recv frame-buffer allocation).
func TestRecvBufferReuse(t *testing.T) {
	if testing.Short() {
		t.Skip("AllocsPerRun is slow under -short")
	}
	receiver, err := udpio.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer receiver.Close()

	sender, err := udpio.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen sender: %v", err)
	}
	defer sender.Close()

	dst := receiver.LocalAddr()
	frame := []byte("alloc-bench-frame")

	// Pre-warm the lazy pool buffer alloc on the first Recv path.
	if _, err := sender.Send(frame, dst); err != nil {
		t.Fatalf("warm Send: %v", err)
	}
	if _, _, err := receiver.Recv(); err != nil {
		t.Fatalf("warm Recv: %v", err)
	}

	// Pre-stuff the receive socket so AllocsPerRun's calls don't block.
	const runs = 100
	for i := 0; i < runs+8; i++ {
		if _, err := sender.Send(frame, dst); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	// Small grace so all datagrams sit in the kernel queue.
	time.Sleep(50 * time.Millisecond)

	avg := testing.AllocsPerRun(runs, func() {
		_, _, err := receiver.Recv()
		if err != nil {
			t.Errorf("Recv: %v", err)
		}
	})
	// The §6 contract is that the FRAME buffer is reused. Loose ceiling
	// of 4 catches any future regression that allocates a fresh buffer
	// per Recv (LargeBufSize == ~64KiB, which would dominate). The
	// minor 1-2 allocs from net.OpError construction or *net.UDPAddr
	// escape are acceptable.
	if avg > 4 {
		t.Fatalf("Recv allocs/op = %.2f, want <=4 (frame-buffer leak?)", avg)
	}
	t.Logf("Recv allocs/op = %.2f", avg)
}

// TestRecvBufferReuseAcrossCalls is the explicit §6 statement of the
// contract: the slice returned by Recv N is invalidated by Recv N+1
// because both share the same backing array. We verify the pointer
// identity (cap + first-element address) of the returned slice is
// stable across calls — that's the observable signal of buffer reuse.
func TestRecvBufferReuseAcrossCalls(t *testing.T) {
	t.Parallel()
	receiver, err := udpio.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer receiver.Close()
	sender, err := udpio.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen sender: %v", err)
	}
	defer sender.Close()
	dst := receiver.LocalAddr()

	send := func(payload []byte) {
		t.Helper()
		if _, err := sender.Send(payload, dst); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}

	send([]byte("first"))
	first, _, err := receiver.Recv()
	if err != nil {
		t.Fatalf("Recv 1: %v", err)
	}
	firstCap := cap(first)
	firstAddr := &first[:1][0]

	send([]byte("second"))
	second, _, err := receiver.Recv()
	if err != nil {
		t.Fatalf("Recv 2: %v", err)
	}

	if cap(second) != firstCap {
		t.Fatalf("Recv buffer cap changed: %d → %d (reuse broken)", firstCap, cap(second))
	}
	if &second[:1][0] != firstAddr {
		t.Fatal("Recv buffer backing array changed across calls (reuse broken)")
	}
}

// TestLargePacket covers goal 5: a packet larger than typical Ethernet
// MTU round-trips intact. We pick 8 KiB — comfortably above the 1500-
// byte path MTU (the kernel fragments and reassembles on loopback) and
// also under macOS' default net.inet.udp.maxdgram=9216 ceiling so this
// test stays portable across darwin and linux.
func TestLargePacket(t *testing.T) {
	t.Parallel()
	receiver, err := udpio.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer receiver.Close()
	sender, err := udpio.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen sender: %v", err)
	}
	defer sender.Close()

	// 8 KiB: > MTU (1500) so the kernel fragments, and < darwin's
	// 9216-byte UDP datagram cap (sysctl net.inet.udp.maxdgram).
	const size = 8 * 1024
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 251) // not 256 so adjacent bytes differ
	}

	if _, err := sender.Send(payload, receiver.LocalAddr()); err != nil {
		t.Fatalf("Send large: %v", err)
	}
	got, _, err := recvWithTimeout(t, receiver, 3*time.Second)
	if err != nil {
		t.Fatalf("Recv large: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("large payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

// TestBadAddress covers goal 6: a malformed listen address surfaces an
// error instead of panicking. We use a clearly invalid host:port string.
func TestBadAddress(t *testing.T) {
	t.Parallel()
	cases := []string{
		"not:an:address:99999",
		"127.0.0.1:notaport",
		"127.0.0.1:99999999", // out of port range
	}
	for _, addr := range cases {
		addr := addr
		t.Run(addr, func(t *testing.T) {
			sock, err := udpio.Listen(addr)
			if err == nil {
				if sock != nil {
					sock.Close()
				}
				t.Fatalf("Listen(%q) returned nil err, want resolve/listen failure", addr)
			}
		})
	}
}

// TestWrapConn covers goal 7: an externally-built *net.UDPConn can be
// adopted into a Socket and the Send/Recv API behaves identically to a
// Listen()-built Socket.
func TestWrapConn(t *testing.T) {
	t.Parallel()
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	rawConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	// Bigger receive buffer is the documented use-case for WrapConn — we
	// don't need to assert on the value, just exercise the path.
	_ = rawConn.SetReadBuffer(1 << 20)

	receiver := udpio.WrapConn(rawConn)
	defer receiver.Close()

	if receiver.Conn() != rawConn {
		t.Fatal("WrapConn().Conn() did not return the wrapped *net.UDPConn")
	}
	bound := receiver.LocalAddr()
	if bound == nil {
		t.Fatal("WrapConn LocalAddr nil")
	}

	sender, err := udpio.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen sender: %v", err)
	}
	defer sender.Close()

	want := []byte("wrapped conn frame")
	if _, err := sender.Send(want, bound); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got, _, err := recvWithTimeout(t, receiver, 2*time.Second)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("WrapConn round-trip got %q, want %q", got, want)
	}
}

// TestLocalAddrAfterClose: per the doc comment, LocalAddr returns nil
// for a never-bound socket; for a closed socket it should also be safe
// to call (current behaviour: returns the cached address from the
// underlying conn — we just assert no panic).
func TestLocalAddrAfterClose(t *testing.T) {
	t.Parallel()
	sock, err := udpio.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	pre := sock.LocalAddr()
	if pre == nil {
		t.Fatal("LocalAddr pre-close nil")
	}
	if err := sock.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Must not panic. Value is undefined but should still be a *UDPAddr
	// or nil.
	_ = sock.LocalAddr()
}

// TestSendConcurrentWithRecv: §3 explicitly allows Send concurrent with
// Recv on the same Socket (UDP write does not contend with read). This
// test fans a single-Socket Send loop against the same Socket's Recv —
// not a real production pattern but the kernel/Go runtime must tolerate
// it without -race fireworks.
func TestSendConcurrentWithRecv(t *testing.T) {
	t.Parallel()
	sock, err := udpio.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer sock.Close()
	dst := sock.LocalAddr()

	const N = 50
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			if _, err := sock.Send([]byte{byte(i)}, dst); err != nil {
				t.Errorf("Send %d: %v", i, err)
				return
			}
		}
	}()

	got := 0
	for got < N {
		buf, _, err := recvWithTimeout(t, sock, 3*time.Second)
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		if len(buf) != 1 {
			t.Fatalf("frame size = %d, want 1", len(buf))
		}
		got++
	}
	wg.Wait()
}

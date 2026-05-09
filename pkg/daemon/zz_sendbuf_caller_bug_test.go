// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestConnAdapterWriteSurfacesErrSendBufFullToCaller reproduces the
// "ErrSendBufFull leaks through net.Conn.Write" bug.
//
// Symptom: iter 4 added a 32 KB cap on per-Connection NagleBuf with
// ErrSendBufFull returned to the caller of daemon.SendData. The
// per-port services use a `connAdapter` to expose Connections as
// net.Conn (so http.ServeConn, io.Copy, gRPC etc. can run unchanged
// over Pilot tunnels). connAdapter.Write currently propagates
// ErrSendBufFull directly:
//
//	func (a *connAdapter) Write(p []byte) (int, error) {
//	    if err := a.daemon.SendData(a.conn, p); err != nil {
//	        return 0, err
//	    }
//	    return len(p), nil
//	}
//
// This violates the implicit net.Conn contract. Standard-library
// callers (net/http, io.Copy, bufio.Writer) treat ANY non-nil Write
// error as "connection broken" and abort. A slow peer with a
// momentarily full NagleBuf — a transient, recoverable condition —
// silently breaks every HTTP/gRPC/stream consumer running on top of
// the daemon, manifesting as "connection reset" or "EOF" errors at
// the application boundary.
//
// Real-world impact: webhook senders, port-forwarded HTTP servers,
// gateway-mode TCP proxying, the dataexchange service all break the
// moment a peer's cwnd fills (which iter 4's cap is *meant* to handle
// gracefully — bound memory without dropping data).
//
// What v1.9.1's fix should change: connAdapter.Write must treat
// ErrSendBufFull as a transient back-pressure signal, not a fatal
// error. The simplest correct behavior is bounded-time retry:
//   - Sleep a short interval (e.g. 5 ms with capped exponential)
//   - Re-attempt SendData
//   - Surface a non-transient error only if the connection is
//     actually broken (not Established, peer closed, etc.) OR if a
//     deadline elapses
//
// This keeps net.Conn semantics intact: callers see Write block
// briefly under back-pressure (just like a real TCP socket whose
// kernel send buffer is full), then succeed.
//
// FIXED (v1.9.1): connAdapter.Write now blocks-and-retries on
// ErrSendBufFull with capped exponential backoff (5ms-100ms),
// surfacing the error only if (a) the connection moves out of
// Established or (b) connAdapterWriteDeadline (30s) elapses. Net
// effect: net.Conn callers see Write block briefly under back-
// pressure, then succeed — exactly like a real TCP socket whose
// kernel send buffer is full.
func TestConnAdapterWriteSurfacesErrSendBufFullToCaller(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peerNode uint32 = 0xCAFEBABE
	peerConn := addPeerOnDaemon(t, d, peerNode)
	t.Cleanup(func() { peerConn.Close() })

	d.setNodeID_testhelper(0x33330000)

	conn := d.ports.NewConnection(40001, protocol.Addr{Network: 0, Node: peerNode}, 80)
	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x33330000}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: peerNode}
	conn.RemotePort = 80
	conn.State = StateEstablished
	conn.PeerRecvWin = 1 << 20
	conn.Mu.Unlock()

	// Fill NagleBuf right at the cap so the next byte tips it over.
	conn.NagleMu.Lock()
	conn.NagleBuf = make([]byte, MaxNagleBuf)
	conn.NagleMu.Unlock()

	a := newConnAdapter(d, conn)

	// FIXED: Write blocks while NagleBuf is full. After we drain the
	// buffer in a side goroutine (simulating the daemon's flush path
	// catching up on slow peer), Write completes successfully.
	done := make(chan struct{})
	var n int
	var err error
	go func() {
		n, err = a.Write([]byte("ABC"))
		close(done)
	}()

	// Confirm Write is blocking, not returning instantly.
	select {
	case <-done:
		t.Fatalf("Write returned before NagleBuf was drained; n=%d err=%v", n, err)
	case <-time.After(20 * time.Millisecond):
		// Expected: Write is sleeping in the backoff loop.
	}

	// Drain NagleBuf. The next SendData attempt inside Write's retry
	// loop now sees room and succeeds.
	conn.NagleMu.Lock()
	conn.NagleBuf = nil
	conn.NagleMu.Unlock()

	select {
	case <-done:
		if err != nil {
			t.Errorf("expected Write to succeed after NagleBuf drained; got err=%v", err)
		}
		if n != 3 {
			t.Errorf("expected n=3 (full payload written); got %d", n)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Write did not return within 500ms after NagleBuf drained")
	}
}

// TestConnAdapterWriteSurfacesNonBufferErrors pins the inverse: any
// error from SendData that ISN'T ErrSendBufFull (e.g. "connection not
// established", a real broken-tunnel error) must propagate immediately
// — the retry loop is for transient back-pressure only.
func TestConnAdapterWriteSurfacesNonBufferErrors(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peerNode uint32 = 0xCAFEFEED
	peerConn := addPeerOnDaemon(t, d, peerNode)
	t.Cleanup(func() { peerConn.Close() })

	d.setNodeID_testhelper(0x33330001)

	conn := d.ports.NewConnection(40002, protocol.Addr{Network: 0, Node: peerNode}, 80)
	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x33330001}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: peerNode}
	conn.RemotePort = 80
	conn.State = StateClosed // not Established → SendData returns "connection not established"
	conn.Mu.Unlock()

	a := newConnAdapter(d, conn)

	start := time.Now()
	n, err := a.Write([]byte("ABC"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected non-nil error from Write on closed conn; got n=%d", n)
	}
	if errors.Is(err, ErrSendBufFull) {
		t.Errorf("non-buffer error should propagate; got ErrSendBufFull")
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("non-buffer errors must surface immediately; took %v", elapsed)
	}
}

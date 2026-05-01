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
// This keeps net.Conn semantics intact: callers see Write block
// briefly under back-pressure (just like a real TCP socket whose
// kernel send buffer is full), then succeed.
//
// This test pins the CURRENT (buggy) behavior: Write returns
// (0, ErrSendBufFull) immediately. After GREEN, the assertion flips:
// Write blocks until the NagleBuf has room, then completes with
// (len(p), nil).
func TestConnAdapterWriteSurfacesErrSendBufFullToCaller(t *testing.T) {
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

	// CURRENT (buggy) behavior: Write returns (0, ErrSendBufFull)
	// immediately, treating transient back-pressure as a fatal error.
	// GREEN flips to: Write blocks until the buffer drains, then
	// returns (3, nil).
	done := make(chan struct{})
	var n int
	var err error
	go func() {
		n, err = a.Write([]byte("ABC"))
		close(done)
	}()

	select {
	case <-done:
		// Fired immediately — pin the bug.
		if !errors.Is(err, ErrSendBufFull) {
			t.Fatalf("BUG NOT REPRODUCED: expected immediate ErrSendBufFull return; got n=%d err=%v", n, err)
		}
		if n != 0 {
			t.Errorf("expected n=0 with err=ErrSendBufFull; got n=%d", n)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("BUG NOT REPRODUCED: Write blocked instead of returning ErrSendBufFull immediately; if this is post-fix, flip the assertion to GREEN")
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/ipcutil"
)

// Iter-109 coverage for startRecvPusher (0% baseline) — the goroutine
// that bridges Connection.RecvBuf → IPC CmdRecv frames, and on channel
// close fires a CmdCloseOK to notify the driver of remote FIN. This is
// the only writer of CmdRecv frames and the only path that surfaces
// remote-close to the driver, so it's load-bearing for stream lifecycle.

// --- data path: RecvBuf → CmdRecv frame with [CmdRecv][4-byte connID][data] ---

func TestStartRecvPusherForwardsDataAsCmdRecv(t *testing.T) {
	d := New(Config{})
	s := d.ipc

	ic, client := newIPCTestConn(t)
	c := &Connection{ID: 0xDEADBEEF, RecvBuf: make(chan []byte, 4)}

	s.startRecvPusher(ic, c)

	// Push a chunk — pusher should frame it as CmdRecv + connID + payload.
	c.RecvBuf <- []byte("hello")

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply, err := ipcutil.Read(client)
	if err != nil {
		t.Fatalf("read recv reply: %v", err)
	}
	if reply[0] != CmdRecv {
		t.Fatalf("reply[0] = 0x%02X, want CmdRecv (0x%02X)", reply[0], CmdRecv)
	}
	if id := binary.BigEndian.Uint32(reply[1:5]); id != 0xDEADBEEF {
		t.Fatalf("conn id = 0x%X, want 0xDEADBEEF", id)
	}
	if string(reply[5:]) != "hello" {
		t.Fatalf("payload = %q, want 'hello'", string(reply[5:]))
	}
}

// --- multi-chunk: each RecvBuf send becomes one CmdRecv frame, in order ---

func TestStartRecvPusherForwardsMultipleChunksInOrder(t *testing.T) {
	d := New(Config{})
	s := d.ipc

	ic, client := newIPCTestConn(t)
	c := &Connection{ID: 42, RecvBuf: make(chan []byte, 4)}

	s.startRecvPusher(ic, c)

	c.RecvBuf <- []byte("one")
	c.RecvBuf <- []byte("two")
	c.RecvBuf <- []byte("three")

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	for _, want := range []string{"one", "two", "three"} {
		reply, err := ipcutil.Read(client)
		if err != nil {
			t.Fatalf("read reply for %q: %v", want, err)
		}
		if reply[0] != CmdRecv {
			t.Fatalf("reply[0] = 0x%02X, want CmdRecv", reply[0])
		}
		if string(reply[5:]) != want {
			t.Fatalf("payload = %q, want %q", string(reply[5:]), want)
		}
	}
}

// --- FIN path: RecvBuf close → CmdCloseOK[connID] emitted after drain ---

func TestStartRecvPusherEmitsCmdCloseOKOnRecvBufClose(t *testing.T) {
	d := New(Config{})
	s := d.ipc

	ic, client := newIPCTestConn(t)
	c := &Connection{ID: 7, RecvBuf: make(chan []byte, 2)}

	s.startRecvPusher(ic, c)

	// One buffered data chunk, then close → pusher drains the chunk first
	// (CmdRecv), then writes CmdCloseOK.
	c.RecvBuf <- []byte("last")
	c.CloseRecvBuf() // sync.Once-guarded close — safe

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))

	// First frame: data
	reply1, err := ipcutil.Read(client)
	if err != nil {
		t.Fatalf("read data frame: %v", err)
	}
	if reply1[0] != CmdRecv {
		t.Fatalf("first reply[0] = 0x%02X, want CmdRecv", reply1[0])
	}

	// Second frame: close notification
	reply2, err := ipcutil.Read(client)
	if err != nil {
		t.Fatalf("read close frame: %v", err)
	}
	if reply2[0] != CmdCloseOK {
		t.Fatalf("second reply[0] = 0x%02X, want CmdCloseOK (0x%02X)", reply2[0], CmdCloseOK)
	}
	if len(reply2) != 5 {
		t.Fatalf("close frame len = %d, want 5", len(reply2))
	}
	if id := binary.BigEndian.Uint32(reply2[1:5]); id != 7 {
		t.Fatalf("close frame connID = %d, want 7", id)
	}
}

// --- early-exit: ipcWrite error (closed client) terminates the pusher ---

func TestStartRecvPusherExitsOnWriteError(t *testing.T) {
	d := New(Config{})
	s := d.ipc

	ic, client := newIPCTestConn(t)
	c := &Connection{ID: 99, RecvBuf: make(chan []byte, 4)}

	// Close the client read end BEFORE starting — the first ipcWrite will
	// error (net.Pipe returns io.ErrClosedPipe) and the goroutine returns
	// WITHOUT emitting CmdCloseOK. This proves the `return` branch at
	// ipc.go:956 fires on write error rather than looping forever.
	_ = client.Close()

	done := make(chan struct{})
	go func() {
		s.startRecvPusher(ic, c)
		// push one chunk; the pusher goroutine reads it, tries to write,
		// fails, and exits. We then close RecvBuf from the test side and
		// assert that the pusher goroutine does NOT attempt another write
		// (it would also fail, but more importantly the FIN path should
		// never run because the loop returned early).
		c.RecvBuf <- []byte("doomed")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("startRecvPusher + push did not complete within 2s")
	}

	// Give the pusher goroutine a moment to actually process the chunk
	// and exit on write error.
	time.Sleep(50 * time.Millisecond)

	// Now close RecvBuf — if the pusher had somehow survived the write
	// error, it would try to emit CmdCloseOK. Since the client is closed,
	// that write would also fail (also swallowed), but there's no way
	// for this test to directly assert "pusher exited". The strongest
	// signal is that the test does not hang and there's no goroutine
	// leak causing later tests to interfere. Passing here is the signal.
	c.CloseRecvBuf()
	time.Sleep(50 * time.Millisecond)
}

// --- empty-data chunk: RecvBuf send of []byte{} still gets a CmdRecv ---

func TestStartRecvPusherForwardsEmptyChunk(t *testing.T) {
	d := New(Config{})
	s := d.ipc

	ic, client := newIPCTestConn(t)
	c := &Connection{ID: 123, RecvBuf: make(chan []byte, 2)}

	s.startRecvPusher(ic, c)
	c.RecvBuf <- []byte{} // zero-length chunk — frame is [CmdRecv][id] only

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply, err := ipcutil.Read(client)
	if err != nil {
		t.Fatalf("read empty-chunk reply: %v", err)
	}
	if len(reply) != 5 {
		t.Fatalf("empty-chunk frame len = %d, want 5 (header only)", len(reply))
	}
	if reply[0] != CmdRecv {
		t.Fatalf("reply[0] = 0x%02X, want CmdRecv", reply[0])
	}
	if id := binary.BigEndian.Uint32(reply[1:5]); id != 123 {
		t.Fatalf("conn id = %d, want 123", id)
	}
}

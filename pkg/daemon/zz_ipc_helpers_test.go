// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/ipcutil"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// newPipePair returns a connected pair. The server side is wrapped in ipcConn
// (the thing the daemon would write to). The client side is a raw net.Conn
// the test reads from.
func newPipePair(t *testing.T) (*ipcConn, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	ic := newIPCConn(server)
	t.Cleanup(func() {
		ic.Close()
		client.Close()
	})
	return ic, client
}

func TestIPCWriteRoundTrip(t *testing.T) {
	t.Parallel()
	ic, client := newPipePair(t)

	got := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		msg, err := ipcutil.Read(client)
		if err != nil {
			errCh <- err
			return
		}
		got <- msg
	}()

	payload := []byte{0x01, 0x02, 0x03}
	if err := ic.ipcWrite(payload); err != nil {
		t.Fatalf("ipcWrite: %v", err)
	}

	select {
	case msg := <-got:
		if string(msg) != string(payload) {
			t.Fatalf("got %v, want %v", msg, payload)
		}
	case err := <-errCh:
		t.Fatalf("read: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ipc message")
	}
}

func TestIPCWriteConcurrentSerializesFrames(t *testing.T) {
	t.Parallel()
	ic, client := newPipePair(t)

	// Two writers racing. Each frame is tagged by first byte so we can verify
	// neither one interleaved with the other (the framing would be ruined by
	// any interleave).
	const n = 20
	firstFrame := make([]byte, 64)
	secondFrame := make([]byte, 64)
	for i := range firstFrame {
		firstFrame[i] = 0xAA
	}
	for i := range secondFrame {
		secondFrame[i] = 0xBB
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			if err := ic.ipcWrite(firstFrame); err != nil {
				t.Errorf("ipcWrite A: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			if err := ic.ipcWrite(secondFrame); err != nil {
				t.Errorf("ipcWrite B: %v", err)
				return
			}
		}
	}()

	// Drain frames as writers send.
	drain := make(chan error, 1)
	go func() {
		for i := 0; i < 2*n; i++ {
			msg, err := ipcutil.Read(client)
			if err != nil {
				drain <- err
				return
			}
			if len(msg) != 64 {
				drain <- nil
				return
			}
			// Every byte must be the same (no interleave).
			first := msg[0]
			for _, b := range msg {
				if b != first {
					drain <- nil
					return
				}
			}
		}
		drain <- nil
	}()

	wg.Wait()
	select {
	case err := <-drain:
		if err != nil {
			t.Fatalf("drain: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("drain timed out")
	}
}

func TestTrackPortAppends(t *testing.T) {
	t.Parallel()
	ic := &ipcConn{}
	ic.trackPort(10)
	ic.trackPort(20)
	ic.trackPort(10) // duplicates are allowed — it's a tracking list
	if len(ic.ports) != 3 {
		t.Fatalf("ports = %v, want 3 entries", ic.ports)
	}
	if ic.ports[0] != 10 || ic.ports[1] != 20 || ic.ports[2] != 10 {
		t.Fatalf("unexpected order: %v", ic.ports)
	}
}

func TestTrackConnAppends(t *testing.T) {
	t.Parallel()
	ic := &ipcConn{}
	ic.trackConn(100)
	ic.trackConn(200)
	if len(ic.conns) != 2 {
		t.Fatalf("conns = %v, want 2 entries", ic.conns)
	}
	if ic.conns[0] != 100 || ic.conns[1] != 200 {
		t.Fatalf("unexpected order: %v", ic.conns)
	}
}

func TestTrackPortConnConcurrent(t *testing.T) {
	t.Parallel()
	ic := &ipcConn{}
	const n = 500
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			ic.trackPort(uint16(i))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			ic.trackConn(uint32(i))
		}
	}()
	wg.Wait()
	if len(ic.ports) != n {
		t.Fatalf("ports len = %d, want %d", len(ic.ports), n)
	}
	if len(ic.conns) != n {
		t.Fatalf("conns len = %d, want %d", len(ic.conns), n)
	}
}

func TestNewIPCServerInitializes(t *testing.T) {
	t.Parallel()
	d := &Daemon{}
	s := NewIPCServer("/tmp/does-not-need-to-exist.sock", d)
	if s.socketPath != "/tmp/does-not-need-to-exist.sock" {
		t.Fatalf("socketPath = %q", s.socketPath)
	}
	if s.daemon != d {
		t.Fatal("daemon pointer not set")
	}
	if s.clients == nil {
		t.Fatal("clients map not initialized")
	}
	if s.listener != nil {
		t.Fatal("listener should be nil before Start()")
	}
}

func TestIPCServerCloseNilListenerNoPanic(t *testing.T) {
	t.Parallel()
	d := &Daemon{}
	s := NewIPCServer("/tmp/does-not-need-to-exist.sock", d)
	// Close with nil listener and no clients — must not panic, must be safe.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestIPCServerCloseClosesClients(t *testing.T) {
	t.Parallel()
	d := &Daemon{}
	s := NewIPCServer("/tmp/x.sock", d)

	client, server := net.Pipe()
	t.Cleanup(func() { client.Close() })
	ic := newIPCConn(server)
	s.clients[ic] = true

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The server side should have been closed; writing must fail.
	_ = server.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := server.Write([]byte("x")); err == nil {
		t.Fatal("expected write on closed server side to fail")
	}
}

func TestSendErrorFrame(t *testing.T) {
	t.Parallel()
	ic, client := newPipePair(t)
	s := &IPCServer{clients: map[*ipcConn]bool{}}

	got := make(chan []byte, 1)
	go func() {
		msg, err := ipcutil.Read(client)
		if err != nil {
			return
		}
		got <- msg
	}()

	s.sendError(ic, 0, "boom")

	select {
	case msg := <-got:
		if len(msg) < IPCEnvelopeHeaderSize+2 {
			t.Fatalf("frame too short: %v", msg)
		}
		if msg[0] != CmdError {
			t.Fatalf("cmd = 0x%02X, want CmdError (0x%02X)", msg[0], CmdError)
		}
		payload := msg[IPCEnvelopeHeaderSize:]
		if code := binary.BigEndian.Uint16(payload[0:2]); code != 1 {
			t.Fatalf("code = %d, want 1", code)
		}
		if string(payload[2:]) != "boom" {
			t.Fatalf("body = %q, want 'boom'", string(payload[2:]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no frame received")
	}
}

func TestIPCWriteHandshakeOK(t *testing.T) {
	t.Parallel()
	ic, client := newPipePair(t)
	s := &IPCServer{}

	got := make(chan []byte, 1)
	go func() {
		msg, _ := ipcutil.Read(client)
		got <- msg
	}()

	s.ipcWriteHandshakeOK(ic, 0, []byte(`{"ok":true}`))

	select {
	case msg := <-got:
		if msg[0] != CmdHandshakeOK {
			t.Fatalf("cmd = 0x%02X, want CmdHandshakeOK", msg[0])
		}
		if string(msg[IPCEnvelopeHeaderSize:]) != `{"ok":true}` {
			t.Fatalf("body = %q", string(msg[IPCEnvelopeHeaderSize:]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no frame")
	}
}

func TestIPCWriteNetworkOK(t *testing.T) {
	t.Parallel()
	ic, client := newPipePair(t)
	s := &IPCServer{}

	got := make(chan []byte, 1)
	go func() {
		msg, _ := ipcutil.Read(client)
		got <- msg
	}()

	s.ipcWriteNetworkOK(ic, 0, []byte("net"))

	select {
	case msg := <-got:
		if msg[0] != CmdNetworkOK {
			t.Fatalf("cmd = 0x%02X, want CmdNetworkOK", msg[0])
		}
		if string(msg[IPCEnvelopeHeaderSize:]) != "net" {
			t.Fatalf("body = %q", string(msg[IPCEnvelopeHeaderSize:]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no frame")
	}
}

func TestIPCWriteManagedOK(t *testing.T) {
	t.Parallel()
	ic, client := newPipePair(t)
	s := &IPCServer{}

	got := make(chan []byte, 1)
	go func() {
		msg, _ := ipcutil.Read(client)
		got <- msg
	}()

	s.ipcWriteManagedOK(ic, 0, []byte("m"))

	select {
	case msg := <-got:
		if msg[0] != CmdManagedOK {
			t.Fatalf("cmd = 0x%02X, want CmdManagedOK", msg[0])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no frame")
	}
}

func TestDeliverDatagramFansOutToAllClients(t *testing.T) {
	t.Parallel()
	d := &Daemon{}
	s := NewIPCServer("/tmp/x.sock", d)

	const n = 3
	readers := make([]net.Conn, n)
	for i := 0; i < n; i++ {
		ic, client := newIPCTestConn(t)
		s.mu.Lock()
		s.clients[ic] = true
		s.mu.Unlock()
		readers[i] = client
	}

	src := protocol.Addr{Network: 1, Node: 7}
	payload := []byte("hello")

	// Reads must happen concurrently with DeliverDatagram since net.Pipe is sync.
	type readResult struct {
		msg []byte
		err error
	}
	resCh := make(chan readResult, n)
	for _, r := range readers {
		r := r
		go func() {
			_ = r.SetReadDeadline(time.Now().Add(2 * time.Second))
			msg, err := ipcutil.Read(r)
			resCh <- readResult{msg, err}
		}()
	}

	s.DeliverDatagram(src, 7, 8, payload)

	for i := 0; i < n; i++ {
		select {
		case res := <-resCh:
			if res.err != nil {
				t.Fatalf("client %d read: %v", i, res.err)
			}
			if res.msg[0] != CmdRecvFrom {
				t.Fatalf("client %d cmd = 0x%02X, want CmdRecvFrom", i, res.msg[0])
			}
			// Wire: [cmd(1)][reqID(8)][srcAddr(6)][srcPort(2)][dstPort(2)][data...]
			tail := res.msg[IPCEnvelopeHeaderSize+protocol.AddrSize+2+2:]
			if string(tail) != "hello" {
				t.Fatalf("client %d payload %q, want 'hello'", i, string(tail))
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("client %d timed out", i)
		}
	}
}

func TestDeliverDatagramNoClientsNoOp(t *testing.T) {
	t.Parallel()
	d := &Daemon{}
	s := NewIPCServer("/tmp/x.sock", d)
	// Must not panic and must not block even with no connected clients.
	s.DeliverDatagram(protocol.Addr{Network: 1, Node: 2}, 3, 4, []byte("x"))
}

func TestFindManagedEngineMissing(t *testing.T) {
	t.Parallel()
	d := &Daemon{managed: map[uint16]*ManagedEngine{}}
	s := &IPCServer{daemon: d}
	if me := s.findManagedEngine(5); me != nil {
		t.Fatalf("expected nil for missing netID, got %v", me)
	}
	if me := s.findManagedEngine(0); me != nil {
		t.Fatalf("expected nil when map empty and netID=0, got %v", me)
	}
}

func TestFindManagedEnginePresent(t *testing.T) {
	t.Parallel()
	eng := &ManagedEngine{}
	d := &Daemon{managed: map[uint16]*ManagedEngine{7: eng}}
	s := &IPCServer{daemon: d}

	if got := s.findManagedEngine(7); got != eng {
		t.Fatalf("netID=7 lookup returned %v, want eng", got)
	}
	// netID=0 returns first (only) engine.
	if got := s.findManagedEngine(0); got != eng {
		t.Fatalf("netID=0 with one engine returned %v, want eng", got)
	}
	// Unmatched netID still returns nil.
	if got := s.findManagedEngine(8); got != nil {
		t.Fatalf("netID=8 returned %v, want nil", got)
	}
}


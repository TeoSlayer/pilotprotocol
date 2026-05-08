// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/ipcutil"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// Iter-110 coverage for the remaining gaps in ipc.go handleBind (53.6%),
// handleSend (81.8%), DeliverDatagram (78.6%), and the post-bind accept
// goroutine at ipc.go:275-292. The accept goroutine is the path that
// surfaces incoming connections from the listener to the driver as
// CmdAccept frames and then transitions the Connection into the
// recv-push cycle — load-bearing for any inbound stream.

// --- handleBind: feed an accepted Connection into the listener's AcceptCh,
//     expect CmdAccept with per-port + connID + remote addr + remote port. ---

func TestHandleBindAcceptGoroutineEmitsCmdAccept(t *testing.T) {
	d := New(Config{})
	s := d.ipc

	ic, client := newIPCTestConn(t)

	// First read must drain CmdBindOK before the goroutine picks up the accept.
	done := make(chan struct{})
	go func() {
		s.handleBind(ic, 0, []byte{0x08, 0x00}) // port 2048
		close(done)
	}()

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	bindReply, err := ipcutil.Read(client)
	if err != nil {
		t.Fatalf("read bind-ok: %v", err)
	}
	// Wire format (issue #99): [cmd(1)][reqID(8)][body...]. Strip the
	// reqID header so the existing offset assertions stay readable.
	if len(bindReply) < IPCEnvelopeHeaderSize {
		t.Fatalf("bind reply too short: %d", len(bindReply))
	}
	bindBody := bindReply[IPCEnvelopeHeaderSize:]
	if bindReply[0] != CmdBindOK {
		t.Fatalf("bind reply[0] = 0x%02X, want CmdBindOK", bindReply[0])
	}
	_ = bindBody // body is just [port]; the test below only cares about the cmd byte.
	<-done

	// Feed an accepted Connection into the bound listener's AcceptCh.
	ln := d.ports.GetListener(2048)
	if ln == nil {
		t.Fatal("listener not registered for port 2048")
	}
	accepted := &Connection{
		ID:         0xABCD,
		RemoteAddr: protocol.Addr{Network: 1, Node: 0x10203040},
		RemotePort: 5555,
		RecvBuf:    make(chan []byte, 1),
	}
	ln.AcceptCh <- accepted

	// Expect CmdAccept frame: [CmdAccept(1)][reqID(8)=0][port(2)][connID(4)][addr(6)][remotePort(2)]
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	acceptReply, err := ipcutil.Read(client)
	if err != nil {
		t.Fatalf("read accept frame: %v", err)
	}
	want := IPCEnvelopeHeaderSize + 2 + 4 + protocol.AddrSize + 2
	if len(acceptReply) != want {
		t.Fatalf("accept frame len = %d, want %d", len(acceptReply), want)
	}
	if acceptReply[0] != CmdAccept {
		t.Fatalf("accept reply[0] = 0x%02X, want CmdAccept (0x%02X)", acceptReply[0], CmdAccept)
	}
	body := acceptReply[IPCEnvelopeHeaderSize:]
	if p := binary.BigEndian.Uint16(body[0:2]); p != 2048 {
		t.Fatalf("accept.port = %d, want 2048", p)
	}
	if id := binary.BigEndian.Uint32(body[2:6]); id != 0xABCD {
		t.Fatalf("accept.connID = 0x%X, want 0xABCD", id)
	}
	gotAddr := protocol.UnmarshalAddr(body[6 : 6+protocol.AddrSize])
	if gotAddr.Network != 1 || gotAddr.Node != 0x10203040 {
		t.Fatalf("accept.addr = %+v, want {Network:1 Node:0x10203040}", gotAddr)
	}
	if rp := binary.BigEndian.Uint16(body[6+protocol.AddrSize:]); rp != 5555 {
		t.Fatalf("accept.remotePort = %d, want 5555", rp)
	}

	// Goroutine-tracking: the ipcConn should now track the accepted conn ID.
	ic.rmu.Lock()
	tracked := append([]uint32(nil), ic.conns...)
	ic.rmu.Unlock()
	found := false
	for _, id := range tracked {
		if id == 0xABCD {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("accepted connID 0xABCD not tracked; tracked=%v", tracked)
	}

	// Clean up the listener so startRecvPusher's drain loop can exit.
	d.ports.Unbind(2048)
}

// --- handleBind: Bind(port) error path (port already bound) emits CmdError ---

func TestHandleBindPortAlreadyBoundReturnsError(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	s := d.ipc

	// Pre-bind port 1500 so the second Bind fails.
	if _, err := d.ports.Bind(1500); err != nil {
		t.Fatalf("pre-bind: %v", err)
	}
	defer d.ports.Unbind(1500)

	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleBind(ic, 0, []byte{0x05, 0xDC}) // port 1500
	})
	assertErrorReply(t, reply, "already bound")
}

// --- handleSend: fire-and-forget — no reply on error ---

func TestHandleSendShortPayloadEmitsError(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	s := d.ipc

	ic, client := newIPCTestConn(t)
	done := make(chan struct{})
	go func() { s.handleSend(ic, 0, []byte{0x01, 0x02}); close(done) }()
	assertNoReply(t, client) // fire-and-forget: no reply on error
	<-done
}

func TestHandleSendUnknownConnIDEmitsError(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	s := d.ipc

	ic, client := newIPCTestConn(t)
	payload := []byte{0x00, 0x00, 0xFF, 0xFE, 'x'}
	done := make(chan struct{})
	go func() { s.handleSend(ic, 0, payload); close(done) }()
	assertNoReply(t, client) // fire-and-forget: no reply on error
	<-done
}

// --- handleClose: unknown connID still writes CmdCloseOK (no error path) ---

func TestHandleCloseUnknownConnIDStillWritesCloseOK(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	s := d.ipc

	ic, client := newIPCTestConn(t)
	// connID = 0xCAFEBABE — no such connection, but close is idempotent.
	payload := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	reply := runHandler(t, client, func() { s.handleClose(ic, 0, payload) })

	if reply[0] != CmdCloseOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdCloseOK", reply[0])
	}
	if id := binary.BigEndian.Uint32(reply[1:5]); id != 0xCAFEBABE {
		t.Fatalf("close.connID = 0x%X, want 0xCAFEBABE", id)
	}
}

// --- handleClose: short payload emits CmdError ---

func TestHandleCloseShortPayloadEmitsError(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	s := d.ipc

	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleClose(ic, 0, []byte{0x01}) // 1 byte < 4
	})
	assertErrorReply(t, reply, "close: missing conn_id")
}

// --- DeliverDatagram: with 0 clients, no writes happen and no panic ---

func TestDeliverDatagramWithNoClientsIsNoop(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	s := d.ipc

	// No clients registered. Should return cleanly without panicking.
	s.DeliverDatagram(protocol.Addr{Network: 1, Node: 0x11}, 100, 200, []byte("x"))
}

// --- DeliverDatagram: with one registered client, emits CmdRecvFrom frame ---

func TestDeliverDatagramWritesCmdRecvFromToClient(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	s := d.ipc

	ic, client := newIPCTestConn(t)
	// Register ic in the clients map — this is what acceptLoop does.
	s.mu.Lock()
	s.clients[ic] = true
	s.mu.Unlock()
	t.Cleanup(func() {
		s.mu.Lock()
		delete(s.clients, ic)
		s.mu.Unlock()
	})

	srcAddr := protocol.Addr{Network: 2, Node: 0x0A0B0C0D}
	payload := []byte("udp-data")

	done := make(chan struct{})
	go func() {
		s.DeliverDatagram(srcAddr, 443, 8080, payload)
		close(done)
	}()

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply, err := ipcutil.Read(client)
	if err != nil {
		t.Fatalf("read RecvFrom: %v", err)
	}
	<-done

	// Frame layout (issue #99 envelope): [CmdRecvFrom(1)][reqID(8)=0][addr(6)][srcPort(2)][dstPort(2)][data...]
	wantLen := IPCEnvelopeHeaderSize + protocol.AddrSize + 2 + 2 + len(payload)
	if len(reply) != wantLen {
		t.Fatalf("frame len = %d, want %d", len(reply), wantLen)
	}
	if reply[0] != CmdRecvFrom {
		t.Fatalf("reply[0] = 0x%02X, want CmdRecvFrom (0x%02X)", reply[0], CmdRecvFrom)
	}
	body := reply[IPCEnvelopeHeaderSize:]
	gotAddr := protocol.UnmarshalAddr(body[0:protocol.AddrSize])
	if gotAddr != srcAddr {
		t.Fatalf("srcAddr = %+v, want %+v", gotAddr, srcAddr)
	}
	if sp := binary.BigEndian.Uint16(body[protocol.AddrSize:]); sp != 443 {
		t.Fatalf("srcPort = %d, want 443", sp)
	}
	if dp := binary.BigEndian.Uint16(body[protocol.AddrSize+2:]); dp != 8080 {
		t.Fatalf("dstPort = %d, want 8080", dp)
	}
	if string(body[protocol.AddrSize+4:]) != "udp-data" {
		t.Fatalf("payload = %q, want 'udp-data'", string(body[protocol.AddrSize+4:]))
	}
}

// --- DeliverDatagram: with multiple clients, all get the same frame ---

func TestDeliverDatagramBroadcastsToAllClients(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	s := d.ipc

	ic1, client1 := newIPCTestConn(t)
	ic2, client2 := newIPCTestConn(t)
	s.mu.Lock()
	s.clients[ic1] = true
	s.clients[ic2] = true
	s.mu.Unlock()
	t.Cleanup(func() {
		s.mu.Lock()
		delete(s.clients, ic1)
		delete(s.clients, ic2)
		s.mu.Unlock()
	})

	go s.DeliverDatagram(protocol.Addr{Network: 3, Node: 7}, 9, 10, []byte("ping"))

	_ = client1.SetReadDeadline(time.Now().Add(2 * time.Second))
	_ = client2.SetReadDeadline(time.Now().Add(2 * time.Second))
	r1, err := ipcutil.Read(client1)
	if err != nil {
		t.Fatalf("read client1: %v", err)
	}
	r2, err := ipcutil.Read(client2)
	if err != nil {
		t.Fatalf("read client2: %v", err)
	}
	if r1[0] != CmdRecvFrom || r2[0] != CmdRecvFrom {
		t.Fatalf("wrong cmd: r1=0x%02X r2=0x%02X", r1[0], r2[0])
	}
}

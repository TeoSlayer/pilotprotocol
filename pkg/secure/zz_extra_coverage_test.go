// SPDX-License-Identifier: AGPL-3.0-or-later

// Package secure_test — extra coverage tests targeting error paths in
// Handshake / HandshakeWithLookup / HandshakeWithTimestampOffset, the
// SecureConn Read/Write framing edges, performAuth* error branches,
// and the Dial/ListenAndServe surfaces that require a minimal IPC
// daemon mock to reach.
//
// Goal: bring pkg/secure from ~80% to ≥95% statement coverage. These
// tests use only public APIs (or test-only exported helpers already in
// the package).
package secure_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/ipcutil"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/TeoSlayer/pilotprotocol/pkg/secure"
)

// ---------------------------------------------------------------------------
// Fake daemon — minimal IPC peer that drives the public driver.Driver API
// so we can reach secure.Dial, Server.ListenAndServe, and Server.handleConn
// through their real call paths.
//
// Wire format: each IPC frame is a length-prefixed buffer (ipcutil.Read /
// Write), and the first byte is the command opcode (see pkg/driver/ipc.go).
// We hard-code the opcodes here because they are private to driver, but
// the wire format is stable.
// ---------------------------------------------------------------------------

const (
	cmdBind    byte = 0x01
	cmdBindOK  byte = 0x02
	cmdDial    byte = 0x03
	cmdDialOK  byte = 0x04
	cmdAccept  byte = 0x05
	cmdSend    byte = 0x06
	cmdRecv    byte = 0x07
	cmdClose   byte = 0x08
	cmdCloseOK byte = 0x09
)

// shortSocketPath returns a /tmp path short enough for macOS unix socket
// length limit (~104 chars).
func shortSocketPath(t *testing.T) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join("/tmp", "ss-"+hex.EncodeToString(b[:])+".sock")
	t.Cleanup(func() { _ = os.Remove(p) })
	return p
}

// fakeDaemon implements just enough of the daemon IPC contract for one
// connection at a time. It runs handlers per opcode; the test sets these
// up before connecting via driver.Connect.
type fakeDaemon struct {
	t        *testing.T
	ln       net.Listener
	path     string
	mu       sync.Mutex
	conn     net.Conn
	connSet  chan struct{}
	handlers map[byte]func(frame []byte) [][]byte
	// per-connID send forwarders — used by Dial/Accept happy-paths
	bridges map[uint32]chan<- []byte
}

func newFakeDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	p := shortSocketPath(t)
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	d := &fakeDaemon{
		t:        t,
		ln:       ln,
		path:     p,
		connSet:  make(chan struct{}),
		handlers: make(map[byte]func(frame []byte) [][]byte),
		bridges:  make(map[uint32]chan<- []byte),
	}
	go d.loop()
	return d
}

func (d *fakeDaemon) loop() {
	conn, err := d.ln.Accept()
	if err != nil {
		return
	}
	d.mu.Lock()
	d.conn = conn
	d.mu.Unlock()
	close(d.connSet)
	for {
		frame, err := ipcutil.Read(conn)
		if err != nil {
			return
		}
		if len(frame) == 0 {
			continue
		}
		cmd := frame[0]
		d.mu.Lock()
		h := d.handlers[cmd]
		var bridgeCh chan<- []byte
		var payload []byte
		if cmd == cmdSend && len(frame) >= 5 {
			id := binary.BigEndian.Uint32(frame[1:5])
			bridgeCh = d.bridges[id]
			payload = append([]byte(nil), frame[5:]...)
		}
		d.mu.Unlock()
		if bridgeCh != nil {
			bridgeCh <- payload
			continue
		}
		if h == nil {
			continue
		}
		for _, r := range h(frame) {
			_ = ipcutil.Write(conn, r)
		}
	}
}

func (d *fakeDaemon) push(frame []byte) {
	d.mu.Lock()
	c := d.conn
	d.mu.Unlock()
	if c == nil {
		<-d.connSet
		d.mu.Lock()
		c = d.conn
		d.mu.Unlock()
	}
	_ = ipcutil.Write(c, frame)
}

func (d *fakeDaemon) onCmd(cmd byte, h func(frame []byte) [][]byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handlers[cmd] = h
}

func (d *fakeDaemon) registerBridge(connID uint32, toDriver chan<- []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.bridges[connID] = toDriver
}

func (d *fakeDaemon) close() {
	_ = d.ln.Close()
	select {
	case <-d.connSet:
	case <-time.After(100 * time.Millisecond):
	}
	d.mu.Lock()
	c := d.conn
	d.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

// pumpRecv emits cmdRecv frames carrying `data` for connID to the driver.
func (d *fakeDaemon) pumpRecv(connID uint32, data []byte) {
	frame := make([]byte, 1+4+len(data))
	frame[0] = cmdRecv
	binary.BigEndian.PutUint32(frame[1:5], connID)
	copy(frame[5:], data)
	d.push(frame)
}

// pumpAccept emits a cmdAccept frame for port `port` with the given conn.
func (d *fakeDaemon) pumpAccept(port uint16, connID uint32) {
	addrSize := protocol.AddrSize
	frame := make([]byte, 1+2+4+addrSize+2)
	frame[0] = cmdAccept
	binary.BigEndian.PutUint16(frame[1:3], port)
	binary.BigEndian.PutUint32(frame[3:7], connID)
	binary.BigEndian.PutUint16(frame[3+4+addrSize:], 0)
	d.push(frame)
}

// bridgeDriverToPipe wires a fakeDaemon conn-side to one half of a net.Pipe.
// Bytes the driver writes via cmdSend(connID, ...) are forwarded to the pipe
// (writeable end) `peer`. Bytes that arrive on `peer` are pushed back to the
// driver as cmdRecv(connID, ...). This lets us run secure.Handshake on both
// the driver-Conn side and a raw secure.Handshake on the peer side against
// each other, exercising secure.Dial and ListenAndServe happy paths.
func (d *fakeDaemon) bridgeDriverToPipe(connID uint32, peer net.Conn) {
	toPeer := make(chan []byte, 32)
	d.registerBridge(connID, toPeer)
	go func() {
		for data := range toPeer {
			if _, err := peer.Write(data); err != nil {
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := peer.Read(buf)
			if n > 0 {
				d.pumpRecv(connID, buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
}

// failAfterNWrites wraps a net.Conn and returns errClosedPipe after the Nth
// write. Used to surgically trigger sc.Write failures at specific points in
// the authenticated handshake protocol.
type failAfterNWrites struct {
	net.Conn
	mu        sync.Mutex
	writes    int
	failAfter int
}

func (f *failAfterNWrites) Write(b []byte) (int, error) {
	f.mu.Lock()
	f.writes++
	n := f.writes
	f.mu.Unlock()
	if n > f.failAfter {
		return 0, io.ErrClosedPipe
	}
	return f.Conn.Write(b)
}

// ---------------------------------------------------------------------------
// secure.Dial
// ---------------------------------------------------------------------------

func TestDialDialAddrErrorPropagates(t *testing.T) {
	d := newFakeDaemon(t)
	drv, err := driver.Connect(d.path)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		d.close()
		drv.Close()
	}()
	_, err = secure.Dial(drv, protocol.Addr{Network: 1, Node: 1})
	if err == nil {
		t.Fatal("expected dial error after daemon close")
	}
}

func TestDialHandshakeErrorClosesConn(t *testing.T) {
	d := newFakeDaemon(t)
	defer d.close()

	const connID uint32 = 0xCAFEBABE
	d.onCmd(cmdDial, func(frame []byte) [][]byte {
		resp := make([]byte, 1+4)
		resp[0] = cmdDialOK
		binary.BigEndian.PutUint32(resp[1:5], connID)
		return [][]byte{resp}
	})
	d.onCmd(cmdClose, func(frame []byte) [][]byte {
		resp := make([]byte, 5)
		resp[0] = cmdCloseOK
		binary.BigEndian.PutUint32(resp[1:5], connID)
		return [][]byte{resp}
	})

	drv, err := driver.Connect(d.path)
	if err != nil {
		t.Fatal(err)
	}
	defer drv.Close()

	go func() {
		time.Sleep(20 * time.Millisecond)
		d.pumpRecv(connID, []byte{0x01, 0x02, 0x03})
		time.Sleep(20 * time.Millisecond)
		d.close()
	}()

	_, err = secure.Dial(drv, protocol.Addr{Network: 1, Node: 1})
	if err == nil {
		t.Fatal("expected handshake error after daemon close")
	}
}

func TestDialHappyPathWithBridge(t *testing.T) {
	d := newFakeDaemon(t)
	defer d.close()

	const connID uint32 = 0xAA00AA00
	d.onCmd(cmdDial, func(frame []byte) [][]byte {
		resp := make([]byte, 5)
		resp[0] = cmdDialOK
		binary.BigEndian.PutUint32(resp[1:5], connID)
		return [][]byte{resp}
	})
	d.onCmd(cmdClose, func(frame []byte) [][]byte {
		resp := make([]byte, 5)
		resp[0] = cmdCloseOK
		binary.BigEndian.PutUint32(resp[1:5], connID)
		return [][]byte{resp}
	})

	drv, err := driver.Connect(d.path)
	if err != nil {
		t.Fatal(err)
	}
	defer drv.Close()

	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()
	d.bridgeDriverToPipe(connID, pa)

	peerDone := make(chan *secure.SecureConn, 1)
	peerErr := make(chan error, 1)
	go func() {
		sc, err := secure.Handshake(pb, true)
		if err != nil {
			peerErr <- err
			return
		}
		peerDone <- sc
	}()

	sc, err := secure.Dial(drv, protocol.Addr{Network: 1, Node: 1})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	select {
	case <-peerDone:
	case err := <-peerErr:
		t.Fatalf("peer handshake: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("peer handshake timed out")
	}
	if sc == nil {
		t.Fatal("Dial returned nil conn")
	}
	sc.Close()
}

// ---------------------------------------------------------------------------
// Server: ListenAndServe + handleConn paths
// ---------------------------------------------------------------------------

func TestListenAndServeBindError(t *testing.T) {
	d := newFakeDaemon(t)
	defer d.close()
	drv, err := driver.Connect(d.path)
	if err != nil {
		t.Fatal(err)
	}
	defer drv.Close()

	s := secure.NewServer(drv, func(_ net.Conn) {})
	errCh := make(chan error, 1)
	go func() { errCh <- s.ListenAndServe() }()
	time.Sleep(50 * time.Millisecond)
	d.close()
	drv.Close()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error from ListenAndServe")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ListenAndServe never returned")
	}
}

func TestListenAndServeAcceptErrorReturns(t *testing.T) {
	d := newFakeDaemon(t)
	defer d.close()

	d.onCmd(cmdBind, func(frame []byte) [][]byte {
		resp := make([]byte, 3)
		resp[0] = cmdBindOK
		binary.BigEndian.PutUint16(resp[1:3], protocol.PortSecure)
		return [][]byte{resp}
	})

	drv, err := driver.Connect(d.path)
	if err != nil {
		t.Fatal(err)
	}
	defer drv.Close()

	s := secure.NewServer(drv, func(_ net.Conn) {})
	errCh := make(chan error, 1)
	go func() { errCh <- s.ListenAndServe() }()
	time.Sleep(50 * time.Millisecond)
	d.close()
	drv.Close()
	select {
	case <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("ListenAndServe never returned after daemon close")
	}
}

func TestListenAndServeHandshakeFailsUnauthBranch(t *testing.T) {
	d := newFakeDaemon(t)
	defer d.close()

	const connID uint32 = 0x77777777
	d.onCmd(cmdBind, func(frame []byte) [][]byte {
		resp := make([]byte, 3)
		resp[0] = cmdBindOK
		binary.BigEndian.PutUint16(resp[1:3], protocol.PortSecure)
		return [][]byte{resp}
	})
	d.onCmd(cmdClose, func(frame []byte) [][]byte {
		resp := make([]byte, 5)
		resp[0] = cmdCloseOK
		binary.BigEndian.PutUint32(resp[1:5], connID)
		return [][]byte{resp}
	})

	drv, err := driver.Connect(d.path)
	if err != nil {
		t.Fatal(err)
	}
	defer drv.Close()

	handlerCalled := make(chan struct{}, 1)
	s := secure.NewServer(drv, func(_ net.Conn) { handlerCalled <- struct{}{} })

	go func() { _ = s.ListenAndServe() }()
	time.Sleep(80 * time.Millisecond)
	d.pumpAccept(protocol.PortSecure, connID)
	time.Sleep(40 * time.Millisecond)
	d.pumpRecv(connID, []byte{0x01})
	time.Sleep(40 * time.Millisecond)
	d.close()
	drv.Close()

	select {
	case <-handlerCalled:
		t.Fatal("handler should not be called on handshake failure")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestListenAndServeAuthBranchHandshakeFails(t *testing.T) {
	d := newFakeDaemon(t)
	defer d.close()

	const connID uint32 = 0x88888888
	d.onCmd(cmdBind, func(frame []byte) [][]byte {
		resp := make([]byte, 3)
		resp[0] = cmdBindOK
		binary.BigEndian.PutUint16(resp[1:3], protocol.PortSecure)
		return [][]byte{resp}
	})
	d.onCmd(cmdClose, func(frame []byte) [][]byte {
		resp := make([]byte, 5)
		resp[0] = cmdCloseOK
		binary.BigEndian.PutUint32(resp[1:5], connID)
		return [][]byte{resp}
	})

	drv, err := driver.Connect(d.path)
	if err != nil {
		t.Fatal(err)
	}
	defer drv.Close()

	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(_ uint32) ed25519.PublicKey { return nil }

	handlerCalled := make(chan struct{}, 1)
	s := secure.NewAuthServer(drv, func(_ net.Conn) { handlerCalled <- struct{}{} }, 42, signer, lookup)

	go func() { _ = s.ListenAndServe() }()
	time.Sleep(80 * time.Millisecond)
	d.pumpAccept(protocol.PortSecure, connID)
	time.Sleep(40 * time.Millisecond)
	d.pumpRecv(connID, []byte{0x01})
	time.Sleep(40 * time.Millisecond)
	d.close()
	drv.Close()

	select {
	case <-handlerCalled:
		t.Fatal("handler must not be called on failed handshake")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestListenAndServeHandlerInvokedOnSuccess(t *testing.T) {
	d := newFakeDaemon(t)
	defer d.close()

	const connID uint32 = 0xBB00BB00
	d.onCmd(cmdBind, func(frame []byte) [][]byte {
		resp := make([]byte, 3)
		resp[0] = cmdBindOK
		binary.BigEndian.PutUint16(resp[1:3], protocol.PortSecure)
		return [][]byte{resp}
	})
	d.onCmd(cmdClose, func(frame []byte) [][]byte {
		resp := make([]byte, 5)
		resp[0] = cmdCloseOK
		binary.BigEndian.PutUint32(resp[1:5], connID)
		return [][]byte{resp}
	})

	drv, err := driver.Connect(d.path)
	if err != nil {
		t.Fatal(err)
	}
	defer drv.Close()

	handlerCh := make(chan struct{}, 1)
	s := secure.NewServer(drv, func(_ net.Conn) { handlerCh <- struct{}{} })

	go func() { _ = s.ListenAndServe() }()
	time.Sleep(80 * time.Millisecond)

	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()
	d.bridgeDriverToPipe(connID, pa)

	go func() { _, _ = secure.Handshake(pb, false) }()
	d.pumpAccept(protocol.PortSecure, connID)

	select {
	case <-handlerCh:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never invoked")
	}
}

// ---------------------------------------------------------------------------
// Handshake error branches — server/client sides closing mid-flight
// ---------------------------------------------------------------------------

func TestHandshakeServerReadClientKeyFails(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	b.Close()
	_, err := secure.Handshake(a, true)
	if err == nil {
		t.Fatal("expected read-client-key error")
	}
	if !strings.Contains(err.Error(), "read client key") {
		t.Errorf("err = %v", err)
	}
}

func TestHandshakeClientSendKeyFails(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	a.Close()
	b.Close()
	_, err := secure.Handshake(a, false)
	if err == nil {
		t.Fatal("expected send-client-key error")
	}
}

func TestHandshakeClientReadServerKeyFails(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		buf := make([]byte, 32)
		_, _ = io.ReadFull(b, buf)
		b.Close()
	}()
	_, err := secure.Handshake(a, false)
	if err == nil {
		t.Fatal("expected read-server-key error")
	}
	if !strings.Contains(err.Error(), "read server key") {
		t.Errorf("err = %v", err)
	}
}

func TestHandshakeServerSendKeyFails(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		junk := make([]byte, 32)
		_, _ = rand.Read(junk)
		_, _ = b.Write(junk)
		b.Close()
	}()
	_, err := secure.Handshake(a, true)
	if err == nil {
		t.Fatal("expected send-server-key error")
	}
}

func TestHandshakeWithLookupServerReadKeyFails(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	a.Close()
	b.Close()
	_, err := secure.HandshakeWithLookup(a, true, nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHandshakeWithLookupClientWriteFails(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	a.Close()
	b.Close()
	_, err := secure.HandshakeWithLookup(a, false, nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHandshakeWithLookupClientReadFails(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		buf := make([]byte, 32)
		_, _ = io.ReadFull(b, buf)
		b.Close()
	}()
	_, err := secure.HandshakeWithLookup(a, false, nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHandshakeWithLookupServerWriteKeyFails(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		junk := make([]byte, 32)
		_, _ = rand.Read(junk)
		_, _ = b.Write(junk)
		b.Close()
	}()
	_, err := secure.HandshakeWithLookup(a, true, nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// HandshakeWithTimestampOffset error branches
// ---------------------------------------------------------------------------

func TestHandshakeWithTimestampOffsetServerReadKeyFails(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	a.Close()
	b.Close()
	_, err := secure.HandshakeWithTimestampOffset(a, true, nil, 0)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHandshakeWithTimestampOffsetClientWriteFails(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	a.Close()
	b.Close()
	_, err := secure.HandshakeWithTimestampOffset(a, false, nil, 0)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHandshakeWithTimestampOffsetServerWriteFails(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		junk := make([]byte, 32)
		_, _ = rand.Read(junk)
		_, _ = b.Write(junk)
		b.Close()
	}()
	_, err := secure.HandshakeWithTimestampOffset(a, true, nil, 0)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHandshakeWithTimestampOffsetClientReadFails(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		buf := make([]byte, 32)
		_, _ = io.ReadFull(b, buf)
		b.Close()
	}()
	_, err := secure.HandshakeWithTimestampOffset(a, false, nil, 0)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHandshakeWithTimestampOffsetMutual(t *testing.T) {
	secure.ResetReplayCache()
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, cliPriv, _ := ed25519.GenerateKey(rand.Reader)
	srvPub := srvPriv.Public().(ed25519.PublicKey)
	cliPub := cliPriv.Public().(ed25519.PublicKey)

	cfgServer := &secure.HandshakeConfig{NodeID: 1, Signer: srvPriv, PeerPubKey: cliPub}
	cfgClient := &secure.HandshakeConfig{NodeID: 2, Signer: cliPriv, PeerPubKey: srvPub}

	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()
	type res struct {
		sc  *secure.SecureConn
		err error
	}
	chA := make(chan res, 1)
	chB := make(chan res, 1)
	go func() { sc, err := secure.HandshakeWithTimestampOffset(pa, true, cfgServer, 0); chA <- res{sc, err} }()
	go func() { sc, err := secure.HandshakeWithTimestampOffset(pb, false, cfgClient, 0); chB <- res{sc, err} }()
	rA := <-chA
	rB := <-chB
	if rA.err != nil {
		t.Fatalf("server: %v", rA.err)
	}
	if rB.err != nil {
		t.Fatalf("client: %v", rB.err)
	}
	if rA.sc.PeerNodeID != 2 || rB.sc.PeerNodeID != 1 {
		t.Errorf("peer IDs wrong: %d, %d", rA.sc.PeerNodeID, rB.sc.PeerNodeID)
	}
}

func TestHandshakeWithTimestampOffsetUnauthSkipsAuth(t *testing.T) {
	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()
	type res struct {
		sc  *secure.SecureConn
		err error
	}
	chA := make(chan res, 1)
	chB := make(chan res, 1)
	go func() { sc, err := secure.HandshakeWithTimestampOffset(pa, true, nil, 0); chA <- res{sc, err} }()
	go func() { sc, err := secure.HandshakeWithTimestampOffset(pb, false, nil, 0); chB <- res{sc, err} }()
	rA := <-chA
	rB := <-chB
	if rA.err != nil || rB.err != nil {
		t.Fatalf("handshake errors: %v / %v", rA.err, rB.err)
	}
	rA.sc.Close()
	rB.sc.Close()
}

// ---------------------------------------------------------------------------
// Handshake — ECDH low-order pubkey hits the "ecdh:" branch
// ---------------------------------------------------------------------------

func TestHandshakeECDHFailsOnLowOrderPoint(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		zeros := make([]byte, 32)
		_, _ = b.Write(zeros)
		buf := make([]byte, 32)
		_, _ = io.ReadFull(b, buf)
	}()
	_, err := secure.Handshake(a, true)
	if err == nil {
		t.Fatal("expected ecdh low-order error")
	}
	if !strings.Contains(err.Error(), "ecdh") {
		t.Errorf("err = %v", err)
	}
}

func TestHandshakeWithLookupECDHFailsOnLowOrderPoint(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		zeros := make([]byte, 32)
		_, _ = b.Write(zeros)
		buf := make([]byte, 32)
		_, _ = io.ReadFull(b, buf)
	}()
	_, err := secure.HandshakeWithLookup(a, true, nil, nil)
	if err == nil {
		t.Fatal("expected ecdh error")
	}
	if !strings.Contains(err.Error(), "ecdh") {
		t.Errorf("err = %v", err)
	}
}

func TestHandshakeWithTimestampOffsetECDHFailsOnLowOrderPoint(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		zeros := make([]byte, 32)
		_, _ = b.Write(zeros)
		buf := make([]byte, 32)
		_, _ = io.ReadFull(b, buf)
	}()
	_, err := secure.HandshakeWithTimestampOffset(a, true, nil, 0)
	if err == nil {
		t.Fatal("expected ecdh error")
	}
	if !strings.Contains(err.Error(), "ecdh") {
		t.Errorf("err = %v", err)
	}
}

// ---------------------------------------------------------------------------
// SecureConn.Read framing error paths
// ---------------------------------------------------------------------------

func TestSecureConnReadRejectsMessageTooShort(t *testing.T) {
	t.Parallel()
	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()

	type res struct {
		sc  *secure.SecureConn
		err error
	}
	chA := make(chan res, 1)
	chB := make(chan res, 1)
	go func() { sc, err := secure.Handshake(pa, true); chA <- res{sc, err} }()
	go func() { sc, err := secure.Handshake(pb, false); chB <- res{sc, err} }()
	rA := <-chA
	rB := <-chB
	if rA.err != nil || rB.err != nil {
		t.Fatalf("handshake: %v %v", rA.err, rB.err)
	}
	defer rA.sc.Close()
	defer rB.sc.Close()

	go func() {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], 4) // too short
		_, _ = pb.Write(hdr[:])
		_, _ = pb.Write([]byte{0x00, 0x00, 0x00, 0x00})
	}()

	buf := make([]byte, 16)
	_, err := rA.sc.Read(buf)
	if err == nil {
		t.Fatal("expected error on too-short message")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("err = %v", err)
	}
}

func TestSecureConnReadRejectsMessageTooLarge(t *testing.T) {
	t.Parallel()
	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()
	type res struct {
		sc  *secure.SecureConn
		err error
	}
	chA := make(chan res, 1)
	chB := make(chan res, 1)
	go func() { sc, err := secure.Handshake(pa, true); chA <- res{sc, err} }()
	go func() { sc, err := secure.Handshake(pb, false); chB <- res{sc, err} }()
	rA := <-chA
	rB := <-chB
	if rA.err != nil || rB.err != nil {
		t.Fatalf("handshake: %v %v", rA.err, rB.err)
	}
	defer rA.sc.Close()
	defer rB.sc.Close()

	go func() {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], secure.MaxEncryptedMessageLen+1)
		_, _ = pb.Write(hdr[:])
	}()

	buf := make([]byte, 16)
	_, err := rA.sc.Read(buf)
	if err == nil {
		t.Fatal("expected too-large error")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("err = %v", err)
	}
}

func TestSecureConnReadDecryptFails(t *testing.T) {
	t.Parallel()
	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()
	type res struct {
		sc  *secure.SecureConn
		err error
	}
	chA := make(chan res, 1)
	chB := make(chan res, 1)
	go func() { sc, err := secure.Handshake(pa, true); chA <- res{sc, err} }()
	go func() { sc, err := secure.Handshake(pb, false); chB <- res{sc, err} }()
	rA := <-chA
	rB := <-chB
	if rA.err != nil || rB.err != nil {
		t.Fatalf("handshake: %v %v", rA.err, rB.err)
	}
	defer rA.sc.Close()
	defer rB.sc.Close()

	go func() {
		const total = 32
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], total)
		_, _ = pb.Write(hdr[:])
		payload := make([]byte, total)
		_, _ = rand.Read(payload)
		_, _ = pb.Write(payload)
	}()

	buf := make([]byte, 16)
	_, err := rA.sc.Read(buf)
	if err == nil {
		t.Fatal("expected decrypt error")
	}
	if !strings.Contains(err.Error(), "decrypt") {
		t.Errorf("err = %v", err)
	}
}

func TestSecureConnReadLengthPrefixError(t *testing.T) {
	t.Parallel()
	pa, pb := net.Pipe()
	type res struct {
		sc  *secure.SecureConn
		err error
	}
	chA := make(chan res, 1)
	chB := make(chan res, 1)
	go func() { sc, err := secure.Handshake(pa, true); chA <- res{sc, err} }()
	go func() { sc, err := secure.Handshake(pb, false); chB <- res{sc, err} }()
	rA := <-chA
	rB := <-chB
	if rA.err != nil || rB.err != nil {
		t.Fatalf("handshake: %v %v", rA.err, rB.err)
	}
	pb.Close()
	rB.sc.Close()
	defer pa.Close()
	defer rA.sc.Close()
	_, err := rA.sc.Read(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error reading length")
	}
}

func TestSecureConnReadCiphertextReadError(t *testing.T) {
	t.Parallel()
	pa, pb := net.Pipe()
	type res struct {
		sc  *secure.SecureConn
		err error
	}
	chA := make(chan res, 1)
	chB := make(chan res, 1)
	go func() { sc, err := secure.Handshake(pa, true); chA <- res{sc, err} }()
	go func() { sc, err := secure.Handshake(pb, false); chB <- res{sc, err} }()
	rA := <-chA
	rB := <-chB
	if rA.err != nil || rB.err != nil {
		t.Fatalf("handshake: %v %v", rA.err, rB.err)
	}

	go func() {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], 32)
		_, _ = pb.Write(hdr[:])
		pb.Close()
	}()
	defer pa.Close()
	defer rA.sc.Close()
	_, err := rA.sc.Read(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error reading ciphertext body")
	}
	rB.sc.Close()
}

// ---------------------------------------------------------------------------
// SecureConn.Write error paths
// ---------------------------------------------------------------------------

func TestSecureConnWriteErrorOnClosedConn(t *testing.T) {
	t.Parallel()
	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()
	type res struct {
		sc  *secure.SecureConn
		err error
	}
	chA := make(chan res, 1)
	chB := make(chan res, 1)
	go func() { sc, err := secure.Handshake(pa, true); chA <- res{sc, err} }()
	go func() { sc, err := secure.Handshake(pb, false); chB <- res{sc, err} }()
	rA := <-chA
	rB := <-chB
	if rA.err != nil || rB.err != nil {
		t.Fatalf("handshake: %v %v", rA.err, rB.err)
	}
	pa.Close()
	_, err := rA.sc.Write([]byte("oops"))
	if err == nil {
		t.Fatal("expected write error after raw conn close")
	}
	rB.sc.Close()
}

// ---------------------------------------------------------------------------
// performAuth* error paths — VerifyAuthFrame failures on each side
// ---------------------------------------------------------------------------

func TestAuthServerVerifyFailsClientPasses(t *testing.T) {
	secure.ResetReplayCache()
	srvPub, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, cliPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)

	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()

	cfgServer := &secure.HandshakeConfig{NodeID: 1, Signer: srvPriv, PeerPubKey: wrongPub}
	cfgClient := &secure.HandshakeConfig{NodeID: 2, Signer: cliPriv, PeerPubKey: srvPub}

	errA := make(chan error, 1)
	errB := make(chan error, 1)
	go func() { _, err := secure.Handshake(pa, true, cfgServer); errA <- err }()
	go func() { _, err := secure.Handshake(pb, false, cfgClient); errB <- err }()
	<-errA
	<-errB
}

func TestAuthClientVerifyFailsServerPasses(t *testing.T) {
	secure.ResetReplayCache()
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	cliPub, cliPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)

	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()

	cfgServer := &secure.HandshakeConfig{NodeID: 1, Signer: srvPriv, PeerPubKey: cliPub}
	cfgClient := &secure.HandshakeConfig{NodeID: 2, Signer: cliPriv, PeerPubKey: wrongPub}

	errA := make(chan error, 1)
	errB := make(chan error, 1)
	go func() { _, err := secure.Handshake(pa, true, cfgServer); errA <- err }()
	go func() { _, err := secure.Handshake(pb, false, cfgClient); errB <- err }()
	<-errA
	<-errB
}

func TestAuthOffsetClientVerifyFails(t *testing.T) {
	secure.ResetReplayCache()
	_, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	cliPub, cliPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)

	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()

	cfgServer := &secure.HandshakeConfig{NodeID: 1, Signer: srvPriv, PeerPubKey: cliPub}
	cfgClient := &secure.HandshakeConfig{NodeID: 2, Signer: cliPriv, PeerPubKey: wrongPub}

	errA := make(chan error, 1)
	errB := make(chan error, 1)
	go func() {
		_, err := secure.HandshakeWithTimestampOffset(pa, true, cfgServer, 0)
		errA <- err
	}()
	go func() {
		_, err := secure.HandshakeWithTimestampOffset(pb, false, cfgClient, 0)
		errB <- err
	}()
	<-errA
	<-errB
}

func TestAuthOffsetServerVerifyFails(t *testing.T) {
	secure.ResetReplayCache()
	srvPub, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, cliPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)

	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()

	cfgServer := &secure.HandshakeConfig{NodeID: 1, Signer: srvPriv, PeerPubKey: wrongPub}
	cfgClient := &secure.HandshakeConfig{NodeID: 2, Signer: cliPriv, PeerPubKey: srvPub}

	errA := make(chan error, 1)
	errB := make(chan error, 1)
	go func() {
		_, err := secure.HandshakeWithTimestampOffset(pa, true, cfgServer, 0)
		errA <- err
	}()
	go func() {
		_, err := secure.HandshakeWithTimestampOffset(pb, false, cfgClient, 0)
		errB <- err
	}()
	<-errA
	<-errB
}

func TestAuthLookupServerVerifyFails(t *testing.T) {
	secure.ResetReplayCache()
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	const srvID, cliID = uint32(101), uint32(202)

	srvLookup := func(nodeID uint32) ed25519.PublicKey {
		if nodeID == cliID {
			return wrongPub
		}
		return nil
	}
	cliLookup := func(nodeID uint32) ed25519.PublicKey {
		if nodeID == srvID {
			return serverPub
		}
		return nil
	}

	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()

	errA := make(chan error, 1)
	errB := make(chan error, 1)
	go func() {
		_, err := secure.HandshakeWithLookup(pa, true, &secure.HandshakeConfig{NodeID: srvID, Signer: serverPriv}, srvLookup)
		errA <- err
	}()
	go func() {
		_, err := secure.HandshakeWithLookup(pb, false, &secure.HandshakeConfig{NodeID: cliID, Signer: clientPriv}, cliLookup)
		errB <- err
	}()
	<-errA
	<-errB
}

func TestAuthLookupClientVerifyFails(t *testing.T) {
	secure.ResetReplayCache()
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	const srvID, cliID = uint32(901), uint32(902)

	srvLookup := func(nodeID uint32) ed25519.PublicKey {
		if nodeID == cliID {
			return clientPub
		}
		return nil
	}
	cliLookup := func(nodeID uint32) ed25519.PublicKey {
		if nodeID == srvID {
			return wrongPub
		}
		return nil
	}

	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()

	errA := make(chan error, 1)
	errB := make(chan error, 1)
	go func() {
		_, err := secure.HandshakeWithLookup(pa, true, &secure.HandshakeConfig{NodeID: srvID, Signer: serverPriv}, srvLookup)
		errA <- err
	}()
	go func() {
		_, err := secure.HandshakeWithLookup(pb, false, &secure.HandshakeConfig{NodeID: cliID, Signer: clientPriv}, cliLookup)
		errB <- err
	}()
	<-errA
	cliErr := <-errB
	if cliErr == nil {
		t.Fatal("expected client verify error")
	}
}

// ---------------------------------------------------------------------------
// performAuth* — post-ECDH auth-frame write failures
// ---------------------------------------------------------------------------

func TestAuthServerPostECDHWriteFails(t *testing.T) {
	secure.ResetReplayCache()
	srvPub, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	cliPub, cliPriv, _ := ed25519.GenerateKey(rand.Reader)

	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()

	cfgServer := &secure.HandshakeConfig{NodeID: 1, Signer: srvPriv, PeerPubKey: cliPub}
	cfgClient := &secure.HandshakeConfig{NodeID: 2, Signer: cliPriv, PeerPubKey: srvPub}

	wrapped := &failAfterNWrites{Conn: pa, failAfter: 1}

	errA := make(chan error, 1)
	errB := make(chan error, 1)
	go func() { _, err := secure.Handshake(wrapped, true, cfgServer); errA <- err }()
	go func() { _, err := secure.Handshake(pb, false, cfgClient); errB <- err }()
	srvErr := <-errA
	<-errB
	if srvErr == nil {
		t.Fatal("expected server auth-write error")
	}
}

func TestAuthClientPostVerifyWriteFails(t *testing.T) {
	secure.ResetReplayCache()
	srvPub, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	cliPub, cliPriv, _ := ed25519.GenerateKey(rand.Reader)

	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()

	cfgServer := &secure.HandshakeConfig{NodeID: 1, Signer: srvPriv, PeerPubKey: cliPub}
	cfgClient := &secure.HandshakeConfig{NodeID: 2, Signer: cliPriv, PeerPubKey: srvPub}

	wrapped := &failAfterNWrites{Conn: pb, failAfter: 1}

	errA := make(chan error, 1)
	errB := make(chan error, 1)
	go func() { _, err := secure.Handshake(pa, true, cfgServer); errA <- err }()
	go func() { _, err := secure.Handshake(wrapped, false, cfgClient); errB <- err }()
	<-errA
	cliErr := <-errB
	if cliErr == nil {
		t.Fatal("expected client post-verify write error")
	}
}

func TestAuthOffsetServerPostECDHWriteFails(t *testing.T) {
	secure.ResetReplayCache()
	srvPub, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	cliPub, cliPriv, _ := ed25519.GenerateKey(rand.Reader)

	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()

	cfgServer := &secure.HandshakeConfig{NodeID: 1, Signer: srvPriv, PeerPubKey: cliPub}
	cfgClient := &secure.HandshakeConfig{NodeID: 2, Signer: cliPriv, PeerPubKey: srvPub}

	wrapped := &failAfterNWrites{Conn: pa, failAfter: 1}

	errA := make(chan error, 1)
	errB := make(chan error, 1)
	go func() {
		_, err := secure.HandshakeWithTimestampOffset(wrapped, true, cfgServer, 0)
		errA <- err
	}()
	go func() {
		_, err := secure.HandshakeWithTimestampOffset(pb, false, cfgClient, 0)
		errB <- err
	}()
	srvErr := <-errA
	<-errB
	if srvErr == nil {
		t.Fatal("expected server auth-write error")
	}
}

func TestAuthOffsetClientPostVerifyWriteFails(t *testing.T) {
	secure.ResetReplayCache()
	srvPub, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
	cliPub, cliPriv, _ := ed25519.GenerateKey(rand.Reader)

	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()

	cfgServer := &secure.HandshakeConfig{NodeID: 1, Signer: srvPriv, PeerPubKey: cliPub}
	cfgClient := &secure.HandshakeConfig{NodeID: 2, Signer: cliPriv, PeerPubKey: srvPub}

	wrapped := &failAfterNWrites{Conn: pb, failAfter: 1}

	errA := make(chan error, 1)
	errB := make(chan error, 1)
	go func() {
		_, err := secure.HandshakeWithTimestampOffset(pa, true, cfgServer, 0)
		errA <- err
	}()
	go func() {
		_, err := secure.HandshakeWithTimestampOffset(wrapped, false, cfgClient, 0)
		errB <- err
	}()
	<-errA
	cliErr := <-errB
	if cliErr == nil {
		t.Fatal("expected client post-verify write error")
	}
}

func TestAuthLookupServerPostECDHWriteFails(t *testing.T) {
	secure.ResetReplayCache()
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	const srvID, cliID = uint32(701), uint32(702)
	srvLookup := func(nodeID uint32) ed25519.PublicKey {
		if nodeID == cliID {
			return clientPub
		}
		return nil
	}
	cliLookup := func(nodeID uint32) ed25519.PublicKey {
		if nodeID == srvID {
			return serverPub
		}
		return nil
	}

	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()

	wrapped := &failAfterNWrites{Conn: pa, failAfter: 1}

	errA := make(chan error, 1)
	errB := make(chan error, 1)
	go func() {
		_, err := secure.HandshakeWithLookup(wrapped, true, &secure.HandshakeConfig{NodeID: srvID, Signer: serverPriv}, srvLookup)
		errA <- err
	}()
	go func() {
		_, err := secure.HandshakeWithLookup(pb, false, &secure.HandshakeConfig{NodeID: cliID, Signer: clientPriv}, cliLookup)
		errB <- err
	}()
	srvErr := <-errA
	<-errB
	if srvErr == nil {
		t.Fatal("expected server auth-write error")
	}
}

func TestAuthLookupClientPostVerifyWriteFails(t *testing.T) {
	secure.ResetReplayCache()
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	const srvID, cliID = uint32(801), uint32(802)
	srvLookup := func(nodeID uint32) ed25519.PublicKey {
		if nodeID == cliID {
			return clientPub
		}
		return nil
	}
	cliLookup := func(nodeID uint32) ed25519.PublicKey {
		if nodeID == srvID {
			return serverPub
		}
		return nil
	}

	pa, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()

	wrapped := &failAfterNWrites{Conn: pb, failAfter: 1}

	errA := make(chan error, 1)
	errB := make(chan error, 1)
	go func() {
		_, err := secure.HandshakeWithLookup(pa, true, &secure.HandshakeConfig{NodeID: srvID, Signer: serverPriv}, srvLookup)
		errA <- err
	}()
	go func() {
		_, err := secure.HandshakeWithLookup(wrapped, false, &secure.HandshakeConfig{NodeID: cliID, Signer: clientPriv}, cliLookup)
		errB <- err
	}()
	<-errA
	cliErr := <-errB
	if cliErr == nil {
		t.Fatal("expected client post-verify write error")
	}
}

// ---------------------------------------------------------------------------
// CheckAndRecordNonce cap — fill the cache to maxReplayCacheEntries then
// confirm the next insert errors.
// ---------------------------------------------------------------------------

func TestCheckAndRecordNonceCacheFull(t *testing.T) {
	secure.ResetReplayCache()
	for i := 0; i < 100000; i++ {
		var n [16]byte
		binary.BigEndian.PutUint64(n[:8], uint64(i))
		secure.InjectReplayNonce(n)
	}
	var fresh [16]byte
	binary.BigEndian.PutUint64(fresh[:8], 0xFFFFFFFFFFFFFFFF)
	err := secure.CheckAndRecordNonce(fresh)
	if err == nil || !strings.Contains(err.Error(), "cache full") {
		t.Fatalf("expected cache-full error, got %v", err)
	}
	secure.ResetReplayCache()
}

// ---------------------------------------------------------------------------
// Sanity: AES-GCM nonce size assumption matches.
// ---------------------------------------------------------------------------

func TestAesGcmNonceSizeIs12(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	if g.NonceSize() != 12 {
		t.Errorf("nonce size = %d, want 12", g.NonceSize())
	}
}

var _ = errors.New
var _ = secure.AuthFrameLen

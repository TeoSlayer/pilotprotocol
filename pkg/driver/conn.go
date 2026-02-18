package driver

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// Conn implements net.Conn over a Pilot Protocol stream.
type Conn struct {
	id         uint32
	localAddr  protocol.SocketAddr
	remoteAddr protocol.SocketAddr
	ipc        *ipcClient
	recvCh     chan []byte
	recvBuf    []byte // leftover from previous read
	closed     bool

	mu           sync.Mutex
	readDeadline time.Time
	deadlineCh   chan struct{} // closed when deadline is set/changed
}

func (c *Conn) Read(b []byte) (int, error) {
	// Drain leftover first
	if len(c.recvBuf) > 0 {
		n := copy(b, c.recvBuf)
		c.recvBuf = c.recvBuf[n:]
		return n, nil
	}

	c.mu.Lock()
	dl := c.readDeadline
	dch := c.deadlineCh
	c.mu.Unlock()

	// Check if deadline already passed
	if !dl.IsZero() && !time.Now().Before(dl) {
		return 0, os.ErrDeadlineExceeded
	}

	// Set up timer if deadline is set
	var timer <-chan time.Time
	if !dl.IsZero() {
		t := time.NewTimer(time.Until(dl))
		defer t.Stop()
		timer = t.C
	}

	select {
	case data, ok := <-c.recvCh:
		if !ok {
			return 0, io.EOF
		}
		n := copy(b, data)
		if n < len(data) {
			c.recvBuf = data[n:]
		}
		return n, nil
	case <-timer:
		return 0, os.ErrDeadlineExceeded
	case <-dch:
		// Deadline was changed, re-check
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, protocol.ErrConnClosed
	}
	c.mu.Unlock()

	msg := make([]byte, 1+4+len(b))
	msg[0] = cmdSend
	binary.BigEndian.PutUint32(msg[1:5], c.id)
	copy(msg[5:], b)

	if err := c.ipc.send(msg); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	c.ipc.unregisterRecvCh(c.id)

	msg := make([]byte, 5)
	msg[0] = cmdClose
	binary.BigEndian.PutUint32(msg[1:5], c.id)
	return c.ipc.send(msg)
}

func (c *Conn) LocalAddr() net.Addr  { return pilotAddr(c.localAddr) }
func (c *Conn) RemoteAddr() net.Addr { return pilotAddr(c.remoteAddr) }

func (c *Conn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	// Signal any blocked Read to re-check
	if c.deadlineCh != nil {
		close(c.deadlineCh)
	}
	c.deadlineCh = make(chan struct{})
	c.mu.Unlock()
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }

// pilotAddr wraps SocketAddr to satisfy net.Addr.
type pilotAddr protocol.SocketAddr

func (a pilotAddr) Network() string { return "pilot" }
func (a pilotAddr) String() string  { return protocol.SocketAddr(a).String() }

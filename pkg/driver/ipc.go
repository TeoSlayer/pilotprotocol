package driver

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"web4/internal/ipcutil"
	"web4/pkg/protocol"
)

// IPC commands (must match daemon/ipc.go)
const (
	cmdBind     byte = 0x01
	cmdBindOK   byte = 0x02
	cmdDial     byte = 0x03
	cmdDialOK   byte = 0x04
	cmdAccept   byte = 0x05
	cmdSend     byte = 0x06
	cmdRecv     byte = 0x07
	cmdClose    byte = 0x08
	cmdCloseOK  byte = 0x09
	cmdError    byte = 0x0A
	cmdSendTo   byte = 0x0B
	cmdRecvFrom byte = 0x0C
	cmdInfo        byte = 0x0D
	cmdInfoOK      byte = 0x0E
	cmdHandshake         byte = 0x0F
	cmdHandshakeOK       byte = 0x10
	cmdResolveHostname   byte = 0x11
	cmdResolveHostnameOK byte = 0x12
	cmdSetHostname       byte = 0x13
	cmdSetHostnameOK     byte = 0x14
	cmdSetVisibility     byte = 0x15
	cmdSetVisibilityOK   byte = 0x16
	cmdDeregister        byte = 0x17
	cmdDeregisterOK      byte = 0x18
	cmdSetTags           byte = 0x19
	cmdSetTagsOK         byte = 0x1A
	cmdSetWebhook        byte = 0x1B
	cmdSetWebhookOK      byte = 0x1C
)

// Datagram represents a received unreliable datagram.
type Datagram struct {
	SrcAddr protocol.Addr
	SrcPort uint16
	DstPort uint16
	Data    []byte
}

type ipcClient struct {
	conn     net.Conn
	mu       sync.Mutex
	handlers map[byte][]chan []byte // command type → waiting channels
	recvMu   sync.Mutex
	recvChs  map[uint32]chan []byte // conn_id → data channel
	pendRecv map[uint32][][]byte   // conn_id → buffered data before recvCh registered
	acceptMu sync.Mutex
	acceptChs map[uint16]chan []byte // H12 fix: per-port accept channels
	dgCh     chan *Datagram // incoming datagrams
	doneCh   chan struct{}  // closed when readLoop exits
}

func newIPCClient(socketPath string) (*ipcClient, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to daemon: %w", err)
	}

	c := &ipcClient{
		conn:      conn,
		handlers:  make(map[byte][]chan []byte),
		recvChs:   make(map[uint32]chan []byte),
		pendRecv:  make(map[uint32][][]byte),
		acceptChs: make(map[uint16]chan []byte),
		dgCh:      make(chan *Datagram, 256),
		doneCh:    make(chan struct{}),
	}

	go c.readLoop()
	return c, nil
}

func (c *ipcClient) close() error {
	return c.conn.Close()
}

func (c *ipcClient) readLoop() {
	defer c.cleanup()
	for {
		msg, err := ipcutil.Read(c.conn)
		if err != nil {
			return
		}
		if len(msg) < 1 {
			continue
		}

		cmd := msg[0]
		payload := msg[1:]

		switch cmd {
		case cmdRecv:
			if len(payload) >= 4 {
				connID := binary.BigEndian.Uint32(payload[0:4])
				data := append([]byte(nil), payload[4:]...)
				c.recvMu.Lock()
				ch, ok := c.recvChs[connID]
				if ok {
					c.recvMu.Unlock()
					ch <- data
				} else {
					// Buffer data that arrives before recvCh is registered
					c.pendRecv[connID] = append(c.pendRecv[connID], data)
					c.recvMu.Unlock()
				}
			}
		case cmdCloseOK:
			if len(payload) >= 4 {
				connID := binary.BigEndian.Uint32(payload[0:4])
				c.recvMu.Lock()
				ch, ok := c.recvChs[connID]
				if ok {
					delete(c.recvChs, connID)
					close(ch)
				}
				c.recvMu.Unlock()
			}
		case cmdRecvFrom:
			// Datagram: [6-byte src_addr][2-byte src_port][2-byte dst_port][data]
			if len(payload) >= protocol.AddrSize+4 {
				srcAddr := protocol.UnmarshalAddr(payload[0:protocol.AddrSize])
				srcPort := binary.BigEndian.Uint16(payload[protocol.AddrSize:])
				dstPort := binary.BigEndian.Uint16(payload[protocol.AddrSize+2:])
				data := append([]byte(nil), payload[protocol.AddrSize+4:]...)
				select {
				case c.dgCh <- &Datagram{SrcAddr: srcAddr, SrcPort: srcPort, DstPort: dstPort, Data: data}:
				default:
				}
			}
		case cmdAccept:
			// H12 fix: parse local port and route to per-port channel
			if len(payload) >= 2 {
				port := binary.BigEndian.Uint16(payload[0:2])
				rest := append([]byte(nil), payload[2:]...)
				c.acceptMu.Lock()
				ch, ok := c.acceptChs[port]
				c.acceptMu.Unlock()
				if ok {
					select {
					case ch <- rest:
					default:
					}
				}
			}
		default:
			// Response to a waiting request
			c.mu.Lock()
			if chs, ok := c.handlers[cmd]; ok && len(chs) > 0 {
				ch := chs[0]
				c.handlers[cmd] = chs[1:]
				c.mu.Unlock()
				ch <- append([]byte(nil), payload...)
			} else {
				c.mu.Unlock()
			}
		}
	}
}

// cleanup closes all pending channels when readLoop exits (daemon disconnect).
func (c *ipcClient) cleanup() {
	close(c.doneCh)

	// Close all waiting handler channels
	c.mu.Lock()
	for cmd, chs := range c.handlers {
		for _, ch := range chs {
			close(ch)
		}
		delete(c.handlers, cmd)
	}
	c.mu.Unlock()

	// Close all receive channels
	c.recvMu.Lock()
	for id, ch := range c.recvChs {
		close(ch)
		delete(c.recvChs, id)
	}
	c.recvMu.Unlock()

	// Close all accept channels (H12 fix)
	c.acceptMu.Lock()
	for port, ch := range c.acceptChs {
		close(ch)
		delete(c.acceptChs, port)
	}
	c.acceptMu.Unlock()
}

func (c *ipcClient) send(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ipcutil.Write(c.conn, data)
}

func (c *ipcClient) sendAndWait(data []byte, expectCmd byte) ([]byte, error) {
	ch := make(chan []byte, 1)

	c.mu.Lock()
	c.handlers[expectCmd] = append(c.handlers[expectCmd], ch)
	if err := ipcutil.Write(c.conn, data); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	// Also listen for error responses
	errCh := make(chan []byte, 1)
	c.handlers[cmdError] = append(c.handlers[cmdError], errCh)
	c.mu.Unlock()

	select {
	case resp, ok := <-ch:
		c.removeHandler(cmdError, errCh)
		if !ok {
			return nil, fmt.Errorf("daemon disconnected")
		}
		return resp, nil
	case errResp, ok := <-errCh:
		c.removeHandler(expectCmd, ch)
		if !ok {
			return nil, fmt.Errorf("daemon disconnected")
		}
		if len(errResp) >= 2 {
			return nil, fmt.Errorf("daemon: %s", string(errResp[2:]))
		}
		return nil, fmt.Errorf("daemon error")
	case <-c.doneCh:
		return nil, fmt.Errorf("daemon disconnected")
	}
}

func (c *ipcClient) removeHandler(cmd byte, ch chan []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	chs := c.handlers[cmd]
	for i, h := range chs {
		if h == ch {
			c.handlers[cmd] = append(chs[:i], chs[i+1:]...)
			break
		}
	}
}

// H12 fix: per-port accept channel management
func (c *ipcClient) registerAcceptCh(port uint16) chan []byte {
	ch := make(chan []byte, 64)
	c.acceptMu.Lock()
	defer c.acceptMu.Unlock()
	c.acceptChs[port] = ch
	return ch
}

func (c *ipcClient) unregisterAcceptCh(port uint16) {
	c.acceptMu.Lock()
	defer c.acceptMu.Unlock()
	if ch, ok := c.acceptChs[port]; ok {
		close(ch)
		delete(c.acceptChs, port)
	}
}

func (c *ipcClient) registerRecvCh(connID uint32) chan []byte {
	ch := make(chan []byte, 256)
	c.recvMu.Lock()
	c.recvChs[connID] = ch
	// Drain any data that arrived before registration
	pending := c.pendRecv[connID]
	delete(c.pendRecv, connID)
	c.recvMu.Unlock()
	for _, data := range pending {
		ch <- data
	}
	return ch
}

func (c *ipcClient) unregisterRecvCh(connID uint32) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	delete(c.recvChs, connID)
}


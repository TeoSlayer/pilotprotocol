package driver

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"web4/pkg/protocol"
)

// Listener implements net.Listener over a Pilot Protocol port.
type Listener struct {
	port     uint16
	ipc      *ipcClient
	acceptCh chan []byte // H12 fix: per-port accept channel
	mu       sync.Mutex
	closed   bool
	done     chan struct{} // closed on Close() to unblock Accept (H13 fix)
}

func (l *Listener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, fmt.Errorf("listener closed")
	}
	l.mu.Unlock()

	// H12 fix: wait on per-port accept channel
	var payload []byte
	var ok bool
	select {
	case payload, ok = <-l.acceptCh:
		if !ok {
			return nil, fmt.Errorf("listener closed")
		}
	case <-l.done:
		return nil, fmt.Errorf("listener closed")
	}

	// Parse: [4 bytes conn_id][6 bytes remote addr][2 bytes remote port]
	if len(payload) < 4+protocol.AddrSize+2 {
		return nil, fmt.Errorf("invalid accept payload")
	}

	connID := binary.BigEndian.Uint32(payload[0:4])
	remoteAddr := protocol.UnmarshalAddr(payload[4 : 4+protocol.AddrSize])
	remotePort := binary.BigEndian.Uint16(payload[4+protocol.AddrSize:])

	recvCh := l.ipc.registerRecvCh(connID)

	conn := &Conn{
		id:         connID,
		localAddr:  protocol.SocketAddr{Port: l.port},
		remoteAddr: protocol.SocketAddr{Addr: remoteAddr, Port: remotePort},
		ipc:        l.ipc,
		recvCh:     recvCh,
		deadlineCh: make(chan struct{}),
	}

	return conn, nil
}

func (l *Listener) Close() error {
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		close(l.done) // unblock Accept() (H13 fix)
	}
	l.mu.Unlock()
	return nil
}

// closeFull closes the listener and unregisters the accept channel.
func (l *Listener) closeFull() {
	l.Close()
	l.ipc.unregisterAcceptCh(l.port)
}

func (l *Listener) Addr() net.Addr {
	return pilotAddr(protocol.SocketAddr{Port: l.port})
}

package daemon

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"web4/pkg/dataexchange"
	"web4/pkg/eventstream"
	"web4/pkg/protocol"
)

// connAdapter wraps a daemon *Connection as a net.Conn so that existing
// service packages (dataexchange, eventstream) that use io.Reader/io.Writer
// can work directly on top of the daemon's port infrastructure.
type connAdapter struct {
	conn   *Connection
	daemon *Daemon
	buf    []byte // leftover from previous RecvBuf read
}

func newConnAdapter(d *Daemon, conn *Connection) *connAdapter {
	return &connAdapter{conn: conn, daemon: d}
}

func (a *connAdapter) Read(p []byte) (int, error) {
	// Drain leftover buffer first
	if len(a.buf) > 0 {
		n := copy(p, a.buf)
		a.buf = a.buf[n:]
		return n, nil
	}
	data, ok := <-a.conn.RecvBuf
	if !ok {
		return 0, fmt.Errorf("connection closed")
	}
	n := copy(p, data)
	if n < len(data) {
		a.buf = data[n:]
	}
	return n, nil
}

func (a *connAdapter) Write(p []byte) (int, error) {
	if err := a.daemon.SendData(a.conn, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (a *connAdapter) Close() error {
	a.daemon.CloseConnection(a.conn)
	return nil
}

func (a *connAdapter) LocalAddr() net.Addr {
	return pilotAddr{addr: a.conn.LocalAddr, port: a.conn.LocalPort}
}

func (a *connAdapter) RemoteAddr() net.Addr {
	return pilotAddr{addr: a.conn.RemoteAddr, port: a.conn.RemotePort}
}

// pilotAddr implements net.Addr for Pilot Protocol endpoints.
type pilotAddr struct {
	addr protocol.Addr
	port uint16
}

func (p pilotAddr) Network() string { return "pilot" }
func (p pilotAddr) String() string {
	return fmt.Sprintf("%s:%d", p.addr.String(), p.port)
}

func (a *connAdapter) SetDeadline(t time.Time) error      { return nil }
func (a *connAdapter) SetReadDeadline(t time.Time) error   { return nil }
func (a *connAdapter) SetWriteDeadline(t time.Time) error  { return nil }

// startBuiltinServices starts all enabled built-in port services.
func (d *Daemon) startBuiltinServices() {
	if !d.config.DisableEcho {
		if err := d.startEchoService(); err != nil {
			slog.Warn("echo service failed to start", "error", err)
		}
	}
	if !d.config.DisableDataExchange {
		if err := d.startDataExchangeService(); err != nil {
			slog.Warn("dataexchange service failed to start", "error", err)
		}
	}
	if !d.config.DisableEventStream {
		if err := d.startEventStreamService(); err != nil {
			slog.Warn("eventstream service failed to start", "error", err)
		}
	}
}

// startEchoService binds port 7 and echoes back all received data.
func (d *Daemon) startEchoService() error {
	ln, err := d.ports.Bind(protocol.PortEcho)
	if err != nil {
		return err
	}
	go func() {
		for {
			select {
			case conn, ok := <-ln.AcceptCh:
				if !ok {
					return
				}
				go d.handleEchoConn(conn)
			case <-d.stopCh:
				return
			}
		}
	}()
	slog.Info("echo service listening", "port", protocol.PortEcho)
	return nil
}

func (d *Daemon) handleEchoConn(conn *Connection) {
	for {
		data, ok := <-conn.RecvBuf
		if !ok {
			return
		}
		if err := d.SendData(conn, data); err != nil {
			return
		}
	}
}

// startDataExchangeService binds port 1001 and handles data exchange frames.
func (d *Daemon) startDataExchangeService() error {
	ln, err := d.ports.Bind(protocol.PortDataExchange)
	if err != nil {
		return err
	}
	go func() {
		for {
			select {
			case conn, ok := <-ln.AcceptCh:
				if !ok {
					return
				}
				go d.handleDataExchangeConn(conn)
			case <-d.stopCh:
				return
			}
		}
	}()
	slog.Info("dataexchange service listening", "port", protocol.PortDataExchange)
	return nil
}

func (d *Daemon) handleDataExchangeConn(conn *Connection) {
	adapter := newConnAdapter(d, conn)
	defer adapter.Close()
	for {
		frame, err := dataexchange.ReadFrame(adapter)
		if err != nil {
			return
		}
		slog.Debug("dataexchange frame received",
			"type", dataexchange.TypeName(frame.Type),
			"bytes", len(frame.Payload),
			"remote", conn.RemoteAddr,
		)
		// ACK: echo back a text frame confirming receipt
		ack := &dataexchange.Frame{
			Type:    dataexchange.TypeText,
			Payload: []byte(fmt.Sprintf("ACK %s %d bytes", dataexchange.TypeName(frame.Type), len(frame.Payload))),
		}
		if err := dataexchange.WriteFrame(adapter, ack); err != nil {
			return
		}
	}
}

// startEventStreamService binds port 1002 and runs a pub/sub broker.
func (d *Daemon) startEventStreamService() error {
	ln, err := d.ports.Bind(protocol.PortEventStream)
	if err != nil {
		return err
	}
	broker := &eventBroker{
		subs: make(map[string][]*connAdapter),
	}
	go func() {
		for {
			select {
			case conn, ok := <-ln.AcceptCh:
				if !ok {
					return
				}
				adapter := newConnAdapter(d, conn)
				go broker.handleConn(adapter)
			case <-d.stopCh:
				return
			}
		}
	}()
	slog.Info("eventstream service listening", "port", protocol.PortEventStream)
	return nil
}

// eventBroker is an in-process pub/sub broker for the event stream service.
type eventBroker struct {
	mu   sync.RWMutex
	subs map[string][]*connAdapter // topic → subscribers
}

func (b *eventBroker) handleConn(adapter *connAdapter) {
	defer func() {
		b.removeSub(adapter)
		adapter.Close()
	}()

	// First event = subscription
	subEvt, err := eventstream.ReadEvent(adapter)
	if err != nil {
		return
	}
	topic := subEvt.Topic
	b.addSub(topic, adapter)
	slog.Debug("eventstream subscription", "remote", adapter.RemoteAddr(), "topic", topic)

	// Remaining events = publish
	for {
		evt, err := eventstream.ReadEvent(adapter)
		if err != nil {
			return
		}
		b.publish(evt, adapter)
	}
}

func (b *eventBroker) addSub(topic string, adapter *connAdapter) {
	b.mu.Lock()
	b.subs[topic] = append(b.subs[topic], adapter)
	b.mu.Unlock()
}

func (b *eventBroker) removeSub(adapter *connAdapter) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for topic, conns := range b.subs {
		for i, c := range conns {
			if c == adapter {
				b.subs[topic] = append(conns[:i], conns[i+1:]...)
				break
			}
		}
		if len(b.subs[topic]) == 0 {
			delete(b.subs, topic)
		}
	}
}

func (b *eventBroker) publish(evt *eventstream.Event, sender *connAdapter) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, conn := range b.subs[evt.Topic] {
		if conn != sender {
			eventstream.WriteEvent(conn, evt)
		}
	}
	if evt.Topic != "*" {
		for _, conn := range b.subs["*"] {
			if conn != sender {
				eventstream.WriteEvent(conn, evt)
			}
		}
	}
	slog.Debug("eventstream published", "topic", evt.Topic, "bytes", len(evt.Payload), "from", sender.RemoteAddr())
}

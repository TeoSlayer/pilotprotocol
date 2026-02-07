package eventstream

import (
	"log/slog"
	"net"
	"sync"

	"web4/pkg/driver"
	"web4/pkg/protocol"
)

// Server is a pub/sub event broker on port 1002.
// Clients connect, subscribe to topics, and publish events.
// The first event from a client is treated as a subscription:
// - Topic "*" subscribes to all events
// - Any other topic subscribes to that specific topic
// Subsequent events are published to all matching subscribers.
type Server struct {
	driver *driver.Driver
	mu     sync.RWMutex
	subs   map[string][]net.Conn // topic → subscribers
}

// NewServer creates an event stream server.
func NewServer(d *driver.Driver) *Server {
	return &Server{
		driver: d,
		subs:   make(map[string][]net.Conn),
	}
}

// ListenAndServe binds port 1002 and starts the broker.
func (s *Server) ListenAndServe() error {
	ln, err := s.driver.Listen(protocol.PortEventStream)
	if err != nil {
		return err
	}

	slog.Info("eventstream listening", "port", protocol.PortEventStream)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer func() {
		s.removeSub(conn)
		conn.Close()
	}()

	// First event = subscription
	subEvt, err := ReadEvent(conn)
	if err != nil {
		return
	}

	topic := subEvt.Topic
	s.addSub(topic, conn)
	slog.Debug("eventstream subscription", "remote", conn.RemoteAddr(), "topic", topic)

	// Remaining events = publish
	for {
		evt, err := ReadEvent(conn)
		if err != nil {
			return
		}
		s.publish(evt, conn)
	}
}

func (s *Server) addSub(topic string, conn net.Conn) {
	s.mu.Lock()
	s.subs[topic] = append(s.subs[topic], conn)
	s.mu.Unlock()
}

func (s *Server) removeSub(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for topic, conns := range s.subs {
		for i, c := range conns {
			if c == conn {
				s.subs[topic] = append(conns[:i], conns[i+1:]...)
				break
			}
		}
		if len(s.subs[topic]) == 0 {
			delete(s.subs, topic)
		}
	}
}

func (s *Server) publish(evt *Event, sender net.Conn) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Send to topic-specific subscribers
	for _, conn := range s.subs[evt.Topic] {
		if conn != sender {
			WriteEvent(conn, evt)
		}
	}
	// Send to wildcard subscribers
	if evt.Topic != "*" {
		for _, conn := range s.subs["*"] {
			if conn != sender {
				WriteEvent(conn, evt)
			}
		}
	}

	slog.Debug("eventstream published", "topic", evt.Topic, "bytes", len(evt.Payload), "from", sender.RemoteAddr())
}

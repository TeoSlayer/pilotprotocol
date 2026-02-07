package dataexchange

import (
	"log/slog"
	"net"

	"web4/pkg/driver"
	"web4/pkg/protocol"
)

// Handler is called for each incoming frame on a connection.
type Handler func(conn net.Conn, frame *Frame)

// Server listens on port 1001 and dispatches incoming frames to a handler.
type Server struct {
	driver   *driver.Driver
	listener *driver.Listener
	handler  Handler
}

// NewServer creates a data exchange server.
func NewServer(d *driver.Driver, handler Handler) *Server {
	return &Server{driver: d, handler: handler}
}

// ListenAndServe binds port 1001 and starts accepting connections.
func (s *Server) ListenAndServe() error {
	ln, err := s.driver.Listen(protocol.PortDataExchange)
	if err != nil {
		return err
	}
	s.listener = ln

	slog.Info("dataexchange listening", "port", protocol.PortDataExchange)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	for {
		frame, err := ReadFrame(conn)
		if err != nil {
			return
		}
		s.handler(conn, frame)
	}
}

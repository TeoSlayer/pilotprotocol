package secure

import (
	"log/slog"
	"net"

	"web4/pkg/driver"
	"web4/pkg/protocol"
)

// Handler is called for each new secure connection.
type Handler func(conn net.Conn)

// Server listens on port 443 and upgrades connections to encrypted channels.
type Server struct {
	driver  *driver.Driver
	handler Handler
}

// NewServer creates a secure channel server.
func NewServer(d *driver.Driver, handler Handler) *Server {
	return &Server{driver: d, handler: handler}
}

// ListenAndServe binds port 443 and starts accepting secure connections.
func (s *Server) ListenAndServe() error {
	ln, err := s.driver.Listen(protocol.PortSecure)
	if err != nil {
		return err
	}

	slog.Info("secure server listening", "port", protocol.PortSecure)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	sc, err := Handshake(conn, true)
	if err != nil {
		slog.Warn("secure handshake failed", "err", err)
		conn.Close()
		return
	}
	s.handler(sc)
}

package nameserver

import (
	"fmt"
	"log/slog"
	"net"

	"web4/pkg/driver"
	"web4/pkg/protocol"
)

// Server is the Pilot Protocol nameserver. It runs on the overlay
// network itself, listening on port 53.
type Server struct {
	store  *RecordStore
	driver *driver.Driver
	ln     net.Listener
	ready  chan struct{}
}

// New creates a nameserver backed by a fresh record store.
// If storePath is non-empty, records are persisted to that file.
func New(d *driver.Driver, storePath string) *Server {
	store := NewRecordStore()
	if storePath != "" {
		store.SetStorePath(storePath)
	}
	return &Server{
		store:  store,
		driver: d,
		ready:  make(chan struct{}),
	}
}

// Ready returns a channel that is closed once the server is listening.
func (s *Server) Ready() <-chan struct{} {
	return s.ready
}

// Store returns the underlying record store for external manipulation.
func (s *Server) Store() *RecordStore {
	return s.store
}

// ListenAndServe listens on Pilot port 53 and handles name queries.
func (s *Server) ListenAndServe() error {
	ln, err := s.driver.Listen(protocol.PortNameserver)
	if err != nil {
		return fmt.Errorf("listen port %d: %w", protocol.PortNameserver, err)
	}
	s.ln = ln
	close(s.ready)
	slog.Info("nameserver listening", "port", protocol.PortNameserver)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go s.handleConn(conn)
	}
}

// Close shuts down the nameserver.
func (s *Server) Close() error {
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	line := string(buf[:n])
	req, err := ParseRequest(line)
	if err != nil {
		conn.Write([]byte(FormatResponseErr(err.Error())))
		return
	}

	resp := s.handleRequest(req, conn.RemoteAddr())
	conn.Write([]byte(resp))
}

func (s *Server) handleRequest(req Request, remoteAddr net.Addr) string {
	switch req.Command {
	case "QUERY":
		return s.handleQuery(req)
	case "REGISTER":
		return s.handleRegister(req, remoteAddr)
	default:
		return FormatResponseErr("unknown command: " + req.Command)
	}
}

func (s *Server) handleQuery(req Request) string {
	switch req.RecordType {
	case RecordA:
		addr, err := s.store.LookupA(req.Name)
		if err != nil {
			return FormatResponseErr(err.Error())
		}
		return FormatResponseA(req.Name, addr)

	case RecordN:
		netID, err := s.store.LookupN(req.Name)
		if err != nil {
			return FormatResponseErr(err.Error())
		}
		return FormatResponseN(req.Name, netID)

	case RecordS:
		entries := s.store.LookupS(req.NetID, req.Port)
		return FormatResponseS(entries)

	default:
		return FormatResponseErr("unknown record type: " + req.RecordType)
	}
}

func (s *Server) handleRegister(req Request, remoteAddr net.Addr) string {
	// Extract caller's node ID from RemoteAddr for source validation
	callerNode := extractCallerNode(remoteAddr)

	switch req.RecordType {
	case RecordA:
		addr, err := protocol.ParseAddr(req.Address)
		if err != nil {
			return FormatResponseErr(err.Error())
		}
		// Validate: caller can only register addresses for their own node
		if callerNode != 0 && addr.Node != callerNode {
			return FormatResponseErr("cannot register address for another node")
		}
		s.store.RegisterA(req.Name, addr)
		slog.Debug("nameserver registered A record", "name", req.Name, "addr", addr)
		return FormatResponseOK()

	case RecordN:
		s.store.RegisterN(req.Name, req.NetID)
		slog.Debug("nameserver registered N record", "name", req.Name, "network_id", req.NetID)
		return FormatResponseOK()

	case RecordS:
		addr, err := protocol.ParseAddr(req.Address)
		if err != nil {
			return FormatResponseErr(err.Error())
		}
		// Validate: caller can only register services for their own node
		if callerNode != 0 && addr.Node != callerNode {
			return FormatResponseErr("cannot register service for another node")
		}
		s.store.RegisterS(req.Name, addr, req.NetID, req.Port)
		slog.Debug("nameserver registered S record", "name", req.Name, "addr", addr, "port", req.Port, "network_id", req.NetID)
		return FormatResponseOK()

	default:
		return FormatResponseErr("unknown record type: " + req.RecordType)
	}
}

// extractCallerNode gets the node ID from a driver.Conn RemoteAddr().
// RemoteAddr format: "N:NNNN.HHHH.LLLL:port" — we parse the address part.
func extractCallerNode(addr net.Addr) uint32 {
	if addr == nil {
		return 0
	}
	s := addr.String()
	// driver.Conn.RemoteAddr returns "addr:port"
	// Try to parse the address portion
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		host = s
	}
	pilotAddr, err := protocol.ParseAddr(host)
	if err != nil {
		return 0
	}
	return pilotAddr.Node
}

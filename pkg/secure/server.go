// SPDX-License-Identifier: AGPL-3.0-or-later

package secure

import (
	"crypto/ed25519"
	"log/slog"
	"net"

	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// Handler is called for each new secure connection.
type Handler func(conn net.Conn)

// Server listens on port 443 and upgrades connections to encrypted channels.
type Server struct {
	driver     *driver.Driver
	handler    Handler
	authNodeID uint32
	authSigner ed25519.PrivateKey
	peerLookup PeerPubKeyLookup
}

// NewServer creates a secure channel server (unauthenticated ECDH).
func NewServer(d *driver.Driver, handler Handler) *Server {
	return &Server{driver: d, handler: handler}
}

// NewAuthServer creates a secure channel server with Ed25519 authentication.
// The server authenticates itself and verifies connecting clients using the
// lookup function to obtain each client's expected Ed25519 public key.
func NewAuthServer(d *driver.Driver, handler Handler, nodeID uint32, signer ed25519.PrivateKey, lookup PeerPubKeyLookup) *Server {
	return &Server{
		driver:     d,
		handler:    handler,
		authNodeID: nodeID,
		authSigner: signer,
		peerLookup: lookup,
	}
}

// Driver returns the underlying packet driver. Exposed for tests.
func (s *Server) Driver() *driver.Driver { return s.driver }

// Handler returns the per-connection handler callback. Exposed for tests.
func (s *Server) Handler() Handler { return s.handler }

// AuthNodeID returns the authenticated node id (zero when unauth).
// Exposed for tests.
func (s *Server) AuthNodeID() uint32 { return s.authNodeID }

// AuthSigner returns the server's Ed25519 signing key (nil when unauth).
// Exposed for tests.
func (s *Server) AuthSigner() ed25519.PrivateKey { return s.authSigner }

// PeerLookup returns the per-peer pubkey lookup (nil when unauth).
// Exposed for tests.
func (s *Server) PeerLookup() PeerPubKeyLookup { return s.peerLookup }

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
	var sc *SecureConn
	var err error

	if s.authSigner != nil {
		// Use lookup-based handshake: the peer's nodeID is extracted from
		// their auth frame, then the lookup function resolves their Ed25519
		// pubkey for signature verification.
		sc, err = HandshakeWithLookup(conn, true, &HandshakeConfig{
			NodeID: s.authNodeID,
			Signer: s.authSigner,
		}, s.peerLookup)
	} else {
		sc, err = Handshake(conn, true)
	}

	if err != nil {
		slog.Warn("secure handshake failed", "err", err)
		conn.Close()
		return
	}
	s.handler(sc)
}

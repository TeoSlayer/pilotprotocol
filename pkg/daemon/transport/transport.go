// SPDX-License-Identifier: AGPL-3.0-or-later

// Package transport defines the L2 datagram-I/O abstraction the daemon
// uses for the central tunnel socket.
//
// Today there is one implementation: *udpio.Socket. v1.10.2 introduces a
// second one — pkg/daemon/transport/wss — that tunnels Pilot packets over
// a WebSocket Secure connection to the beacon for compat-mode daemons
// running in UDP-blocked environments (Docker on Render/Railway/Vercel/
// Lambda). See docs/SPEC-compat-mode.md.
//
// The interface uses *net.UDPAddr as the address type even for non-UDP
// transports. The WSS implementation will pass a synthetic address that
// represents "the beacon" so all of L3+ (tunnel manager, routing manager,
// dispatch) stays transport-agnostic. The synthetic address is opaque
// to upper layers — they only key on the source nodeID inside the
// Pilot packet header, not the wire-level src addr.
package transport

import (
	"errors"
	"net"
)

// ErrClosed is the sentinel returned by Transport.Recv after the
// transport has been Close()d (or a remote close has propagated, for
// stream-oriented transports like WSS). The readLoop in pkg/daemon
// checks this with errors.Is to distinguish "I/O error on this frame"
// (continue + log) from "transport is gone" (exit cleanly).
//
// Both implementations — udpio.Socket and the planned WSS transport —
// must return ErrClosed (or wrap it) on a closed transport.
var ErrClosed = errors.New("transport: closed")

// Transport is the L2 read/write interface. Implementations must be
// safe for one concurrent reader (Recv) and one concurrent writer
// (Send) — matches the contract today's pkg/daemon/tunnel.go relies on
// (single readLoop goroutine driving Recv; multiple Send goroutines
// from L4 routing serialized at the kernel level).
//
// Close is idempotent. After Close, Recv must return a sentinel error
// the caller can identify (today: udpio.ErrClosed; the WSS transport
// will return the same error so the read-loop teardown is uniform).
type Transport interface {
	// Send writes frame to dst as one datagram. For UDP this is a
	// kernel UDPConn.WriteToUDP; for WSS this is a single binary WS
	// frame written to the beacon connection (dst is ignored — the
	// destination is implicit). Returns bytes-written and the
	// underlying error.
	Send(frame []byte, dst *net.UDPAddr) (int, error)

	// Recv reads one datagram. Returns the frame slice (valid until
	// the next Recv call — caller must copy if retaining), the source
	// address (real *net.UDPAddr for UDP; synthetic for WSS), and any
	// I/O error. On Close, returns the implementation's sentinel
	// closed-socket error.
	Recv() ([]byte, *net.UDPAddr, error)

	// LocalAddr returns the bind address for UDP transports; for WSS
	// returns a synthetic address representing the local end of the
	// compat tunnel. Never nil for a live transport.
	LocalAddr() *net.UDPAddr

	// Close releases resources. Idempotent.
	Close() error
}

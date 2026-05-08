// SPDX-License-Identifier: AGPL-3.0-or-later

package coreapi

import (
	"context"
	"io"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// Addr is the 48-bit virtual address used throughout the protocol.
// Re-exported here so plugins can stay free of pkg/protocol if they want.
type Addr = protocol.Addr

// Stream is one bidirectional ordered byte stream between two
// (Addr, port) endpoints. It mirrors net.Conn so plugins can wrap it
// behind any io-aware library.
type Stream interface {
	io.ReadWriteCloser

	LocalAddr() Addr
	LocalPort() uint16
	RemoteAddr() Addr
	RemotePort() uint16

	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// Listener accepts inbound streams on a single well-known or ephemeral
// port. Returned by Streams.Listen.
type Listener interface {
	Accept() (Stream, error)
	Close() error
	Addr() Addr
	Port() uint16
}

// Streams is the L7 surface plugins consume. The daemon-side
// implementation routes through L7 → L6 → L5 → L4 → L2.
//
// SendDatagram is the connectionless variant (one packet, no ACK,
// no retransmit). Used by plugins that don't need stream semantics.
type Streams interface {
	Dial(ctx context.Context, dst Addr, port uint16) (Stream, error)
	Listen(port uint16) (Listener, error)
	SendDatagram(ctx context.Context, dst Addr, port uint16, data []byte) error
}

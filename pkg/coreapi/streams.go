// SPDX-License-Identifier: AGPL-3.0-or-later

package coreapi

import (
	"context"
	"io"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// Addr is the 48-bit virtual address used throughout the protocol.
// Re-exported here so plugins can stay free of pkg/protocol if they want.
type Addr = protocol.Addr

// Stream is one bidirectional ordered byte stream between two
// (Addr, port) endpoints. It satisfies io.ReadWriteCloser with
// Pilot Protocol addressing extensions. Deadline methods are
// intentionally excluded — the runtime currently cannot honor
// them, and removing them from the interface forces callers to
// get a compile-time signal rather than a silent no-op.
type Stream interface {
	io.ReadWriteCloser

	LocalAddr() Addr
	LocalPort() uint16
	RemoteAddr() Addr
	RemotePort() uint16
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

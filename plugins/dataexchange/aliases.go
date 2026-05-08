// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"io"
	"net"

	internaldx "github.com/TeoSlayer/pilotprotocol/internal/dataexchange"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// Re-exports for source compatibility. The wire format and the
// driver-based client/server moved to internal/dataexchange so
// cmd/pilotctl and other L12 callers can use them without an L11
// import. plugins/dataexchange retains the L11 Service shell.

// Frame types and limits.
const (
	TypeText     = internaldx.TypeText
	TypeBinary   = internaldx.TypeBinary
	TypeJSON     = internaldx.TypeJSON
	TypeFile     = internaldx.TypeFile
	MaxFrameSize = internaldx.MaxFrameSize
)

// Type aliases.
type (
	Frame   = internaldx.Frame
	Client  = internaldx.Client
	Server  = internaldx.Server
	Handler = internaldx.Handler
)

// Wire helpers.
func WriteFrame(w io.Writer, f *Frame) error  { return internaldx.WriteFrame(w, f) }
func ReadFrame(r io.Reader) (*Frame, error)   { return internaldx.ReadFrame(r) }
func TypeName(t uint32) string                { return internaldx.TypeName(t) }

// Client.
func Dial(d *driver.Driver, addr protocol.Addr) (*Client, error) {
	return internaldx.Dial(d, addr)
}

// Server.
func NewServer(d *driver.Driver, h func(conn net.Conn, frame *Frame)) *Server {
	return internaldx.NewServer(d, h)
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package eventstream

import (
	"io"

	internales "github.com/TeoSlayer/pilotprotocol/internal/eventstream"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// Re-exports for source compatibility. The wire format and the
// driver-based broker/client moved to internal/eventstream so
// cmd/pilotctl and other L12 callers can use them without an L11
// import. plugins/eventstream retains the L11 Service shell.

// Type aliases.
type (
	Event  = internales.Event
	Client = internales.Client
	Server = internales.Server
)

// Wire helpers.
func WriteEvent(w io.Writer, e *Event) error { return internales.WriteEvent(w, e) }
func ReadEvent(r io.Reader) (*Event, error)  { return internales.ReadEvent(r) }

// Client.
func Subscribe(d *driver.Driver, addr protocol.Addr, topic string) (*Client, error) {
	return internales.Subscribe(d, addr, topic)
}

// Server.
func NewServer(d *driver.Driver) *Server {
	return internales.NewServer(d)
}

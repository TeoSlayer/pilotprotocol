// SPDX-License-Identifier: AGPL-3.0-or-later

package eventstream

import (
	"io"

	internales "github.com/TeoSlayer/pilotprotocol/internal/eventstream"
)

// Re-exports for source compatibility. The wire format and the
// driver-based broker/client live in internal/eventstream; L12 callers
// (cmd/pilotctl, examples) import from there directly.

// Type aliases.
type (
	Event  = internales.Event
	Client = internales.Client
	Server = internales.Server
)

// Wire helpers.
func WriteEvent(w io.Writer, e *Event) error { return internales.WriteEvent(w, e) }
func ReadEvent(r io.Reader) (*Event, error)  { return internales.ReadEvent(r) }

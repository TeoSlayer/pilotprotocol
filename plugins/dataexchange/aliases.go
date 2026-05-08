// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"io"

	internaldx "github.com/TeoSlayer/pilotprotocol/internal/dataexchange"
)

// Re-exports for source compatibility. The wire format and the
// driver-based client/server live in internal/dataexchange; L12 callers
// (cmd/pilotctl, examples) import from there directly.

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
func WriteFrame(w io.Writer, f *Frame) error { return internaldx.WriteFrame(w, f) }
func ReadFrame(r io.Reader) (*Frame, error)  { return internaldx.ReadFrame(r) }
func TypeName(t uint32) string               { return internaldx.TypeName(t) }

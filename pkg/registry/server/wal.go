// SPDX-License-Identifier: AGPL-3.0-or-later

package server

// This file re-exports WAL types from the wal sub-package so that the rest of
// the server package can reference them without qualification. The actual
// implementation lives in pkg/registry/server/wal (R6.1 extraction).

import walpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/wal"

// WAL is an alias for the WAL type in the wal sub-package.
type WAL = walpkg.WAL

// NewWAL opens or creates a WAL file at the given path.
func NewWAL(path string) (*WAL, error) { return walpkg.NewWAL(path) }

// ErrWALFull is returned by WAL.Append when the size cap is exceeded.
var ErrWALFull = walpkg.ErrWALFull

// MaxWALSize is the upper bound enforced by WAL.Append. Exposed for tests.
const MaxWALSize = walpkg.MaxWALSize

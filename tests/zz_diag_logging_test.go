// SPDX-License-Identifier: AGPL-3.0-or-later
//go:build diaglog

// Diagnostic logging hook for the keysync-isolate worktree.
// Only compiled with -tags diaglog so it never interferes with regular runs.
//
// Enables Debug-level slog output for the entire ./tests package, so we
// can see PILA/PILK send/receive, rekey retransmit attempts, drop-gate
// firings, and the rest of the L5/L6 chatter that is normally Debug.

package tests

import (
	"os"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/logging"
)

func TestMain(m *testing.M) {
	logging.Setup("debug", "text")
	os.Exit(m.Run())
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package server_test

import (
	"path/filepath"
	"testing"

	"github.com/pilot-protocol/rendezvous"
)

// TestWALAppendRefusesWhenAtCap ensures Append returns an error rather
// than growing past MaxWALSize. This is the disk-exhaustion guard:
// without it, a long-running flushSave failure would let the WAL grow
// until the volume fills up.
func TestWALAppendRefusesWhenAtCap(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	w, err := server.NewWAL(path)
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	defer w.Close()

	// Pretend we've already exceeded the cap (real production scenario:
	// flushSave keeps failing, WAL keeps growing, finally hits the wall).
	w.SetSize(server.MaxWALSize)

	entry := server.DeltaEntry{Type: server.DeltaRegister, NodeID: 1}
	if err := w.Append(entry); err != server.ErrWALFull {
		t.Fatalf("expected ErrWALFull, got %v", err)
	}
}

// TestWALAppendBelowCapStillWorks confirms the cap doesn't break the
// happy path.
func TestWALAppendBelowCapStillWorks(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	w, err := server.NewWAL(path)
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	defer w.Close()

	for i := 0; i < 10; i++ {
		if err := w.Append(server.DeltaEntry{Type: server.DeltaRegister, NodeID: uint32(i)}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	if w.Size() == 0 {
		t.Fatalf("expected size > 0 after appends")
	}
	if w.Size() > server.MaxWALSize {
		t.Fatalf("WAL grew past cap unexpectedly: %d > %d", w.Size(), server.MaxWALSize)
	}
}

// TestWALTruncateResetsCap verifies that after Truncate, Append works
// again. Otherwise a one-time overflow would permanently brick the WAL.
func TestWALTruncateResetsCap(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	w, err := server.NewWAL(path)
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	defer w.Close()

	w.SetSize(server.MaxWALSize + 1)
	if err := w.Append(server.DeltaEntry{Type: server.DeltaRegister, NodeID: 1}); err != server.ErrWALFull {
		t.Fatalf("expected ErrWALFull, got %v", err)
	}
	if err := w.Truncate(); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	if err := w.Append(server.DeltaEntry{Type: server.DeltaRegister, NodeID: 1}); err != nil {
		t.Fatalf("Append after Truncate: %v", err)
	}
}

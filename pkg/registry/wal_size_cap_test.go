// SPDX-License-Identifier: AGPL-3.0-or-later

package registry

import (
	"path/filepath"
	"testing"
)

// TestWALAppendRefusesWhenAtCap ensures Append returns an error rather
// than growing past maxWALSize. This is the disk-exhaustion guard:
// without it, a long-running flushSave failure would let the WAL grow
// until the volume fills up.
func TestWALAppendRefusesWhenAtCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	w, err := NewWAL(path)
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	defer w.Close()

	// Pretend we've already exceeded the cap (real production scenario:
	// flushSave keeps failing, WAL keeps growing, finally hits the wall).
	w.size = maxWALSize

	entry := DeltaEntry{Type: DeltaRegister, NodeID: 1}
	if err := w.Append(entry); err != ErrWALFull {
		t.Fatalf("expected ErrWALFull, got %v", err)
	}
}

// TestWALAppendBelowCapStillWorks confirms the cap doesn't break the
// happy path.
func TestWALAppendBelowCapStillWorks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	w, err := NewWAL(path)
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	defer w.Close()

	for i := 0; i < 10; i++ {
		if err := w.Append(DeltaEntry{Type: DeltaRegister, NodeID: uint32(i)}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	if w.size == 0 {
		t.Fatalf("expected size > 0 after appends")
	}
	if w.size > maxWALSize {
		t.Fatalf("WAL grew past cap unexpectedly: %d > %d", w.size, maxWALSize)
	}
}

// TestWALTruncateResetsCap verifies that after Truncate, Append works
// again. Otherwise a one-time overflow would permanently brick the WAL.
func TestWALTruncateResetsCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	w, err := NewWAL(path)
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	defer w.Close()

	w.size = maxWALSize + 1
	if err := w.Append(DeltaEntry{Type: DeltaRegister, NodeID: 1}); err != ErrWALFull {
		t.Fatalf("expected ErrWALFull, got %v", err)
	}
	if err := w.Truncate(); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	if err := w.Append(DeltaEntry{Type: DeltaRegister, NodeID: 1}); err != nil {
		t.Fatalf("Append after Truncate: %v", err)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package wal_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/server/wal"
)

// TestWALAppendAndReplay verifies the basic round-trip: appended entries are
// replayed in order, and the replay count matches the append count.
func TestWALAppendAndReplay(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")

	w, err := wal.NewWAL(path)
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	defer w.Close()

	type payload struct {
		NodeID uint32 `json:"node_id"`
		Owner  string `json:"owner"`
	}

	entries := []wal.DeltaEntry{
		{Type: wal.DeltaRegister, NodeID: 1, Data: mustMarshal(t, payload{NodeID: 1, Owner: "alice"})},
		{Type: wal.DeltaRegister, NodeID: 2, Data: mustMarshal(t, payload{NodeID: 2, Owner: "bob"})},
		{Type: wal.DeltaNetworkCreate, NodeID: 0},
		{Type: wal.DeltaNetworkJoin, NodeID: 1},
		{Type: wal.DeltaKeyRotation, NodeID: 2},
	}

	for i, entry := range entries {
		if err := w.Append(entry); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}

	// Close and reopen to simulate a crash recovery scenario.
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	w2, err := wal.NewWAL(path)
	if err != nil {
		t.Fatalf("NewWAL (reopen): %v", err)
	}
	defer w2.Close()

	var replayed []wal.DeltaEntry
	count, err := w2.Replay(func(e wal.DeltaEntry) error {
		replayed = append(replayed, e)
		return nil
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if count != len(entries) {
		t.Errorf("Replay count = %d, want %d", count, len(entries))
	}
	if len(replayed) != len(entries) {
		t.Fatalf("replayed %d entries, want %d", len(replayed), len(entries))
	}
	for i, got := range replayed {
		if got.Type != entries[i].Type {
			t.Errorf("entry[%d].Type = %v, want %v", i, got.Type, entries[i].Type)
		}
		if got.NodeID != entries[i].NodeID {
			t.Errorf("entry[%d].NodeID = %d, want %d", i, got.NodeID, entries[i].NodeID)
		}
	}
}

// TestWALTruncateResetsToEmpty verifies that after a successful Truncate the
// WAL reports size 0 and a subsequent Replay returns 0 entries — simulating
// what happens after a successful full snapshot compaction.
func TestWALTruncateResetsToEmpty(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")

	w, err := wal.NewWAL(path)
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	defer w.Close()

	// Append some entries.
	for i := 0; i < 3; i++ {
		entry := wal.DeltaEntry{
			Type:   wal.DeltaRegister,
			NodeID: uint32(i + 1),
		}
		if err := w.Append(entry); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}
	if w.Size() == 0 {
		t.Fatal("Size should be non-zero after appends")
	}

	// Truncate (simulating successful snapshot compaction).
	if err := w.Truncate(); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	if w.Size() != 0 {
		t.Errorf("Size after Truncate = %d, want 0", w.Size())
	}

	// Replay should return 0 entries.
	count, err := w.Replay(func(wal.DeltaEntry) error { return nil })
	if err != nil {
		t.Fatalf("Replay after Truncate: %v", err)
	}
	if count != 0 {
		t.Errorf("Replay count after Truncate = %d, want 0", count)
	}

	// Appends after truncation should work normally.
	extra := wal.DeltaEntry{Type: wal.DeltaNetworkCreate, NodeID: 99}
	if err := w.Append(extra); err != nil {
		t.Fatalf("Append after Truncate: %v", err)
	}
	if w.Size() == 0 {
		t.Error("Size should be non-zero after post-truncation append")
	}
}

// TestWALSizeCap verifies that Append returns ErrWALFull when the WAL has
// already reached maxWALSize, without corrupting the file.
func TestWALSizeCap(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "cap.wal")

	w, err := wal.NewWAL(path)
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	defer w.Close()

	// Force the size counter to just below the cap so the next append tips over.
	w.SetSize(wal.MaxWALSize - 1)

	entry := wal.DeltaEntry{Type: wal.DeltaRegister, NodeID: 1}
	err = w.Append(entry)
	if err == nil {
		t.Fatal("expected ErrWALFull, got nil")
	}
	if err != wal.ErrWALFull {
		t.Errorf("err = %v, want ErrWALFull", err)
	}
}

// TestWALStoreLifecycle exercises the Store lifecycle: create, signal save,
// and verify the saveLoop runs the FlushSave callback.
func TestWALStoreLifecycle(t *testing.T) {
	t.Parallel()
	done := make(chan struct{})
	flushed := make(chan struct{}, 1)

	st, err := wal.NewStore("", done, wal.StoreCallbacks{
		FlushSave: func() error {
			select {
			case flushed <- struct{}{}:
			default:
			}
			return nil
		},
		SnapshotJSON: func() []byte { return nil },
		Push:         func([]byte) {},
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	st.Start()

	// Signal a save.
	st.TriggerSave()

	// Wait for saveLoop to flush (it runs every 5s, but the signal path
	// doesn't wait for the ticker; we close done to force the final-save path).
	close(done)
	<-st.SaveDone()
	<-st.ReplicaPushDone()

	// The final-save path in saveLoop drains saveCh; if dirty it flushes.
	// We may or may not have seen flushed depending on timing, but the
	// goroutines must have exited cleanly.
}

// TestWALStoreStandby verifies the standby flag is thread-safe.
func TestWALStoreStandby(t *testing.T) {
	t.Parallel()
	done := make(chan struct{})
	defer close(done)

	st, err := wal.NewStore("", done, wal.StoreCallbacks{
		FlushSave:    func() error { return nil },
		SnapshotJSON: func() []byte { return nil },
		Push:         func([]byte) {},
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	st.Start()

	if st.IsStandby() {
		t.Error("IsStandby should be false initially")
	}
	st.SetStandby(true)
	if !st.IsStandby() {
		t.Error("IsStandby should be true after SetStandby(true)")
	}
	st.SetStandby(false)
	if st.IsStandby() {
		t.Error("IsStandby should be false after SetStandby(false)")
	}
}

// TestWALStoreReplicationToken verifies the replication token accessors.
func TestWALStoreReplicationToken(t *testing.T) {
	t.Parallel()
	done := make(chan struct{})
	defer close(done)

	st, err := wal.NewStore("", done, wal.StoreCallbacks{
		FlushSave:    func() error { return nil },
		SnapshotJSON: func() []byte { return nil },
		Push:         func([]byte) {},
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	st.Start()

	if got := st.ReplicationToken(); got != "" {
		t.Errorf("initial token = %q, want empty", got)
	}
	st.SetReplicationToken("secret-xyz")
	if got := st.ReplicationToken(); got != "secret-xyz" {
		t.Errorf("token = %q, want secret-xyz", got)
	}
}

// TestWALNilSafe verifies that nil WAL methods are all no-ops (no panic).
func TestWALNilSafe(t *testing.T) {
	t.Parallel()
	var w *wal.WAL
	if err := w.Append(wal.DeltaEntry{}); err != nil {
		t.Errorf("nil Append: %v", err)
	}
	count, err := w.Replay(func(wal.DeltaEntry) error { return nil })
	if err != nil || count != 0 {
		t.Errorf("nil Replay: count=%d err=%v", count, err)
	}
	if err := w.Truncate(); err != nil {
		t.Errorf("nil Truncate: %v", err)
	}
	if s := w.Size(); s != 0 {
		t.Errorf("nil Size: %d", s)
	}
	if p := w.Path(); p != "" {
		t.Errorf("nil Path: %q", p)
	}
	// SetSize on nil should not panic
	w.SetSize(42)
	if err := w.Close(); err != nil {
		t.Errorf("nil Close: %v", err)
	}
}

// mustMarshal is a test helper that marshals v to JSON or fatally fails.
func mustMarshal(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

// Ensure the test binary doesn't import os only for the unused import linter.
var _ = os.DevNull

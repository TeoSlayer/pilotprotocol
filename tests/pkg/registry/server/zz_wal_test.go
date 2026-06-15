// SPDX-License-Identifier: AGPL-3.0-or-later

package server_test

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pilot-protocol/rendezvous"
)

// --- NewWAL ---------------------------------------------------------------

func TestNewWALEmptyPathReturnsNilNil(t *testing.T) {
	t.Parallel()
	w, err := server.NewWAL("")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if w != nil {
		t.Fatalf("expected nil WAL for empty path, got %+v", w)
	}
}

func TestNewWALCreatesFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "x.wal")
	w, err := server.NewWAL(p)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer w.Close()

	if w.Path() != p {
		t.Fatalf("path: %s", w.Path())
	}
	if w.Size() != 0 {
		t.Fatalf("size: %d", w.Size())
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}

func TestNewWALOpensExistingWithSize(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "x.wal")
	if err := os.WriteFile(p, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	w, err := server.NewWAL(p)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer w.Close()
	if w.Size() != 5 {
		t.Fatalf("expected size=5 from pre-existing file, got %d", w.Size())
	}
}

func TestNewWALErrorOnBadPath(t *testing.T) {
	t.Parallel()
	// Path where a component is a file rather than a directory.
	dir := t.TempDir()
	file := filepath.Join(dir, "notadir")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := server.NewWAL(filepath.Join(file, "child.wal")); err == nil {
		t.Fatalf("expected error when parent is not a directory")
	}
}

// --- Nil-receiver safety --------------------------------------------------

func TestAppendNilSafe(t *testing.T) {
	t.Parallel()
	var w *server.WAL
	if err := w.Append(server.DeltaEntry{SeqNo: 1}); err != nil {
		t.Fatalf("nil Append: %v", err)
	}
}

func TestReplayNilSafe(t *testing.T) {
	t.Parallel()
	var w *server.WAL
	n, err := w.Replay(func(server.DeltaEntry) error { return nil })
	if err != nil || n != 0 {
		t.Fatalf("nil Replay: n=%d err=%v", n, err)
	}
}

func TestTruncateNilSafe(t *testing.T) {
	t.Parallel()
	var w *server.WAL
	if err := w.Truncate(); err != nil {
		t.Fatalf("nil Truncate: %v", err)
	}
}

func TestSizeNilSafe(t *testing.T) {
	t.Parallel()
	var w *server.WAL
	if w.Size() != 0 {
		t.Fatalf("nil Size != 0")
	}
}

func TestCloseNilSafeWAL(t *testing.T) {
	t.Parallel()
	var w *server.WAL
	if err := w.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}
}

// --- Append writes length + JSON, tracks size ----------------------------

func TestAppendWritesLengthPrefixedEntry(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "x.wal")
	w, err := server.NewWAL(p)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	entry := server.DeltaEntry{SeqNo: 7, Type: server.DeltaRegister, NodeID: 42, Data: json.RawMessage(`{"hello":"world"}`)}
	if err := w.Append(entry); err != nil {
		t.Fatalf("Append: %v", err)
	}

	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 4 {
		t.Fatalf("file too small: %d", len(raw))
	}
	length := binary.LittleEndian.Uint32(raw[:4])
	if int(length) != len(raw)-4 {
		t.Fatalf("length prefix %d does not match remaining %d", length, len(raw)-4)
	}

	var got server.DeltaEntry
	if err := json.Unmarshal(raw[4:], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SeqNo != 7 || got.Type != server.DeltaRegister || got.NodeID != 42 {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}

	if w.Size() != int64(len(raw)) {
		t.Fatalf("Size %d != file %d", w.Size(), len(raw))
	}
}

func TestAppendAccumulatesSize(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "x.wal")
	w, _ := server.NewWAL(p)
	defer w.Close()

	if err := w.Append(server.DeltaEntry{SeqNo: 1}); err != nil {
		t.Fatal(err)
	}
	s1 := w.Size()
	if err := w.Append(server.DeltaEntry{SeqNo: 2}); err != nil {
		t.Fatal(err)
	}
	s2 := w.Size()
	if s2 <= s1 {
		t.Fatalf("size did not grow: s1=%d s2=%d", s1, s2)
	}
}

// --- Replay reads back entries --------------------------------------------

func TestReplayReadsAllAppendedEntries(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "x.wal")
	w, _ := server.NewWAL(p)
	defer w.Close()

	for i := uint64(1); i <= 3; i++ {
		if err := w.Append(server.DeltaEntry{SeqNo: i, Type: server.DeltaHeartbeat, NodeID: uint32(i * 10)}); err != nil {
			t.Fatal(err)
		}
	}

	var got []server.DeltaEntry
	n, err := w.Replay(func(e server.DeltaEntry) error {
		got = append(got, e)
		return nil
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if n != 3 || len(got) != 3 {
		t.Fatalf("count n=%d got=%d", n, len(got))
	}
	for i, e := range got {
		if e.SeqNo != uint64(i+1) {
			t.Fatalf("out of order: %+v", got)
		}
	}
}

func TestReplayOnEmptyWALReturnsZero(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "x.wal")
	w, _ := server.NewWAL(p)
	defer w.Close()

	n, err := w.Replay(func(server.DeltaEntry) error { return nil })
	if err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestReplayFnErrorStopsAndReturns(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "x.wal")
	w, _ := server.NewWAL(p)
	defer w.Close()

	_ = w.Append(server.DeltaEntry{SeqNo: 1})
	_ = w.Append(server.DeltaEntry{SeqNo: 2})

	count := 0
	_, err := w.Replay(func(server.DeltaEntry) error {
		count++
		return io.ErrClosedPipe // arbitrary non-nil
	})
	if err == nil {
		t.Fatalf("expected error from fn to propagate")
	}
	if count != 1 {
		t.Fatalf("expected stop after first error, processed %d", count)
	}
}

func TestReplaySkipsCorruptJSONEntry(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "x.wal")

	// Manually craft a file: [len1][valid json][len2][garbage][len3][valid]
	good1, _ := json.Marshal(server.DeltaEntry{SeqNo: 1, Type: server.DeltaRegister})
	bad := []byte("{not valid json")
	good2, _ := json.Marshal(server.DeltaEntry{SeqNo: 9, Type: server.DeltaHeartbeat})

	var buf []byte
	for _, chunk := range [][]byte{good1, bad, good2} {
		var lb [4]byte
		binary.LittleEndian.PutUint32(lb[:], uint32(len(chunk)))
		buf = append(buf, lb[:]...)
		buf = append(buf, chunk...)
	}
	if err := os.WriteFile(p, buf, 0600); err != nil {
		t.Fatal(err)
	}

	w, _ := server.NewWAL(p)
	defer w.Close()

	var seen []uint64
	n, err := w.Replay(func(e server.DeltaEntry) error {
		seen = append(seen, e.SeqNo)
		return nil
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	// The corrupt entry triggers continue (not counted), so n == # applied.
	if n != 2 || len(seen) != 2 || seen[0] != 1 || seen[1] != 9 {
		t.Fatalf("expected seen=[1,9] n=2, got seen=%v n=%d", seen, n)
	}
}

func TestReplayRejectsOversizedEntry(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "x.wal")

	var lb [4]byte
	binary.LittleEndian.PutUint32(lb[:], (1<<20)+1) // length > 1MB
	if err := os.WriteFile(p, lb[:], 0600); err != nil {
		t.Fatal(err)
	}
	w, _ := server.NewWAL(p)
	defer w.Close()

	_, err := w.Replay(func(server.DeltaEntry) error { return nil })
	if err == nil {
		t.Fatalf("expected oversize error")
	}
}

// TestReplayToleratesTornTail asserts the WAL's torn-tail recovery
// contract: a length prefix written without (all of) its payload — e.g. a
// crash between the length write and the data write — is tolerated.
// Replay applies every complete entry and drops the torn tail, returning
// no error. (Mirrors rendezvous wal.TestWALReplayTornTail; this package's
// older expectation of a hard error predated that deliberate relaxation.)
func TestReplayToleratesTornTail(t *testing.T) {
	t.Parallel()

	t.Run("lone torn record replays nothing", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		p := filepath.Join(dir, "x.wal")

		// Claim length 100 but only write 3 bytes of data.
		var lb [4]byte
		binary.LittleEndian.PutUint32(lb[:], 100)
		if err := os.WriteFile(p, append(lb[:], []byte("abc")...), 0600); err != nil {
			t.Fatal(err)
		}

		w, _ := server.NewWAL(p)
		defer w.Close()

		count, err := w.Replay(func(server.DeltaEntry) error { return nil })
		if err != nil {
			t.Fatalf("Replay should tolerate a torn tail, got error: %v", err)
		}
		if count != 0 {
			t.Fatalf("Replay count = %d, want 0 (torn tail dropped)", count)
		}
	})

	t.Run("complete entry survives a trailing torn tail", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		p := filepath.Join(dir, "x.wal")

		w, _ := server.NewWAL(p)
		if err := w.Append(server.DeltaEntry{SeqNo: 1, Type: server.DeltaRegister, NodeID: 42}); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()

		// Append a torn record (length prefix, no payload) after the
		// complete entry, simulating a crash mid-append.
		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		var lb [4]byte
		binary.LittleEndian.PutUint32(lb[:], 512)
		if _, err := f.Write(lb[:]); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()

		w2, _ := server.NewWAL(p)
		defer w2.Close()

		var replayed []server.DeltaEntry
		count, err := w2.Replay(func(e server.DeltaEntry) error {
			replayed = append(replayed, e)
			return nil
		})
		if err != nil {
			t.Fatalf("Replay should tolerate a torn tail, got error: %v", err)
		}
		if count != 1 || len(replayed) != 1 {
			t.Fatalf("Replay count = %d (replayed %d), want 1 complete entry", count, len(replayed))
		}
		if replayed[0].NodeID != 42 {
			t.Errorf("replayed entry NodeID = %d, want 42", replayed[0].NodeID)
		}
	})
}

func TestReplayLeavesFileAtEndForAppend(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "x.wal")
	w, _ := server.NewWAL(p)
	defer w.Close()

	_ = w.Append(server.DeltaEntry{SeqNo: 1})
	_ = w.Append(server.DeltaEntry{SeqNo: 2})
	before := w.Size()

	if _, err := w.Replay(func(server.DeltaEntry) error { return nil }); err != nil {
		t.Fatal(err)
	}

	// A subsequent Append must land at the end, not overwrite existing bytes.
	if err := w.Append(server.DeltaEntry{SeqNo: 3}); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Size() <= before {
		t.Fatalf("append after replay did not extend file: before=%d after=%d", before, fi.Size())
	}
}

// --- Truncate --------------------------------------------------------------

func TestTruncateClearsFileAndResetsSize(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "x.wal")
	w, _ := server.NewWAL(p)
	defer w.Close()

	_ = w.Append(server.DeltaEntry{SeqNo: 1})
	_ = w.Append(server.DeltaEntry{SeqNo: 2})
	if w.Size() == 0 {
		t.Fatalf("expected nonzero size before truncate")
	}

	if err := w.Truncate(); err != nil {
		t.Fatalf("Truncate: %v", err)
	}

	if w.Size() != 0 {
		t.Fatalf("Size after truncate: %d", w.Size())
	}
	fi, _ := os.Stat(p)
	if fi.Size() != 0 {
		t.Fatalf("file size after truncate: %d", fi.Size())
	}
}

func TestTruncateThenAppendYieldsSingleEntry(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "x.wal")
	w, _ := server.NewWAL(p)
	defer w.Close()

	_ = w.Append(server.DeltaEntry{SeqNo: 1})
	_ = w.Truncate()
	if err := w.Append(server.DeltaEntry{SeqNo: 99, Type: server.DeltaTags}); err != nil {
		t.Fatal(err)
	}

	var seen []uint64
	n, err := w.Replay(func(e server.DeltaEntry) error {
		seen = append(seen, e.SeqNo)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(seen) != 1 || seen[0] != 99 {
		t.Fatalf("post-truncate replay: n=%d seen=%v", n, seen)
	}
}

// --- Close ----------------------------------------------------------------

func TestCloseClosesUnderlyingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "x.wal")
	w, _ := server.NewWAL(p)

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Second close of the same *os.File returns an error on most platforms —
	// the method is documented to just return whatever the file's Close does.
	if err := w.Close(); err == nil {
		t.Fatalf("expected error on double close of underlying file")
	}
}

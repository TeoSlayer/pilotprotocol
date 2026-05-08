// SPDX-License-Identifier: AGPL-3.0-or-later

package registry

import (
	"encoding/json"
	"sync"
	"testing"
)

// --- newDeltaLog ----------------------------------------------------------

func TestNewDeltaLogInitialState(t *testing.T) {
	dl := newDeltaLog()
	if dl == nil {
		t.Fatal("newDeltaLog returned nil")
	}
	if dl.Len() != 0 {
		t.Fatalf("Len: %d", dl.Len())
	}
	if got := dl.CurrentSeq(); got != 0 {
		t.Fatalf("CurrentSeq before any Append: %d, want 0 (nextSeq=1 → 1-1=0)", got)
	}
	if cap(dl.entries) != 1024 {
		t.Fatalf("entries cap: %d, want 1024", cap(dl.entries))
	}
}

// --- Append ---------------------------------------------------------------

func TestAppendReturnsMonotonicSeq(t *testing.T) {
	dl := newDeltaLog()
	data := json.RawMessage(`{"k":1}`)
	s1 := dl.Append(DeltaRegister, 10, data)
	s2 := dl.Append(DeltaHeartbeat, 20, nil)
	s3 := dl.Append(DeltaDeregister, 30, nil)
	if s1 != 1 || s2 != 2 || s3 != 3 {
		t.Fatalf("seq sequence: %d %d %d, want 1 2 3", s1, s2, s3)
	}
	if dl.Len() != 3 {
		t.Fatalf("Len: %d", dl.Len())
	}
	if dl.CurrentSeq() != 3 {
		t.Fatalf("CurrentSeq: %d", dl.CurrentSeq())
	}
}

func TestAppendPopulatesFields(t *testing.T) {
	dl := newDeltaLog()
	raw := json.RawMessage(`{"hello":"world"}`)
	dl.Append(DeltaRegister, 42, raw)
	dl.mu.Lock()
	e := dl.entries[0]
	dl.mu.Unlock()
	if e.SeqNo != 1 || e.Type != DeltaRegister || e.NodeID != 42 || string(e.Data) != `{"hello":"world"}` {
		t.Fatalf("entry: %+v", e)
	}
}

func TestAppendTrimsOldestWhenExceedingMax(t *testing.T) {
	dl := newDeltaLog()
	// Fill beyond maxDeltaLogSize (10000) — add exactly +5 over max.
	total := maxDeltaLogSize + 5
	for i := 0; i < total; i++ {
		dl.Append(DeltaHeartbeat, uint32(i), nil)
	}
	if dl.Len() != maxDeltaLogSize {
		t.Fatalf("Len after overflow: %d, want %d", dl.Len(), maxDeltaLogSize)
	}
	// Oldest 5 entries (SeqNos 1..5) should have been dropped.
	// Now the smallest seq in the log should be 6.
	dl.mu.Lock()
	first := dl.entries[0].SeqNo
	last := dl.entries[len(dl.entries)-1].SeqNo
	dl.mu.Unlock()
	if first != 6 {
		t.Fatalf("oldest retained SeqNo: %d, want 6", first)
	}
	if last != uint64(total) {
		t.Fatalf("newest SeqNo: %d, want %d", last, total)
	}
	if dl.CurrentSeq() != uint64(total) {
		t.Fatalf("CurrentSeq: %d, want %d", dl.CurrentSeq(), total)
	}
}

func TestAppendConcurrentProducesUniqueMonotonicSeqs(t *testing.T) {
	dl := newDeltaLog()
	const goroutines = 10
	const per = 50
	var wg sync.WaitGroup
	seqs := make(chan uint64, goroutines*per)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				seqs <- dl.Append(DeltaHeartbeat, 0, nil)
			}
		}()
	}
	wg.Wait()
	close(seqs)

	seen := make(map[uint64]bool, goroutines*per)
	for s := range seqs {
		if seen[s] {
			t.Fatalf("duplicate seq %d", s)
		}
		seen[s] = true
	}
	if len(seen) != goroutines*per {
		t.Fatalf("seqs: %d, want %d", len(seen), goroutines*per)
	}
	// Must be contiguous from 1..N.
	for i := uint64(1); i <= uint64(goroutines*per); i++ {
		if !seen[i] {
			t.Fatalf("missing seq %d", i)
		}
	}
}

// --- Since ----------------------------------------------------------------

func TestSinceEmptyLogReturnsNil(t *testing.T) {
	dl := newDeltaLog()
	if got := dl.Since(0); got != nil {
		t.Fatalf("Since on empty log: %v, want nil", got)
	}
}

func TestSinceTooOldReturnsNil(t *testing.T) {
	dl := newDeltaLog()
	// Forge the log to start at SeqNo=100 — simulates a log that has trimmed old entries.
	dl.mu.Lock()
	dl.entries = []DeltaEntry{
		{SeqNo: 100}, {SeqNo: 101}, {SeqNo: 102},
	}
	dl.nextSeq = 103
	dl.mu.Unlock()

	// Asking for Since(50) is before oldest → nil, caller must fall back to full snapshot.
	if got := dl.Since(50); got != nil {
		t.Fatalf("Since(50) too old: %v, want nil", got)
	}
}

func TestSinceUpToDateReturnsEmptyNonNil(t *testing.T) {
	dl := newDeltaLog()
	dl.Append(DeltaRegister, 1, nil) // seq 1
	dl.Append(DeltaRegister, 2, nil) // seq 2
	got := dl.Since(2)               // nothing newer than 2
	if got == nil {
		t.Fatalf("Since(2) when current=2 should return empty non-nil slice (up-to-date signal)")
	}
	if len(got) != 0 {
		t.Fatalf("Since(2): %d entries, want 0", len(got))
	}
}

func TestSinceReturnsOnlyNewerEntries(t *testing.T) {
	dl := newDeltaLog()
	for i := uint32(1); i <= 5; i++ {
		dl.Append(DeltaHeartbeat, i, nil) // seqs 1..5
	}
	got := dl.Since(2)
	if len(got) != 3 {
		t.Fatalf("Since(2): %d entries, want 3 (3,4,5)", len(got))
	}
	for i, want := range []uint64{3, 4, 5} {
		if got[i].SeqNo != want {
			t.Fatalf("got[%d].SeqNo=%d, want %d", i, got[i].SeqNo, want)
		}
	}
}

func TestSinceReturnsCopyNotAlias(t *testing.T) {
	dl := newDeltaLog()
	dl.Append(DeltaRegister, 1, nil) // seq 1
	dl.Append(DeltaRegister, 2, nil) // seq 2
	dl.Append(DeltaRegister, 3, nil) // seq 3
	// Since(1) returns entries with SeqNo > 1, i.e. seq 2 and seq 3.
	got := dl.Since(1)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	got[0].SeqNo = 999 // mutate returned slice
	got[1].NodeID = 999
	// Internal state must be unaffected.
	again := dl.Since(1)
	// Internal should still reflect the values passed to Append (seq 2,3 / nodeID 2,3).
	if again[0].SeqNo != 2 || again[1].SeqNo != 3 || again[1].NodeID != 3 {
		t.Fatalf("mutation leaked into internal entries: %+v", again)
	}
}

func TestSinceBoundaryAtOldestEntry(t *testing.T) {
	dl := newDeltaLog()
	for i := uint32(1); i <= 3; i++ {
		dl.Append(DeltaHeartbeat, i, nil)
	}
	// sinceSeq == oldest.SeqNo exactly → NOT too-old, should return entries > 1.
	got := dl.Since(1)
	if len(got) != 2 {
		t.Fatalf("Since(1) at exact oldest: %d entries, want 2 (2,3)", len(got))
	}
	if got[0].SeqNo != 2 {
		t.Fatalf("first entry SeqNo: %d, want 2", got[0].SeqNo)
	}
}

// --- CurrentSeq + Len -----------------------------------------------------

func TestCurrentSeqTracksNextSeq(t *testing.T) {
	dl := newDeltaLog()
	for i := 1; i <= 4; i++ {
		dl.Append(DeltaRegister, uint32(i), nil)
		if dl.CurrentSeq() != uint64(i) {
			t.Fatalf("after %d Appends CurrentSeq=%d want %d", i, dl.CurrentSeq(), i)
		}
	}
}

func TestCurrentSeqReturnsZeroWhenNextSeqZero(t *testing.T) {
	// Explicitly test the `nextSeq == 0` guard branch.
	dl := &deltaLog{nextSeq: 0}
	if dl.CurrentSeq() != 0 {
		t.Fatalf("CurrentSeq with nextSeq=0: %d, want 0", dl.CurrentSeq())
	}
}

func TestLenReflectsActualCount(t *testing.T) {
	dl := newDeltaLog()
	if dl.Len() != 0 {
		t.Fatalf("empty Len: %d", dl.Len())
	}
	for i := 0; i < 7; i++ {
		dl.Append(DeltaHeartbeat, 0, nil)
		if dl.Len() != i+1 {
			t.Fatalf("Len after %d Appends: %d, want %d", i+1, dl.Len(), i+1)
		}
	}
}

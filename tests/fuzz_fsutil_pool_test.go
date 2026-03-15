package tests

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/internal/fsutil"
	"github.com/TeoSlayer/pilotprotocol/internal/pool"
)

// ---------------------------------------------------------------------------
// AtomicWrite
// ---------------------------------------------------------------------------

func TestAtomicWriteBasic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	data := []byte(`{"key": "value"}`)
	if err := fsutil.AtomicWrite(path, data); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("content mismatch")
	}
}

func TestAtomicWriteOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	fsutil.AtomicWrite(path, []byte("old"))
	fsutil.AtomicWrite(path, []byte("new"))

	got, _ := os.ReadFile(path)
	if string(got) != "new" {
		t.Fatalf("expected 'new', got %q", got)
	}
}

func TestAtomicWriteEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")

	if err := fsutil.AtomicWrite(path, []byte{}); err != nil {
		t.Fatalf("AtomicWrite empty: %v", err)
	}

	got, _ := os.ReadFile(path)
	if len(got) != 0 {
		t.Fatalf("expected empty file, got %d bytes", len(got))
	}
}

func TestAtomicWriteNilData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nil.json")

	if err := fsutil.AtomicWrite(path, nil); err != nil {
		t.Fatalf("AtomicWrite nil: %v", err)
	}
}

func TestAtomicWriteLargeData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.bin")

	data := bytes.Repeat([]byte("A"), 1<<20) // 1MB
	if err := fsutil.AtomicWrite(path, data); err != nil {
		t.Fatalf("AtomicWrite large: %v", err)
	}

	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, data) {
		t.Fatal("large data mismatch")
	}
}

func TestAtomicWriteInvalidPath(t *testing.T) {
	err := fsutil.AtomicWrite("/nonexistent/dir/file.json", []byte("data"))
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestAtomicWriteNoTmpLeftover(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	fsutil.AtomicWrite(path, []byte("data"))

	// Ensure no .tmp file left
	tmpPath := path + ".tmp"
	if _, err := os.Stat(tmpPath); err == nil {
		t.Fatal("tmp file should not exist after successful write")
	}
}

func TestAtomicWriteConcurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "concurrent.json")

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			data := bytes.Repeat([]byte{byte(id)}, 100)
			fsutil.AtomicWrite(path, data)
		}(i)
	}
	wg.Wait()

	// File should exist and be valid (one of the writes)
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after concurrent: %v", err)
	}
	if len(got) != 100 {
		t.Fatalf("expected 100 bytes, got %d", len(got))
	}
	// All bytes should be the same (from one write)
	for _, b := range got {
		if b != got[0] {
			t.Fatal("file content is corrupted (interleaved writes)")
		}
	}
}

func TestAtomicWriteBinaryData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "binary.bin")

	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	if err := fsutil.AtomicWrite(path, data); err != nil {
		t.Fatalf("AtomicWrite binary: %v", err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, data) {
		t.Fatal("binary data mismatch")
	}
}

// ---------------------------------------------------------------------------
// Buffer Pool
// ---------------------------------------------------------------------------

func TestPoolSmallGetPut(t *testing.T) {
	b := pool.GetSmall()
	if b == nil {
		t.Fatal("GetSmall returned nil")
	}
	if len(*b) != pool.SmallBufSize {
		t.Fatalf("expected %d, got %d", pool.SmallBufSize, len(*b))
	}

	// Write some data
	(*b)[0] = 0xFF

	pool.PutSmall(b)
}

func TestPoolLargeGetPut(t *testing.T) {
	b := pool.GetLarge()
	if b == nil {
		t.Fatal("GetLarge returned nil")
	}
	if len(*b) != pool.LargeBufSize {
		t.Fatalf("expected %d, got %d", pool.LargeBufSize, len(*b))
	}

	pool.PutLarge(b)
}

func TestPoolSmallPutNil(t *testing.T) {
	pool.PutSmall(nil) // should not panic
}

func TestPoolLargePutNil(t *testing.T) {
	pool.PutLarge(nil) // should not panic
}

func TestPoolSmallPutUndersized(t *testing.T) {
	small := make([]byte, 10)
	pool.PutSmall(&small) // should be silently ignored (undersized)
}

func TestPoolLargePutUndersized(t *testing.T) {
	small := make([]byte, 10)
	pool.PutLarge(&small) // should be silently ignored (undersized)
}

func TestPoolSmallReuse(t *testing.T) {
	// Get, put, get again — may or may not get the same buffer
	b1 := pool.GetSmall()
	pool.PutSmall(b1)
	b2 := pool.GetSmall()
	pool.PutSmall(b2)

	// Both should be valid
	if len(*b1) != pool.SmallBufSize || len(*b2) != pool.SmallBufSize {
		t.Fatal("reused buffers have wrong size")
	}
}

func TestPoolLargeReuse(t *testing.T) {
	b1 := pool.GetLarge()
	pool.PutLarge(b1)
	b2 := pool.GetLarge()
	pool.PutLarge(b2)

	if len(*b1) != pool.LargeBufSize || len(*b2) != pool.LargeBufSize {
		t.Fatal("reused buffers have wrong size")
	}
}

func TestPoolConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				b := pool.GetSmall()
				(*b)[0] = byte(j)
				pool.PutSmall(b)

				lb := pool.GetLarge()
				(*lb)[0] = byte(j)
				pool.PutLarge(lb)
			}
		}()
	}
	wg.Wait()
}

func TestPoolSmallSizeAfterPut(t *testing.T) {
	b := pool.GetSmall()
	// Reslice to smaller
	*b = (*b)[:100]
	pool.PutSmall(b)

	// Get again — should be reset to full size
	b2 := pool.GetSmall()
	if len(*b2) != pool.SmallBufSize {
		t.Fatalf("expected reset to %d after Put, got %d", pool.SmallBufSize, len(*b2))
	}
	pool.PutSmall(b2)
}

func TestPoolLargeSizeAfterPut(t *testing.T) {
	b := pool.GetLarge()
	*b = (*b)[:100]
	pool.PutLarge(b)

	b2 := pool.GetLarge()
	if len(*b2) != pool.LargeBufSize {
		t.Fatalf("expected reset to %d after Put, got %d", pool.LargeBufSize, len(*b2))
	}
	pool.PutLarge(b2)
}

func TestPoolConstants(t *testing.T) {
	if pool.SmallBufSize != 4096 {
		t.Fatalf("SmallBufSize = %d, expected 4096", pool.SmallBufSize)
	}
	// LargeBufSize = 65535 + 38 = 65573
	if pool.LargeBufSize != 65573 {
		t.Fatalf("LargeBufSize = %d, expected 65573", pool.LargeBufSize)
	}
}

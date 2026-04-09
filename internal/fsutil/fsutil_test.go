package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteCreatesFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	data := []byte(`{"key":"value"}`)
	if err := AtomicWrite(path, data); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("content mismatch: %q", got)
	}
}

func TestAtomicWritePermissions0600(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "perms.json")

	if err := AtomicWrite(path, []byte("secret")); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected 0600, got %04o", perm)
	}
}

func TestAtomicWriteOverwrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "overwrite.json")

	if err := AtomicWrite(path, []byte("first")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := AtomicWrite(path, []byte("second")); err != nil {
		t.Fatalf("second write: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("expected 'second', got %q", got)
	}

	// Permissions still 0600 after overwrite
	info, _ := os.Stat(path)
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected 0600 after overwrite, got %04o", perm)
	}
}

func TestAtomicWriteNoTempFileRemains(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "clean.json")

	if err := AtomicWrite(path, []byte("data")); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}

	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file should not exist after successful write")
	}
}

func TestAtomicWriteEmptyData(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")

	if err := AtomicWrite(path, []byte{}); err != nil {
		t.Fatalf("AtomicWrite empty: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty file, got %d bytes", len(got))
	}
}

func TestAtomicWriteLargeData(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "large.json")

	data := make([]byte, 1<<20) // 1MB
	for i := range data {
		data[i] = byte(i % 256)
	}

	if err := AtomicWrite(path, data); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(got) != len(data) {
		t.Fatalf("size mismatch: %d != %d", len(got), len(data))
	}
}

func TestAtomicWriteBadDirectory(t *testing.T) {
	t.Parallel()
	err := AtomicWrite("/nonexistent/dir/file.json", []byte("data"))
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestAppendSyncCreatesFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "append.log")

	if err := AppendSync(path, []byte("line1\n")); err != nil {
		t.Fatalf("AppendSync: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "line1\n" {
		t.Fatalf("expected 'line1\\n', got %q", got)
	}
}

func TestAppendSyncAppends(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "multi.log")

	if err := AppendSync(path, []byte("a\n")); err != nil {
		t.Fatalf("first AppendSync: %v", err)
	}
	if err := AppendSync(path, []byte("b\n")); err != nil {
		t.Fatalf("second AppendSync: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "a\nb\n" {
		t.Fatalf("expected 'a\\nb\\n', got %q", got)
	}
}

func TestAppendSyncPermissions0600(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "perms.log")

	if err := AppendSync(path, []byte("x")); err != nil {
		t.Fatalf("AppendSync: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected 0600, got %04o", perm)
	}
}

func TestAppendSyncBadDirectory(t *testing.T) {
	t.Parallel()
	err := AppendSync("/nonexistent/dir/file.log", []byte("data"))
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

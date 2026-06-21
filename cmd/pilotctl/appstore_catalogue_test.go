package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUntarUnder_RejectsDecompressionBomb verifies that a tar entry
// exceeding maxUntarFileSize is rejected (decompression bomb guard).
func TestUntarUnder_RejectsDecompressionBomb(t *testing.T) {
	dst := t.TempDir()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	// Create a file entry with size = maxUntarFileSize + 1
	size := maxUntarFileSize + 1
	hdr := &tar.Header{
		Name:     "bomb.bin",
		Size:     size,
		Typeflag: tar.TypeReg,
		Mode:     0644,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	// Write exactly the declared size (128 MiB + 1)
	chunk := make([]byte, 65536)
	written := int64(0)
	for written < size {
		n := int64(len(chunk))
		if written+n > size {
			n = size - written
		}
		if _, err := tw.Write(chunk[:n]); err != nil {
			t.Fatal(err)
		}
		written += n
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	gzr, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	defer gzr.Close()
	err = untarUnder(gzr, dst)
	if err == nil {
		t.Fatal("expected decompression bomb rejection, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maxUntarFileSize") {
		t.Fatalf("expected maxUntarFileSize error, got: %v", err)
	}

	// The entry must NOT have been written to disk
	entries, _ := os.ReadDir(dst)
	for _, e := range entries {
		if e.Name() == "bomb.bin" {
			t.Fatal("decompression bomb entry was written to disk despite being rejected")
		}
	}
}

// TestUntarUnder_RejectsPathTraversal ensures the existing traversal
// guard still works.
func TestUntarUnder_RejectsPathTraversal(t *testing.T) {
	dst := t.TempDir()
	traversal := []string{
		"../../../etc/passwd",
		"foo/../../etc/passwd",
		"..",
	}
	for _, p := range traversal {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)

		hdr := &tar.Header{
			Name:     p,
			Size:     4,
			Typeflag: tar.TypeReg,
			Mode:     0644,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte("data")); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		if err := untarUnder(&buf, dst); err == nil {
			t.Errorf("expected path traversal rejection for %q", p)
		}
	}
}

// TestUntarUnder_AcceptsNormalBundle ensures a legitimate tarball
// still extracts correctly.
func TestUntarUnder_AcceptsNormalBundle(t *testing.T) {
	dst := t.TempDir()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	if err := tw.WriteHeader(&tar.Header{Name: "app/", Typeflag: tar.TypeDir, Mode: 0755}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "app/v1", Size: 5, Typeflag: tar.TypeReg, Mode: 0644}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "app/manifest.json", Size: 2, Typeflag: tar.TypeReg, Mode: 0644}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("{}")); err != nil {
		t.Fatal(err)
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	gzr, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	defer gzr.Close()
	if err := untarUnder(gzr, dst); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dst, "app", "v1")); os.IsNotExist(err) {
		t.Fatal("expected app/v1 to exist")
	}
	if _, err := os.Stat(filepath.Join(dst, "app", "manifest.json")); os.IsNotExist(err) {
		t.Fatal("expected app/manifest.json to exist")
	}
}

// TestUntarUnder_AllowsFileUpToLimit ensures a file at exactly
// maxUntarFileSize is accepted.
func TestUntarUnder_AllowsFileUpToLimit(t *testing.T) {
	dst := t.TempDir()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	hdr := &tar.Header{
		Name:     "bigfile.bin",
		Size:     maxUntarFileSize,
		Typeflag: tar.TypeReg,
		Mode:     0644,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 65536)
	written := int64(0)
	for written < maxUntarFileSize {
		n := int64(len(chunk))
		if written+n > maxUntarFileSize {
			n = maxUntarFileSize - written
		}
		if _, err := tw.Write(chunk[:n]); err != nil {
			t.Fatal(err)
		}
		written += n
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	gzr, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	defer gzr.Close()
	if err := untarUnder(gzr, dst); err != nil {
		t.Fatalf("expected no error for file at limit, got: %v", err)
	}

	fi, err := os.Stat(filepath.Join(dst, "bigfile.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != maxUntarFileSize {
		t.Fatalf("expected file size %d, got %d", maxUntarFileSize, fi.Size())
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBackupIdentityNoFile: nothing to back up when the path is absent.
// Returns ("", nil) so the caller proceeds to write a fresh identity.
func TestBackupIdentityNoFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")

	bak, err := backupIdentity(path)
	if err != nil {
		t.Fatalf("backupIdentity on missing file: unexpected error %v", err)
	}
	if bak != "" {
		t.Fatalf("expected empty backup path for missing file, got %q", bak)
	}
}

// TestBackupIdentityCopiesExisting: an existing identity is copied to a
// timestamped .bak file with its contents preserved, and the original is
// left in place for SaveIdentity to overwrite.
func TestBackupIdentityCopiesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	const content = `{"node_id":42,"private_key":"old"}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	bak, err := backupIdentity(path)
	if err != nil {
		t.Fatalf("backupIdentity: unexpected error %v", err)
	}
	if bak == "" {
		t.Fatal("expected a backup path, got empty")
	}
	if !strings.HasPrefix(bak, path+".bak-") {
		t.Fatalf("backup path %q lacks expected prefix %q.bak-", bak, path)
	}

	got, err := os.ReadFile(bak)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(got) != content {
		t.Fatalf("backup content mismatch: got %q want %q", got, content)
	}

	// Original must still exist (we copy, not move) so the overwrite path
	// has something to replace.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("original identity should remain: %v", err)
	}
}

// TestBackupIdentityRefusesUnwritable: when a file exists but the backup
// cannot be written, an error is returned so the caller refuses to
// overwrite the live identity blind.
func TestBackupIdentityRefusesUnwritable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	// Make the directory read-only so the .bak sibling can't be created.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions")
	}

	if _, err := backupIdentity(path); err == nil {
		t.Fatal("expected error when backup cannot be written, got nil")
	}
}

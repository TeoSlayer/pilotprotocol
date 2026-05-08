// SPDX-License-Identifier: AGPL-3.0-or-later

package account

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Save's error paths: MkdirAll, AtomicWrite (surfaced through a regular file
// sitting on the intended directory path).
func TestSaveMkdirAllFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Create a regular file where Save wants to place the directory: writing
	// into blocker/ fails because blocker is not a directory.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}
	target := filepath.Join(blocker, "account.json")
	err := Save(target, &Account{Email: "x@example.com"})
	if err == nil {
		t.Fatal("expected MkdirAll failure when a file exists where dir should go")
	}
	if !strings.Contains(err.Error(), "create account dir") {
		t.Fatalf("error should mention create account dir, got %v", err)
	}
}

func TestLoadReadErrorNonExistIsNil(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	acct, err := Load(filepath.Join(dir, "missing.json"))
	if err != nil {
		t.Fatalf("missing file should return (nil,nil): %v", err)
	}
	if acct != nil {
		t.Fatalf("expected nil account, got %+v", acct)
	}
}

func TestLoadReadErrorPermission(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Pointing Load at a directory: os.ReadFile returns a non-IsNotExist error
	// ("is a directory" on darwin/linux), hitting the read-account branch.
	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error reading a directory as a file")
	}
	if !strings.Contains(err.Error(), "read account") {
		t.Fatalf("expected wrapped error, got %v", err)
	}
}

func TestLoadMalformedJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
	if !strings.Contains(err.Error(), "unmarshal account") {
		t.Fatalf("expected wrapped unmarshal error, got %v", err)
	}
}

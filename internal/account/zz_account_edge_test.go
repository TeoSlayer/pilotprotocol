// SPDX-License-Identifier: AGPL-3.0-or-later

package account_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pilot-protocol/pilotprotocol/internal/account"
)

func TestSave_MkdirAllError(t *testing.T) {
	t.Parallel()
	// Use a file as the parent directory — MkdirAll will fail because we
	// can't create a directory under a regular file.
	dir := t.TempDir()
	regularFile := filepath.Join(dir, "block")
	if err := os.WriteFile(regularFile, []byte("x"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Attempt to save under <regularFile>/sub/account.json — MkdirAll fails.
	err := account.Save(filepath.Join(regularFile, "sub", "account.json"), &account.Account{Email: "a@b.co"})
	if err == nil {
		t.Fatal("Save() under regular-file parent: want error, got nil")
	}
	if !strings.Contains(err.Error(), "create account dir") {
		t.Errorf("want 'create account dir' error, got %v", err)
	}
}

func TestSave_AtomicWriteError(t *testing.T) {
	t.Parallel()
	// AtomicWrite fails when the path is a directory (it can't truncate
	// a directory as if it were a file).
	dir := t.TempDir()
	subdir := filepath.Join(dir, "iam-a-directory")
	if err := os.MkdirAll(subdir, 0700); err != nil {
		t.Fatalf("setup: %v", err)
	}
	err := account.Save(subdir, &account.Account{Email: "a@b.co"})
	if err == nil {
		t.Fatal("Save() on a directory path: want error, got nil")
	}
	// The error path is either "write account" (AtomicWrite tried to open
	// dir as file) or Chmod failure — either is fine, both exercise the
	// uncovered branches.
}

package account

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "account.json")

	acct := &Account{Email: "user@example.com"}
	if err := Save(path, acct); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded == nil {
		t.Fatal("Load returned nil")
	}
	if loaded.Email != "user@example.com" {
		t.Errorf("Email = %q, want %q", loaded.Email, "user@example.com")
	}

	// Check file permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("permissions = %o, want 0600", perm)
	}
}

func TestLoadNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.json")

	acct, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if acct != nil {
		t.Errorf("expected nil account for nonexistent file, got %+v", acct)
	}
}

func TestSaveOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "account.json")

	if err := Save(path, &Account{Email: "old@example.com"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := Save(path, &Account{Email: "new@example.com"}); err != nil {
		t.Fatalf("Save overwrite: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Email != "new@example.com" {
		t.Errorf("Email = %q, want %q", loaded.Email, "new@example.com")
	}
}

func TestPathFromIdentity(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"/var/lib/pilot/identity.json", "/var/lib/pilot/account.json"},
		{"/home/user/.pilot/identity.json", "/home/user/.pilot/account.json"},
		{"identity.json", "account.json"},
	}
	for _, tc := range cases {
		got := PathFromIdentity(tc.input)
		if got != tc.want {
			t.Errorf("PathFromIdentity(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSaveCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "account.json")

	if err := Save(path, &Account{Email: "user@example.com"}); err != nil {
		t.Fatalf("Save with nested dir: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Email != "user@example.com" {
		t.Errorf("Email = %q, want %q", loaded.Email, "user@example.com")
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverManagedEnterpriseControlRequiresOwnerOnlyRegularFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if _, ok := discoverManagedEnterpriseControl(); ok {
		t.Fatal("missing attachment was discovered")
	}
	path := filepath.Join(home, ".pilot", "managed", "enterprise-control.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if discovered, ok := discoverManagedEnterpriseControl(); !ok || discovered != path {
		t.Fatalf("discovered=%q ok=%v", discovered, ok)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := discoverManagedEnterpriseControl(); ok {
		t.Fatal("group/world-readable attachment was discovered")
	}
}

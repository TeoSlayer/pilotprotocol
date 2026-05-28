// SPDX-License-Identifier: AGPL-3.0-or-later

package compat

import (
	"embed"
	"strings"
	"testing"
)

// noPemRootsFS — embed.FS containing exactly one entry under "roots/" that
// does NOT end in ".pem". When swapped in for the package-private rootsFS,
// PinnedRoots ReadDirs "roots", finds one entry, skips it via the
// !HasSuffix(".pem") guard, loaded stays at 0, and the function returns
// the "no embedded Pilot Protocol roots found" error.
//
// The fixture file lives at internal/transport/compat/roots/.testdata-marker
// — a dot-file ignored by production's `//go:embed roots/*.pem` glob (Go
// embed patterns follow shell semantics; `*` does not match dot files).
// This keeps the production binary's embedded roots set unchanged.
//
//go:embed roots/.testdata-marker
var noPemRootsFS embed.FS

// TestPinnedRoots_ReadDirError swaps rootsFS to a zero-valued embed.FS so
// that fs.ReadDir(emptyFS, "roots") returns "file does not exist", which
// PinnedRoots wraps as "read embedded roots: %w".
//
// This branch is unreachable with the real rootsFS because the production
// embed always contains the prod-*.pem files under roots/.
//
// IMPORTANT: tests in this file mutate the package-global rootsFS. We
// save+restore it in t.Cleanup so the rest of the suite (e.g.
// zz_roots_test.go) sees the original embed.
func TestPinnedRoots_ReadDirError(t *testing.T) {
	orig := rootsFS
	t.Cleanup(func() { rootsFS = orig })
	rootsFS = embed.FS{} // zero value: no entries, "roots" path missing

	_, err := PinnedRoots()
	if err == nil {
		t.Fatal("expected ReadDir error on empty FS")
	}
	if !strings.Contains(err.Error(), "read embedded roots") {
		t.Errorf("err = %v", err)
	}
}

// TestPinnedRoots_NoPemEntriesYieldsNoRootsError covers two coverage gaps
// in one go:
//
//  1. the for-loop's `if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem")`
//     skip-branch fires when scanning a non-pem entry, exercising the
//     `continue` statement
//  2. with no .pem files loaded, the final `if loaded == 0` branch returns
//     "no embedded Pilot Protocol roots found"
//
// Both are unreachable with the production rootsFS, which always contains
// at least one valid prod-*.pem file.
func TestPinnedRoots_NoPemEntriesYieldsNoRootsError(t *testing.T) {
	orig := rootsFS
	t.Cleanup(func() { rootsFS = orig })
	rootsFS = noPemRootsFS

	_, err := PinnedRoots()
	if err == nil {
		t.Fatal("expected no-roots error when only non-pem entries exist")
	}
	if !strings.Contains(err.Error(), "no embedded") {
		t.Errorf("err = %v, want 'no embedded' substring", err)
	}
}

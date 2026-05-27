// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"path/filepath"
	"testing"
	"time"

	registry "github.com/pilot-protocol/rendezvous"
)

// startTestServer + startTestServerWithStore were originally defined
// in zz_fuzz_registry_server_test.go but that file became
// //go:build nightly when it was scoped out of PR CI. Two non-nightly
// files (zz_security_phase2_test.go, zz_security_fixes_test.go) still
// reference these helpers, so they need to live in a default-tag
// file. Keeping them in their own helper file rather than testenv.go
// so the dependency on `pilot-protocol/rendezvous` stays narrowly
// scoped.

func startTestServer(t *testing.T) *registry.Server {
	t.Helper()
	s := registry.New("")
	go s.ListenAndServe("127.0.0.1:0")
	select {
	case <-s.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("registry server did not start in time")
	}
	return s
}

func startTestServerWithStore(t *testing.T) (*registry.Server, string) {
	t.Helper()
	dir := t.TempDir()
	storePath := filepath.Join(dir, "registry.json")
	s := registry.NewWithStore("", storePath)
	go s.ListenAndServe("127.0.0.1:0")
	select {
	case <-s.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("registry server did not start in time")
	}
	return s, storePath
}

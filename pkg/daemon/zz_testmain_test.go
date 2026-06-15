package daemon

import (
	"os"
	"testing"
)

// TestMain isolates HOME for the entire package test binary.
//
// Many tests here construct a daemon with New(Config{}) (empty
// IdentityPath). Such a daemon resolves its on-disk state — managed-engine
// files (~/.pilot/managed_<netID>.json), the hostname cache, the network
// snapshot — under os.UserHomeDir(). Without isolation those tests read and
// write the *real* home concurrently: both within this package's parallel
// tests and across the packages that `go test ./...` runs in parallel on a
// shared CI runner. That races on the same files and flakes (observed
// reddening macOS CI on the snapshot / hostname-cache / managed-engine
// tests, which pass in isolation).
//
// Pointing HOME (and USERPROFILE, for os.UserHomeDir on Windows) at a
// throwaway directory before any test runs makes every test in this
// package hermetic. Tests that set their own HOME via t.Setenv still work —
// they override and restore relative to this base.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "pilot-daemon-test-home-")
	if err != nil {
		panic("daemon test: create temp HOME: " + err.Error())
	}
	_ = os.Setenv("HOME", tmp)
	_ = os.Setenv("USERPROFILE", tmp)

	code := m.Run()

	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

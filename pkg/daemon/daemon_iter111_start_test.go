package daemon

import (
	"strings"
	"testing"
)

// Iter-111 coverage for Daemon.Start (0% baseline) — the main entry point
// at daemon.go:341. Full Start() needs a registry, beacon, UDP socket, etc.
// and is very hard to exercise end-to-end in unit tests. But the early
// validation branches (email required, email format check) short-circuit
// before any network I/O and are purely input-validation — high value,
// low cost to cover.

// --- Start: empty email → "email address required" ---

func TestDaemonStartEmptyEmailReturnsError(t *testing.T) {
	d := New(Config{})
	err := d.Start()
	if err == nil {
		t.Fatal("Start with no email should return error")
	}
	if !strings.Contains(err.Error(), "email address required") {
		t.Fatalf("err = %q, want 'email address required'", err.Error())
	}
}

// --- Start: invalid email format → "invalid email" ---

func TestDaemonStartInvalidEmailReturnsError(t *testing.T) {
	d := New(Config{Email: "not-an-email-address"})
	err := d.Start()
	if err == nil {
		t.Fatal("Start with malformed email should return error")
	}
	if !strings.Contains(err.Error(), "invalid email") {
		t.Fatalf("err = %q, want 'invalid email'", err.Error())
	}
}

// --- Start: Owner (deprecated) falls back as email when Email is empty ---

func TestDaemonStartUsesOwnerAsEmailFallback(t *testing.T) {
	// Config with Owner set but Email empty. The fallback at daemon.go:343-345
	// should copy Owner into email, then validate it. We pass a MALFORMED Owner
	// so validation still fails — but now with "invalid email" (proving Owner
	// was picked up), not "email address required".
	d := New(Config{Owner: "bad-owner"})
	err := d.Start()
	if err == nil {
		t.Fatal("Start with bad Owner should fail email validation")
	}
	if strings.Contains(err.Error(), "email address required") {
		t.Fatalf("err = %q — Owner fallback didn't kick in (required path hit)", err.Error())
	}
	if !strings.Contains(err.Error(), "invalid email") {
		t.Fatalf("err = %q, want 'invalid email' (proves Owner→email copy ran)", err.Error())
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon_test

import (
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
)

// Daemon.Start validation coverage. Empty-email no longer hard-fails —
// the daemon synthesises a `<fp>@nodes.pilotprotocol.network` address from
// the public-key fingerprint when no email is supplied. Invalid-format and
// Owner-fallback paths still return the same errors.

// --- Start: invalid email format → "invalid email" ---

func TestDaemonStartInvalidEmailReturnsError(t *testing.T) {
	t.Parallel()
	d := daemon.New(daemon.Config{Email: "not-an-email-address"})
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
	t.Parallel()
	// Config with Owner set but Email empty. The fallback should copy Owner
	// into email, then validate it. A MALFORMED Owner means validation fails
	// with "invalid email" (proving Owner was picked up), not the synthesised
	// path.
	d := daemon.New(daemon.Config{Owner: "bad-owner"})
	err := d.Start()
	if err == nil {
		t.Fatal("Start with bad Owner should fail email validation")
	}
	if !strings.Contains(err.Error(), "invalid email") {
		t.Fatalf("err = %q, want 'invalid email' (proves Owner→email copy ran)", err.Error())
	}
}

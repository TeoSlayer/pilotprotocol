package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/internal/account"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
)

func TestDaemonRequiresEmail(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	sockPath := env.SocketPath("no-email")
	d := daemon.New(daemon.Config{
		RegistryAddr: env.RegistryAddr,
		BeaconAddr:   env.BeaconAddr,
		ListenAddr:   ":0",
		SocketPath:   sockPath,
		Public:       true,
	})

	err := d.Start()
	if err == nil {
		d.Stop()
		t.Fatal("expected error when starting without email, got nil")
	}
	if !strings.Contains(err.Error(), "email address required") {
		t.Fatalf("expected 'email address required' error, got: %v", err)
	}
}

func TestDaemonStartsWithEmail(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	tmpDir, err := os.MkdirTemp("/tmp", "w4-email-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	identityPath := filepath.Join(tmpDir, "identity.json")
	sockPath := env.SocketPath("with-email")

	d := daemon.New(daemon.Config{
		RegistryAddr: env.RegistryAddr,
		BeaconAddr:   env.BeaconAddr,
		ListenAddr:   ":0",
		SocketPath:   sockPath,
		IdentityPath: identityPath,
		Email:        "user@example.com",
		Public:       true,
	})

	if err := d.Start(); err != nil {
		t.Fatalf("daemon start: %v", err)
	}
	defer d.Stop()

	// Verify account file was created
	acctPath := account.PathFromIdentity(identityPath)
	acct, err := account.Load(acctPath)
	if err != nil {
		t.Fatalf("load account: %v", err)
	}
	if acct == nil {
		t.Fatal("account file not created")
	}
	if acct.Email != "user@example.com" {
		t.Errorf("account email = %q, want %q", acct.Email, "user@example.com")
	}
}

func TestDaemonLoadsEmailFromAccount(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	tmpDir, err := os.MkdirTemp("/tmp", "w4-email-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	identityPath := filepath.Join(tmpDir, "identity.json")

	// First start: provide email, creates account file
	sockPath1 := env.SocketPath("load-email-1")
	d1 := daemon.New(daemon.Config{
		RegistryAddr: env.RegistryAddr,
		BeaconAddr:   env.BeaconAddr,
		ListenAddr:   ":0",
		SocketPath:   sockPath1,
		IdentityPath: identityPath,
		Email:        "user@example.com",
		Public:       true,
	})
	if err := d1.Start(); err != nil {
		t.Fatalf("first start: %v", err)
	}
	d1.Stop()

	// Second start: no email flag, should load from account file
	sockPath2 := env.SocketPath("load-email-2")
	d2 := daemon.New(daemon.Config{
		RegistryAddr: env.RegistryAddr,
		BeaconAddr:   env.BeaconAddr,
		ListenAddr:   ":0",
		SocketPath:   sockPath2,
		IdentityPath: identityPath,
		Public:       true,
	})
	if err := d2.Start(); err != nil {
		t.Fatalf("second start (should load from account): %v", err)
	}
	defer d2.Stop()

	// Verify the daemon has the correct email
	info := d2.Info()
	if info.Email != "user@example.com" {
		t.Errorf("Email = %q, want %q", info.Email, "user@example.com")
	}
}

func TestDaemonEmailUpdateOverwrite(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	tmpDir, err := os.MkdirTemp("/tmp", "w4-email-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	identityPath := filepath.Join(tmpDir, "identity.json")

	// First start with original email
	sockPath1 := env.SocketPath("overwrite-1")
	d1 := daemon.New(daemon.Config{
		RegistryAddr: env.RegistryAddr,
		BeaconAddr:   env.BeaconAddr,
		ListenAddr:   ":0",
		SocketPath:   sockPath1,
		IdentityPath: identityPath,
		Email:        "old@example.com",
		Public:       true,
	})
	if err := d1.Start(); err != nil {
		t.Fatalf("first start: %v", err)
	}
	d1.Stop()

	// Second start with new email
	sockPath2 := env.SocketPath("overwrite-2")
	d2 := daemon.New(daemon.Config{
		RegistryAddr: env.RegistryAddr,
		BeaconAddr:   env.BeaconAddr,
		ListenAddr:   ":0",
		SocketPath:   sockPath2,
		IdentityPath: identityPath,
		Email:        "new@example.com",
		Public:       true,
	})
	if err := d2.Start(); err != nil {
		t.Fatalf("second start: %v", err)
	}
	defer d2.Stop()

	// Verify account file was updated
	acctPath := account.PathFromIdentity(identityPath)
	acct, err := account.Load(acctPath)
	if err != nil {
		t.Fatalf("load account: %v", err)
	}
	if acct.Email != "new@example.com" {
		t.Errorf("account email = %q, want %q", acct.Email, "new@example.com")
	}
}

func TestDaemonEmailValidation(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	invalidEmails := []string{
		"noatsign",
		"user@nodot",
		"user with spaces@example.com",
	}

	for _, email := range invalidEmails {
		sockPath := env.SocketPath("invalid-email")
		d := daemon.New(daemon.Config{
			RegistryAddr: env.RegistryAddr,
			BeaconAddr:   env.BeaconAddr,
			ListenAddr:   ":0",
			SocketPath:   sockPath,
			Email:        email,
			Public:       true,
		})
		err := d.Start()
		if err == nil {
			d.Stop()
			t.Errorf("expected error for email %q, got nil", email)
			continue
		}
		if !strings.Contains(err.Error(), "invalid email") {
			t.Errorf("email %q: expected 'invalid email' error, got: %v", email, err)
		}
	}
}

func TestDaemonOwnerFlagBackcompat(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	sockPath := env.SocketPath("owner-compat")
	d := daemon.New(daemon.Config{
		RegistryAddr: env.RegistryAddr,
		BeaconAddr:   env.BeaconAddr,
		ListenAddr:   ":0",
		SocketPath:   sockPath,
		Owner:        "compat@example.com",
		Public:       true,
	})

	if err := d.Start(); err != nil {
		t.Fatalf("daemon start with -owner: %v", err)
	}
	defer d.Stop()

	info := d.Info()
	if info.Email != "compat@example.com" {
		t.Errorf("Email = %q, want %q", info.Email, "compat@example.com")
	}
}

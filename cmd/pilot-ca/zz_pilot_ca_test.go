// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestInitRoot_HappyPath pins that init-root produces a self-signed
// Ed25519 CA with the right validity, key usage, and file modes.
// Anyone breaking these properties — wrong KeyUsage, longer validity,
// world-readable .key — fails this test before they ship.
func TestInitRoot_HappyPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := initRoot(dir); err != nil {
		t.Fatalf("initRoot: %v", err)
	}

	// Files exist with the right modes.
	keyInfo, err := os.Stat(filepath.Join(dir, "root.key"))
	if err != nil {
		t.Fatalf("root.key missing: %v", err)
	}
	if mode := keyInfo.Mode().Perm(); mode != 0o600 {
		t.Errorf("root.key mode = %o; want 0600 (private)", mode)
	}
	crtInfo, err := os.Stat(filepath.Join(dir, "root.crt"))
	if err != nil {
		t.Fatalf("root.crt missing: %v", err)
	}
	if mode := crtInfo.Mode().Perm(); mode != 0o644 {
		t.Errorf("root.crt mode = %o; want 0644", mode)
	}

	cert := mustReadCert(t, filepath.Join(dir, "root.crt"))

	if !cert.IsCA {
		t.Error("root cert IsCA = false; want true")
	}
	if !cert.BasicConstraintsValid {
		t.Error("root cert BasicConstraintsValid = false")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("root cert missing KeyUsageCertSign")
	}
	if cert.Subject.CommonName != caCommonName {
		t.Errorf("root CN = %q; want %q", cert.Subject.CommonName, caCommonName)
	}

	// Validity: should be ~10 years out.
	yrs := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24 / 365
	if yrs < float64(rootValidYears)-0.5 || yrs > float64(rootValidYears)+0.5 {
		t.Errorf("root validity = %.2f years; want %d", yrs, rootValidYears)
	}

	// Self-signed.
	if cert.Issuer.CommonName != cert.Subject.CommonName {
		t.Errorf("root is not self-signed: issuer=%q subject=%q", cert.Issuer.CommonName, cert.Subject.CommonName)
	}
}

// TestInitRoot_RefusesOverwrite pins the safety check: if root.key
// already exists in the target dir, init-root must abort. Operators
// run this on the offline host; an accidental re-run would silently
// destroy the live root key and brick every leaf cert ever issued.
func TestInitRoot_RefusesOverwrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := initRoot(dir); err != nil {
		t.Fatalf("first initRoot: %v", err)
	}
	err := initRoot(dir)
	if err == nil {
		t.Fatal("second initRoot returned nil; want refusal-to-overwrite error")
	}
	if !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Errorf("error = %q; want it to mention 'refusing to overwrite'", err.Error())
	}
}

// TestIssueBeacon_ChainsToRoot is the integration test: end-to-end
// init-root → issue-beacon → verify produces a leaf that x509.Verify
// accepts against the root. If the leaf doesn't chain, every compat
// daemon would reject every TLS handshake.
func TestIssueBeacon_ChainsToRoot(t *testing.T) {
	t.Parallel()
	rootDir := t.TempDir()
	leafDir := t.TempDir()
	if err := initRoot(rootDir); err != nil {
		t.Fatalf("initRoot: %v", err)
	}
	host := "beacon-test.example.invalid"
	if err := issueBeacon(rootDir, host, leafDir); err != nil {
		t.Fatalf("issueBeacon: %v", err)
	}

	leafCrt := filepath.Join(leafDir, host+".crt")
	leafKey := filepath.Join(leafDir, host+".key")

	leaf := mustReadCert(t, leafCrt)

	// File modes are correct (leaf .key must be 0600).
	if info, err := os.Stat(leafKey); err != nil {
		t.Fatalf("leaf .key missing: %v", err)
	} else if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("leaf .key mode = %o; want 0600", mode)
	}

	// Leaf has the right SAN.
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != host {
		t.Errorf("leaf DNSNames = %v; want [%s]", leaf.DNSNames, host)
	}
	// Leaf is NOT a CA.
	if leaf.IsCA {
		t.Error("leaf cert IsCA = true; want false (leaves must not sign other certs)")
	}
	// Leaf has serverAuth EKU.
	hasServerAuth := false
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}
	if !hasServerAuth {
		t.Error("leaf missing ExtKeyUsageServerAuth")
	}

	// Validity: ~90 days.
	days := leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24
	if days < float64(leafValidDays)-1 || days > float64(leafValidDays)+1 {
		t.Errorf("leaf validity = %.1f days; want %d", days, leafValidDays)
	}

	// END-TO-END: leaf chains to root using stdlib verify.
	root := mustReadCert(t, filepath.Join(rootDir, "root.crt"))
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       pool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:     host,
		CurrentTime: time.Now(),
	}); err != nil {
		t.Fatalf("leaf does NOT chain to root: %v", err)
	}
}

// TestIssueBeacon_RejectsEmptyHostname pins that we don't silently
// produce a cert with empty CN/SAN. Empty SAN matches no hostname →
// every TLS handshake would fail, but the operator wouldn't know
// until deploy.
func TestIssueBeacon_RejectsEmptyHostname(t *testing.T) {
	t.Parallel()
	rootDir := t.TempDir()
	if err := initRoot(rootDir); err != nil {
		t.Fatalf("initRoot: %v", err)
	}
	err := issueBeacon(rootDir, "", t.TempDir())
	if err == nil {
		t.Fatal("expected error for empty hostname; got nil")
	}
	if !strings.Contains(err.Error(), "hostname") {
		t.Errorf("error = %q; want it to mention 'hostname'", err.Error())
	}
}

// TestIssueBeacon_FailsWithoutRoot pins that if the operator points
// issue-beacon at a directory with no root.key (e.g. forgot to mount
// from custody hardware), the tool fails loudly instead of silently
// minting an unverified or self-signed leaf.
func TestIssueBeacon_FailsWithoutRoot(t *testing.T) {
	t.Parallel()
	emptyDir := t.TempDir() // no root.key, no root.crt
	err := issueBeacon(emptyDir, "test.example", t.TempDir())
	if err == nil {
		t.Fatal("issueBeacon succeeded with empty root dir; expected error")
	}
}

// TestVerifyChain_AcceptsValid is the happy path: mint root + leaf,
// confirm verifyChain returns nil.
func TestVerifyChain_AcceptsValid(t *testing.T) {
	t.Parallel()
	rootDir := t.TempDir()
	leafDir := t.TempDir()
	if err := initRoot(rootDir); err != nil {
		t.Fatalf("initRoot: %v", err)
	}
	host := "verify-happy.example.invalid"
	if err := issueBeacon(rootDir, host, leafDir); err != nil {
		t.Fatalf("issueBeacon: %v", err)
	}
	if err := verifyChain(filepath.Join(rootDir, "root.crt"), filepath.Join(leafDir, host+".crt")); err != nil {
		t.Errorf("verifyChain rejected valid chain: %v", err)
	}
}

// TestVerifyChain_RejectsUnrelatedRoot pins the negative case: a leaf
// signed by root A must NOT verify against root B. Catches a regression
// where verify might fall back to "any root" or accept self-signed
// leaves.
func TestVerifyChain_RejectsUnrelatedRoot(t *testing.T) {
	t.Parallel()
	rootA := t.TempDir()
	rootB := t.TempDir()
	leafDir := t.TempDir()
	if err := initRoot(rootA); err != nil {
		t.Fatalf("initRoot A: %v", err)
	}
	if err := initRoot(rootB); err != nil {
		t.Fatalf("initRoot B: %v", err)
	}
	host := "wrong-root.example.invalid"
	if err := issueBeacon(rootA, host, leafDir); err != nil {
		t.Fatalf("issueBeacon: %v", err)
	}
	// Leaf was signed by rootA, but we verify against rootB.
	err := verifyChain(filepath.Join(rootB, "root.crt"), filepath.Join(leafDir, host+".crt"))
	if err == nil {
		t.Fatal("verifyChain accepted leaf signed by a different root; expected rejection")
	}
}

// TestVerifyChain_RejectsBadPEM pins that bogus inputs fail with a
// clear error, not a panic.
func TestVerifyChain_RejectsBadPEM(t *testing.T) {
	t.Parallel()
	junk := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(junk, []byte("not a pem"), 0o644); err != nil {
		t.Fatalf("seed junk: %v", err)
	}
	err := verifyChain(junk, junk)
	if err == nil {
		t.Fatal("verifyChain accepted garbage PEM; expected rejection")
	}
}

// TestRandomSerial_Unique pins that serial generation produces 128-bit
// values with no detectable bias (sanity-check across N draws).
func TestRandomSerial_Unique(t *testing.T) {
	t.Parallel()
	seen := map[string]struct{}{}
	for i := 0; i < 100; i++ {
		s, err := randomSerial()
		if err != nil {
			t.Fatalf("randomSerial: %v", err)
		}
		key := s.String()
		if _, dup := seen[key]; dup {
			t.Fatalf("serial collision after %d draws — RNG broken", i)
		}
		seen[key] = struct{}{}
		if s.BitLen() < 64 {
			t.Errorf("serial too small (%d bits); want ~128", s.BitLen())
		}
	}
}

// mustReadCert reads a PEM-encoded cert and parses it, failing the
// test on any error.
func mustReadCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("%s: invalid PEM", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("%s: parse: %v", path, err)
	}
	return cert
}

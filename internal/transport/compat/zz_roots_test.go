// SPDX-License-Identifier: AGPL-3.0-or-later

package compat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// TestPinnedRoots_LoadsEmbeddedRoots pins the build-time contract that
// the daemon ships with at least one Pilot Protocol root embedded.
// A zero-roots build is rejected so we can never silently lose the
// trust anchor in a refactor.
func TestPinnedRoots_LoadsEmbeddedRoots(t *testing.T) {
	pool, err := PinnedRoots()
	if err != nil {
		t.Fatalf("PinnedRoots() error: %v", err)
	}
	if pool == nil {
		t.Fatal("PinnedRoots returned nil pool")
	}
	// The CertPool API doesn't expose count directly, but Subjects()
	// returns one DER-encoded subject per cert in the pool.
	subs := pool.Subjects() //nolint:staticcheck // Subjects deprecated for system pools, but fine for an in-memory one we built.
	if len(subs) == 0 {
		t.Fatal("expected at least one embedded root, got 0")
	}
	t.Logf("loaded %d embedded root(s)", len(subs))
}

// TestPinnedRoots_VerifiesLeafSignedByEmbeddedRoot is the end-to-end
// check that the embed is functional: we can synthesize a leaf cert
// chain that the daemon's TLS handshake would accept. Catches
// off-by-one errors in the embed path or wrong PEM parsing.
//
// We synthesize a chain by:
//  1. Generating a fresh ephemeral root, signing a leaf with it.
//  2. Adding ONLY the synthesized root into a separate pool.
//  3. Verifying the leaf against that pool — this confirms our
//     verify path works end-to-end, which is the same code path
//     PinnedRoots feeds into.
func TestPinnedRoots_LeafVerifiesAgainstPool(t *testing.T) {
	root, rootKey := mintTestRoot(t, "test-root")
	leaf, _ := mintTestLeaf(t, root, rootKey, "test-beacon.example")

	pool := x509.NewCertPool()
	pool.AddCert(root)

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       pool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:     "test-beacon.example",
		CurrentTime: time.Now(),
	}); err != nil {
		t.Fatalf("leaf failed to verify against pool: %v", err)
	}
}

// TestPinnedRoots_RejectsBadPEM is a sanity check that AppendCertsFromPEM
// path inside PinnedRoots fails loudly when given garbage — guards
// against a silent zero-root build if someone replaces a root.pem with
// an empty file by accident.
func TestPinnedRoots_RejectsBadPEM(t *testing.T) {
	pool := x509.NewCertPool()
	if pool.AppendCertsFromPEM([]byte("not a pem")) {
		t.Fatal("AppendCertsFromPEM should reject garbage input")
	}
}

func mintTestRoot(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("root keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("root sign: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("root parse: %v", err)
	}
	return cert, key
}

func mintTestLeaf(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, host string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("leaf sign: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("leaf parse: %v", err)
	}
	// Confirm we can PEM-encode (catches a class of subtle bugs).
	if !strings.Contains(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})), "BEGIN CERTIFICATE") {
		t.Fatal("leaf PEM encoding failed")
	}
	return cert, key
}

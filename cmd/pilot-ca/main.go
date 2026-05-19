// SPDX-License-Identifier: AGPL-3.0-or-later

// pilot-ca — offline tooling for the Pilot Protocol root CA used to
// authenticate beacon WSS endpoints in compat mode.
//
// The root CA private key is the trust anchor for every compat-mode
// daemon's TLS handshake. It must never leave the operator's secure
// machine (Yubikey-backed or air-gapped). This binary is the only
// production code that touches it.
//
// Subcommands:
//
//	pilot-ca init-root <out-dir>
//	   Generate a fresh Ed25519 root CA keypair + self-signed root cert.
//	   Writes <out-dir>/root.key (mode 0600) and <out-dir>/root.crt.
//	   The .key file must be moved to offline storage immediately.
//
//	pilot-ca issue-beacon <root-dir> <hostname> <out-dir>
//	   Sign a leaf cert for a beacon hostname using the root CA in
//	   <root-dir>. Writes <out-dir>/<hostname>.key and <out-dir>/<hostname>.crt.
//	   Leaf certs are P-256 ECDSA (TLS-friendly) with SAN = hostname.
//	   Validity: 90 days. Re-run before expiry; Caddy reloads
//	   automatically on file change.
//
//	pilot-ca verify <root.crt> <leaf.crt>
//	   Confirm a leaf cert chains to the root and is currently valid.
//	   Exit 0 on success.
//
// The root cert (PEM) is what gets embedded in pilot-daemon via
// //go:embed. The root key stays offline. Beacon operators receive
// only the leaf cert + leaf key.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	rootValidYears = 10 // root rotates rarely
	leafValidDays  = 90 // leaf rotates often
	caCommonName   = "Pilot Protocol Root CA"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: pilot-ca <subcommand> [args...]")
		fmt.Fprintln(os.Stderr, "  init-root    <out-dir>")
		fmt.Fprintln(os.Stderr, "  issue-beacon <root-dir> <hostname> <out-dir>")
		fmt.Fprintln(os.Stderr, "  verify       <root.crt> <leaf.crt>")
	}
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(2)
	}
	switch args[0] {
	case "init-root":
		if len(args) != 2 {
			flag.Usage()
			os.Exit(2)
		}
		if err := initRoot(args[1]); err != nil {
			die("init-root: %v", err)
		}
	case "issue-beacon":
		if len(args) != 4 {
			flag.Usage()
			os.Exit(2)
		}
		if err := issueBeacon(args[1], args[2], args[3]); err != nil {
			die("issue-beacon: %v", err)
		}
	case "verify":
		if len(args) != 3 {
			flag.Usage()
			os.Exit(2)
		}
		if err := verifyChain(args[1], args[2]); err != nil {
			die("verify: %v", err)
		}
	default:
		flag.Usage()
		os.Exit(2)
	}
}

// initRoot generates a fresh Ed25519 keypair and a self-signed CA
// certificate. The .key file is written with mode 0600 — the operator
// is expected to move it to offline storage immediately after running.
func initRoot(outDir string) error {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	keyPath := filepath.Join(outDir, "root.key")
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing %s — move it to offline storage first", keyPath)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   caCommonName,
			Organization: []string{"Pilot Protocol"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(rootValidYears, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return fmt.Errorf("self-sign root: %w", err)
	}

	if err := writePEM(keyPath, "PRIVATE KEY", mustMarshalPKCS8(priv), 0o600); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(outDir, "root.crt"), "CERTIFICATE", der, 0o644); err != nil {
		return err
	}

	fmt.Printf("Root CA generated.\n")
	fmt.Printf("  root.key  %s  (mode 0600 — MOVE TO OFFLINE STORAGE NOW)\n", keyPath)
	fmt.Printf("  root.crt  %s  (mode 0644 — embed in cmd/daemon)\n", filepath.Join(outDir, "root.crt"))
	fmt.Printf("  not-after %s\n", tmpl.NotAfter.Format(time.RFC3339))
	return nil
}

// issueBeacon signs a leaf cert for one beacon hostname. Output is a
// P-256 ECDSA keypair + leaf cert chained to the root. Leaf cert
// validity is 90 days; re-issue before expiry.
func issueBeacon(rootDir, hostname, outDir string) error {
	if hostname == "" {
		return fmt.Errorf("hostname required")
	}
	rootCert, rootKey, err := loadRoot(rootDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"Pilot Protocol"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, leafValidDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{hostname},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		return fmt.Errorf("sign leaf: %w", err)
	}

	keyPath := filepath.Join(outDir, hostname+".key")
	crtPath := filepath.Join(outDir, hostname+".crt")
	if err := writePEM(keyPath, "PRIVATE KEY", mustMarshalPKCS8(leafKey), 0o600); err != nil {
		return err
	}
	if err := writePEM(crtPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}

	fmt.Printf("Leaf cert issued for %s.\n", hostname)
	fmt.Printf("  %s  (mode 0600 — deploy to beacon TLS config)\n", keyPath)
	fmt.Printf("  %s  (mode 0644 — deploy alongside .key)\n", crtPath)
	fmt.Printf("  not-after %s (rotate before)\n", tmpl.NotAfter.Format(time.RFC3339))
	return nil
}

// verifyChain confirms a leaf cert chains to a root cert and is valid
// for the current wall clock. Used in CI before bundling a leaf into
// a beacon deployment, and as a sanity check in install/upgrade
// scripts.
func verifyChain(rootCrtPath, leafCrtPath string) error {
	rootPEM, err := os.ReadFile(rootCrtPath)
	if err != nil {
		return fmt.Errorf("read root cert: %w", err)
	}
	leafPEM, err := os.ReadFile(leafCrtPath)
	if err != nil {
		return fmt.Errorf("read leaf cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		return fmt.Errorf("root cert PEM parse failed")
	}
	leafBlock, _ := pem.Decode(leafPEM)
	if leafBlock == nil {
		return fmt.Errorf("leaf cert PEM parse failed")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return fmt.Errorf("leaf parse: %w", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("verify failed: %w", err)
	}
	fmt.Printf("OK — %s chains to %s\n", leafCrtPath, rootCrtPath)
	fmt.Printf("  CN=%s  not-after=%s\n", leaf.Subject.CommonName, leaf.NotAfter.Format(time.RFC3339))
	return nil
}

// loadRoot reads root.crt + root.key out of rootDir. Errors loudly
// if either is missing — the operator should never invoke issue-beacon
// without the root key being present.
func loadRoot(rootDir string) (*x509.Certificate, any, error) {
	crtPEM, err := os.ReadFile(filepath.Join(rootDir, "root.crt"))
	if err != nil {
		return nil, nil, fmt.Errorf("read root.crt: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(rootDir, "root.key"))
	if err != nil {
		return nil, nil, fmt.Errorf("read root.key: %w (must be online for issue-beacon — temporary mount from offline storage)", err)
	}
	crtBlock, _ := pem.Decode(crtPEM)
	if crtBlock == nil {
		return nil, nil, fmt.Errorf("root.crt: invalid PEM")
	}
	crt, err := x509.ParseCertificate(crtBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("root.crt parse: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("root.key: invalid PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("root.key parse: %w", err)
	}
	return crt, key, nil
}

func mustMarshalPKCS8(key any) []byte {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return b
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	return nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128) // 128-bit serial
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	return n, nil
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "pilot-ca: "+format+"\n", a...)
	os.Exit(1)
}

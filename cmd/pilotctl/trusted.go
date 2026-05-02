// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/trustedagents"
)

// signerKeyFile is the on-disk format for the offline signing keypair —
// same shape as crypto.identityFile so an operator can use either format
// interchangeably.
type signerKeyFile struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

func defaultSignerKeyPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".pilot", "trusted-agents-signer.key")
}

func cmdTrusted(args []string) {
	if len(args) < 1 {
		fatalHint("invalid_argument",
			"available: pilotctl trusted list | verify | sign | keygen",
			"missing subcommand")
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "list":
		cmdTrustedList(rest)
	case "verify":
		cmdTrustedVerify(rest)
	case "sign":
		cmdTrustedSign(rest)
	case "keygen":
		cmdTrustedKeygen(rest)
	default:
		fatalHint("invalid_argument",
			"available: list, verify, sign, keygen",
			"unknown trusted subcommand: %s", sub)
	}
}

// cmdTrustedList prints the trusted-agents list embedded in this binary
// (what the local daemon would auto-accept handshakes from).
func cmdTrustedList(_ []string) {
	store, err := trustedagents.NewStore("")
	if err != nil {
		fatalCode("verification_failed", "load embedded list: %v", err)
	}
	snap := store.Snapshot()
	if jsonOutput {
		out := map[string]interface{}{
			"version":   snap.Version,
			"issued_at": snap.IssuedAt,
			"agents":    snap.Agents,
		}
		output(out)
		return
	}
	fmt.Printf("trusted-agents list v%d (issued %s)\n", snap.Version, snap.IssuedAt)
	if len(snap.Agents) == 0 {
		fmt.Println("(no agents — list is empty; daemon will never auto-accept via this path)")
		return
	}
	for _, a := range snap.Agents {
		fmt.Printf("  %-20s %s  added=%s\n", a.Name, a.PublicKey, a.AddedAt)
	}
}

// cmdTrustedVerify verifies that FILE and FILE.sig form a valid signed
// pair under the baked SignerPublicKey. Useful for pre-commit sanity
// checks after editing trusted-agents.json.
func cmdTrustedVerify(args []string) {
	if len(args) != 1 {
		fatalCode("invalid_argument", "usage: pilotctl trusted verify <trusted-agents.json>")
	}
	path := args[0]
	raw, err := os.ReadFile(path)
	if err != nil {
		fatalCode("not_found", "read %s: %v", path, err)
	}
	sig, err := os.ReadFile(path + ".sig")
	if err != nil {
		fatalCode("not_found", "read %s.sig: %v", path, err)
	}
	signerPub, err := base64.StdEncoding.DecodeString(trustedagents.SignerPublicKey)
	if err != nil {
		fatalCode("internal", "bad SignerPublicKey constant")
	}
	sigStr := strings.TrimSpace(string(sig))
	sigBytes, err := base64.StdEncoding.DecodeString(sigStr)
	if err != nil {
		fatalCode("verification_failed", "decode sig: %v", err)
	}
	if !ed25519.Verify(signerPub, raw, sigBytes) {
		fatalCode("verification_failed", "signature does not verify against baked SignerPublicKey")
	}
	var l trustedagents.List
	if err := json.Unmarshal(raw, &l); err != nil {
		fatalCode("verification_failed", "decode list: %v", err)
	}
	if jsonOutput {
		output(map[string]interface{}{
			"verified":  true,
			"version":   l.Version,
			"issued_at": l.IssuedAt,
			"agents":    len(l.Agents),
		})
		return
	}
	fmt.Printf("OK: signature verifies. version=%d agents=%d issued=%s\n", l.Version, len(l.Agents), l.IssuedAt)
}

// cmdTrustedSign reads FILE, signs it with the offline private key, and
// writes FILE.sig. The default key path is ~/.pilot/trusted-agents-signer.key
// — override with -key.
//
// As a safety check the resulting sig is verified against the baked
// SignerPublicKey before we write it; that way an operator who
// accidentally swaps in the wrong key gets a loud failure here, not a
// silent rejection on every daemon in the field once they push.
func cmdTrustedSign(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) != 1 {
		fatalCode("invalid_argument", "usage: pilotctl trusted sign [-key PATH] <trusted-agents.json>")
	}
	keyPath := flagString(flags, "key", defaultSignerKeyPath())
	dataPath := pos[0]

	keyJSON, err := os.ReadFile(keyPath)
	if err != nil {
		fatalHint("not_found",
			"run `pilotctl trusted keygen -out "+keyPath+"` to bootstrap a new offline signer",
			"read signer key %s: %v", keyPath, err)
	}
	var kf signerKeyFile
	if err := json.Unmarshal(keyJSON, &kf); err != nil {
		fatalCode("invalid_argument", "parse signer key: %v", err)
	}
	priv, err := base64.StdEncoding.DecodeString(kf.PrivateKey)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		fatalCode("invalid_argument", "signer private key wrong size or encoding")
	}

	raw, err := os.ReadFile(dataPath)
	if err != nil {
		fatalCode("not_found", "read %s: %v", dataPath, err)
	}
	sig := ed25519.Sign(ed25519.PrivateKey(priv), raw)

	// Sanity: does the resulting sig verify under the baked pubkey?
	bakedPub, err := base64.StdEncoding.DecodeString(trustedagents.SignerPublicKey)
	if err != nil {
		fatalCode("internal", "bad SignerPublicKey constant")
	}
	if !ed25519.Verify(bakedPub, raw, sig) {
		fatalHint("verification_failed",
			"the key at "+keyPath+" does not match the SignerPublicKey baked into this binary; rotate the constant or use a different key file",
			"signed payload would NOT verify against baked SignerPublicKey")
	}

	sigPath := dataPath + ".sig"
	sigB64 := base64.StdEncoding.EncodeToString(sig) + "\n"
	if err := os.WriteFile(sigPath, []byte(sigB64), 0644); err != nil {
		fatalCode("internal", "write sig: %v", err)
	}
	if jsonOutput {
		output(map[string]interface{}{
			"signed":   dataPath,
			"sig_path": sigPath,
			"verified": true,
		})
		return
	}
	fmt.Printf("signed %s -> %s (verified against baked SignerPublicKey)\n", dataPath, sigPath)
}

// cmdTrustedKeygen generates a fresh Ed25519 offline signer keypair. The
// public half goes to stdout for the operator to paste into
// internal/trustedagents/signer.go (SignerPublicKey constant); the
// private half is written to PATH with mode 0600. The operator is
// expected to move this file to offline storage (USB, paper, hardware
// token) — anyone with this file can sign a trusted-agents list that
// every daemon in the field will accept.
func cmdTrustedKeygen(args []string) {
	flags, _ := parseFlags(args)
	out := flagString(flags, "out", defaultSignerKeyPath())

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatalCode("internal", "generate key: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
		fatalCode("internal", "mkdir: %v", err)
	}
	kf := signerKeyFile{
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
	}
	data, _ := json.MarshalIndent(kf, "", "  ")
	if err := os.WriteFile(out, data, 0600); err != nil {
		fatalCode("internal", "write key: %v", err)
	}

	pubB64 := base64.StdEncoding.EncodeToString(pub)
	if jsonOutput {
		output(map[string]interface{}{
			"key_path":   out,
			"public_key": pubB64,
			"created_at": time.Now().UTC().Format(time.RFC3339),
		})
		return
	}
	fmt.Printf("generated offline signer keypair\n")
	fmt.Printf("  private key: %s (mode 0600)\n", out)
	fmt.Printf("  public key:  %s\n", pubB64)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Bake the public key into internal/trustedagents/signer.go (SignerPublicKey constant)")
	fmt.Println("  2. Move the private key file to offline storage (USB, paper, HSM)")
	fmt.Println("  3. Sign trusted-agents.json with: pilotctl trusted sign -key " + out + " internal/trustedagents/trusted-agents.json")
}

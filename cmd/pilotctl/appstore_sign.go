// SPDX-License-Identifier: AGPL-3.0-or-later
//
// pilotctl appstore sign / gen-key — publisher-side manifest signing.
//
// The app-store supervisor refuses to spawn an app whose manifest's
// ed25519 store.signature doesn't verify against store.publisher. This
// file gives an operator the two commands needed to publish a bundle:
//
//   1. gen-key — once per publisher identity, write a fresh
//      ed25519 private key to disk. The matching public key is
//      printed so it can be pasted into the manifest.
//
//   2. sign --key <key> <manifest> — recompute the canonical signing
//      payload (publisher || ":" || id || ":" || manifest_version ||
//      ":" || binary.sha256 || ":" || grants-sha256-hex) and write
//      a fresh signature into the manifest's store fields. Publisher
//      is also rewritten to match the key — preventing the
//      footgun where someone swaps the key but leaves a stale
//      publisher line and ships a half-broken bundle.
//
// Format note: the signing payload is reconstructed manually here
// because manifest.signingPayload is package-private. The format is
// documented in app-store/pkg/manifest/manifest.go:185 — keep them in
// lockstep.

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/pilot-protocol/app-store/pkg/manifest"
)

func cmdAppStoreGenKey(args []string) {
	if len(args) != 1 {
		fatalHint("invalid_argument",
			"usage: pilotctl appstore gen-key <key-file>",
			"missing or extra argument")
	}
	keyFile := args[0]
	if _, err := os.Stat(keyFile); err == nil {
		fatalHint("invalid_argument",
			"refuse to overwrite an existing key; pass a fresh path or remove the old one first",
			"%s already exists", keyFile)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatalHint("crypto_error", "the ed25519 keygen failed; retry once", "generate: %v", err)
	}
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		fatalHint("io_error",
			"check the parent dir is writable and not full",
			"write key: %v", err)
	}
	fmt.Printf("private key written to %s (mode 0600 — protect this file)\n", keyFile)
	fmt.Printf("publisher (paste verbatim into manifest.store.publisher):\n")
	fmt.Printf("ed25519:%s\n", base64.StdEncoding.EncodeToString(pub))
}

func cmdAppStoreSign(args []string) {
	var keyFile string
	rest := args
	for len(rest) > 0 {
		switch rest[0] {
		case "--key", "-k":
			if len(rest) < 2 {
				fatalHint("invalid_argument",
					"--key takes a path",
					"missing value after %s", rest[0])
			}
			keyFile = rest[1]
			rest = rest[2:]
		default:
			if keyFile == "" {
				fatalHint("invalid_argument",
					"usage: pilotctl appstore sign --key <key-file> <manifest>",
					"--key must come before the manifest path")
			}
			// Anything that isn't a flag is the manifest path.
			break
		}
		if len(rest) > 0 && rest[0] != "--key" && rest[0] != "-k" {
			break
		}
	}
	if keyFile == "" || len(rest) == 0 {
		fatalHint("invalid_argument",
			"usage: pilotctl appstore sign --key <key-file> <manifest>",
			"missing --key or manifest path")
	}
	mfPath := rest[0]

	keyHex, err := os.ReadFile(keyFile)
	if err != nil {
		fatalHint("io_error",
			"the key path doesn't exist or is unreadable; did you mean a different file?",
			"read key: %v", err)
	}
	privBytes, err := hex.DecodeString(string(keyHex))
	if err != nil {
		fatalHint("invalid_argument",
			"the file should be a single hex-encoded ed25519 private key — same shape `pilotctl appstore gen-key` produces",
			"decode key: %v", err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		fatalHint("invalid_argument",
			fmt.Sprintf("expected %d bytes; got %d — wrong file?", ed25519.PrivateKeySize, len(privBytes)),
			"key length mismatch")
	}
	priv := ed25519.PrivateKey(privBytes)
	pub := priv.Public().(ed25519.PublicKey)

	raw, err := os.ReadFile(mfPath)
	if err != nil {
		fatalHint("io_error",
			"pass the path to a manifest.json file",
			"read manifest: %v", err)
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		fatalHint("invalid_argument",
			"the manifest JSON failed to parse; check it loads without errors first",
			"parse: %v", err)
	}

	// Set publisher to match the supplied key BEFORE building the
	// signing payload — the publisher is part of the payload, so any
	// mismatch would silently produce a signature that doesn't verify.
	m.Store.Publisher = "ed25519:" + base64.StdEncoding.EncodeToString(pub)

	// Canonical signing payload — must match manifest.signingPayload
	// in the app-store package (private). See manifest.go:185.
	grantsJSON, err := json.Marshal(m.Grants)
	if err != nil {
		fatalHint("internal_error",
			"the manifest's grants slice failed to marshal — bug",
			"%v", err)
	}
	grantsHash := sha256.Sum256(grantsJSON)
	payload := fmt.Sprintf("%s:%s:%d:%s:%x",
		m.Store.Publisher, m.ID, m.ManifestVersion, m.Binary.SHA256, grantsHash)

	sig := ed25519.Sign(priv, []byte(payload))
	m.Store.Signature = base64.StdEncoding.EncodeToString(sig)

	// Self-verify before writing — refuse to ship a manifest the
	// supervisor will then reject. Belt-and-braces: a future
	// change to the payload format would surface here, not at
	// install time.
	if err := m.VerifySignature(); err != nil {
		fatalHint("internal_error",
			"self-verify after signing failed — pilotctl and the app-store package may be on different signing-payload formats; rebuild pilotctl",
			"%v", err)
	}

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		fatalHint("internal_error", "marshal signed manifest", "%v", err)
	}
	if err := os.WriteFile(mfPath, out, 0o644); err != nil {
		fatalHint("io_error",
			"check the manifest path is writable",
			"write manifest: %v", err)
	}
	fmt.Printf("signed %s\n", mfPath)
	fmt.Printf("publisher: %s\n", m.Store.Publisher)
}

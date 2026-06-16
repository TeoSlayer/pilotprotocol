// SPDX-License-Identifier: AGPL-3.0-or-later

package catalogtrust

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
)

// SignWithEphemeralKey is a TEST-ONLY helper for packages outside
// catalogtrust (e.g. cmd/pilotctl) that need to stage a catalogue fixture
// the fail-closed loader will accept. It generates a throwaway ed25519
// keypair, swaps the package's embedded public key (publicKeyB64) to the
// generated public half, signs data with the private half, and returns the
// detached signature plus a restore func that puts the original embedded
// key back.
//
// This exists so fixture-based tests exercise REAL fail-closed verification
// against a VALID signature, rather than disabling or weakening the gate.
// It is not referenced by any production code path.
//
// Usage:
//
//	sig, restore := catalogtrust.SignWithEphemeralKey(catalogueBytes)
//	defer restore()
//	// write catalogueBytes + base64(sig) and point the loader at them
func SignWithEphemeralKey(data []byte) (sig []byte, restore func()) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic("catalogtrust: ephemeral key generation failed: " + err.Error())
	}
	orig := publicKeyB64
	publicKeyB64 = base64.StdEncoding.EncodeToString(pub)
	return ed25519.Sign(priv, data), func() { publicKeyB64 = orig }
}

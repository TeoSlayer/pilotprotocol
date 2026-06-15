// Package catalogtrust holds the app-store catalogue trust anchor: the
// ed25519 public key the signed catalogue is verified against, plus a
// verify helper. The matching private key is held by the release
// pipeline and is never committed (see catalogue/README.md).
//
// This replaces the all-zeros placeholder trust anchor: pilotctl verifies
// the catalogue signature against PublicKey() before trusting any
// install target, and the daemon passes PublicKey() into the app-store
// service so its Start-time trust-anchor check sees a real key.
package catalogtrust

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
)

// publicKeyB64 is the base64-encoded ed25519 catalogue-signing public
// key. Overridable at build time to rotate the key without a code change:
//
//	-ldflags "-X github.com/TeoSlayer/pilotprotocol/internal/catalogtrust.publicKeyB64=<b64>"
//
// The compiled-in default is the current production catalogue key.
var publicKeyB64 = "5aCD92R0UoZ2lGW6PYZeRrDw63ZNBC5oJZxFB8RNOPQ="

// ErrNoKey is returned when the embedded key is missing or malformed.
// Fail-closed: with no trust anchor, nothing verifies.
var ErrNoKey = errors.New("catalogtrust: no valid embedded catalogue public key")

// ErrBadSignature is returned when a signature does not verify against
// the embedded key.
var ErrBadSignature = errors.New("catalogtrust: catalogue signature verification failed")

// PublicKey returns the embedded catalogue public key, or nil if the
// embedded value is malformed (e.g. a bad ldflags override).
func PublicKey() ed25519.PublicKey {
	raw, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(raw)
}

// Verify checks that sig is a valid ed25519 signature over data, made
// with the catalogue signing key. Fail-closed on a missing/invalid
// embedded key or a wrong-length signature.
func Verify(data, sig []byte) error {
	pk := PublicKey()
	if pk == nil {
		return ErrNoKey
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: wrong signature length %d (want %d)", ErrBadSignature, len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pk, data, sig) {
		return ErrBadSignature
	}
	return nil
}

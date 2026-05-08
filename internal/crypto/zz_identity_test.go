// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateIdentityProducesValidKeypair(t *testing.T) {
	t.Parallel()
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if len(id.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("public key size = %d, want %d", len(id.PublicKey), ed25519.PublicKeySize)
	}
	if len(id.PrivateKey) != ed25519.PrivateKeySize {
		t.Fatalf("private key size = %d, want %d", len(id.PrivateKey), ed25519.PrivateKeySize)
	}
	// Public derived from private must match
	derivedPub := id.PrivateKey.Public().(ed25519.PublicKey)
	if !derivedPub.Equal(id.PublicKey) {
		t.Fatal("derived public key does not match stored public key")
	}
}

func TestGenerateIdentityProducesUniqueKeys(t *testing.T) {
	t.Parallel()
	a, _ := GenerateIdentity()
	b, _ := GenerateIdentity()
	if string(a.PublicKey) == string(b.PublicKey) {
		t.Fatal("two GenerateIdentity calls produced identical public keys")
	}
}

func TestSignAndVerify(t *testing.T) {
	t.Parallel()
	id, _ := GenerateIdentity()
	msg := []byte("hello world")
	sig := id.Sign(msg)
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature size = %d, want %d", len(sig), ed25519.SignatureSize)
	}
	if !Verify(id.PublicKey, msg, sig) {
		t.Fatal("Verify rejected a valid signature")
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	t.Parallel()
	id, _ := GenerateIdentity()
	sig := id.Sign([]byte("original"))
	if Verify(id.PublicKey, []byte("tampered"), sig) {
		t.Fatal("Verify accepted signature for tampered message")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	t.Parallel()
	id1, _ := GenerateIdentity()
	id2, _ := GenerateIdentity()
	msg := []byte("test")
	sig := id1.Sign(msg)
	if Verify(id2.PublicKey, msg, sig) {
		t.Fatal("Verify accepted signature against wrong public key")
	}
}

func TestEncodeDecodePublicKeyRoundTrip(t *testing.T) {
	t.Parallel()
	id, _ := GenerateIdentity()
	enc := EncodePublicKey(id.PublicKey)
	if enc == "" {
		t.Fatal("EncodePublicKey returned empty string")
	}
	dec, err := DecodePublicKey(enc)
	if err != nil {
		t.Fatalf("DecodePublicKey: %v", err)
	}
	if !dec.Equal(id.PublicKey) {
		t.Fatal("round-trip mismatch")
	}
}

func TestDecodePublicKeyInvalidBase64(t *testing.T) {
	t.Parallel()
	_, err := DecodePublicKey("not!base64@@")
	if err == nil {
		t.Fatal("expected base64 decode error")
	}
	if !strings.Contains(err.Error(), "decode public key") {
		t.Fatalf("error %q missing wrap", err)
	}
}

func TestDecodePublicKeyWrongSize(t *testing.T) {
	t.Parallel()
	tooShort := base64.StdEncoding.EncodeToString([]byte("only-12-bytes"))
	_, err := DecodePublicKey(tooShort)
	if err == nil {
		t.Fatal("expected size error")
	}
	if !strings.Contains(err.Error(), "invalid public key size") {
		t.Fatalf("error %q missing 'invalid public key size'", err)
	}
}

func TestEncodeDecodePrivateKeyRoundTrip(t *testing.T) {
	t.Parallel()
	id, _ := GenerateIdentity()
	enc := EncodePrivateKey(id.PrivateKey)
	dec, err := DecodePrivateKey(enc)
	if err != nil {
		t.Fatalf("DecodePrivateKey: %v", err)
	}
	if !dec.Equal(id.PrivateKey) {
		t.Fatal("round-trip mismatch")
	}
}

func TestDecodePrivateKeyInvalidBase64(t *testing.T) {
	t.Parallel()
	_, err := DecodePrivateKey("not!base64@@")
	if err == nil {
		t.Fatal("expected base64 decode error")
	}
	if !strings.Contains(err.Error(), "decode private key") {
		t.Fatalf("error %q missing wrap", err)
	}
}

func TestDecodePrivateKeyWrongSize(t *testing.T) {
	t.Parallel()
	tooShort := base64.StdEncoding.EncodeToString([]byte("only-12-bytes"))
	_, err := DecodePrivateKey(tooShort)
	if err == nil {
		t.Fatal("expected size error")
	}
	if !strings.Contains(err.Error(), "invalid private key size") {
		t.Fatalf("error %q missing 'invalid private key size'", err)
	}
}

// ---------------------------------------------------------------------------
// Save/Load identity
// ---------------------------------------------------------------------------

func TestSaveAndLoadIdentityRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "id.json") // exercises MkdirAll
	id, _ := GenerateIdentity()
	if err := SaveIdentity(path, id); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	// Verify file mode is 0600
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("file mode = %04o, want 0600", perm)
	}

	loaded, err := LoadIdentity(path)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if !loaded.PublicKey.Equal(id.PublicKey) {
		t.Fatal("loaded public key mismatch")
	}
	if !loaded.PrivateKey.Equal(id.PrivateKey) {
		t.Fatal("loaded private key mismatch")
	}
}

func TestLoadIdentityMissingFileReturnsNilNil(t *testing.T) {
	t.Parallel()
	id, err := LoadIdentity("/nonexistent/path/id.json")
	if err != nil {
		t.Fatalf("missing file should return nil err (first run), got %v", err)
	}
	if id != nil {
		t.Fatalf("missing file should return nil identity, got %+v", id)
	}
}

func TestLoadIdentityMalformedJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadIdentity(path)
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
	if !strings.Contains(err.Error(), "unmarshal identity") {
		t.Fatalf("error %q missing wrap", err)
	}
}

func TestLoadIdentityCorruptedKeysMismatch(t *testing.T) {
	t.Parallel()
	// Generate two identities; write priv from A but pub from B.
	idA, _ := GenerateIdentity()
	idB, _ := GenerateIdentity()
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt.json")
	body := `{"private_key":"` + EncodePrivateKey(idA.PrivateKey) + `","public_key":"` + EncodePublicKey(idB.PublicKey) + `"}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadIdentity(path)
	if err == nil {
		t.Fatal("expected corruption detection error")
	}
	if !strings.Contains(err.Error(), "corrupted") {
		t.Fatalf("error %q missing 'corrupted'", err)
	}
}

func TestLoadIdentityBadPubKeyEncoding(t *testing.T) {
	t.Parallel()
	id, _ := GenerateIdentity()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad-pub.json")
	body := `{"private_key":"` + EncodePrivateKey(id.PrivateKey) + `","public_key":"!!!"}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadIdentity(path)
	if err == nil {
		t.Fatal("expected pub key decode error")
	}
}

// Sanity: signatures from random data must be ed25519-valid.
func TestRandomMessageSignVerify(t *testing.T) {
	t.Parallel()
	id, _ := GenerateIdentity()
	msg := make([]byte, 1024)
	if _, err := rand.Read(msg); err != nil {
		t.Fatal(err)
	}
	sig := id.Sign(msg)
	if !Verify(id.PublicKey, msg, sig) {
		t.Fatal("Verify rejected freshly-signed random message")
	}
}

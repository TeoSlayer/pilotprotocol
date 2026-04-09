package tests

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// ---------------------------------------------------------------------------
// Fuzz targets
// ---------------------------------------------------------------------------

func FuzzDecodePublicKey(f *testing.F) {
	// Valid 32-byte key
	id, _ := crypto.GenerateIdentity()
	f.Add(crypto.EncodePublicKey(id.PublicKey))
	f.Add("")
	f.Add("not-base64!!!")
	f.Add(base64.StdEncoding.EncodeToString(make([]byte, 31))) // wrong size
	f.Add(base64.StdEncoding.EncodeToString(make([]byte, 33))) // wrong size
	f.Add(base64.StdEncoding.EncodeToString(make([]byte, 0)))  // empty
	f.Add(strings.Repeat("A", 1000))

	f.Fuzz(func(t *testing.T, s string) {
		_, _ = crypto.DecodePublicKey(s)
	})
}

func FuzzDecodePrivateKey(f *testing.F) {
	id, _ := crypto.GenerateIdentity()
	f.Add(crypto.EncodePrivateKey(id.PrivateKey))
	f.Add("")
	f.Add("not-base64!!!")
	f.Add(base64.StdEncoding.EncodeToString(make([]byte, 63))) // wrong size
	f.Add(base64.StdEncoding.EncodeToString(make([]byte, 65))) // wrong size
	f.Add(base64.StdEncoding.EncodeToString(make([]byte, 0)))  // empty

	f.Fuzz(func(t *testing.T, s string) {
		_, _ = crypto.DecodePrivateKey(s)
	})
}

// ---------------------------------------------------------------------------
// Edge case unit tests
// ---------------------------------------------------------------------------

func TestDecodePublicKeyValidBase64WrongLength(t *testing.T) {
	for _, size := range []int{0, 1, 31, 33, 64, 128} {
		encoded := base64.StdEncoding.EncodeToString(make([]byte, size))
		_, err := crypto.DecodePublicKey(encoded)
		if err == nil {
			t.Errorf("expected error for %d-byte public key", size)
		}
	}
}

func TestDecodePublicKeyEmpty(t *testing.T) {
	_, err := crypto.DecodePublicKey("")
	if err == nil {
		t.Fatal("expected error for empty public key")
	}
}

func TestDecodePublicKeyWhitespace(t *testing.T) {
	_, err := crypto.DecodePublicKey("  \t\n  ")
	if err == nil {
		t.Fatal("expected error for whitespace public key")
	}
}

func TestDecodePublicKeyInvalidBase64(t *testing.T) {
	_, err := crypto.DecodePublicKey("!!!not-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDecodePrivateKeyValidBase64WrongLength(t *testing.T) {
	for _, size := range []int{0, 1, 63, 65, 128} {
		encoded := base64.StdEncoding.EncodeToString(make([]byte, size))
		_, err := crypto.DecodePrivateKey(encoded)
		if err == nil {
			t.Errorf("expected error for %d-byte private key", size)
		}
	}
}

func TestIdentitySaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	if err := crypto.SaveIdentity(path, id); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	loaded, err := crypto.LoadIdentity(path)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}

	if !id.PublicKey.Equal(loaded.PublicKey) {
		t.Fatal("public key mismatch after save/load")
	}
	if !id.PrivateKey.Equal(loaded.PrivateKey) {
		t.Fatal("private key mismatch after save/load")
	}
}

func TestLoadIdentityNonExistent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.json")

	id, err := crypto.LoadIdentity(path)
	if err != nil {
		t.Fatalf("LoadIdentity non-existent: %v", err)
	}
	if id != nil {
		t.Fatal("expected nil for non-existent identity")
	}
}

func TestLoadIdentityCorruptedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")

	os.WriteFile(path, []byte("not json at all"), 0600)

	_, err := crypto.LoadIdentity(path)
	if err == nil {
		t.Fatal("expected error for corrupted JSON")
	}
}

func TestLoadIdentityMissingFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")

	os.WriteFile(path, []byte(`{"public_key":""}`), 0600)

	_, err := crypto.LoadIdentity(path)
	if err == nil {
		t.Fatal("expected error for missing private key")
	}
}

func TestLoadIdentityExtraFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")

	id, _ := crypto.GenerateIdentity()
	data := map[string]string{
		"public_key":  crypto.EncodePublicKey(id.PublicKey),
		"private_key": crypto.EncodePrivateKey(id.PrivateKey),
		"extra":       "should be ignored",
	}
	b, _ := json.Marshal(data)
	os.WriteFile(path, b, 0600)

	loaded, err := crypto.LoadIdentity(path)
	if err != nil {
		t.Fatalf("LoadIdentity with extra fields: %v", err)
	}
	if !id.PublicKey.Equal(loaded.PublicKey) {
		t.Fatal("public key mismatch")
	}
}

func TestLoadIdentityMismatchedKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")

	id1, _ := crypto.GenerateIdentity()
	id2, _ := crypto.GenerateIdentity()

	// Save id1's private key with id2's public key
	data := map[string]string{
		"public_key":  crypto.EncodePublicKey(id2.PublicKey),
		"private_key": crypto.EncodePrivateKey(id1.PrivateKey),
	}
	b, _ := json.Marshal(data)
	os.WriteFile(path, b, 0600)

	_, err := crypto.LoadIdentity(path)
	if err == nil {
		t.Fatal("expected error for mismatched keys")
	}
}

func TestLoadIdentityInvalidBase64InKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")

	data := map[string]string{
		"public_key":  "!!!invalid!!!",
		"private_key": "!!!invalid!!!",
	}
	b, _ := json.Marshal(data)
	os.WriteFile(path, b, 0600)

	_, err := crypto.LoadIdentity(path)
	if err == nil {
		t.Fatal("expected error for invalid base64 in keys")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	id, _ := crypto.GenerateIdentity()

	messages := [][]byte{
		{},                  // empty
		{0x42},              // 1 byte
		make([]byte, 1024),  // 1KB
		make([]byte, 1<<20), // 1MB
	}

	for _, msg := range messages {
		sig := id.Sign(msg)
		if !crypto.Verify(id.PublicKey, msg, sig) {
			t.Fatalf("verify failed for %d-byte message", len(msg))
		}
	}
}

func TestVerifyWrongPublicKey(t *testing.T) {
	id1, _ := crypto.GenerateIdentity()
	id2, _ := crypto.GenerateIdentity()

	msg := []byte("test message")
	sig := id1.Sign(msg)

	if crypto.Verify(id2.PublicKey, msg, sig) {
		t.Fatal("verify should fail with wrong public key")
	}
}

func TestFuzzVerifyTamperedSignature(t *testing.T) {
	id, _ := crypto.GenerateIdentity()
	msg := []byte("test message")
	sig := id.Sign(msg)

	// Flip a bit
	sig[0] ^= 0x01
	if crypto.Verify(id.PublicKey, msg, sig) {
		t.Fatal("verify should fail with tampered signature")
	}
}

func TestVerifyTamperedMessage(t *testing.T) {
	id, _ := crypto.GenerateIdentity()
	msg := []byte("test message")
	sig := id.Sign(msg)

	tampered := []byte("test messagE") // last byte changed
	if crypto.Verify(id.PublicKey, tampered, sig) {
		t.Fatal("verify should fail with tampered message")
	}
}

func TestEncodeDecodePublicKeyRoundTrip(t *testing.T) {
	id, _ := crypto.GenerateIdentity()
	encoded := crypto.EncodePublicKey(id.PublicKey)
	decoded, err := crypto.DecodePublicKey(encoded)
	if err != nil {
		t.Fatalf("DecodePublicKey: %v", err)
	}
	if !id.PublicKey.Equal(decoded) {
		t.Fatal("round-trip mismatch")
	}
}

func TestEncodeDecodePrivateKeyRoundTrip(t *testing.T) {
	id, _ := crypto.GenerateIdentity()
	encoded := crypto.EncodePrivateKey(id.PrivateKey)
	decoded, err := crypto.DecodePrivateKey(encoded)
	if err != nil {
		t.Fatalf("DecodePrivateKey: %v", err)
	}
	if !id.PrivateKey.Equal(decoded) {
		t.Fatal("round-trip mismatch")
	}
}

func TestDecodePublicKeyExact32(t *testing.T) {
	key := make([]byte, ed25519.PublicKeySize)
	encoded := base64.StdEncoding.EncodeToString(key)
	decoded, err := crypto.DecodePublicKey(encoded)
	if err != nil {
		t.Fatalf("DecodePublicKey 32 zeros: %v", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		t.Fatalf("expected %d bytes, got %d", ed25519.PublicKeySize, len(decoded))
	}
}

func TestDecodePrivateKeyExact64(t *testing.T) {
	key := make([]byte, ed25519.PrivateKeySize)
	encoded := base64.StdEncoding.EncodeToString(key)
	decoded, err := crypto.DecodePrivateKey(encoded)
	if err != nil {
		t.Fatalf("DecodePrivateKey 64 zeros: %v", err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		t.Fatalf("expected %d bytes, got %d", ed25519.PrivateKeySize, len(decoded))
	}
}

func TestSaveIdentityCreatesDirectories(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "dir", "identity.json")

	id, _ := crypto.GenerateIdentity()
	if err := crypto.SaveIdentity(path, id); err != nil {
		t.Fatalf("SaveIdentity nested: %v", err)
	}

	loaded, err := crypto.LoadIdentity(path)
	if err != nil {
		t.Fatalf("LoadIdentity nested: %v", err)
	}
	if !id.PublicKey.Equal(loaded.PublicKey) {
		t.Fatal("mismatch after nested save/load")
	}
}

func TestFuzzSaveIdentityFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")

	id, _ := crypto.GenerateIdentity()
	if err := crypto.SaveIdentity(path, id); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Fatalf("expected 0600, got %04o", perm)
	}
}

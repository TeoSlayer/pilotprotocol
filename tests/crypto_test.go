package tests

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

func TestGenerateIdentity(t *testing.T) {
	t.Parallel()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if len(id.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("public key size = %d, want %d", len(id.PublicKey), ed25519.PublicKeySize)
	}
	if len(id.PrivateKey) != ed25519.PrivateKeySize {
		t.Fatalf("private key size = %d, want %d", len(id.PrivateKey), ed25519.PrivateKeySize)
	}
}

func TestGenerateIdentityUnique(t *testing.T) {
	t.Parallel()
	id1, _ := crypto.GenerateIdentity()
	id2, _ := crypto.GenerateIdentity()
	if id1.PublicKey.Equal(id2.PublicKey) {
		t.Fatal("two generated identities should have different keys")
	}
}

func TestSignVerify(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	msg := []byte("hello pilot protocol")
	sig := id.Sign(msg)

	if !crypto.Verify(id.PublicKey, msg, sig) {
		t.Fatal("valid signature rejected")
	}
}

func TestVerifyWrongMessage(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	sig := id.Sign([]byte("original message"))
	if crypto.Verify(id.PublicKey, []byte("different message"), sig) {
		t.Fatal("should reject signature for wrong message")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	t.Parallel()
	id1, _ := crypto.GenerateIdentity()
	id2, _ := crypto.GenerateIdentity()
	msg := []byte("test")
	sig := id1.Sign(msg)
	if crypto.Verify(id2.PublicKey, msg, sig) {
		t.Fatal("should reject signature from wrong key")
	}
}

func TestVerifyTamperedSignature(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	msg := []byte("test")
	sig := id.Sign(msg)
	sig[0] ^= 0xFF // tamper
	if crypto.Verify(id.PublicKey, msg, sig) {
		t.Fatal("should reject tampered signature")
	}
}

func TestEncodeDecodePublicKey(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	encoded := crypto.EncodePublicKey(id.PublicKey)
	if len(encoded) == 0 {
		t.Fatal("encoded key is empty")
	}
	decoded, err := crypto.DecodePublicKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !id.PublicKey.Equal(decoded) {
		t.Fatal("roundtrip failed")
	}
}

func TestEncodeDecodePrivateKey(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	encoded := crypto.EncodePrivateKey(id.PrivateKey)
	decoded, err := crypto.DecodePrivateKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !id.PrivateKey.Equal(decoded) {
		t.Fatal("roundtrip failed")
	}
}

func TestDecodePublicKeyInvalid(t *testing.T) {
	t.Parallel()
	_, err := crypto.DecodePublicKey("not-valid-base64!!!")
	if err == nil {
		t.Fatal("should fail on invalid base64")
	}
	_, err = crypto.DecodePublicKey("AQID") // 3 bytes
	if err == nil {
		t.Fatal("should fail on wrong size")
	}
}

func TestDecodePrivateKeyInvalid(t *testing.T) {
	t.Parallel()
	_, err := crypto.DecodePrivateKey("not-valid-base64!!!")
	if err == nil {
		t.Fatal("should fail on invalid base64")
	}
	_, err = crypto.DecodePrivateKey("AQID")
	if err == nil {
		t.Fatal("should fail on wrong size")
	}
}

func TestSaveLoadIdentity(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "id.json")

	id, _ := crypto.GenerateIdentity()
	if err := crypto.SaveIdentity(path, id); err != nil {
		t.Fatal(err)
	}

	loaded, err := crypto.LoadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if !id.PublicKey.Equal(loaded.PublicKey) {
		t.Fatal("public key mismatch")
	}
	if !id.PrivateKey.Equal(loaded.PrivateKey) {
		t.Fatal("private key mismatch")
	}
}

func TestLoadIdentityNotExist(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.json")

	id, err := crypto.LoadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if id != nil {
		t.Fatal("expected nil identity for nonexistent file")
	}
}

func TestLoadIdentityInvalidJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("not json"), 0600)

	_, err := crypto.LoadIdentity(path)
	if err == nil {
		t.Fatal("should fail on invalid JSON")
	}
}

func TestSaveIdentityCreatesDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "dir", "id.json")

	id, _ := crypto.GenerateIdentity()
	if err := crypto.SaveIdentity(path, id); err != nil {
		t.Fatal(err)
	}

	loaded, err := crypto.LoadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if !id.PublicKey.Equal(loaded.PublicKey) {
		t.Fatal("roundtrip through nested dir failed")
	}
}

func TestSaveIdentityFilePermissions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "id.json")

	id, _ := crypto.GenerateIdentity()
	crypto.SaveIdentity(path, id)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}
}

func TestSignEmptyMessage(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	sig := id.Sign([]byte{})
	if !crypto.Verify(id.PublicKey, []byte{}, sig) {
		t.Fatal("should verify empty message")
	}
}

func TestSignLargeMessage(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	msg := make([]byte, 1<<16) // 64KB
	for i := range msg {
		msg[i] = byte(i)
	}
	sig := id.Sign(msg)
	if !crypto.Verify(id.PublicKey, msg, sig) {
		t.Fatal("should verify large message")
	}
}

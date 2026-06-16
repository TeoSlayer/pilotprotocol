package catalogtrust

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

// TestVerify covers the happy path plus tamper and short-signature
// rejection, using a freshly-generated key swapped in for the embedded
// one (white-box).
func TestVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	orig := publicKeyB64
	publicKeyB64 = base64.StdEncoding.EncodeToString(pub)
	defer func() { publicKeyB64 = orig }()

	data := []byte(`{"version":1,"apps":[]}`)
	sig := ed25519.Sign(priv, data)

	if err := Verify(data, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := Verify([]byte(`{"version":2,"apps":[]}`), sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered data err = %v, want ErrBadSignature", err)
	}
	if err := Verify(data, sig[:10]); !errors.Is(err, ErrBadSignature) {
		t.Errorf("short signature err = %v, want ErrBadSignature", err)
	}
}

// TestVerify_NoKey asserts a malformed embedded key fails closed.
func TestVerify_NoKey(t *testing.T) {
	orig := publicKeyB64
	publicKeyB64 = "not-valid-base64!!!"
	defer func() { publicKeyB64 = orig }()
	if PublicKey() != nil {
		t.Fatal("malformed key should yield nil PublicKey")
	}
	if err := Verify([]byte("x"), make([]byte, ed25519.SignatureSize)); !errors.Is(err, ErrNoKey) {
		t.Errorf("err = %v, want ErrNoKey", err)
	}
}

// TestEmbeddedKeyIsValid guards against shipping a build whose compiled-in
// catalogue key is malformed (which would fail-close every install).
func TestEmbeddedKeyIsValid(t *testing.T) {
	if PublicKey() == nil {
		t.Fatal("embedded catalogue public key is malformed")
	}
}

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Identity holds an Ed25519 keypair for a node.
type Identity struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// GenerateIdentity creates a new random Ed25519 keypair.
func GenerateIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return &Identity{PublicKey: pub, PrivateKey: priv}, nil
}

// Sign signs a message with the private key.
func (id *Identity) Sign(message []byte) []byte {
	return ed25519.Sign(id.PrivateKey, message)
}

// Verify checks a signature against the public key.
func Verify(publicKey ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}

// EncodePublicKey returns the public key as base64.
func EncodePublicKey(key ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(key)
}

// DecodePublicKey decodes a base64 public key.
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: %d", len(b))
	}
	return ed25519.PublicKey(b), nil
}

// EncodePrivateKey returns the private key as base64.
func EncodePrivateKey(key ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(key)
}

// DecodePrivateKey decodes a base64 private key.
func DecodePrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: %d", len(b))
	}
	return ed25519.PrivateKey(b), nil
}

// identityFile is the on-disk format for a persisted identity.
type identityFile struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// SaveIdentity writes the identity keypair to a JSON file.
// Creates parent directories if needed. File is written with mode 0600.
func SaveIdentity(path string, id *Identity) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create identity dir: %w", err)
	}

	f := identityFile{
		PrivateKey: EncodePrivateKey(id.PrivateKey),
		PublicKey:  EncodePublicKey(id.PublicKey),
	}

	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal identity: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write identity: %w", err)
	}
	return nil
}

// LoadIdentity reads an identity keypair from a JSON file.
// Returns nil, nil if the file does not exist (first run).
func LoadIdentity(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // first run
		}
		return nil, fmt.Errorf("read identity: %w", err)
	}

	var f identityFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("unmarshal identity: %w", err)
	}

	priv, err := DecodePrivateKey(f.PrivateKey)
	if err != nil {
		return nil, err
	}
	pub, err := DecodePublicKey(f.PublicKey)
	if err != nil {
		return nil, err
	}

	// Verify key consistency: the public key stored on disk must match
	// the public key derived from the private key (L5 fix)
	derivedPub := priv.Public().(ed25519.PublicKey)
	if !derivedPub.Equal(pub) {
		return nil, fmt.Errorf("identity file corrupted: public key does not match private key")
	}

	return &Identity{PublicKey: pub, PrivateKey: priv}, nil
}

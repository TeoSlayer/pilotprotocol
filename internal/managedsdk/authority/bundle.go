// SPDX-License-Identifier: AGPL-3.0-or-later

// Package authority defines tenant-root-signed key distribution state used by
// local Pilot enforcement points.
package authority

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SchemaVersion      uint16 = 1
	TrustDomain               = "pilot-trust-bundle-v1"
	MaxBundleTTL              = 7 * 24 * time.Hour
	MaxBundleKeys             = 256
	MaxBundleClockSkew        = time.Minute
)

type KeyUsage string

const (
	UsageIntent   KeyUsage = "intent"
	UsageDecision KeyUsage = "decision"
	UsagePolicy   KeyUsage = "policy"
	UsageMandate  KeyUsage = "mandate"
	UsageApproval KeyUsage = "approval"
	UsageReceipt  KeyUsage = "receipt"
)

// AuthorityKey is an online key delegated by the tenant root. Intent and
// receipt keys are scoped to one agent; authority-wide issuer keys leave
// AgentID empty.
type AuthorityKey struct {
	KeyID     string     `json:"key_id"`
	AgentID   string     `json:"agent_id,omitempty"`
	PublicKey string     `json:"public_key"`
	Usages    []KeyUsage `json:"usages"`
	NotBefore int64      `json:"not_before"`
	ExpiresAt int64      `json:"expires_at"`
}

// TrustBundle is the complete signed online-key view for one tenant. Removing
// or narrowing a previously active key requires a higher RevocationEpoch.
type TrustBundle struct {
	Version         uint16         `json:"version"`
	TenantID        string         `json:"tenant_id"`
	Revision        uint64         `json:"revision"`
	PolicyRevision  uint64         `json:"policy_revision"`
	RevocationEpoch uint64         `json:"revocation_epoch"`
	IssuedAt        int64          `json:"issued_at"`
	ExpiresAt       int64          `json:"expires_at"`
	RootKeyID       string         `json:"root_key_id"`
	Keys            []AuthorityKey `json:"keys"`
	Signature       string         `json:"signature"`
}

func (bundle TrustBundle) Validate() error {
	if bundle.Version != SchemaVersion {
		return fmt.Errorf("authority: trust bundle version %d is unsupported", bundle.Version)
	}
	if err := validateIdentifier("tenant_id", bundle.TenantID); err != nil {
		return err
	}
	if err := validateIdentifier("root_key_id", bundle.RootKeyID); err != nil {
		return err
	}
	if bundle.Revision == 0 {
		return fmt.Errorf("authority: trust bundle revision must be positive")
	}
	if bundle.IssuedAt <= 0 || bundle.ExpiresAt <= bundle.IssuedAt {
		return fmt.Errorf("authority: invalid trust bundle validity window")
	}
	if bundle.ExpiresAt-bundle.IssuedAt > int64(MaxBundleTTL/time.Second) {
		return fmt.Errorf("authority: trust bundle validity exceeds %s", MaxBundleTTL)
	}
	if len(bundle.Keys) > MaxBundleKeys {
		return fmt.Errorf("authority: trust bundle exceeds %d keys", MaxBundleKeys)
	}
	seen := make(map[string]struct{}, len(bundle.Keys))
	for _, key := range bundle.Keys {
		if err := key.validate(bundle.IssuedAt, bundle.ExpiresAt); err != nil {
			return err
		}
		if _, exists := seen[key.KeyID]; exists {
			return fmt.Errorf("authority: duplicate key_id %q", key.KeyID)
		}
		seen[key.KeyID] = struct{}{}
	}
	return nil
}

func (key AuthorityKey) validate(bundleIssuedAt, bundleExpiresAt int64) error {
	if err := validateIdentifier("key_id", key.KeyID); err != nil {
		return err
	}
	if key.AgentID != "" {
		if err := validateIdentifier("agent_id", key.AgentID); err != nil {
			return err
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return fmt.Errorf("authority: key %q has invalid Ed25519 public_key", key.KeyID)
	}
	if base64.StdEncoding.EncodeToString(decoded) != key.PublicKey {
		return fmt.Errorf("authority: key %q public_key is not canonically encoded", key.KeyID)
	}
	if key.NotBefore <= 0 || key.ExpiresAt > bundleExpiresAt || key.ExpiresAt <= key.NotBefore || key.ExpiresAt <= bundleIssuedAt {
		return fmt.Errorf("authority: key %q validity exceeds its trust bundle", key.KeyID)
	}
	if len(key.Usages) == 0 || len(key.Usages) > 6 {
		return fmt.Errorf("authority: key %q must have 1-6 usages", key.KeyID)
	}
	seen := make(map[KeyUsage]struct{}, len(key.Usages))
	for _, usage := range key.Usages {
		switch usage {
		case UsageIntent, UsageDecision, UsagePolicy, UsageMandate, UsageApproval, UsageReceipt:
		default:
			return fmt.Errorf("authority: key %q has unknown usage %q", key.KeyID, usage)
		}
		if _, exists := seen[usage]; exists {
			return fmt.Errorf("authority: key %q repeats usage %q", key.KeyID, usage)
		}
		seen[usage] = struct{}{}
	}
	if _, hasIntent := seen[UsageIntent]; hasIntent && key.AgentID == "" {
		return fmt.Errorf("authority: intent key %q must be scoped to an agent", key.KeyID)
	}
	if _, hasReceipt := seen[UsageReceipt]; hasReceipt && key.AgentID == "" {
		return fmt.Errorf("authority: receipt key %q must be scoped to an agent", key.KeyID)
	}
	if key.AgentID != "" {
		for usage := range seen {
			if usage != UsageIntent && usage != UsageReceipt {
				return fmt.Errorf("authority: tenant issuer key %q cannot be agent-scoped", key.KeyID)
			}
		}
	}
	return nil
}

func (bundle TrustBundle) Canonical() ([]byte, error) {
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	keys := append([]AuthorityKey(nil), bundle.Keys...)
	sort.Slice(keys, func(i, j int) bool { return keys[i].KeyID < keys[j].KeyID })
	writer := canonicalWriter{}
	writer.string(TrustDomain)
	writer.u16(bundle.Version)
	writer.string(bundle.TenantID)
	writer.u64(bundle.Revision)
	writer.u64(bundle.PolicyRevision)
	writer.u64(bundle.RevocationEpoch)
	writer.i64(bundle.IssuedAt)
	writer.i64(bundle.ExpiresAt)
	writer.string(bundle.RootKeyID)
	// #nosec G115 -- Validate limits keys to MaxBundleKeys, which is below uint16 capacity.
	writer.u16(uint16(len(keys)))
	for _, key := range keys {
		writer.string(key.KeyID)
		writer.string(key.AgentID)
		writer.string(key.PublicKey)
		usages := append([]KeyUsage(nil), key.Usages...)
		sort.Slice(usages, func(i, j int) bool { return usages[i] < usages[j] })
		// #nosec G115 -- AuthorityKey.Validate bounds usages below uint16 capacity.
		writer.u16(uint16(len(usages)))
		for _, usage := range usages {
			writer.string(string(usage))
		}
		writer.i64(key.NotBefore)
		writer.i64(key.ExpiresAt)
	}
	if writer.err != nil {
		return nil, writer.err
	}
	return writer.Buffer.Bytes(), nil
}

func (bundle TrustBundle) Hash() (string, error) {
	canonical, err := bundle.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func (bundle *TrustBundle) Sign(rootPrivateKey ed25519.PrivateKey) error {
	if len(rootPrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("authority: invalid tenant root private key")
	}
	canonical, err := bundle.Canonical()
	if err != nil {
		return err
	}
	bundle.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(rootPrivateKey, canonical))
	return nil
}

func (bundle TrustBundle) Verify(rootPublicKey ed25519.PublicKey, now time.Time) error {
	if err := bundle.VerifySignature(rootPublicKey); err != nil {
		return err
	}
	nowUnix := now.Unix()
	if bundle.IssuedAt > nowUnix+int64(MaxBundleClockSkew/time.Second) {
		return fmt.Errorf("authority: trust bundle is not yet valid")
	}
	if bundle.ExpiresAt < nowUnix {
		return fmt.Errorf("authority: trust bundle is expired")
	}
	return nil
}

func (bundle TrustBundle) VerifySignature(rootPublicKey ed25519.PublicKey) error {
	canonical, err := bundle.Canonical()
	if err != nil {
		return err
	}
	if len(rootPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("authority: invalid pinned tenant root public key")
	}
	signature, err := base64.StdEncoding.DecodeString(bundle.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(rootPublicKey, canonical, signature) {
		return fmt.Errorf("authority: invalid trust bundle signature")
	}
	return nil
}

func (key AuthorityKey) publicKey() ed25519.PublicKey {
	decoded, _ := base64.StdEncoding.DecodeString(key.PublicKey)
	return append(ed25519.PublicKey(nil), decoded...)
}

func (key AuthorityKey) permits(usage KeyUsage) bool {
	for _, candidate := range key.Usages {
		if candidate == usage {
			return true
		}
	}
	return false
}

func validateIdentifier(name, value string) error {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) {
		return fmt.Errorf("authority: invalid %s", name)
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._:/@-", character) {
			continue
		}
		return fmt.Errorf("authority: invalid %s", name)
	}
	return nil
}

type canonicalWriter struct {
	bytes.Buffer
	err error
}

func (writer *canonicalWriter) u16(value uint16) { writer.write(value) }
func (writer *canonicalWriter) u64(value uint64) { writer.write(value) }
func (writer *canonicalWriter) i64(value int64)  { writer.write(value) }
func (writer *canonicalWriter) boolean(value bool) {
	if value {
		writer.u16(1)
		return
	}
	writer.u16(0)
}
func (writer *canonicalWriter) write(value any) {
	if writer.err == nil {
		writer.err = binary.Write(&writer.Buffer, binary.BigEndian, value)
	}
}
func (writer *canonicalWriter) string(value string) {
	if len(value) > int(^uint32(0)) {
		writer.err = fmt.Errorf("authority: canonical string is too large")
		return
	}
	// #nosec G115 -- the immediately preceding guard rejects lengths above uint32 capacity.
	writer.write(uint32(len(value)))
	if writer.err == nil {
		_, writer.err = writer.WriteString(value)
	}
}

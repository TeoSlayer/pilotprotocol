// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	PolicyDomain          = "pilot-policy-bundle-v1"
	MaxPolicyPayloadBytes = 1 << 20
	MaxPolicyTTL          = 7 * 24 * time.Hour
	PolicyFailureDeny     = "deny"
)

// PolicyBundle is compiled/validated tenant policy state distributed to local
// enforcement points. Payload interpretation is engine-specific; its signed
// envelope and activation semantics are protocol-level.
type PolicyBundle struct {
	Version         uint16 `json:"version"`
	TenantID        string `json:"tenant_id"`
	Revision        uint64 `json:"revision"`
	RevocationEpoch uint64 `json:"revocation_epoch"`
	IssuedAt        int64  `json:"issued_at"`
	ActivatesAt     int64  `json:"activates_at"`
	ExpiresAt       int64  `json:"expires_at"`
	Engine          string `json:"engine"`
	EngineVersion   string `json:"engine_version"`
	ContentType     string `json:"content_type"`
	PayloadHash     string `json:"payload_hash"`
	Payload         []byte `json:"payload"`
	FailureMode     string `json:"failure_mode"`
	KeyID           string `json:"key_id"`
	Signature       string `json:"signature"`
}

func NewPolicyBundle(tenantID string, revision, revocationEpoch uint64, issuedAt, activatesAt, expiresAt time.Time, engine, engineVersion, contentType, keyID string, payload []byte) PolicyBundle {
	return PolicyBundle{
		Version: SchemaVersion, TenantID: tenantID, Revision: revision, RevocationEpoch: revocationEpoch,
		IssuedAt: issuedAt.Unix(), ActivatesAt: activatesAt.Unix(), ExpiresAt: expiresAt.Unix(),
		Engine: engine, EngineVersion: engineVersion, ContentType: contentType,
		PayloadHash: hashPolicyPayload(payload), Payload: append([]byte(nil), payload...),
		FailureMode: PolicyFailureDeny, KeyID: keyID,
	}
}

func (bundle PolicyBundle) Validate() error {
	if bundle.Version != SchemaVersion {
		return fmt.Errorf("authority: policy bundle version %d is unsupported", bundle.Version)
	}
	for name, value := range map[string]string{
		"tenant_id": bundle.TenantID, "engine": bundle.Engine, "key_id": bundle.KeyID,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if err := validateBoundedText("engine_version", bundle.EngineVersion, 128); err != nil {
		return err
	}
	if err := validateBoundedText("content_type", bundle.ContentType, 128); err != nil {
		return err
	}
	if bundle.Revision == 0 {
		return fmt.Errorf("authority: policy revision must be positive")
	}
	if bundle.IssuedAt <= 0 || bundle.ActivatesAt < bundle.IssuedAt || bundle.ExpiresAt <= bundle.ActivatesAt {
		return fmt.Errorf("authority: invalid policy validity or activation window")
	}
	if bundle.ExpiresAt-bundle.IssuedAt > int64(MaxPolicyTTL/time.Second) {
		return fmt.Errorf("authority: policy validity exceeds %s", MaxPolicyTTL)
	}
	if len(bundle.Payload) == 0 || len(bundle.Payload) > MaxPolicyPayloadBytes {
		return fmt.Errorf("authority: policy payload must be 1-%d bytes", MaxPolicyPayloadBytes)
	}
	if bundle.PayloadHash != hashPolicyPayload(bundle.Payload) {
		return fmt.Errorf("authority: policy payload hash mismatch")
	}
	if bundle.FailureMode != PolicyFailureDeny {
		return fmt.Errorf("authority: policy failure_mode must be %q in schema v1", PolicyFailureDeny)
	}
	return nil
}

func (bundle PolicyBundle) Canonical() ([]byte, error) {
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	writer := canonicalWriter{}
	writer.string(PolicyDomain)
	writer.u16(bundle.Version)
	writer.string(bundle.TenantID)
	writer.u64(bundle.Revision)
	writer.u64(bundle.RevocationEpoch)
	writer.i64(bundle.IssuedAt)
	writer.i64(bundle.ActivatesAt)
	writer.i64(bundle.ExpiresAt)
	writer.string(bundle.Engine)
	writer.string(bundle.EngineVersion)
	writer.string(bundle.ContentType)
	writer.string(bundle.PayloadHash)
	writer.string(string(bundle.Payload))
	writer.string(bundle.FailureMode)
	writer.string(bundle.KeyID)
	if writer.err != nil {
		return nil, writer.err
	}
	return writer.Buffer.Bytes(), nil
}

func (bundle PolicyBundle) Hash() (string, error) {
	canonical, err := bundle.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func (bundle *PolicyBundle) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("authority: invalid policy issuer private key")
	}
	canonical, err := bundle.Canonical()
	if err != nil {
		return err
	}
	bundle.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return nil
}

func (bundle PolicyBundle) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := bundle.Canonical()
	if err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("authority: invalid policy issuer public key")
	}
	nowUnix := now.Unix()
	if bundle.IssuedAt > nowUnix+int64(MaxBundleClockSkew/time.Second) {
		return fmt.Errorf("authority: policy bundle is not yet issued")
	}
	if bundle.ExpiresAt < nowUnix {
		return fmt.Errorf("authority: policy bundle is expired")
	}
	signature, err := base64.StdEncoding.DecodeString(bundle.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("authority: invalid policy bundle signature")
	}
	return nil
}

type PolicyValidator interface {
	ValidatePolicy(ctx context.Context, engine, engineVersion, contentType string, payload []byte) error
}

type PolicyTrustStore interface {
	PolicyKey(tenantID, keyID string) (ed25519.PublicKey, error)
	MinimumState(context.Context, string) (uint64, uint64, error)
}

// PolicyManager validates, stages, and activates signed policy without ever
// falling back to an older revision. Persistence/distribution is supplied by
// the embedding control-plane process.
type PolicyManager struct {
	mu        sync.RWMutex
	trust     PolicyTrustStore
	validator PolicyValidator
	now       func() time.Time
	active    map[string]PolicyBundle
	staged    map[string]PolicyBundle
	held      map[string]uint64
}

func NewPolicyManager(trust PolicyTrustStore, validator PolicyValidator, now func() time.Time) (*PolicyManager, error) {
	if trust == nil || validator == nil {
		return nil, fmt.Errorf("authority: trust store and policy validator are required")
	}
	if now == nil {
		now = time.Now
	}
	return &PolicyManager{
		trust: trust, validator: validator, now: now,
		active: make(map[string]PolicyBundle), staged: make(map[string]PolicyBundle), held: make(map[string]uint64),
	}, nil
}

func (manager *PolicyManager) Install(ctx context.Context, bundle PolicyBundle) error {
	return manager.install(ctx, bundle, nil, false)
}

// InstallWithCommit validates and compiles the candidate, then invokes commit
// while the manager's revision lock is held and before the candidate becomes
// visible. A failed durable commit therefore cannot advance in-memory policy.
func (manager *PolicyManager) InstallWithCommit(ctx context.Context, bundle PolicyBundle, commit func() error) error {
	return manager.install(ctx, bundle, commit, false)
}

// InstallHeldWithCommit persists and stages managed desired state without
// allowing time alone to activate it. A verified rollout activation is needed.
func (manager *PolicyManager) InstallHeldWithCommit(ctx context.Context, bundle PolicyBundle, commit func() error) error {
	return manager.install(ctx, bundle, commit, true)
}

func (manager *PolicyManager) install(ctx context.Context, bundle PolicyBundle, commit func() error, held bool) error {
	if err := manager.Validate(ctx, bundle); err != nil {
		return err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := manager.rejectRollbackLocked(bundle); err != nil {
		return err
	}
	if commit != nil {
		if err := commit(); err != nil {
			return fmt.Errorf("authority: durable policy commit failed: %w", err)
		}
	}
	if held {
		manager.staged[bundle.TenantID] = clonePolicyBundle(bundle)
		manager.held[bundle.TenantID] = bundle.Revision
	} else if bundle.ActivatesAt <= manager.now().Unix() {
		manager.active[bundle.TenantID] = clonePolicyBundle(bundle)
		delete(manager.staged, bundle.TenantID)
		delete(manager.held, bundle.TenantID)
	} else {
		manager.staged[bundle.TenantID] = clonePolicyBundle(bundle)
		delete(manager.held, bundle.TenantID)
	}
	return nil
}

// Validate authenticates, checks state floors, and compiles a policy bundle
// without mutating active or staged state.
func (manager *PolicyManager) Validate(ctx context.Context, bundle PolicyBundle) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	publicKey, err := manager.trust.PolicyKey(bundle.TenantID, bundle.KeyID)
	if err != nil {
		return fmt.Errorf("authority: resolve policy key: %w", err)
	}
	if err := bundle.Verify(publicKey, manager.now()); err != nil {
		return err
	}
	minimumPolicy, minimumRevocation, err := manager.trust.MinimumState(ctx, bundle.TenantID)
	if err != nil {
		return err
	}
	if bundle.Revision < minimumPolicy || bundle.RevocationEpoch < minimumRevocation {
		return fmt.Errorf("authority: policy bundle is below tenant state floor")
	}
	if err := manager.validator.ValidatePolicy(ctx, bundle.Engine, bundle.EngineVersion, bundle.ContentType, append([]byte(nil), bundle.Payload...)); err != nil {
		return fmt.Errorf("authority: policy validation failed: %w", err)
	}
	return nil
}

func (manager *PolicyManager) ValidateInstall(ctx context.Context, bundle PolicyBundle) error {
	if err := manager.Validate(ctx, bundle); err != nil {
		return err
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return manager.rejectRollbackLocked(bundle)
}

type PolicySnapshot struct {
	Active *PolicyBundle
	Staged *PolicyBundle
	Held   bool
}

func (manager *PolicyManager) Snapshot(tenantID string) PolicySnapshot {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	snapshot := PolicySnapshot{}
	if active, exists := manager.active[tenantID]; exists {
		clone := clonePolicyBundle(active)
		snapshot.Active = &clone
	}
	if staged, exists := manager.staged[tenantID]; exists {
		clone := clonePolicyBundle(staged)
		snapshot.Staged = &clone
		snapshot.Held = manager.held[tenantID] == staged.Revision
	}
	return snapshot
}

func (manager *PolicyManager) Active(ctx context.Context, tenantID string) (PolicyBundle, error) {
	if err := ctx.Err(); err != nil {
		return PolicyBundle{}, err
	}
	manager.mu.Lock()
	now := manager.now().Unix()
	if staged, exists := manager.staged[tenantID]; exists && staged.ActivatesAt <= now && manager.held[tenantID] != staged.Revision {
		manager.active[tenantID] = staged
		delete(manager.staged, tenantID)
		delete(manager.held, tenantID)
	}
	active, exists := manager.active[tenantID]
	active = clonePolicyBundle(active)
	manager.mu.Unlock()
	if !exists {
		return PolicyBundle{}, fmt.Errorf("authority: tenant %q has no active policy", tenantID)
	}
	if active.ExpiresAt < now {
		return PolicyBundle{}, fmt.Errorf("authority: tenant %q active policy is expired", tenantID)
	}
	minimumPolicy, minimumRevocation, err := manager.trust.MinimumState(ctx, tenantID)
	if err != nil {
		return PolicyBundle{}, err
	}
	if active.Revision < minimumPolicy || active.RevocationEpoch < minimumRevocation {
		return PolicyBundle{}, fmt.Errorf("authority: tenant %q active policy is stale", tenantID)
	}
	return active, nil
}

// ActivateHeldWithCommit promotes a managed staged revision only after its
// signed earliest activation time and only after durable activation commit.
func (manager *PolicyManager) ActivateHeldWithCommit(ctx context.Context, tenantID string, revision uint64, commit func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	staged, exists := manager.staged[tenantID]
	if !exists || staged.Revision != revision || manager.held[tenantID] != revision {
		return fmt.Errorf("authority: managed policy revision is not held for activation")
	}
	if manager.now().Unix() < staged.ActivatesAt {
		return fmt.Errorf("authority: managed policy activation is too early")
	}
	minimumPolicy, minimumRevocation, err := manager.trust.MinimumState(ctx, tenantID)
	if err != nil {
		return err
	}
	if staged.Revision < minimumPolicy || staged.RevocationEpoch < minimumRevocation {
		return fmt.Errorf("authority: managed policy is below tenant state floor")
	}
	if commit != nil {
		if err := commit(); err != nil {
			return fmt.Errorf("authority: durable policy activation commit failed: %w", err)
		}
	}
	manager.active[tenantID] = staged
	delete(manager.staged, tenantID)
	delete(manager.held, tenantID)
	return nil
}

func (manager *PolicyManager) rejectRollbackLocked(candidate PolicyBundle) error {
	candidateHash, _ := candidate.Hash()
	for _, installed := range []PolicyBundle{manager.active[candidate.TenantID], manager.staged[candidate.TenantID]} {
		if installed.Revision == 0 {
			continue
		}
		installedHash, _ := installed.Hash()
		if installed.Revision == candidate.Revision && installedHash == candidateHash && installed.Signature == candidate.Signature {
			continue
		}
		if candidate.Revision <= installed.Revision {
			return fmt.Errorf("authority: policy revision rollback")
		}
		if candidate.RevocationEpoch < installed.RevocationEpoch {
			return fmt.Errorf("authority: policy revocation epoch rollback")
		}
	}
	return nil
}

func clonePolicyBundle(bundle PolicyBundle) PolicyBundle {
	clone := bundle
	clone.Payload = append([]byte(nil), bundle.Payload...)
	return clone
}

func hashPolicyPayload(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func validateBoundedText(name, value string, limit int) error {
	if value == "" || len(value) > limit || !utf8.ValidString(value) {
		return fmt.Errorf("authority: invalid %s", name)
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("authority: invalid %s", name)
		}
	}
	return nil
}

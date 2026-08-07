// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	PolicyPublicationDomain = "pilot-policy-publication-v1"
	PolicyAckDomain         = "pilot-policy-ack-v1"
	PolicyActivationDomain  = "pilot-policy-activation-v1"
	PolicyWithdrawalDomain  = "pilot-policy-withdrawal-v1"
	MaxRolloutTargets       = 10_000
)

type PolicyPublication struct {
	Version              uint16   `json:"version"`
	ID                   string   `json:"id"`
	TenantID             string   `json:"tenant_id"`
	PolicyRevision       uint64   `json:"policy_revision"`
	RevocationEpoch      uint64   `json:"revocation_epoch"`
	PolicyHash           string   `json:"policy_hash"`
	ExpectedAgents       []string `json:"expected_agents"`
	RequiredAcknowledged uint32   `json:"required_acknowledged"`
	IssuedAt             int64    `json:"issued_at"`
	KeyID                string   `json:"key_id"`
	Signature            string   `json:"signature"`
}

type PolicyAckStatus string

const (
	PolicyAckStaged   PolicyAckStatus = "staged"
	PolicyAckEnforced PolicyAckStatus = "enforced"
	PolicyAckRejected PolicyAckStatus = "rejected"
)

type PolicyAcknowledgement struct {
	Version         uint16          `json:"version"`
	ID              string          `json:"id"`
	PublicationID   string          `json:"publication_id"`
	PolicyHash      string          `json:"policy_hash"`
	TenantID        string          `json:"tenant_id"`
	AgentID         string          `json:"agent_id"`
	PolicyRevision  uint64          `json:"policy_revision"`
	RevocationEpoch uint64          `json:"revocation_epoch"`
	Status          PolicyAckStatus `json:"status"`
	ObservedAt      int64           `json:"observed_at"`
	KeyID           string          `json:"key_id"`
	Signature       string          `json:"signature"`
}

type PolicyActivation struct {
	Version         uint16 `json:"version"`
	ID              string `json:"id"`
	PublicationID   string `json:"publication_id"`
	PublicationHash string `json:"publication_hash"`
	PolicyHash      string `json:"policy_hash"`
	TenantID        string `json:"tenant_id"`
	PolicyRevision  uint64 `json:"policy_revision"`
	RevocationEpoch uint64 `json:"revocation_epoch"`
	IssuedAt        int64  `json:"issued_at"`
	ActivatesAt     int64  `json:"activates_at"`
	KeyID           string `json:"key_id"`
	Signature       string `json:"signature"`
}

// PolicyWithdrawal is the signed terminal state for a published candidate or
// a future activation. It never rolls back an already-active policy; that
// requires a higher signed policy revision. Agents and authority replicas can
// therefore distinguish an intentional withdrawal from transport absence.
type PolicyWithdrawal struct {
	Version         uint16 `json:"version"`
	ID              string `json:"id"`
	PublicationID   string `json:"publication_id"`
	PublicationHash string `json:"publication_hash"`
	TenantID        string `json:"tenant_id"`
	PolicyRevision  uint64 `json:"policy_revision"`
	Reason          string `json:"reason"`
	IssuedAt        int64  `json:"issued_at"`
	KeyID           string `json:"key_id"`
	Signature       string `json:"signature"`
}

func (publication PolicyPublication) Validate() error {
	if publication.Version != SchemaVersion {
		return fmt.Errorf("authority: unsupported policy publication version")
	}
	for name, value := range map[string]string{"id": publication.ID, "tenant_id": publication.TenantID, "key_id": publication.KeyID} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if publication.PolicyRevision == 0 || !lowerHexAuthority(publication.PolicyHash, 64) || publication.IssuedAt <= 0 {
		return fmt.Errorf("authority: invalid policy publication state")
	}
	if len(publication.ExpectedAgents) == 0 || len(publication.ExpectedAgents) > MaxRolloutTargets {
		return fmt.Errorf("authority: policy publication requires 1-%d target agents", MaxRolloutTargets)
	}
	if publication.RequiredAcknowledged == 0 || int(publication.RequiredAcknowledged) > len(publication.ExpectedAgents) {
		return fmt.Errorf("authority: invalid required acknowledgement count")
	}
	seen := make(map[string]struct{}, len(publication.ExpectedAgents))
	for _, agentID := range publication.ExpectedAgents {
		if err := validateIdentifier("expected agent", agentID); err != nil {
			return err
		}
		if _, exists := seen[agentID]; exists {
			return fmt.Errorf("authority: duplicate expected agent %q", agentID)
		}
		seen[agentID] = struct{}{}
	}
	return nil
}

func (publication PolicyPublication) Canonical() ([]byte, error) {
	if err := publication.Validate(); err != nil {
		return nil, err
	}
	agents := append([]string(nil), publication.ExpectedAgents...)
	sort.Strings(agents)
	writer := canonicalWriter{}
	writer.string(PolicyPublicationDomain)
	writer.u16(publication.Version)
	writer.string(publication.ID)
	writer.string(publication.TenantID)
	writer.u64(publication.PolicyRevision)
	writer.u64(publication.RevocationEpoch)
	writer.string(publication.PolicyHash)
	// #nosec G115 -- Validate limits expected agents below uint16 capacity.
	writer.u16(uint16(len(agents)))
	for _, agentID := range agents {
		writer.string(agentID)
	}
	writer.u64(uint64(publication.RequiredAcknowledged))
	writer.i64(publication.IssuedAt)
	writer.string(publication.KeyID)
	if writer.err != nil {
		return nil, writer.err
	}
	return writer.Buffer.Bytes(), nil
}

func (publication PolicyPublication) Hash() (string, error) {
	canonical, err := publication.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func (publication *PolicyPublication) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("authority: invalid policy publication private key")
	}
	canonical, err := publication.Canonical()
	if err != nil {
		return err
	}
	publication.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return nil
}

func (publication PolicyPublication) VerifyFor(bundle PolicyBundle, publicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := publication.Canonical()
	if err != nil {
		return err
	}
	if publication.IssuedAt > now.Unix()+int64(MaxBundleClockSkew/time.Second) {
		return fmt.Errorf("authority: policy publication is not yet valid")
	}
	signature, err := base64.StdEncoding.DecodeString(publication.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("authority: invalid policy publication signature")
	}
	bundleHash, err := bundle.Hash()
	if err != nil {
		return err
	}
	if publication.TenantID != bundle.TenantID || publication.PolicyRevision != bundle.Revision ||
		publication.RevocationEpoch != bundle.RevocationEpoch || publication.PolicyHash != bundleHash ||
		publication.KeyID != bundle.KeyID || publication.IssuedAt < bundle.IssuedAt || publication.IssuedAt > bundle.ExpiresAt {
		return fmt.Errorf("authority: policy publication bundle binding mismatch")
	}
	return nil
}

func NewPolicyAcknowledgement(publication PolicyPublication, agentID string, status PolicyAckStatus, observedAt time.Time, keyID string) (PolicyAcknowledgement, error) {
	ack := PolicyAcknowledgement{
		Version: SchemaVersion, PublicationID: publication.ID, PolicyHash: publication.PolicyHash,
		TenantID: publication.TenantID, AgentID: agentID, PolicyRevision: publication.PolicyRevision,
		RevocationEpoch: publication.RevocationEpoch, Status: status, ObservedAt: observedAt.Unix(), KeyID: keyID,
	}
	ack.ID = acknowledgementID(ack)
	if err := ack.Validate(); err != nil {
		return PolicyAcknowledgement{}, err
	}
	return ack, nil
}

func (ack PolicyAcknowledgement) Validate() error {
	if ack.Version != SchemaVersion || !lowerHexAuthority(ack.ID, 64) || !lowerHexAuthority(ack.PolicyHash, 64) {
		return fmt.Errorf("authority: invalid policy acknowledgement identity")
	}
	for name, value := range map[string]string{
		"publication_id": ack.PublicationID, "tenant_id": ack.TenantID, "agent_id": ack.AgentID, "key_id": ack.KeyID,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if ack.PolicyRevision == 0 || ack.ObservedAt <= 0 {
		return fmt.Errorf("authority: invalid policy acknowledgement state")
	}
	switch ack.Status {
	case PolicyAckStaged, PolicyAckEnforced, PolicyAckRejected:
	default:
		return fmt.Errorf("authority: invalid policy acknowledgement status %q", ack.Status)
	}
	if ack.ID != acknowledgementID(ack) {
		return fmt.Errorf("authority: noncanonical policy acknowledgement id")
	}
	return nil
}

func (ack PolicyAcknowledgement) Canonical() ([]byte, error) {
	if err := ack.Validate(); err != nil {
		return nil, err
	}
	writer := canonicalWriter{}
	writer.string(PolicyAckDomain)
	writer.u16(ack.Version)
	writer.string(ack.ID)
	writer.string(ack.PublicationID)
	writer.string(ack.PolicyHash)
	writer.string(ack.TenantID)
	writer.string(ack.AgentID)
	writer.u64(ack.PolicyRevision)
	writer.u64(ack.RevocationEpoch)
	writer.string(string(ack.Status))
	writer.i64(ack.ObservedAt)
	writer.string(ack.KeyID)
	if writer.err != nil {
		return nil, writer.err
	}
	return writer.Buffer.Bytes(), nil
}

func (ack *PolicyAcknowledgement) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("authority: invalid policy acknowledgement private key")
	}
	return ack.SignWith(func(message []byte) ([]byte, error) {
		return ed25519.Sign(privateKey, message), nil
	})
}

func (ack *PolicyAcknowledgement) SignWith(signer func([]byte) ([]byte, error)) error {
	if signer == nil {
		return fmt.Errorf("authority: policy acknowledgement signer is required")
	}
	canonical, err := ack.Canonical()
	if err != nil {
		return err
	}
	signature, err := signer(canonical)
	if err != nil {
		return fmt.Errorf("authority: sign policy acknowledgement: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("authority: policy acknowledgement signer returned invalid signature length")
	}
	ack.Signature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

func (ack PolicyAcknowledgement) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := ack.Canonical()
	if err != nil {
		return err
	}
	if ack.ObservedAt > now.Unix()+int64(MaxBundleClockSkew/time.Second) {
		return fmt.Errorf("authority: policy acknowledgement is from the future")
	}
	signature, err := base64.StdEncoding.DecodeString(ack.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("authority: invalid policy acknowledgement signature")
	}
	return nil
}

func NewPolicyActivation(publication PolicyPublication, bundle PolicyBundle, issuedAt, activatesAt time.Time, keyID string) (PolicyActivation, error) {
	publicationHash, err := publication.Hash()
	if err != nil {
		return PolicyActivation{}, err
	}
	activation := PolicyActivation{
		Version: SchemaVersion, PublicationID: publication.ID, PublicationHash: publicationHash,
		PolicyHash: publication.PolicyHash, TenantID: publication.TenantID,
		PolicyRevision: publication.PolicyRevision, RevocationEpoch: publication.RevocationEpoch,
		IssuedAt: issuedAt.Unix(), ActivatesAt: activatesAt.Unix(), KeyID: keyID,
	}
	activation.ID = policyActivationID(activation)
	if err := activation.Validate(); err != nil {
		return PolicyActivation{}, err
	}
	if activation.ActivatesAt < bundle.ActivatesAt || activation.ActivatesAt >= bundle.ExpiresAt {
		return PolicyActivation{}, fmt.Errorf("authority: activation time is outside policy window")
	}
	return activation, nil
}

func (activation PolicyActivation) Validate() error {
	if activation.Version != SchemaVersion || !lowerHexAuthority(activation.ID, 64) ||
		!lowerHexAuthority(activation.PublicationHash, 64) || !lowerHexAuthority(activation.PolicyHash, 64) {
		return fmt.Errorf("authority: invalid policy activation identity")
	}
	for name, value := range map[string]string{
		"publication_id": activation.PublicationID, "tenant_id": activation.TenantID, "key_id": activation.KeyID,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if activation.PolicyRevision == 0 || activation.IssuedAt <= 0 || activation.ActivatesAt < activation.IssuedAt {
		return fmt.Errorf("authority: invalid policy activation state")
	}
	if activation.ID != policyActivationID(activation) {
		return fmt.Errorf("authority: noncanonical policy activation id")
	}
	return nil
}

func (activation PolicyActivation) Canonical() ([]byte, error) {
	if err := activation.Validate(); err != nil {
		return nil, err
	}
	writer := canonicalWriter{}
	writer.string(PolicyActivationDomain)
	writer.u16(activation.Version)
	writer.string(activation.ID)
	writer.string(activation.PublicationID)
	writer.string(activation.PublicationHash)
	writer.string(activation.PolicyHash)
	writer.string(activation.TenantID)
	writer.u64(activation.PolicyRevision)
	writer.u64(activation.RevocationEpoch)
	writer.i64(activation.IssuedAt)
	writer.i64(activation.ActivatesAt)
	writer.string(activation.KeyID)
	if writer.err != nil {
		return nil, writer.err
	}
	return writer.Buffer.Bytes(), nil
}

func (activation *PolicyActivation) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("authority: invalid policy activation private key")
	}
	canonical, err := activation.Canonical()
	if err != nil {
		return err
	}
	activation.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return nil
}

func (activation PolicyActivation) VerifyFor(publication PolicyPublication, bundle PolicyBundle, publicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := activation.Canonical()
	if err != nil {
		return err
	}
	if activation.IssuedAt > now.Unix()+int64(MaxBundleClockSkew/time.Second) {
		return fmt.Errorf("authority: policy activation is not yet issued")
	}
	signature, err := base64.StdEncoding.DecodeString(activation.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("authority: invalid policy activation signature")
	}
	publicationHash, _ := publication.Hash()
	if activation.PublicationID != publication.ID || activation.PublicationHash != publicationHash ||
		activation.PolicyHash != publication.PolicyHash || activation.TenantID != publication.TenantID ||
		activation.PolicyRevision != publication.PolicyRevision || activation.RevocationEpoch != publication.RevocationEpoch ||
		activation.ActivatesAt < bundle.ActivatesAt || activation.ActivatesAt >= bundle.ExpiresAt ||
		activation.IssuedAt < publication.IssuedAt-int64(MaxBundleClockSkew/time.Second) {
		return fmt.Errorf("authority: policy activation binding mismatch")
	}
	return nil
}

func NewPolicyWithdrawal(publication PolicyPublication, reason string, issuedAt time.Time, keyID string) (PolicyWithdrawal, error) {
	publicationHash, err := publication.Hash()
	if err != nil {
		return PolicyWithdrawal{}, err
	}
	withdrawal := PolicyWithdrawal{
		Version: SchemaVersion, PublicationID: publication.ID, PublicationHash: publicationHash,
		TenantID: publication.TenantID, PolicyRevision: publication.PolicyRevision,
		Reason: strings.TrimSpace(reason), IssuedAt: issuedAt.Unix(), KeyID: keyID,
	}
	withdrawal.ID = policyWithdrawalID(withdrawal)
	if err := withdrawal.Validate(); err != nil {
		return PolicyWithdrawal{}, err
	}
	return withdrawal, nil
}

func (withdrawal PolicyWithdrawal) Validate() error {
	if withdrawal.Version != SchemaVersion || !lowerHexAuthority(withdrawal.ID, 64) || !lowerHexAuthority(withdrawal.PublicationHash, 64) {
		return fmt.Errorf("authority: invalid policy withdrawal identity")
	}
	for name, value := range map[string]string{"publication_id": withdrawal.PublicationID, "tenant_id": withdrawal.TenantID, "key_id": withdrawal.KeyID} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if withdrawal.PolicyRevision == 0 || withdrawal.IssuedAt <= 0 || !boundedAuditText(withdrawal.Reason, 2048, false) || withdrawal.ID != policyWithdrawalID(withdrawal) {
		return fmt.Errorf("authority: invalid policy withdrawal state")
	}
	return nil
}

func (withdrawal PolicyWithdrawal) Canonical() ([]byte, error) {
	if err := withdrawal.Validate(); err != nil {
		return nil, err
	}
	writer := canonicalWriter{}
	writer.string(PolicyWithdrawalDomain)
	writer.u16(withdrawal.Version)
	writer.string(withdrawal.ID)
	writer.string(withdrawal.PublicationID)
	writer.string(withdrawal.PublicationHash)
	writer.string(withdrawal.TenantID)
	writer.u64(withdrawal.PolicyRevision)
	writer.string(withdrawal.Reason)
	writer.i64(withdrawal.IssuedAt)
	writer.string(withdrawal.KeyID)
	if writer.err != nil {
		return nil, writer.err
	}
	return writer.Buffer.Bytes(), nil
}

func (withdrawal *PolicyWithdrawal) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("authority: invalid policy withdrawal private key")
	}
	canonical, err := withdrawal.Canonical()
	if err != nil {
		return err
	}
	withdrawal.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return nil
}

func (withdrawal PolicyWithdrawal) VerifyFor(publication PolicyPublication, publicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := withdrawal.Canonical()
	if err != nil {
		return err
	}
	if withdrawal.IssuedAt > now.Unix()+int64(MaxBundleClockSkew/time.Second) {
		return fmt.Errorf("authority: policy withdrawal is not yet issued")
	}
	signature, err := base64.StdEncoding.DecodeString(withdrawal.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("authority: invalid policy withdrawal signature")
	}
	publicationHash, _ := publication.Hash()
	if withdrawal.PublicationID != publication.ID || withdrawal.PublicationHash != publicationHash || withdrawal.TenantID != publication.TenantID ||
		withdrawal.PolicyRevision != publication.PolicyRevision || withdrawal.IssuedAt < publication.IssuedAt-int64(MaxBundleClockSkew/time.Second) {
		return fmt.Errorf("authority: policy withdrawal binding mismatch")
	}
	return nil
}

type RolloutStatus struct {
	Publication PolicyPublication `json:"publication"`
	Staged      int               `json:"staged"`
	Enforced    int               `json:"enforced"`
	Rejected    int               `json:"rejected"`
	Pending     []string          `json:"pending"`
	Ready       bool              `json:"ready"`
	Activation  *PolicyActivation `json:"activation,omitempty"`
	Withdrawal  *PolicyWithdrawal `json:"withdrawal,omitempty"`
}

type RolloutTrustStore interface {
	ManagesTenant(string) bool
	ManagedTenants() []string
	PolicyKey(tenantID, keyID string) (ed25519.PublicKey, error)
	PolicyKeyAt(tenantID, keyID string, at time.Time) (ed25519.PublicKey, error)
	IntentKey(context.Context, string, string, string) (ed25519.PublicKey, error)
	IntentKeyAt(tenantID, agentID, keyID string, at time.Time) (ed25519.PublicKey, error)
	MinimumState(context.Context, string) (uint64, uint64, error)
}

type RolloutManager struct {
	mu           sync.RWMutex
	refreshMu    sync.Mutex
	trust        RolloutTrustStore
	policies     *PolicyManager
	repository   RolloutPersistence
	now          func() time.Time
	publications map[string]PolicyPublication
	acks         map[string]map[string]PolicyAcknowledgement
	bundles      map[string]PolicyBundle
	activations  map[string]PolicyActivation
	withdrawals  map[string]PolicyWithdrawal
	generations  map[string]uint64
}

func NewRolloutManager(trust RolloutTrustStore, policies *PolicyManager, repository RolloutPersistence, now func() time.Time) (*RolloutManager, error) {
	if trust == nil || policies == nil || repository == nil {
		return nil, fmt.Errorf("authority: trust, policy manager, and rollout repository are required")
	}
	if now == nil {
		now = time.Now
	}
	manager := &RolloutManager{
		trust: trust, policies: policies, repository: repository, now: now,
		publications: make(map[string]PolicyPublication), acks: make(map[string]map[string]PolicyAcknowledgement),
		bundles: make(map[string]PolicyBundle), activations: make(map[string]PolicyActivation), withdrawals: make(map[string]PolicyWithdrawal),
		generations: make(map[string]uint64),
	}
	stored, err := loadManagedRollouts(context.Background(), repository, trust.ManagedTenants())
	if err != nil {
		return nil, err
	}
	for _, item := range stored {
		if !manager.trust.ManagesTenant(item.Publication.TenantID) {
			continue
		}
		if err := manager.installLoaded(item); err != nil {
			return nil, err
		}
	}
	return manager, nil
}

func (manager *RolloutManager) Publish(ctx context.Context, publication PolicyPublication, bundle PolicyBundle) error {
	if err := manager.ValidateCandidate(ctx, publication, bundle); err != nil {
		return err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for _, existing := range manager.publications {
		if existing.TenantID == publication.TenantID && existing.PolicyRevision == publication.PolicyRevision && existing.ID != publication.ID {
			return fmt.Errorf("authority: policy revision already has another publication")
		}
	}
	if existing, exists := manager.publications[publication.ID]; exists {
		existingHash, _ := existing.Hash()
		candidateHash, _ := publication.Hash()
		if existingHash == candidateHash && existing.Signature == publication.Signature {
			return nil
		}
		return fmt.Errorf("authority: conflicting policy publication id")
	}
	if err := manager.policies.InstallHeldWithCommit(ctx, bundle, func() error {
		if err := manager.repository.SavePolicyPublication(ctx, publication, bundle); err != nil {
			return persistenceError("save policy publication", err)
		}
		return nil
	}); err != nil {
		return err
	}
	manager.publications[publication.ID] = clonePublication(publication)
	manager.bundles[publication.ID] = clonePolicyBundle(bundle)
	manager.acks[publication.ID] = make(map[string]PolicyAcknowledgement)
	return nil
}

func (manager *RolloutManager) ValidateCandidate(ctx context.Context, publication PolicyPublication, bundle PolicyBundle) error {
	if err := manager.Refresh(ctx); err != nil {
		return err
	}
	publicKey, err := manager.trust.PolicyKey(publication.TenantID, publication.KeyID)
	if err != nil {
		return err
	}
	if err := publication.VerifyFor(bundle, publicKey, manager.now()); err != nil {
		return err
	}
	if err := manager.policies.ValidateInstall(ctx, bundle); err != nil {
		return err
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	for _, existing := range manager.publications {
		if existing.TenantID == publication.TenantID && existing.PolicyRevision == publication.PolicyRevision && existing.ID != publication.ID {
			return fmt.Errorf("authority: policy revision already has another publication")
		}
	}
	if existing, exists := manager.publications[publication.ID]; exists {
		existingHash, _ := existing.Hash()
		candidateHash, _ := publication.Hash()
		if existingHash == candidateHash && existing.Signature == publication.Signature {
			return nil
		}
		return fmt.Errorf("authority: conflicting policy publication id")
	}
	return nil
}

func (manager *RolloutManager) CurrentPolicy(ctx context.Context, tenantID string) (PolicyBundle, error) {
	if err := manager.Refresh(ctx); err != nil {
		return PolicyBundle{}, err
	}
	return manager.policies.Active(ctx, tenantID)
}

// CandidateForAgent returns the newest unactivated policy publication that
// explicitly targets agentID. The bundle remains held at the authority until
// the signed acknowledgement threshold and a signed activation are present;
// callers must not treat this response as active authority.
func (manager *RolloutManager) CandidateForAgent(ctx context.Context, tenantID, agentID string) (PolicyPublication, PolicyBundle, bool, error) {
	if err := manager.Refresh(ctx); err != nil {
		return PolicyPublication{}, PolicyBundle{}, false, err
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	var (
		candidate PolicyPublication
		found     bool
	)
	for publicationID, publication := range manager.publications {
		if publication.TenantID != tenantID || !publicationTargets(publication, agentID) {
			continue
		}
		if _, withdrawn := manager.withdrawals[publicationID]; withdrawn {
			continue
		}
		if activation, activated := manager.activations[publicationID]; activated && activation.ActivatesAt <= manager.now().Unix() {
			continue
		}
		if !found || publication.PolicyRevision > candidate.PolicyRevision || (publication.PolicyRevision == candidate.PolicyRevision && publication.ID > candidate.ID) {
			candidate = publication
			found = true
		}
	}
	if !found {
		return PolicyPublication{}, PolicyBundle{}, false, nil
	}
	bundle, exists := manager.bundles[candidate.ID]
	if !exists {
		return PolicyPublication{}, PolicyBundle{}, false, fmt.Errorf("authority: rollout candidate bundle is missing")
	}
	return clonePublication(candidate), clonePolicyBundle(bundle), true, nil
}

// BundleForPublication returns one immutable historical rollout artifact for
// review or a monotonic superseding rollback. It never changes active state.
func (manager *RolloutManager) BundleForPublication(ctx context.Context, tenantID, publicationID string) (PolicyPublication, PolicyBundle, bool, error) {
	if err := manager.Refresh(ctx); err != nil {
		return PolicyPublication{}, PolicyBundle{}, false, err
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	publication, exists := manager.publications[publicationID]
	if !exists || publication.TenantID != tenantID {
		return PolicyPublication{}, PolicyBundle{}, false, nil
	}
	bundle, exists := manager.bundles[publicationID]
	if !exists {
		return PolicyPublication{}, PolicyBundle{}, false, fmt.Errorf("authority: rollout bundle is missing")
	}
	return clonePublication(publication), clonePolicyBundle(bundle), true, nil
}

// ActiveForAgent returns the active policy together with the publication and
// signed activation that promoted it, but only when the publication explicitly
// targets agentID. A bare signed bundle is intentionally insufficient proof of
// managed activation.
func (manager *RolloutManager) ActiveForAgent(ctx context.Context, tenantID, agentID string) (PolicyPublication, PolicyBundle, PolicyActivation, bool, error) {
	if err := manager.Refresh(ctx); err != nil {
		return PolicyPublication{}, PolicyBundle{}, PolicyActivation{}, false, err
	}
	active, err := manager.policies.Active(ctx, tenantID)
	if err != nil {
		return PolicyPublication{}, PolicyBundle{}, PolicyActivation{}, false, err
	}
	activeHash, err := active.Hash()
	if err != nil {
		return PolicyPublication{}, PolicyBundle{}, PolicyActivation{}, false, err
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	for publicationID, publication := range manager.publications {
		if publication.TenantID != tenantID || !publicationTargets(publication, agentID) || publication.PolicyHash != activeHash || publication.PolicyRevision != active.Revision || publication.RevocationEpoch != active.RevocationEpoch {
			continue
		}
		activation, activated := manager.activations[publicationID]
		if !activated {
			continue
		}
		return clonePublication(publication), clonePolicyBundle(active), activation, true, nil
	}
	return PolicyPublication{}, PolicyBundle{}, PolicyActivation{}, false, nil
}

func (manager *RolloutManager) Acknowledge(ctx context.Context, ack PolicyAcknowledgement) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := manager.Refresh(ctx); err != nil {
		return err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.acknowledgeLocked(ctx, ack, true)
}

func (manager *RolloutManager) acknowledgeLocked(ctx context.Context, ack PolicyAcknowledgement, persist bool) error {
	publication, exists := manager.publications[ack.PublicationID]
	if !exists {
		return ErrUnknownPolicyPublication
	}
	if _, withdrawn := manager.withdrawals[ack.PublicationID]; withdrawn && persist {
		return fmt.Errorf("authority: policy publication is withdrawn")
	}
	if !publicationTargets(publication, ack.AgentID) || ack.PolicyHash != publication.PolicyHash ||
		ack.TenantID != publication.TenantID || ack.PolicyRevision != publication.PolicyRevision ||
		ack.RevocationEpoch != publication.RevocationEpoch {
		return fmt.Errorf("authority: policy acknowledgement publication binding mismatch")
	}
	var publicKey ed25519.PublicKey
	var err error
	if persist {
		publicKey, err = manager.trust.IntentKey(ctx, ack.TenantID, ack.AgentID, ack.KeyID)
	} else {
		publicKey, err = manager.trust.IntentKeyAt(ack.TenantID, ack.AgentID, ack.KeyID, time.Unix(ack.ObservedAt, 0))
	}
	if err != nil {
		return err
	}
	if err := ack.Verify(publicKey, manager.now()); err != nil {
		return err
	}
	if ack.ObservedAt < publication.IssuedAt-int64(MaxBundleClockSkew/time.Second) {
		return fmt.Errorf("authority: policy acknowledgement predates publication")
	}
	activation, activated := manager.activations[publication.ID]
	if existing, exists := manager.acks[publication.ID][ack.AgentID]; exists {
		if existing.ID == ack.ID && existing.Signature == ack.Signature {
			return nil
		}
		if activated {
			if !postActivationEnforcementAllowed(&existing, ack, activation, manager.now()) {
				return fmt.Errorf("authority: only staged-to-enforced acknowledgement is allowed after activation")
			}
		} else if !ackTransitionAllowed(existing.Status, ack.Status) || ack.ObservedAt < existing.ObservedAt {
			return fmt.Errorf("authority: policy acknowledgement status rollback")
		}
	} else if activated && !postActivationEnforcementAllowed(nil, ack, activation, manager.now()) {
		return fmt.Errorf("authority: only enforced acknowledgement is allowed after activation")
	}
	if persist {
		if err := manager.repository.AppendPolicyAcknowledgement(ctx, ack); err != nil {
			return persistenceError("save policy acknowledgement", err)
		}
	}
	manager.acks[publication.ID][ack.AgentID] = ack
	return nil
}

func (manager *RolloutManager) Status(publicationID string) (RolloutStatus, error) {
	if err := manager.Refresh(context.Background()); err != nil {
		return RolloutStatus{}, err
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	publication, exists := manager.publications[publicationID]
	if !exists {
		return RolloutStatus{}, ErrUnknownPolicyPublication
	}
	return manager.statusLocked(publication), nil
}

// Statuses returns every policy rollout for one managed tenant, newest policy
// revision first. It is a read-model for an operator interface: the returned
// records contain immutable signed publication data and derived acknowledgement
// progress, but grant no ability to change policy or activation state.
func (manager *RolloutManager) Statuses(ctx context.Context, tenantID string) ([]RolloutStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !manager.trust.ManagesTenant(tenantID) {
		return nil, fmt.Errorf("authority: tenant %q is not managed", tenantID)
	}
	if err := manager.Refresh(ctx); err != nil {
		return nil, err
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	statuses := make([]RolloutStatus, 0)
	for _, publication := range manager.publications {
		if publication.TenantID == tenantID {
			statuses = append(statuses, manager.statusLocked(publication))
		}
	}
	sort.Slice(statuses, func(left, right int) bool {
		if statuses[left].Publication.PolicyRevision != statuses[right].Publication.PolicyRevision {
			return statuses[left].Publication.PolicyRevision > statuses[right].Publication.PolicyRevision
		}
		return statuses[left].Publication.ID < statuses[right].Publication.ID
	})
	return statuses, nil
}

func (manager *RolloutManager) statusLocked(publication PolicyPublication) RolloutStatus {
	status := RolloutStatus{Publication: clonePublication(publication)}
	for _, agentID := range publication.ExpectedAgents {
		ack, acknowledged := manager.acks[publication.ID][agentID]
		if !acknowledged {
			status.Pending = append(status.Pending, agentID)
			continue
		}
		switch ack.Status {
		case PolicyAckStaged:
			status.Staged++
		case PolicyAckEnforced:
			status.Enforced++
		case PolicyAckRejected:
			status.Rejected++
		}
	}
	sort.Strings(status.Pending)
	status.Ready = status.Rejected == 0 && status.Staged+status.Enforced >= int(publication.RequiredAcknowledged)
	if activation, exists := manager.activations[publication.ID]; exists {
		clone := activation
		status.Activation = &clone
	}
	if withdrawal, exists := manager.withdrawals[publication.ID]; exists {
		clone := withdrawal
		status.Withdrawal = &clone
		status.Ready = false
	}
	return status
}

// Withdraw durably terminates distribution of a candidate or cancels a future
// activation. It intentionally refuses to alter an activation whose time has
// arrived; an active policy is superseded only through a higher revision.
func (manager *RolloutManager) Withdraw(ctx context.Context, withdrawal PolicyWithdrawal) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	persistence, supported := manager.repository.(RolloutWithdrawalPersistence)
	if !supported {
		return fmt.Errorf("authority: rollout withdrawal persistence is unavailable")
	}
	if err := manager.Refresh(ctx); err != nil {
		return err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	publication, exists := manager.publications[withdrawal.PublicationID]
	if !exists {
		return ErrUnknownPolicyPublication
	}
	publicKey, err := manager.trust.PolicyKey(withdrawal.TenantID, withdrawal.KeyID)
	if err != nil {
		return err
	}
	if err := withdrawal.VerifyFor(publication, publicKey, manager.now()); err != nil {
		return err
	}
	if existing, exists := manager.withdrawals[publication.ID]; exists {
		if existing.ID == withdrawal.ID && existing.Signature == withdrawal.Signature {
			return nil
		}
		return fmt.Errorf("authority: conflicting policy withdrawal")
	}
	if activation, exists := manager.activations[publication.ID]; exists && activation.ActivatesAt <= manager.now().Unix() {
		return fmt.Errorf("authority: active policy cannot be withdrawn; publish a higher rollback revision")
	}
	active, activeErr := manager.policies.Active(ctx, publication.TenantID)
	if activeErr == nil && active.Revision >= publication.PolicyRevision {
		return fmt.Errorf("authority: active policy cannot be withdrawn; publish a higher rollback revision")
	}
	if err := persistence.SavePolicyWithdrawal(ctx, withdrawal); err != nil {
		return persistenceError("save policy withdrawal", err)
	}
	manager.withdrawals[publication.ID] = withdrawal
	return nil
}

func (manager *RolloutManager) Activate(ctx context.Context, activation PolicyActivation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := manager.Refresh(ctx); err != nil {
		return err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.activateLocked(ctx, activation, true)
}

// ScheduleActivation durably records a signed future activation. Refresh
// promotes it once its signed time arrives; until then agents can still fetch
// and acknowledge the held candidate.
func (manager *RolloutManager) ScheduleActivation(ctx context.Context, activation PolicyActivation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := manager.Refresh(ctx); err != nil {
		return err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if activation.ActivatesAt <= manager.now().Unix() {
		return fmt.Errorf("authority: scheduled policy activation must be in the future")
	}
	publication, exists := manager.publications[activation.PublicationID]
	if !exists {
		return ErrUnknownPolicyPublication
	}
	if _, withdrawn := manager.withdrawals[publication.ID]; withdrawn {
		return fmt.Errorf("authority: withdrawn policy publication cannot be activated")
	}
	bundle := manager.bundles[publication.ID]
	publicKey, err := manager.trust.PolicyKey(activation.TenantID, activation.KeyID)
	if err != nil {
		return err
	}
	if err := activation.VerifyFor(publication, bundle, publicKey, manager.now()); err != nil {
		return err
	}
	if !manager.statusLocked(publication).Ready {
		return fmt.Errorf("authority: policy rollout acknowledgement threshold is not ready")
	}
	if existing, exists := manager.activations[publication.ID]; exists {
		if existing.ID == activation.ID && existing.Signature == activation.Signature {
			return nil
		}
		return fmt.Errorf("authority: conflicting policy activation")
	}
	if err := manager.repository.SavePolicyActivation(ctx, activation); err != nil {
		return persistenceError("save policy activation", err)
	}
	manager.activations[publication.ID] = activation
	return nil
}

func (manager *RolloutManager) activateLocked(ctx context.Context, activation PolicyActivation, persist bool) error {
	publication, exists := manager.publications[activation.PublicationID]
	if !exists {
		return ErrUnknownPolicyPublication
	}
	if _, withdrawn := manager.withdrawals[publication.ID]; withdrawn {
		return fmt.Errorf("authority: withdrawn policy publication cannot be activated")
	}
	bundle := manager.bundles[publication.ID]
	var publicKey ed25519.PublicKey
	var err error
	if persist {
		publicKey, err = manager.trust.PolicyKey(activation.TenantID, activation.KeyID)
	} else {
		publicKey, err = manager.trust.PolicyKeyAt(activation.TenantID, activation.KeyID, time.Unix(activation.IssuedAt, 0))
	}
	if err != nil {
		return err
	}
	if err := activation.VerifyFor(publication, bundle, publicKey, manager.now()); err != nil {
		return err
	}
	if manager.now().Unix() < activation.ActivatesAt {
		return fmt.Errorf("authority: policy activation time has not arrived")
	}
	status := manager.statusLocked(publication)
	if !status.Ready {
		return fmt.Errorf("authority: policy rollout acknowledgement threshold is not ready")
	}
	if existing, exists := manager.activations[publication.ID]; exists {
		if existing.ID == activation.ID && existing.Signature == activation.Signature {
			return nil
		}
		return fmt.Errorf("authority: conflicting policy activation")
	}
	commit := func() error { return nil }
	if persist {
		commit = func() error {
			if err := manager.repository.SavePolicyActivation(ctx, activation); err != nil {
				return persistenceError("save policy activation", err)
			}
			return nil
		}
	}
	if err := manager.policies.ActivateHeldWithCommit(ctx, publication.TenantID, publication.PolicyRevision, commit); err != nil {
		return err
	}
	manager.activations[publication.ID] = activation
	return nil
}

func (manager *RolloutManager) installLoaded(item StoredRollout) error {
	if existing, exists := manager.publications[item.Publication.ID]; exists {
		existingHash, _ := existing.Hash()
		loadedHash, _ := item.Publication.Hash()
		existingBundleHash, _ := manager.bundles[item.Publication.ID].Hash()
		loadedBundleHash, _ := item.Bundle.Hash()
		if existingHash != loadedHash || existing.Signature != item.Publication.Signature ||
			existingBundleHash != loadedBundleHash || manager.bundles[item.Publication.ID].Signature != item.Bundle.Signature {
			return fmt.Errorf("authority: conflicting durable rollout state")
		}
		for _, ack := range item.Acknowledgements {
			if current, acknowledged := manager.acks[item.Publication.ID][ack.AgentID]; acknowledged {
				if ack.ObservedAt < current.ObservedAt {
					continue
				}
				if ack.ObservedAt == current.ObservedAt {
					if ack.ID == current.ID && ack.Signature == current.Signature {
						continue
					}
					return fmt.Errorf("authority: conflicting durable acknowledgement state")
				}
			}
			if err := manager.acknowledgeLocked(context.Background(), ack, false); err != nil {
				return err
			}
		}
		if err := manager.installWithdrawalLocked(item); err != nil {
			return err
		}
		if item.Activation != nil {
			if existingActivation, activated := manager.activations[item.Publication.ID]; activated {
				if existingActivation.ID != item.Activation.ID || existingActivation.Signature != item.Activation.Signature {
					return fmt.Errorf("authority: conflicting durable activation state")
				}
				return nil
			}
			if item.Withdrawal != nil {
				return manager.installWithdrawnActivationLocked(item)
			}
			if item.Activation.ActivatesAt > manager.now().Unix() {
				return manager.installScheduledActivationLocked(item)
			}
			return manager.activateLocked(context.Background(), *item.Activation, false)
		}
		return nil
	}
	publicKey, err := manager.trust.PolicyKeyAt(item.Publication.TenantID, item.Publication.KeyID, time.Unix(item.Publication.IssuedAt, 0))
	if err != nil {
		return err
	}
	if err := item.Publication.VerifyFor(item.Bundle, publicKey, manager.now()); err != nil {
		return err
	}
	snapshot := manager.policies.Snapshot(item.Bundle.TenantID)
	latestRevision := uint64(0)
	if snapshot.Active != nil {
		latestRevision = snapshot.Active.Revision
	}
	if snapshot.Staged != nil && snapshot.Staged.Revision > latestRevision {
		latestRevision = snapshot.Staged.Revision
	}
	minimumPolicy, minimumRevocation, err := manager.trust.MinimumState(context.Background(), item.Bundle.TenantID)
	if err != nil {
		return err
	}
	loadedAsCurrent := item.Bundle.Revision >= minimumPolicy && item.Bundle.RevocationEpoch >= minimumRevocation && item.Bundle.Revision >= latestRevision
	if loadedAsCurrent {
		if err := manager.policies.InstallHeldWithCommit(context.Background(), item.Bundle, nil); err != nil {
			return err
		}
	}
	manager.publications[item.Publication.ID] = clonePublication(item.Publication)
	manager.bundles[item.Publication.ID] = clonePolicyBundle(item.Bundle)
	manager.acks[item.Publication.ID] = make(map[string]PolicyAcknowledgement)
	for _, ack := range item.Acknowledgements {
		if err := manager.acknowledgeLocked(context.Background(), ack, false); err != nil {
			return err
		}
	}
	if err := manager.installWithdrawalLocked(item); err != nil {
		return err
	}
	if item.Activation != nil {
		if item.Withdrawal != nil {
			return manager.installWithdrawnActivationLocked(item)
		}
		if loadedAsCurrent {
			if item.Activation.ActivatesAt > manager.now().Unix() {
				if err := manager.installScheduledActivationLocked(item); err != nil {
					return err
				}
			} else if err := manager.activateLocked(context.Background(), *item.Activation, false); err != nil {
				return err
			}
		} else {
			publicKey, err := manager.trust.PolicyKeyAt(item.Activation.TenantID, item.Activation.KeyID, time.Unix(item.Activation.IssuedAt, 0))
			if err != nil {
				return err
			}
			if err := item.Activation.VerifyFor(item.Publication, item.Bundle, publicKey, manager.now()); err != nil {
				return err
			}
			if !manager.statusLocked(item.Publication).Ready {
				return fmt.Errorf("authority: historical activation lacks acknowledgement threshold")
			}
			manager.activations[item.Publication.ID] = *item.Activation
		}
	}
	return nil
}

func (manager *RolloutManager) installWithdrawalLocked(item StoredRollout) error {
	if item.Withdrawal == nil {
		return nil
	}
	if existing, found := manager.withdrawals[item.Publication.ID]; found {
		if existing.ID == item.Withdrawal.ID && existing.Signature == item.Withdrawal.Signature {
			return nil
		}
		return fmt.Errorf("authority: conflicting durable withdrawal state")
	}
	publicKey, err := manager.trust.PolicyKeyAt(item.Withdrawal.TenantID, item.Withdrawal.KeyID, time.Unix(item.Withdrawal.IssuedAt, 0))
	if err != nil {
		return err
	}
	if err := item.Withdrawal.VerifyFor(item.Publication, publicKey, manager.now()); err != nil {
		return err
	}
	if item.Activation != nil && item.Activation.ActivatesAt <= item.Withdrawal.IssuedAt {
		return fmt.Errorf("authority: durable withdrawal follows an effective activation")
	}
	manager.withdrawals[item.Publication.ID] = *item.Withdrawal
	return nil
}

func (manager *RolloutManager) installWithdrawnActivationLocked(item StoredRollout) error {
	if item.Activation == nil || item.Withdrawal == nil {
		return nil
	}
	if existing, found := manager.activations[item.Publication.ID]; found {
		if existing.ID == item.Activation.ID && existing.Signature == item.Activation.Signature {
			return nil
		}
		return fmt.Errorf("authority: conflicting durable activation state")
	}
	publicKey, err := manager.trust.PolicyKeyAt(item.Activation.TenantID, item.Activation.KeyID, time.Unix(item.Activation.IssuedAt, 0))
	if err != nil {
		return err
	}
	if err := item.Activation.VerifyFor(item.Publication, item.Bundle, publicKey, manager.now()); err != nil {
		return err
	}
	if !manager.rolloutAcknowledgementReadyLocked(item.Publication) {
		return fmt.Errorf("authority: withdrawn activation lacks acknowledgement threshold")
	}
	manager.activations[item.Publication.ID] = *item.Activation
	return nil
}

func (manager *RolloutManager) rolloutAcknowledgementReadyLocked(publication PolicyPublication) bool {
	ready := 0
	for _, agentID := range publication.ExpectedAgents {
		ack, found := manager.acks[publication.ID][agentID]
		if !found {
			continue
		}
		if ack.Status == PolicyAckRejected {
			return false
		}
		if ack.Status == PolicyAckStaged || ack.Status == PolicyAckEnforced {
			ready++
		}
	}
	return ready >= int(publication.RequiredAcknowledged)
}

func (manager *RolloutManager) installScheduledActivationLocked(item StoredRollout) error {
	if item.Activation == nil {
		return nil
	}
	publicKey, err := manager.trust.PolicyKeyAt(item.Activation.TenantID, item.Activation.KeyID, time.Unix(item.Activation.IssuedAt, 0))
	if err != nil {
		return err
	}
	if err := item.Activation.VerifyFor(item.Publication, item.Bundle, publicKey, manager.now()); err != nil {
		return err
	}
	if !manager.statusLocked(item.Publication).Ready {
		return fmt.Errorf("authority: scheduled activation lacks acknowledgement threshold")
	}
	manager.activations[item.Publication.ID] = *item.Activation
	return nil
}

// Refresh reconciles durable rollout state into this replica. Replaying exact
// records is idempotent; any conflicting immutable record fails closed.
func (manager *RolloutManager) Refresh(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	manager.refreshMu.Lock()
	defer manager.refreshMu.Unlock()
	tenantIDs := manager.trust.ManagedTenants()
	loadTenants := tenantIDs
	observedGenerations := make(map[string]uint64)
	if versioned, ok := manager.repository.(RolloutGenerationPersistence); ok {
		loadTenants = make([]string, 0, len(tenantIDs))
		manager.mu.RLock()
		currentGenerations := make(map[string]uint64, len(manager.generations))
		for tenantID, generation := range manager.generations {
			currentGenerations[tenantID] = generation
		}
		manager.mu.RUnlock()
		for _, tenantID := range tenantIDs {
			generation, err := versioned.RolloutGeneration(ctx, tenantID)
			if err != nil {
				return persistenceError("load rollout generation", err)
			}
			observedGenerations[tenantID] = generation
			if generation != currentGenerations[tenantID] {
				loadTenants = append(loadTenants, tenantID)
			}
		}
	}
	stored, err := loadManagedRollouts(ctx, manager.repository, loadTenants)
	if err != nil {
		return persistenceError("load rollout state", err)
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for _, item := range stored {
		if !manager.trust.ManagesTenant(item.Publication.TenantID) {
			continue
		}
		if err := manager.installLoaded(item); err != nil {
			return err
		}
	}
	for tenantID, generation := range observedGenerations {
		manager.generations[tenantID] = generation
	}
	return manager.promoteDueActivationsLocked(ctx)
}

func (manager *RolloutManager) promoteDueActivationsLocked(ctx context.Context) error {
	now := manager.now().Unix()
	publicationIDs := make([]string, 0, len(manager.activations))
	for publicationID, activation := range manager.activations {
		if _, withdrawn := manager.withdrawals[publicationID]; !withdrawn && activation.ActivatesAt > 0 && activation.ActivatesAt <= now && activation.Validate() == nil {
			publicationIDs = append(publicationIDs, publicationID)
		}
	}
	sort.Slice(publicationIDs, func(i, j int) bool {
		return manager.publications[publicationIDs[i]].PolicyRevision < manager.publications[publicationIDs[j]].PolicyRevision
	})
	for _, publicationID := range publicationIDs {
		publication := manager.publications[publicationID]
		active, err := manager.policies.Active(ctx, publication.TenantID)
		if err == nil && active.Revision >= publication.PolicyRevision {
			continue
		}
		snapshot := manager.policies.Snapshot(publication.TenantID)
		if snapshot.Staged == nil || snapshot.Staged.Revision != publication.PolicyRevision || !snapshot.Held {
			continue
		}
		if err := manager.policies.ActivateHeldWithCommit(ctx, publication.TenantID, publication.PolicyRevision, nil); err != nil {
			return err
		}
	}
	return nil
}

func loadManagedRollouts(ctx context.Context, repository RolloutPersistence, tenantIDs []string) ([]StoredRollout, error) {
	if scoped, ok := repository.(TenantRolloutPersistence); ok {
		var stored []StoredRollout
		for _, tenantID := range tenantIDs {
			rollouts, err := scoped.LoadTenantRollouts(ctx, tenantID)
			if err != nil {
				return nil, err
			}
			stored = append(stored, rollouts...)
		}
		return stored, nil
	}
	return repository.LoadRollouts(ctx)
}

func acknowledgementID(ack PolicyAcknowledgement) string {
	writer := canonicalWriter{}
	writer.string(PolicyAckDomain + "/id")
	writer.string(ack.PublicationID)
	writer.string(ack.PolicyHash)
	writer.string(ack.TenantID)
	writer.string(ack.AgentID)
	writer.u64(ack.PolicyRevision)
	writer.u64(ack.RevocationEpoch)
	writer.string(string(ack.Status))
	writer.i64(ack.ObservedAt)
	writer.string(ack.KeyID)
	sum := sha256.Sum256(writer.Buffer.Bytes())
	return hex.EncodeToString(sum[:])
}

func policyActivationID(activation PolicyActivation) string {
	writer := canonicalWriter{}
	writer.string(PolicyActivationDomain + "/id")
	writer.string(activation.PublicationID)
	writer.string(activation.PublicationHash)
	writer.string(activation.PolicyHash)
	writer.string(activation.TenantID)
	writer.u64(activation.PolicyRevision)
	writer.u64(activation.RevocationEpoch)
	writer.i64(activation.IssuedAt)
	writer.i64(activation.ActivatesAt)
	writer.string(activation.KeyID)
	sum := sha256.Sum256(writer.Buffer.Bytes())
	return hex.EncodeToString(sum[:])
}

func policyWithdrawalID(withdrawal PolicyWithdrawal) string {
	writer := canonicalWriter{}
	writer.string(PolicyWithdrawalDomain + "/id")
	writer.string(withdrawal.PublicationID)
	writer.string(withdrawal.PublicationHash)
	writer.string(withdrawal.TenantID)
	writer.u64(withdrawal.PolicyRevision)
	writer.string(withdrawal.Reason)
	writer.i64(withdrawal.IssuedAt)
	writer.string(withdrawal.KeyID)
	sum := sha256.Sum256(writer.Buffer.Bytes())
	return hex.EncodeToString(sum[:])
}

func publicationTargets(publication PolicyPublication, agentID string) bool {
	for _, expected := range publication.ExpectedAgents {
		if expected == agentID {
			return true
		}
	}
	return false
}

func ackTransitionAllowed(from, to PolicyAckStatus) bool {
	if from == PolicyAckRejected || from == PolicyAckEnforced {
		return false
	}
	// A restarted node may have lost its local delivery cache and reassert the
	// same signed staged state with a newer observation time. Treat that as a
	// liveness refresh while keeping enforced/rejected terminal and continuing
	// to reject older observations.
	return from == PolicyAckStaged && (to == PolicyAckStaged || to == PolicyAckEnforced || to == PolicyAckRejected)
}

// postActivationEnforcementAllowed keeps activation immutable while accepting
// the one operational fact that can only exist afterwards: a target node has
// durably installed the active policy. The transition is terminal and cannot
// weaken, reject, or restage an already activated publication.
func postActivationEnforcementAllowed(existing *PolicyAcknowledgement, next PolicyAcknowledgement, activation PolicyActivation, now time.Time) bool {
	if now.Unix() < activation.ActivatesAt || next.Status != PolicyAckEnforced || next.ObservedAt < activation.ActivatesAt {
		return false
	}
	return existing == nil || existing.Status == PolicyAckStaged && next.ObservedAt >= existing.ObservedAt
}

func clonePublication(publication PolicyPublication) PolicyPublication {
	clone := publication
	clone.ExpectedAgents = append([]string(nil), publication.ExpectedAgents...)
	return clone
}

func lowerHexAuthority(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

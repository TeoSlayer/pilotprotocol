// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sort"
	"sync"
	"time"
)

type PinnedRoot struct {
	TenantID  string
	RootKeyID string
	PublicKey ed25519.PublicKey
}

// Store is a tenant-scoped local trust view. The pinned root is configured
// out-of-band; a signed online bundle cannot replace it.
type Store struct {
	mu      sync.RWMutex
	roots   map[string]PinnedRoot
	bundles map[string]TrustBundle
	history map[string][]TrustBundle
	now     func() time.Time
}

func NewStore(roots []PinnedRoot, now func() time.Time) (*Store, error) {
	store := &Store{roots: make(map[string]PinnedRoot), bundles: make(map[string]TrustBundle), history: make(map[string][]TrustBundle), now: now}
	if store.now == nil {
		store.now = time.Now
	}
	for _, root := range roots {
		if err := validateIdentifier("tenant_id", root.TenantID); err != nil {
			return nil, err
		}
		if err := validateIdentifier("root_key_id", root.RootKeyID); err != nil {
			return nil, err
		}
		if len(root.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("authority: tenant %q has invalid root public key", root.TenantID)
		}
		if _, exists := store.roots[root.TenantID]; exists {
			return nil, fmt.Errorf("authority: duplicate pinned tenant %q", root.TenantID)
		}
		root.PublicKey = append(ed25519.PublicKey(nil), root.PublicKey...)
		store.roots[root.TenantID] = root
	}
	return store, nil
}

func (store *Store) Install(bundle TrustBundle) error {
	return store.install(bundle, true, nil)
}

func (store *Store) InstallWithCommit(bundle TrustBundle, commit func() error) error {
	return store.install(bundle, true, commit)
}

// InstallHistorical retains a root-signed bundle for verification of evidence
// created while its keys were valid. Expired state is never made active, and
// monotonic revision/revocation history is still enforced.
func (store *Store) InstallHistorical(bundle TrustBundle) error {
	return store.install(bundle, false, nil)
}

// InstallHistoricalWithCommit verifies and durably records a historical
// bundle before exposing it to historical key resolution.
func (store *Store) InstallHistoricalWithCommit(bundle TrustBundle, commit func() error) error {
	return store.install(bundle, false, commit)
}

func (store *Store) install(bundle TrustBundle, requireFresh bool, commit func() error) error {
	if store == nil {
		return fmt.Errorf("authority: trust store is not initialized")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	root, exists := store.roots[bundle.TenantID]
	if !exists {
		return fmt.Errorf("authority: tenant %q has no pinned root", bundle.TenantID)
	}
	if bundle.RootKeyID != root.RootKeyID {
		return fmt.Errorf("authority: trust bundle root key is not pinned")
	}
	if requireFresh {
		if err := bundle.Verify(root.PublicKey, store.now()); err != nil {
			return err
		}
	} else {
		if err := bundle.VerifySignature(root.PublicKey); err != nil {
			return err
		}
		if bundle.IssuedAt > store.now().Unix()+int64(MaxBundleClockSkew/time.Second) {
			return fmt.Errorf("authority: historical trust bundle is from the future")
		}
	}
	history := store.history[bundle.TenantID]
	if len(history) > 0 {
		current := history[len(history)-1]
		currentHash, _ := current.Hash()
		candidateHash, _ := bundle.Hash()
		if currentHash == candidateHash && current.Signature == bundle.Signature {
			if commit != nil {
				if err := commit(); err != nil {
					return fmt.Errorf("authority: durable trust commit failed: %w", err)
				}
			}
			return nil
		}
		if bundle.Revision <= current.Revision {
			return fmt.Errorf("authority: trust bundle revision rollback")
		}
		if bundle.IssuedAt < current.IssuedAt {
			return fmt.Errorf("authority: trust bundle issuance time rollback")
		}
		if bundle.PolicyRevision < current.PolicyRevision || bundle.RevocationEpoch < current.RevocationEpoch {
			return fmt.Errorf("authority: trust bundle state rollback")
		}
		if narrowsAuthority(current, bundle) && bundle.RevocationEpoch == current.RevocationEpoch {
			return fmt.Errorf("authority: key removal or narrowing requires a higher revocation epoch")
		}
	}
	if commit != nil {
		if err := commit(); err != nil {
			return fmt.Errorf("authority: durable trust commit failed: %w", err)
		}
	}
	store.history[bundle.TenantID] = append(store.history[bundle.TenantID], cloneBundle(bundle))
	now := store.now().Unix()
	if bundle.IssuedAt <= now+int64(MaxBundleClockSkew/time.Second) && bundle.ExpiresAt >= now {
		store.bundles[bundle.TenantID] = cloneBundle(bundle)
	} else {
		// A newer signed revision supersedes every older revision. If it is
		// not usable now, fail closed instead of falling back to older state.
		delete(store.bundles, bundle.TenantID)
	}
	return nil
}

func (store *Store) IntentKey(_ context.Context, tenantID, agentID, keyID string) (ed25519.PublicKey, error) {
	return store.resolve(tenantID, agentID, keyID, UsageIntent)
}

func (store *Store) DecisionKey(_ context.Context, tenantID, keyID string) (ed25519.PublicKey, error) {
	return store.resolve(tenantID, "", keyID, UsageDecision)
}

func (store *Store) PolicyKey(tenantID, keyID string) (ed25519.PublicKey, error) {
	return store.resolve(tenantID, "", keyID, UsagePolicy)
}

// MandateKey resolves a tenant-wide delegated issuer key for signed mandates.
// Mandates are never signed by a workload-scoped key.
func (store *Store) MandateKey(_ context.Context, tenantID, keyID string) (ed25519.PublicKey, error) {
	return store.resolve(tenantID, "", keyID, UsageMandate)
}

func (store *Store) ApprovalKey(tenantID, keyID string) (ed25519.PublicKey, error) {
	return store.resolve(tenantID, "", keyID, UsageApproval)
}

func (store *Store) PolicyKeyAt(tenantID, keyID string, at time.Time) (ed25519.PublicKey, error) {
	return store.resolveAt(tenantID, "", keyID, UsagePolicy, at)
}

func (store *Store) IntentKeyAt(tenantID, agentID, keyID string, at time.Time) (ed25519.PublicKey, error) {
	return store.resolveAt(tenantID, agentID, keyID, UsageIntent, at)
}

func (store *Store) ApprovalKeyAt(tenantID, keyID string, at time.Time) (ed25519.PublicKey, error) {
	return store.resolveAt(tenantID, "", keyID, UsageApproval, at)
}

func (store *Store) DecisionKeyAt(tenantID, keyID string, at time.Time) (ed25519.PublicKey, error) {
	return store.resolveAt(tenantID, "", keyID, UsageDecision, at)
}

func (store *Store) ReceiptKeyAt(tenantID, agentID, keyID string, at time.Time) (ed25519.PublicKey, error) {
	return store.resolveAt(tenantID, agentID, keyID, UsageReceipt, at)
}

func (store *Store) History(tenantID string) []TrustBundle {
	store.mu.RLock()
	defer store.mu.RUnlock()
	history := store.history[tenantID]
	result := make([]TrustBundle, len(history))
	for index, bundle := range history {
		result[index] = cloneBundle(bundle)
	}
	return result
}

func (store *Store) Latest(tenantID string) (TrustBundle, bool) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	history := store.history[tenantID]
	if len(history) == 0 {
		return TrustBundle{}, false
	}
	return cloneBundle(history[len(history)-1]), true
}

// Current returns the currently active, root-verified trust bundle. Unlike
// Latest, it never returns an expired or future historical revision.
func (store *Store) Current(_ context.Context, tenantID string) (TrustBundle, error) {
	if store == nil {
		return TrustBundle{}, fmt.Errorf("authority: trust store is not initialized")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	bundle, err := store.activeBundleLocked(tenantID)
	if err != nil {
		return TrustBundle{}, err
	}
	return cloneBundle(bundle), nil
}

func (store *Store) ManagesTenant(tenantID string) bool {
	store.mu.RLock()
	defer store.mu.RUnlock()
	_, ok := store.roots[tenantID]
	return ok
}

func (store *Store) ManagedTenants() []string {
	store.mu.RLock()
	defer store.mu.RUnlock()
	tenants := make([]string, 0, len(store.roots))
	for tenantID := range store.roots {
		tenants = append(tenants, tenantID)
	}
	sort.Strings(tenants)
	return tenants
}

func (store *Store) ReceiptKey(tenantID, agentID, keyID string) (ed25519.PublicKey, error) {
	return store.resolve(tenantID, agentID, keyID, UsageReceipt)
}

func (store *Store) MinimumState(_ context.Context, tenantID string) (uint64, uint64, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	bundle, err := store.activeBundleLocked(tenantID)
	if err != nil {
		return 0, 0, err
	}
	return bundle.PolicyRevision, bundle.RevocationEpoch, nil
}

func (store *Store) resolve(tenantID, agentID, keyID string, usage KeyUsage) (ed25519.PublicKey, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	bundle, err := store.activeBundleLocked(tenantID)
	if err != nil {
		return nil, err
	}
	now := store.now().Unix()
	for _, key := range bundle.Keys {
		if key.KeyID != keyID {
			continue
		}
		if !key.permits(usage) || key.AgentID != agentID {
			return nil, fmt.Errorf("authority: key %q is outside requested scope", keyID)
		}
		if key.NotBefore > now || key.ExpiresAt < now {
			return nil, fmt.Errorf("authority: key %q is not currently valid", keyID)
		}
		return key.publicKey(), nil
	}
	return nil, fmt.Errorf("authority: key %q is not active", keyID)
}

func (store *Store) resolveAt(tenantID, agentID, keyID string, usage KeyUsage, at time.Time) (ed25519.PublicKey, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	history := store.history[tenantID]
	atUnix := at.Unix()
	for bundleIndex := len(history) - 1; bundleIndex >= 0; bundleIndex-- {
		bundle := history[bundleIndex]
		if bundle.IssuedAt > atUnix {
			continue
		}
		if bundle.ExpiresAt < atUnix {
			return nil, fmt.Errorf("authority: trust bundle is not valid at requested time")
		}
		for _, key := range bundle.Keys {
			if key.KeyID != keyID {
				continue
			}
			if key.AgentID != agentID || !key.permits(usage) || key.NotBefore > atUnix || key.ExpiresAt < atUnix {
				return nil, fmt.Errorf("authority: historical key %q is outside requested scope or validity", keyID)
			}
			return key.publicKey(), nil
		}
		return nil, fmt.Errorf("authority: historical key %q is not active at requested time", keyID)
	}
	return nil, fmt.Errorf("authority: historical key %q is not valid at requested time", keyID)
}

func (store *Store) activeBundleLocked(tenantID string) (TrustBundle, error) {
	bundle, exists := store.bundles[tenantID]
	if !exists {
		return TrustBundle{}, fmt.Errorf("authority: tenant %q has no active trust bundle", tenantID)
	}
	if bundle.ExpiresAt < store.now().Unix() {
		return TrustBundle{}, fmt.Errorf("authority: tenant %q trust bundle is expired", tenantID)
	}
	return bundle, nil
}

func narrowsAuthority(current, candidate TrustBundle) bool {
	next := make(map[string]AuthorityKey, len(candidate.Keys))
	for _, key := range candidate.Keys {
		next[key.KeyID] = key
	}
	for _, existing := range current.Keys {
		replacement, exists := next[existing.KeyID]
		if !exists || replacement.PublicKey != existing.PublicKey || replacement.AgentID != existing.AgentID ||
			replacement.NotBefore > existing.NotBefore || replacement.ExpiresAt < existing.ExpiresAt {
			return true
		}
		for _, usage := range existing.Usages {
			if !replacement.permits(usage) {
				return true
			}
		}
	}
	return false
}

func cloneBundle(bundle TrustBundle) TrustBundle {
	clone := bundle
	clone.Keys = make([]AuthorityKey, len(bundle.Keys))
	for index, key := range bundle.Keys {
		clone.Keys[index] = key
		clone.Keys[index].Usages = append([]KeyUsage(nil), key.Usages...)
	}
	return clone
}

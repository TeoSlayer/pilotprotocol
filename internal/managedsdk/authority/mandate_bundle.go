// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pilot-protocol/common/decision"
)

// MandateBundleTrustStore resolves only tenant-wide mandate issuer keys and
// supplies the current revocation floor. Workload-scoped keys are deliberately
// unable to publish a distribution snapshot.
type MandateBundleTrustStore interface {
	decision.MandateKeyResolver
	decision.MandateStateResolver
}

// MandateBundlePersistence makes mandate distribution restart-durable. A
// persistence implementation must retain the newest bundle per
// tenant/subject-agent pair and reject conflicting equal revisions.
type MandateBundlePersistence interface {
	SaveMandateBundle(context.Context, decision.MandateBundle) error
	LoadMandateBundles(context.Context) ([]decision.MandateBundle, error)
}

// TenantMandateBundlePersistence can load only one authority domain from a
// shared backend. A single-tenant authority must not attempt to validate or
// serve another tenant's delegation snapshots during startup.
type TenantMandateBundlePersistence interface {
	MandateBundlePersistence
	LoadTenantMandateBundles(context.Context, string) ([]decision.MandateBundle, error)
}

// MandateBundleManager validates, durably publishes, and distributes complete
// signed mandate snapshots. A higher revision replaces the prior snapshot for
// that one agent; a valid empty higher revision therefore revokes every prior
// delegation for the agent.
type MandateBundleManager struct {
	mu          sync.RWMutex
	trust       MandateBundleTrustStore
	persistence MandateBundlePersistence
	tenantID    string
	now         func() time.Time
	bundles     map[string]decision.MandateBundle
}

func NewMandateBundleManager(trust MandateBundleTrustStore, persistence MandateBundlePersistence, now func() time.Time) (*MandateBundleManager, error) {
	return newMandateBundleManager(trust, persistence, "", now)
}

// NewTenantMandateBundleManager scopes a manager to one authority domain when
// the underlying repository is shared by multiple tenants.
func NewTenantMandateBundleManager(trust MandateBundleTrustStore, persistence MandateBundlePersistence, tenantID string, now func() time.Time) (*MandateBundleManager, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, fmt.Errorf("authority: mandate bundle tenant is required")
	}
	return newMandateBundleManager(trust, persistence, tenantID, now)
}

func newMandateBundleManager(trust MandateBundleTrustStore, persistence MandateBundlePersistence, tenantID string, now func() time.Time) (*MandateBundleManager, error) {
	if trust == nil || persistence == nil {
		return nil, fmt.Errorf("authority: mandate trust store and persistence are required")
	}
	if now == nil {
		now = time.Now
	}
	manager := &MandateBundleManager{trust: trust, persistence: persistence, tenantID: tenantID, now: now, bundles: make(map[string]decision.MandateBundle)}
	var (
		stored []decision.MandateBundle
		err    error
	)
	if tenantID != "" {
		if scoped, ok := persistence.(TenantMandateBundlePersistence); ok {
			stored, err = scoped.LoadTenantMandateBundles(context.Background(), tenantID)
		} else {
			stored, err = persistence.LoadMandateBundles(context.Background())
		}
	} else {
		stored, err = persistence.LoadMandateBundles(context.Background())
	}
	if err != nil {
		return nil, persistenceError("load mandate bundles", err)
	}
	for _, bundle := range stored {
		if tenantID != "" && bundle.TenantID != tenantID {
			continue
		}
		// Expiry is a normal fail-closed lifecycle state, not repository
		// corruption. Verify the retained signatures at a point where the whole
		// snapshot was valid, then omit it from the live distribution set. The
		// durable row remains in place so persistence still enforces monotonic
		// revisions when a refreshed bundle is published.
		if bundle.ExpiresAt < manager.now().UTC().Unix() {
			if err := manager.validateExpired(context.Background(), bundle); err != nil {
				return nil, fmt.Errorf("authority: persisted expired mandate bundle: %w", err)
			}
			continue
		}
		if err := manager.validate(context.Background(), bundle); err != nil {
			return nil, fmt.Errorf("authority: persisted mandate bundle: %w", err)
		}
		key := mandateBundleKey(bundle.TenantID, bundle.SubjectAgentID)
		if existing, found := manager.bundles[key]; found {
			if bundle.Revision < existing.Revision {
				continue
			}
			if err := newerMandateBundle(existing, bundle); err != nil {
				return nil, fmt.Errorf("authority: persisted mandate bundle conflict: %w", err)
			}
		}
		manager.bundles[key] = cloneMandateBundle(bundle)
	}
	return manager, nil
}

func (manager *MandateBundleManager) validateExpired(ctx context.Context, bundle decision.MandateBundle) error {
	notBefore, notAfter := bundle.IssuedAt, bundle.ExpiresAt
	for _, mandate := range bundle.Mandates {
		if mandate.IssuedAt > notBefore {
			notBefore = mandate.IssuedAt
		}
		if mandate.ExpiresAt < notAfter {
			notAfter = mandate.ExpiresAt
		}
	}
	if notBefore > notAfter {
		return fmt.Errorf("authority: persisted mandate snapshot has no common validity window")
	}
	issuer, err := manager.trust.MandateKey(ctx, bundle.TenantID, bundle.KeyID)
	if err != nil {
		return fmt.Errorf("authority: resolve expired mandate bundle issuer: %w", err)
	}
	if err := bundle.Verify(ctx, issuer, manager.trust, time.Unix(notBefore, 0)); err != nil {
		return err
	}
	return nil
}

// Publish verifies a pre-signed, complete snapshot before it is stored. It
// never signs or edits a tenant's bundle, keeping authoring keys outside the
// service process.
func (manager *MandateBundleManager) Publish(ctx context.Context, bundle decision.MandateBundle) error {
	if manager == nil {
		return fmt.Errorf("authority: mandate bundle manager is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if manager.tenantID != "" && bundle.TenantID != manager.tenantID {
		return fmt.Errorf("authority: mandate bundle tenant does not match manager")
	}
	if err := manager.validate(ctx, bundle); err != nil {
		return err
	}
	key := mandateBundleKey(bundle.TenantID, bundle.SubjectAgentID)
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if existing, found := manager.bundles[key]; found {
		if err := newerMandateBundle(existing, bundle); err != nil {
			return err
		}
		if bundle.Revision == existing.Revision {
			return nil
		}
	}
	if err := manager.persistence.SaveMandateBundle(ctx, bundle); err != nil {
		return persistenceError("save mandate bundle", err)
	}
	manager.bundles[key] = cloneMandateBundle(bundle)
	return nil
}

// CurrentForAgent returns the one current snapshot for a targeted workload.
// No bundle is a fail-closed result for a mandate-requiring local enforcer;
// it does not imply that ordinary open-protocol traffic is authorized.
func (manager *MandateBundleManager) CurrentForAgent(ctx context.Context, tenantID, agentID string) (decision.MandateBundle, bool, error) {
	if manager == nil {
		return decision.MandateBundle{}, false, fmt.Errorf("authority: mandate bundle manager is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return decision.MandateBundle{}, false, err
	}
	if manager.tenantID != "" && tenantID != manager.tenantID {
		return decision.MandateBundle{}, false, fmt.Errorf("authority: mandate bundle tenant does not match manager")
	}
	manager.mu.RLock()
	bundle, found := manager.bundles[mandateBundleKey(tenantID, agentID)]
	manager.mu.RUnlock()
	if !found {
		return decision.MandateBundle{}, false, nil
	}
	if err := manager.validate(ctx, bundle); err != nil {
		return decision.MandateBundle{}, false, err
	}
	return cloneMandateBundle(bundle), true, nil
}

// Bundles returns a stable, read-only management view for one tenant.
func (manager *MandateBundleManager) Bundles(ctx context.Context, tenantID string) ([]decision.MandateBundle, error) {
	if manager == nil {
		return nil, fmt.Errorf("authority: mandate bundle manager is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if manager.tenantID != "" && tenantID != manager.tenantID {
		return nil, fmt.Errorf("authority: mandate bundle tenant does not match manager")
	}
	manager.mu.RLock()
	bundles := make([]decision.MandateBundle, 0)
	for _, bundle := range manager.bundles {
		if bundle.TenantID == tenantID {
			bundles = append(bundles, cloneMandateBundle(bundle))
		}
	}
	manager.mu.RUnlock()
	sort.Slice(bundles, func(left, right int) bool {
		return bundles[left].SubjectAgentID < bundles[right].SubjectAgentID
	})
	return bundles, nil
}

func (manager *MandateBundleManager) validate(ctx context.Context, bundle decision.MandateBundle) error {
	issuer, err := manager.trust.MandateKey(ctx, bundle.TenantID, bundle.KeyID)
	if err != nil {
		return fmt.Errorf("authority: resolve mandate bundle issuer: %w", err)
	}
	if err := bundle.Verify(ctx, issuer, manager.trust, manager.now()); err != nil {
		return err
	}
	_, revocationEpoch, err := manager.trust.MinimumState(ctx, bundle.TenantID)
	if err != nil {
		return err
	}
	if bundle.RevocationEpoch < revocationEpoch {
		return fmt.Errorf("authority: mandate bundle is below tenant revocation epoch")
	}
	return nil
}

func mandateBundleKey(tenantID, agentID string) string { return tenantID + "\x00" + agentID }

func newerMandateBundle(current, candidate decision.MandateBundle) error {
	if candidate.Revision < current.Revision {
		return fmt.Errorf("authority: mandate bundle revision rollback")
	}
	if candidate.RevocationEpoch < current.RevocationEpoch {
		return fmt.Errorf("authority: mandate bundle revocation epoch rollback")
	}
	if candidate.Revision == current.Revision {
		currentHash, currentErr := current.Hash()
		candidateHash, candidateErr := candidate.Hash()
		if currentErr != nil || candidateErr != nil || currentHash != candidateHash || current.Signature != candidate.Signature {
			return fmt.Errorf("%w: mandate bundle revision", ErrStateConflict)
		}
	}
	return nil
}

func cloneMandateBundle(bundle decision.MandateBundle) decision.MandateBundle {
	bundle.Mandates = append([]decision.Mandate(nil), bundle.Mandates...)
	for index := range bundle.Mandates {
		bundle.Mandates[index].Actions = append([]string(nil), bundle.Mandates[index].Actions...)
		bundle.Mandates[index].ResourcePrefixes = append([]string(nil), bundle.Mandates[index].ResourcePrefixes...)
		bundle.Mandates[index].Constraints = append([]decision.Constraint(nil), bundle.Mandates[index].Constraints...)
	}
	return bundle
}

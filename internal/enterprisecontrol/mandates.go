// SPDX-License-Identifier: AGPL-3.0-or-later

package enterprisecontrol

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pilot-protocol/common/authority"
	"github.com/pilot-protocol/common/decision"
)

// replaceableMandateStore keeps the verifier pointed at one stable store
// object while a successfully verified higher bundle atomically replaces its
// contents. It never treats an unavailable remote response as an empty set;
// only a signed, higher empty bundle can revoke existing delegation.
type replaceableMandateStore struct {
	mu      sync.RWMutex
	current decision.MandateStore
}

func newReplaceableMandateStore(store decision.MandateStore) *replaceableMandateStore {
	return &replaceableMandateStore{current: store}
}

func (store *replaceableMandateStore) Mandate(ctx context.Context, tenantID, mandateID string) (decision.Mandate, error) {
	if store == nil {
		return decision.Mandate{}, fmt.Errorf("mandate store is not initialized")
	}
	store.mu.RLock()
	current := store.current
	store.mu.RUnlock()
	if current == nil {
		return decision.Mandate{}, fmt.Errorf("mandate store is not initialized")
	}
	return current.Mandate(ctx, tenantID, mandateID)
}

func (store *replaceableMandateStore) Replace(next decision.MandateStore) error {
	if store == nil || next == nil {
		return fmt.Errorf("mandate store is not initialized")
	}
	store.mu.Lock()
	store.current = next
	store.mu.Unlock()
	return nil
}

func loadMandateStore(path, tenantID string, trust *authority.Store) (decision.MandateStore, error) {
	if trust == nil {
		return nil, fmt.Errorf("trust store is required")
	}
	items, err := readSecureJSON[[]decision.Mandate](path)
	if err != nil {
		return nil, err
	}
	return decision.NewStaticMandateStore(context.Background(), tenantID, items, trust, trust, time.Now())
}

func loadMandateBundleStore(path, tenantID, agentID string, trust *authority.Store) (decision.MandateBundle, decision.MandateStore, error) {
	if trust == nil {
		return decision.MandateBundle{}, nil, fmt.Errorf("trust store is required")
	}
	bundle, err := readSecureJSON[decision.MandateBundle](path)
	if err != nil {
		return decision.MandateBundle{}, nil, err
	}
	if bundle.TenantID != tenantID || bundle.SubjectAgentID != agentID {
		return decision.MandateBundle{}, nil, fmt.Errorf("bundle tenant or agent binding mismatch")
	}
	store, err := decision.NewStaticMandateStoreFromBundle(context.Background(), bundle, trust, trust, time.Now())
	if err != nil {
		return decision.MandateBundle{}, nil, err
	}
	return bundle, store, nil
}

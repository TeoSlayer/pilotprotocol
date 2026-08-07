// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"context"
	"fmt"
)

// CommercialFeature is an authority-side capability gate. Open protocol and
// single-node local enforcement never consult this interface.
type CommercialFeature string

const (
	CommercialFleet        CommercialFeature = "fleet"
	CommercialLLMApprovals CommercialFeature = "llm_approvals"
)

// EntitlementProvider answers whether a tenant may use a paid capability. A
// production implementation will consume Stripe-backed, Pilot-signed leases;
// the initial mock is deliberately explicit and server-local.
type EntitlementProvider interface {
	Allows(context.Context, string, CommercialFeature) bool
}

// MockEntitlements is a development-only provider. Its configuration belongs
// to the authority process, not an agent attachment or browser request, so it
// cannot be forged by a node.
type MockEntitlements struct {
	features map[CommercialFeature]struct{}
}

// PlatformEntitlements is the hosted control plane's current plan snapshot.
// It is admitted only from the platform-owned tenant runtime bundle. Stripe is
// deliberately outside the action authorization path; the account provisioner
// rewrites this snapshot after subscription or suspension events.
type PlatformEntitlements struct {
	features map[CommercialFeature]struct{}
}

func NewMockEntitlements(features []CommercialFeature) (*MockEntitlements, error) {
	grants, err := validateCommercialFeatures(features)
	if err != nil {
		return nil, err
	}
	return &MockEntitlements{features: grants}, nil
}

func NewPlatformEntitlements(features []CommercialFeature) (*PlatformEntitlements, error) {
	grants, err := validateCommercialFeatures(features)
	if err != nil {
		return nil, err
	}
	return &PlatformEntitlements{features: grants}, nil
}

func validateCommercialFeatures(features []CommercialFeature) (map[CommercialFeature]struct{}, error) {
	grants := make(map[CommercialFeature]struct{}, len(features))
	for _, feature := range features {
		switch feature {
		case CommercialFleet, CommercialLLMApprovals:
		default:
			return nil, fmt.Errorf("authority: unsupported commercial feature %q", feature)
		}
		if _, exists := grants[feature]; exists {
			return nil, fmt.Errorf("authority: duplicate commercial feature %q", feature)
		}
		grants[feature] = struct{}{}
	}
	return grants, nil
}

func (entitlements *PlatformEntitlements) Allows(_ context.Context, _ string, feature CommercialFeature) bool {
	if entitlements == nil {
		return false
	}
	_, allowed := entitlements.features[feature]
	return allowed
}

func (entitlements *MockEntitlements) Allows(_ context.Context, _ string, feature CommercialFeature) bool {
	if entitlements == nil {
		return false
	}
	_, allowed := entitlements.features[feature]
	return allowed
}

var ErrEntitlementRequired = fmt.Errorf("authority: commercial entitlement is required")

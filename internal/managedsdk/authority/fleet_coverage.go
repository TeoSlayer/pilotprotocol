// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"sort"
	"time"

	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/actionregistry"
)

const (
	FleetCoverageReportFreshFor = 2 * time.Minute
	FleetCoverageProofFreshFor  = 24 * time.Hour
)

type FleetCoverageState string

const (
	FleetCoverageUnreported  FleetCoverageState = "unreported"
	FleetCoverageUnsupported FleetCoverageState = "unsupported"
	FleetCoverageObserved    FleetCoverageState = "observed"
	FleetCoverageReported    FleetCoverageState = "reported_enforcing"
	FleetCoverageProtected   FleetCoverageState = "protected"
	FleetCoverageDegraded    FleetCoverageState = "degraded"
)

// FleetActionCoverage is an authority-derived view. A signed adapter claim and
// a signed recent activity are deliberately distinct: configuration alone is
// never displayed as runtime proof.
type FleetActionCoverage struct {
	Action          string                      `json:"action"`
	Description     string                      `json:"description"`
	Privacy         actionregistry.PrivacyClass `json:"privacy"`
	State           FleetCoverageState          `json:"state"`
	Reason          string                      `json:"reason"`
	AdapterID       string                      `json:"adapter_id,omitempty"`
	AdapterVersion  string                      `json:"adapter_version,omitempty"`
	Observe         bool                        `json:"observe"`
	Enforce         bool                        `json:"enforce"`
	ApprovalCapable bool                        `json:"approval_capable"`
	Receipt         bool                        `json:"receipt"`
	LastProofID     string                      `json:"last_proof_id,omitempty"`
	LastProofAt     int64                       `json:"last_proof_at,omitempty"`
	LastProofResult decision.EnforcementResult  `json:"last_proof_result,omitempty"`
}

type FleetCoverageManifest struct {
	Version          uint16                `json:"version"`
	TenantID         string                `json:"tenant_id"`
	AgentID          string                `json:"agent_id"`
	HarnessID        string                `json:"harness_id,omitempty"`
	HarnessVersion   string                `json:"harness_version,omitempty"`
	ConnectorVersion string                `json:"connector_version,omitempty"`
	ReportedAt       int64                 `json:"reported_at,omitempty"`
	Fresh            bool                  `json:"fresh"`
	CatalogActions   int                   `json:"catalog_actions"`
	DeclaredActions  int                   `json:"declared_actions"`
	ProtectedActions int                   `json:"protected_actions"`
	ObservedActions  int                   `json:"observed_actions"`
	ReportedActions  int                   `json:"reported_enforcing_actions"`
	DegradedActions  int                   `json:"degraded_actions"`
	CoveragePercent  int                   `json:"coverage_percent"`
	Actions          []FleetActionCoverage `json:"actions"`
}

func BuildFleetCoverage(report FleetNodeReport, activities []FleetActivity, now time.Time) FleetCoverageManifest {
	registry := actionregistry.Builtins()
	definitions := registry.Definitions()
	manifest := FleetCoverageManifest{
		Version: 1, TenantID: report.TenantID, AgentID: report.AgentID,
		HarnessID: report.HarnessID, HarnessVersion: report.HarnessVersion, ConnectorVersion: report.ConnectorVersion,
		ReportedAt: report.ObservedAt, CatalogActions: len(definitions),
	}
	manifest.Fresh = report.ObservedAt > 0 && !now.Before(time.Unix(report.ObservedAt, 0)) && now.Sub(time.Unix(report.ObservedAt, 0)) <= FleetCoverageReportFreshFor

	latest := make(map[string]FleetActivity)
	for _, activity := range activities {
		if activity.AgentID != report.AgentID || activity.ObservedAt <= 0 {
			continue
		}
		canonical, found := registry.CanonicalName(activity.Action)
		if !found {
			continue
		}
		if current, exists := latest[canonical]; !exists || activity.ObservedAt > current.ObservedAt {
			latest[canonical] = activity
		}
	}

	capabilities := make(map[string]actionregistry.AdapterCapability, len(report.Capabilities))
	if report.Version == FleetReportVersionV2 {
		for _, capability := range report.Capabilities {
			canonical, found := registry.CanonicalName(capability.Action)
			if found {
				capability.Action = canonical
				capabilities[canonical] = capability
			}
		}
	}
	manifest.DeclaredActions = len(capabilities)

	for _, definition := range definitions {
		coverage := FleetActionCoverage{
			Action: definition.Name, Description: definition.Description, Privacy: definition.Privacy,
			State: FleetCoverageUnsupported, Reason: "This node did not report an adapter for this action.",
		}
		capability, declared := capabilities[definition.Name]
		if !declared {
			if report.Version != FleetReportVersionV2 {
				coverage.State = FleetCoverageUnreported
				coverage.Reason = "This node has not sent a capability-aware signed report."
			}
			manifest.Actions = append(manifest.Actions, coverage)
			continue
		}
		coverage.AdapterID, coverage.AdapterVersion = capability.AdapterID, capability.AdapterVersion
		coverage.Observe, coverage.Enforce, coverage.Receipt = capability.Observe, capability.Enforce, capability.Receipt
		coverage.ApprovalCapable = capability.Suspend && capability.Resume
		if !manifest.Fresh {
			coverage.State = FleetCoverageDegraded
			coverage.Reason = "The signed capability report is stale; current enforcement cannot be assumed."
			manifest.DegradedActions++
			manifest.Actions = append(manifest.Actions, coverage)
			continue
		}
		proof, hasProof := latest[definition.Name]
		proofFresh := hasProof && !now.Before(time.Unix(proof.ObservedAt, 0)) && now.Sub(time.Unix(proof.ObservedAt, 0)) <= FleetCoverageProofFreshFor
		if proofFresh {
			coverage.LastProofID, coverage.LastProofAt, coverage.LastProofResult = proof.ID, proof.ObservedAt, proof.Result
		}
		if capability.Enforce {
			if capability.Receipt && proofFresh {
				coverage.State = FleetCoverageProtected
				coverage.Reason = "A current signed adapter claim is backed by recent signed runtime evidence."
				manifest.ProtectedActions++
			} else {
				coverage.State = FleetCoverageReported
				coverage.Reason = "The adapter reports enforcement, but Pilot has no recent signed runtime proof for this action."
				manifest.ReportedActions++
			}
		} else if capability.Observe {
			coverage.State = FleetCoverageObserved
			coverage.Reason = "Pilot can observe this action but this adapter cannot block it."
			manifest.ObservedActions++
		}
		manifest.Actions = append(manifest.Actions, coverage)
	}
	if manifest.DeclaredActions > 0 {
		manifest.CoveragePercent = manifest.ProtectedActions * 100 / manifest.DeclaredActions
	}
	sort.SliceStable(manifest.Actions, func(i, j int) bool {
		left, right := fleetCoverageSortRank(manifest.Actions[i].State), fleetCoverageSortRank(manifest.Actions[j].State)
		if left == right {
			return manifest.Actions[i].Action < manifest.Actions[j].Action
		}
		return left < right
	})
	return manifest
}

func fleetCoverageSortRank(state FleetCoverageState) int {
	switch state {
	case FleetCoverageDegraded:
		return 0
	case FleetCoverageReported:
		return 1
	case FleetCoverageObserved:
		return 2
	case FleetCoverageProtected:
		return 3
	case FleetCoverageUnsupported:
		return 4
	default:
		return 5
	}
}

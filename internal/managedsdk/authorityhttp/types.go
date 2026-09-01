// SPDX-License-Identifier: AGPL-3.0-or-later

// Package authorityhttp contains only the managed node's public wire client.
// Hosted stores, account management, evaluators, and console handlers remain
// in the separately deployed private control plane.
package authorityhttp

import (
	"encoding/json"

	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/decisionhttp"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/decisionpolicy"
)

type PublicationEnvelope struct {
	Publication authority.PolicyPublication `json:"publication"`
	Bundle      authority.PolicyBundle      `json:"bundle"`
}

type ActivePolicyEnvelope struct {
	Publication authority.PolicyPublication `json:"publication"`
	Bundle      authority.PolicyBundle      `json:"bundle"`
	Activation  authority.PolicyActivation  `json:"activation"`
}

type ManagementState struct {
	Trust           authority.TrustBundle         `json:"trust"`
	ActivePolicy    authority.PolicyBundle        `json:"active_policy"`
	Rollouts        []authority.RolloutStatus     `json:"rollouts"`
	MandateBundles  []decision.MandateBundle      `json:"mandate_bundles,omitempty"`
	RecentReceipts  []decision.Receipt            `json:"recent_receipts,omitempty"`
	RecentWorkflows []decisionhttp.WorkflowRecord `json:"recent_workflows,omitempty"`
	UsageExport     *decision.UsageExportStatus   `json:"usage_export,omitempty"`
}

type SimulationRequest struct {
	Publication authority.PolicyPublication      `json:"publication"`
	Bundle      authority.PolicyBundle           `json:"bundle"`
	Intents     []decision.Intent                `json:"intents"`
	Inputs      []decisionpolicy.SimulationInput `json:"inputs,omitempty"`
}

const NodeEnrollmentVersion uint16 = 1

type NodeEnrollmentOptions struct {
	ActionControl bool `json:"action_control"`
	FleetControl  bool `json:"fleet_control"`
	StateSync     bool `json:"state_sync"`
	Apps          bool `json:"apps"`
}

// NodeEnrollmentClaimResponse is the atomic one-time response consumed by
// pilotctl. It intentionally carries no tenant root or platform credential.
type NodeEnrollmentClaimResponse struct {
	Version            uint16                `json:"version"`
	EnrollmentID       string                `json:"enrollment_id"`
	TenantID           string                `json:"tenant_id"`
	AgentID            string                `json:"agent_id"`
	HarnessID          string                `json:"harness_id"`
	DisplayName        string                `json:"display_name"`
	RunID              string                `json:"run_id"`
	PublicOrigin       string                `json:"public_origin"`
	FederationEndpoint string                `json:"federation_endpoint"`
	Options            NodeEnrollmentOptions `json:"options"`
	Credential         json.RawMessage       `json:"credential"`
	Policy             json.RawMessage       `json:"policy"`
	ClaimedAt          int64                 `json:"claimed_at"`
}

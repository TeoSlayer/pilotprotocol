// SPDX-License-Identifier: AGPL-3.0-or-later

package decisionpolicy

import (
	"context"
	"fmt"

	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
)

type RolloutValidation interface {
	ValidateCandidate(context.Context, authority.PolicyPublication, authority.PolicyBundle) error
	CurrentPolicy(context.Context, string) (authority.PolicyBundle, error)
}

type RolloutSimulation struct {
	CurrentRevision   uint64     `json:"current_revision"`
	CandidateRevision uint64     `json:"candidate_revision"`
	Comparison        Comparison `json:"comparison"`
}

type RolloutSimulator struct{ Rollouts RolloutValidation }

func (simulator RolloutSimulator) Simulate(ctx context.Context, publication authority.PolicyPublication, bundle authority.PolicyBundle, intents []decision.Intent) (RolloutSimulation, error) {
	inputs := make([]SimulationInput, len(intents))
	for index, intent := range intents {
		inputs[index] = SimulationInput{Intent: intent}
	}
	return simulator.SimulateInputs(ctx, publication, bundle, inputs)
}

// SimulateInputs compares a candidate against the active signed policy with
// both legacy Intent and hash-bound typed disclosure cases.
func (simulator RolloutSimulator) SimulateInputs(ctx context.Context, publication authority.PolicyPublication, bundle authority.PolicyBundle, inputs []SimulationInput) (RolloutSimulation, error) {
	if simulator.Rollouts == nil {
		return RolloutSimulation{}, fmt.Errorf("decisionpolicy: rollout validator is required")
	}
	if err := simulator.Rollouts.ValidateCandidate(ctx, publication, bundle); err != nil {
		return RolloutSimulation{}, err
	}
	current, err := simulator.Rollouts.CurrentPolicy(ctx, bundle.TenantID)
	if err != nil {
		return RolloutSimulation{}, err
	}
	comparison, err := CompareInputs(current.Payload, bundle.Payload, inputs)
	if err != nil {
		return RolloutSimulation{}, err
	}
	return RolloutSimulation{
		CurrentRevision: current.Revision, CandidateRevision: bundle.Revision, Comparison: comparison,
	}, nil
}

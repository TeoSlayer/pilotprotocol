// SPDX-License-Identifier: AGPL-3.0-or-later

package decisionhttp

import (
	"errors"
	"sort"

	"github.com/pilot-protocol/common/decision"
)

var ErrWorkflowConflict = errors.New("decisionhttp: approval workflow conflict")

type WorkflowRecord struct {
	Transaction      decision.ApprovalTransaction   `json:"transaction"`
	Votes            []decision.ApprovalVote        `json:"votes,omitempty"`
	Certificate      *decision.ApprovalCertificate  `json:"certificate,omitempty"`
	Cancellation     *decision.ApprovalCancellation `json:"cancellation,omitempty"`
	ConsumedIntentID string                         `json:"consumed_intent_hash,omitempty"`
	ConsumedDecision *decision.Decision             `json:"consumed_decision,omitempty"`
}

type WorkflowBeginEnvelope struct {
	Intent     decision.Intent             `json:"intent"`
	Initial    decision.Decision           `json:"initial_decision"`
	Disclosure *decision.DisclosureBinding `json:"disclosure,omitempty"`
}

type WorkflowVoteEnvelope struct {
	TransactionID string                `json:"transaction_id"`
	Vote          decision.ApprovalVote `json:"vote"`
}

type WorkflowExecuteEnvelope struct {
	TransactionID string          `json:"transaction_id"`
	Intent        decision.Intent `json:"intent"`
}

type WorkflowCancelRequest struct {
	TransactionID string `json:"transaction_id"`
	Reason        string `json:"reason"`
}

type WorkflowListResponse struct {
	Workflows []WorkflowRecord `json:"workflows"`
}

func ValidateWorkflowRecord(record WorkflowRecord) error { return validateWorkflowRecord(record) }

func validateWorkflowRecord(record WorkflowRecord) error {
	if err := record.Transaction.Validate(); err != nil {
		return err
	}
	transactionHash, err := record.Transaction.Hash()
	if err != nil {
		return err
	}
	seenKeys := make(map[string]struct{}, len(record.Votes))
	for _, vote := range record.Votes {
		if err := vote.Validate(); err != nil || vote.TransactionHash != transactionHash {
			return ErrWorkflowConflict
		}
		if _, exists := seenKeys[vote.KeyID]; exists {
			return ErrWorkflowConflict
		}
		seenKeys[vote.KeyID] = struct{}{}
	}
	if record.Certificate != nil {
		if err := record.Certificate.Validate(); err != nil || record.Certificate.TransactionHash != transactionHash {
			return ErrWorkflowConflict
		}
		if len(record.Votes) != len(record.Certificate.ApprovalVoteHashes) || len(record.Votes) < int(record.Transaction.RequiredApprovals) {
			return ErrWorkflowConflict
		}
		certificateVotes := make(map[string]struct{}, len(record.Certificate.ApprovalVoteHashes))
		for _, voteHash := range record.Certificate.ApprovalVoteHashes {
			certificateVotes[voteHash] = struct{}{}
		}
		for _, vote := range record.Votes {
			if vote.Choice != decision.ApprovalVoteApprove {
				return ErrWorkflowConflict
			}
			voteHash, err := vote.Hash()
			if err != nil {
				return ErrWorkflowConflict
			}
			if _, found := certificateVotes[voteHash]; !found {
				return ErrWorkflowConflict
			}
		}
	}
	if record.Cancellation != nil {
		if err := record.Cancellation.Validate(); err != nil || record.Cancellation.TransactionHash != transactionHash || record.Cancellation.TenantID != record.Transaction.TenantID {
			return ErrWorkflowConflict
		}
		if record.Certificate != nil || record.ConsumedDecision != nil {
			return ErrWorkflowConflict
		}
	}
	if record.ConsumedDecision != nil {
		if record.Certificate == nil || record.ConsumedIntentID == "" || record.ConsumedDecision.IntentHash != record.ConsumedIntentID {
			return ErrWorkflowConflict
		}
		if err := record.ConsumedDecision.Validate(); err != nil {
			return err
		}
		if record.ConsumedDecision.TenantID != record.Transaction.TenantID ||
			record.ConsumedDecision.AgentID != record.Transaction.AgentID ||
			record.ConsumedDecision.Outcome != record.Certificate.Outcome ||
			!equalDecisionConstraints(record.ConsumedDecision.Constraints, record.Certificate.Constraints) ||
			record.ConsumedDecision.PolicyRevision != record.Certificate.PolicyRevision ||
			record.ConsumedDecision.RevocationEpoch != record.Certificate.RevocationEpoch {
			return ErrWorkflowConflict
		}
	}
	return nil
}

func equalDecisionConstraints(left, right []decision.Constraint) bool {
	if len(left) != len(right) {
		return false
	}
	left = append([]decision.Constraint(nil), left...)
	right = append([]decision.Constraint(nil), right...)
	sort.Slice(left, func(i, j int) bool {
		if left[i].Key != left[j].Key {
			return left[i].Key < left[j].Key
		}
		if left[i].Operator != left[j].Operator {
			return left[i].Operator < left[j].Operator
		}
		return left[i].Value < left[j].Value
	})
	sort.Slice(right, func(i, j int) bool {
		if right[i].Key != right[j].Key {
			return right[i].Key < right[j].Key
		}
		if right[i].Operator != right[j].Operator {
			return right[i].Operator < right[j].Operator
		}
		return right[i].Value < right[j].Value
	})
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validWorkflowTenant(tenantID string) bool {
	if len(tenantID) == 0 || len(tenantID) > 128 {
		return false
	}
	for _, character := range tenantID {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

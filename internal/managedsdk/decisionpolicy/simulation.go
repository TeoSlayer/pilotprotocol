// SPDX-License-Identifier: AGPL-3.0-or-later

package decisionpolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/pilot-protocol/common/decision"
)

const MaxSimulationIntents = 1_000

// SimulationInput is a policy-review case. Disclosure is optional for legacy
// V1 intents, but when present it must be the exact metadata bound by the
// input Intent. This lets policy rollout simulation show the real effect of
// typed data-governance rules before an operator activates them.
type SimulationInput struct {
	Intent     decision.Intent             `json:"intent"`
	Disclosure *decision.DisclosureBinding `json:"disclosure,omitempty"`
}

type SimulationResult struct {
	IntentID    string                `json:"intent_id"`
	Outcome     decision.Outcome      `json:"outcome"`
	Reasons     []string              `json:"reasons,omitempty"`
	Constraints []decision.Constraint `json:"constraints,omitempty"`
	Approval    *ApprovalPlan         `json:"approval,omitempty"`
}

type DocumentDiff struct {
	DefaultOutcomeFrom decision.Outcome `json:"default_outcome_from"`
	DefaultOutcomeTo   decision.Outcome `json:"default_outcome_to"`
	AddedRules         []string         `json:"added_rules"`
	RemovedRules       []string         `json:"removed_rules"`
	ChangedRules       []string         `json:"changed_rules"`
	Changed            bool             `json:"changed"`
}

type ImpactChange struct {
	IntentID          string                `json:"intent_id"`
	Before            decision.Outcome      `json:"before"`
	After             decision.Outcome      `json:"after"`
	BeforeConstraints []decision.Constraint `json:"before_constraints,omitempty"`
	AfterConstraints  []decision.Constraint `json:"after_constraints,omitempty"`
	BeforeApproval    *ApprovalPlan         `json:"before_approval,omitempty"`
	AfterApproval     *ApprovalPlan         `json:"after_approval,omitempty"`
	AuthorityChange   string                `json:"authority_change"`
}

type Comparison struct {
	Diff      DocumentDiff       `json:"diff"`
	Candidate []SimulationResult `json:"candidate"`
	Impacts   []ImpactChange     `json:"impacts"`
}

func Simulate(payload []byte, intents []decision.Intent) ([]SimulationResult, error) {
	inputs := make([]SimulationInput, len(intents))
	for index, intent := range intents {
		inputs[index].Intent = intent
	}
	return SimulateInputs(payload, inputs)
}

func SimulateInputs(payload []byte, inputs []SimulationInput) ([]SimulationResult, error) {
	if len(inputs) > MaxSimulationIntents {
		return nil, fmt.Errorf("decisionpolicy: at most %d simulation inputs are allowed", MaxSimulationIntents)
	}
	policy, err := Compile(payload)
	if err != nil {
		return nil, err
	}
	results := make([]SimulationResult, 0, len(inputs))
	for _, input := range inputs {
		if err := input.Validate(); err != nil {
			return nil, fmt.Errorf("decisionpolicy: invalid simulation intent %q: %w", input.Intent.ID, err)
		}
		result, approval := policy.evaluateInput(input)
		results = append(results, SimulationResult{
			IntentID: input.Intent.ID, Outcome: result.Outcome,
			Reasons:     append([]string(nil), result.Reasons...),
			Constraints: append([]decision.Constraint(nil), result.Constraints...),
			Approval:    approval,
		})
	}
	return results, nil
}

func (input SimulationInput) Validate() error {
	if err := input.Intent.Validate(); err != nil {
		return err
	}
	if input.Disclosure != nil {
		return input.Disclosure.VerifyIntent(input.Intent)
	}
	return nil
}

func (policy *compiled) evaluateInput(input SimulationInput) (decision.Decision, *ApprovalPlan) {
	if input.Disclosure != nil {
		return policy.evaluateDisclosure(input.Intent, *input.Disclosure), policy.approvalPlanDisclosure(input.Intent, *input.Disclosure)
	}
	return policy.evaluate(input.Intent), policy.approvalPlan(input.Intent)
}

func (policy *compiled) approvalPlanDisclosure(intent decision.Intent, disclosure decision.DisclosureBinding) *ApprovalPlan {
	for _, rule := range policy.document.Rules {
		if matches(rule, intent, &disclosure) {
			if rule.Outcome != decision.ApprovalRequired || rule.Approval == nil {
				return nil
			}
			plan := cloneApprovalPlan(*rule.Approval)
			return &plan
		}
	}
	return nil
}

func Compare(currentPayload, candidatePayload []byte, intents []decision.Intent) (Comparison, error) {
	inputs := make([]SimulationInput, len(intents))
	for index, intent := range intents {
		inputs[index] = SimulationInput{Intent: intent}
	}
	return CompareInputs(currentPayload, candidatePayload, inputs)
}

func CompareInputs(currentPayload, candidatePayload []byte, inputs []SimulationInput) (Comparison, error) {
	current, err := Compile(currentPayload)
	if err != nil {
		return Comparison{}, fmt.Errorf("decisionpolicy: current policy: %w", err)
	}
	candidate, err := Compile(candidatePayload)
	if err != nil {
		return Comparison{}, fmt.Errorf("decisionpolicy: candidate policy: %w", err)
	}
	if len(inputs) > MaxSimulationIntents {
		return Comparison{}, fmt.Errorf("decisionpolicy: at most %d simulation intents are allowed", MaxSimulationIntents)
	}
	comparison := Comparison{Diff: diffDocuments(current.document, candidate.document)}
	for _, input := range inputs {
		if err := input.Validate(); err != nil {
			return Comparison{}, fmt.Errorf("decisionpolicy: invalid simulation intent %q: %w", input.Intent.ID, err)
		}
		before, beforeApproval := current.evaluateInput(input)
		after, afterApproval := candidate.evaluateInput(input)
		comparison.Candidate = append(comparison.Candidate, SimulationResult{
			IntentID: input.Intent.ID, Outcome: after.Outcome,
			Reasons: append([]string(nil), after.Reasons...), Constraints: append([]decision.Constraint(nil), after.Constraints...), Approval: afterApproval,
		})
		if before.Outcome != after.Outcome || !constraintSetsEqual(before.Constraints, after.Constraints) || !approvalPlansEqual(beforeApproval, afterApproval) {
			authorityChange := classifyChange(before.Outcome, after.Outcome)
			if before.Outcome == decision.ApprovalRequired && after.Outcome == decision.ApprovalRequired && !approvalPlansEqual(beforeApproval, afterApproval) {
				authorityChange = "approval_changed"
			}
			comparison.Impacts = append(comparison.Impacts, ImpactChange{
				IntentID: input.Intent.ID, Before: before.Outcome, After: after.Outcome,
				BeforeConstraints: append([]decision.Constraint(nil), before.Constraints...),
				AfterConstraints:  append([]decision.Constraint(nil), after.Constraints...),
				BeforeApproval:    beforeApproval, AfterApproval: afterApproval, AuthorityChange: authorityChange,
			})
		}
	}
	return comparison, nil
}

func approvalPlansEqual(first, second *ApprovalPlan) bool {
	if first == nil || second == nil {
		return first == nil && second == nil
	}
	left := cloneApprovalPlan(*first)
	right := cloneApprovalPlan(*second)
	canonicalizeApprovalPlan(&left)
	canonicalizeApprovalPlan(&right)
	firstJSON, firstErr := json.Marshal(left)
	secondJSON, secondErr := json.Marshal(right)
	return firstErr == nil && secondErr == nil && bytes.Equal(firstJSON, secondJSON)
}

func canonicalizeApprovalPlan(plan *ApprovalPlan) {
	if plan == nil {
		return
	}
	sort.Strings(plan.ApproverKeyIDs)
	sort.Slice(plan.Constraints, func(i, j int) bool {
		if plan.Constraints[i].Key != plan.Constraints[j].Key {
			return plan.Constraints[i].Key < plan.Constraints[j].Key
		}
		if plan.Constraints[i].Operator != plan.Constraints[j].Operator {
			return plan.Constraints[i].Operator < plan.Constraints[j].Operator
		}
		return plan.Constraints[i].Value < plan.Constraints[j].Value
	})
}

func diffDocuments(current, candidate Document) DocumentDiff {
	diff := DocumentDiff{DefaultOutcomeFrom: current.DefaultOutcome, DefaultOutcomeTo: candidate.DefaultOutcome}
	currentRules := make(map[string]Rule, len(current.Rules))
	candidateRules := make(map[string]Rule, len(candidate.Rules))
	for _, rule := range current.Rules {
		currentRules[rule.ID] = rule
	}
	for _, rule := range candidate.Rules {
		candidateRules[rule.ID] = rule
	}
	for id, currentRule := range currentRules {
		candidateRule, exists := candidateRules[id]
		if !exists {
			diff.RemovedRules = append(diff.RemovedRules, id)
			continue
		}
		currentJSON, _ := json.Marshal(currentRule)
		candidateJSON, _ := json.Marshal(candidateRule)
		if !bytes.Equal(currentJSON, candidateJSON) {
			diff.ChangedRules = append(diff.ChangedRules, id)
		}
	}
	for id := range candidateRules {
		if _, exists := currentRules[id]; !exists {
			diff.AddedRules = append(diff.AddedRules, id)
		}
	}
	sort.Strings(diff.AddedRules)
	sort.Strings(diff.RemovedRules)
	sort.Strings(diff.ChangedRules)
	diff.Changed = diff.DefaultOutcomeFrom != diff.DefaultOutcomeTo || len(diff.AddedRules)+len(diff.RemovedRules)+len(diff.ChangedRules) > 0
	return diff
}

func classifyChange(before, after decision.Outcome) string {
	rank := map[decision.Outcome]int{
		decision.Deny: 0, decision.ApprovalRequired: 1, decision.Constrain: 2, decision.Allow: 3,
	}
	if rank[after] > rank[before] {
		return "expanded"
	}
	if rank[after] < rank[before] {
		return "narrowed"
	}
	return "constraints_changed"
}

func constraintSetsEqual(first, second []decision.Constraint) bool {
	if len(first) != len(second) {
		return false
	}
	counts := make(map[decision.Constraint]int, len(first))
	for _, constraint := range first {
		counts[constraint]++
	}
	for _, constraint := range second {
		if counts[constraint] == 0 {
			return false
		}
		counts[constraint]--
	}
	return true
}

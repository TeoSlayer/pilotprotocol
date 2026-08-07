// SPDX-License-Identifier: AGPL-3.0-or-later

package decisionpolicy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
)

func simulationIntent(id, action, resource string) decision.Intent {
	return decision.Intent{
		Version: decision.SchemaVersion, ID: id, TenantID: "tenant-a", AgentID: "agent-1",
		Action: action, Resource: resource, PayloadHash: decision.HashPayload([]byte(id)),
		Risk: decision.RiskHigh, IssuedAt: time.Unix(1785500000, 0).Unix(),
		ExpiresAt: time.Unix(1785500000, 0).Add(time.Minute).Unix(),
		Nonce:     strings.Repeat("0", 32), KeyID: "agent-key-1",
	}
}

type rolloutValidationMock struct {
	current authority.PolicyBundle
	err     error
}

func (mock rolloutValidationMock) ValidateCandidate(context.Context, authority.PolicyPublication, authority.PolicyBundle) error {
	return mock.err
}

func (mock rolloutValidationMock) CurrentPolicy(context.Context, string) (authority.PolicyBundle, error) {
	return mock.current, mock.err
}

func encodeDocument(t *testing.T, rules ...Rule) []byte {
	t.Helper()
	body, err := json.Marshal(Document{Version: 1, DefaultOutcome: decision.Deny, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestCompareReportsSemanticDiffAndAuthorityImpact(t *testing.T) {
	t.Parallel()
	current := encodeDocument(t, Rule{
		ID: "wallet", Agents: []string{"agent-1"}, Actions: []string{"wallet.*"},
		ResourcePrefixes: []string{"merchant:"}, Risks: []decision.RiskClass{decision.RiskHigh}, Outcome: decision.Allow,
	})
	candidate := encodeDocument(t,
		Rule{
			ID: "wallet", Agents: []string{"agent-1"}, Actions: []string{"wallet.*"},
			ResourcePrefixes: []string{"merchant:"}, Risks: []decision.RiskClass{decision.RiskHigh},
			Outcome: decision.Constrain, Constraints: []decision.Constraint{{Key: "amount", Operator: "max", Value: "100"}},
		},
		Rule{
			ID: "admin-deny", Agents: []string{"*"}, Actions: []string{"admin.*"},
			ResourcePrefixes: []string{"*"}, Risks: []decision.RiskClass{decision.RiskHigh}, Outcome: decision.Deny,
		},
	)
	comparison, err := Compare(current, candidate, []decision.Intent{
		simulationIntent("wallet-intent", "wallet.pay", "merchant:42"),
		simulationIntent("other-intent", "message.send", "agent:2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !comparison.Diff.Changed || len(comparison.Diff.ChangedRules) != 1 || comparison.Diff.ChangedRules[0] != "wallet" ||
		len(comparison.Diff.AddedRules) != 1 || comparison.Diff.AddedRules[0] != "admin-deny" {
		t.Fatalf("unexpected diff: %+v", comparison.Diff)
	}
	if len(comparison.Impacts) != 1 || comparison.Impacts[0].IntentID != "wallet-intent" ||
		comparison.Impacts[0].AuthorityChange != "narrowed" || comparison.Impacts[0].After != decision.Constrain {
		t.Fatalf("unexpected impacts: %+v", comparison.Impacts)
	}
}

func TestCompareInputsEvaluatesTypedDisclosureRules(t *testing.T) {
	t.Parallel()
	current := encodeDocument(t, Rule{
		ID: "eu-finance", Agents: []string{"agent-1"}, Actions: []string{"file.share"}, ResourcePrefixes: []string{"agent:finance/"},
		Risks: []decision.RiskClass{decision.RiskHigh}, Outcome: decision.Allow,
		Disclosure: &DisclosureRule{LabelsAll: []string{"finance", "pii"}, ContentTypes: []string{"application/pdf"}, Recipients: []string{"agent:finance"}, Purposes: []string{"invoice-payment"}, Residencies: []string{"eu-west-1"}},
	})
	candidate := encodeDocument(t, Rule{
		ID: "eu-finance", Agents: []string{"agent-1"}, Actions: []string{"file.share"}, ResourcePrefixes: []string{"agent:finance/"},
		Risks: []decision.RiskClass{decision.RiskHigh}, Outcome: decision.Allow,
		Disclosure: &DisclosureRule{LabelsAll: []string{"finance", "pii"}, ContentTypes: []string{"application/pdf"}, Recipients: []string{"agent:finance"}, Purposes: []string{"invoice-payment"}, Residencies: []string{"eu-central-1"}},
	})
	disclosure := decision.DisclosureBinding{
		Version: decision.DisclosureBindingVersion, ContentHash: decision.HashPayload([]byte("invoice")), DeclaredBytes: 7,
		ContentType: "application/pdf", Labels: []string{"finance", "pii"}, Recipient: "agent:finance", Purpose: "invoice-payment", Residency: "eu-west-1", Filename: "invoice.pdf",
	}
	hash, err := disclosure.Hash()
	if err != nil {
		t.Fatal(err)
	}
	input := SimulationInput{Intent: decision.Intent{
		Version: decision.SchemaVersion, ID: "finance-disclosure", TenantID: "tenant-a", AgentID: "agent-1", Action: "file.share", Resource: "agent:finance/inbox",
		Audience: disclosure.Recipient, Purpose: disclosure.Purpose, PayloadHash: hash, Risk: decision.RiskHigh,
		IssuedAt: time.Unix(1785500000, 0).Unix(), ExpiresAt: time.Unix(1785500000, 0).Add(time.Minute).Unix(), Nonce: strings.Repeat("b", 32), KeyID: "agent-key-1",
	}, Disclosure: &disclosure}
	comparison, err := CompareInputs(current, candidate, []SimulationInput{input})
	if err != nil {
		t.Fatal(err)
	}
	if len(comparison.Impacts) != 1 || comparison.Impacts[0].Before != decision.Allow || comparison.Impacts[0].After != decision.Deny || comparison.Impacts[0].AuthorityChange != "narrowed" {
		t.Fatalf("typed disclosure impact=%+v", comparison)
	}
	bad := input
	bad.Disclosure = &decision.DisclosureBinding{Version: decision.DisclosureBindingVersion, ContentHash: disclosure.ContentHash, DeclaredBytes: disclosure.DeclaredBytes, ContentType: disclosure.ContentType, Labels: append([]string(nil), disclosure.Labels...), Recipient: disclosure.Recipient, Purpose: disclosure.Purpose, Residency: "us-east-1", Filename: disclosure.Filename}
	if _, err := CompareInputs(current, candidate, []SimulationInput{bad}); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("unbound disclosure simulation accepted: %v", err)
	}
}

func TestCompareReportsApprovalPlanChangeAsAnImpact(t *testing.T) {
	t.Parallel()
	current := encodeDocument(t, Rule{
		ID: "message-approval", Agents: []string{"agent-1"}, Actions: []string{"message.send"}, ResourcePrefixes: []string{"agent:"},
		Risks: []decision.RiskClass{decision.RiskHigh}, Outcome: decision.ApprovalRequired,
		Approval: &ApprovalPlan{ApproverKeyIDs: []string{"approval-a"}, RequiredApprovals: 1, ValiditySeconds: 3600, Outcome: decision.Allow},
	})
	candidate := encodeDocument(t, Rule{
		ID: "message-approval", Agents: []string{"agent-1"}, Actions: []string{"message.send"}, ResourcePrefixes: []string{"agent:"},
		Risks: []decision.RiskClass{decision.RiskHigh}, Outcome: decision.ApprovalRequired,
		Approval: &ApprovalPlan{ApproverKeyIDs: []string{"approval-a", "approval-b"}, RequiredApprovals: 2, ValiditySeconds: 7200, Outcome: decision.Constrain, Constraints: []decision.Constraint{{Key: "recipient", Operator: "eq", Value: "agent:finance"}}},
	})
	comparison, err := Compare(current, candidate, []decision.Intent{simulationIntent("message-intent", "message.send", "agent:finance")})
	if err != nil {
		t.Fatal(err)
	}
	if len(comparison.Impacts) != 1 || comparison.Impacts[0].AuthorityChange != "approval_changed" || comparison.Impacts[0].BeforeApproval == nil || comparison.Impacts[0].AfterApproval == nil || comparison.Impacts[0].AfterApproval.RequiredApprovals != 2 {
		t.Fatalf("approval plan impact=%+v", comparison.Impacts)
	}
}

func TestSimulationRejectsMalformedCandidateAndOversizedCorpus(t *testing.T) {
	t.Parallel()
	current := encodeDocument(t, Rule{
		ID: "deny", Agents: []string{"*"}, Actions: []string{"wallet.*"}, ResourcePrefixes: []string{"*"},
		Risks: []decision.RiskClass{decision.RiskHigh}, Outcome: decision.Deny,
	})
	if _, err := Compare(current, []byte(`{"version":1,"default_outcome":"allow","rules":[]}`), nil); err == nil {
		t.Fatal("unsafe candidate was simulated")
	}
	intents := make([]decision.Intent, MaxSimulationIntents+1)
	if _, err := Simulate(current, intents); err == nil {
		t.Fatal("oversized simulation corpus was accepted")
	}
}

func TestRolloutSimulatorValidatesSignedEnvelopeBeforeComparison(t *testing.T) {
	t.Parallel()
	current := encodeDocument(t, Rule{
		ID: "wallet", Agents: []string{"agent-1"}, Actions: []string{"wallet.*"}, ResourcePrefixes: []string{"*"},
		Risks: []decision.RiskClass{decision.RiskHigh}, Outcome: decision.Allow,
	})
	candidate := encodeDocument(t, Rule{
		ID: "wallet", Agents: []string{"agent-1"}, Actions: []string{"wallet.*"}, ResourcePrefixes: []string{"*"},
		Risks: []decision.RiskClass{decision.RiskHigh}, Outcome: decision.Deny,
	})
	simulator := RolloutSimulator{Rollouts: rolloutValidationMock{current: authority.PolicyBundle{Revision: 1, Payload: current}}}
	result, err := simulator.Simulate(context.Background(), authority.PolicyPublication{}, authority.PolicyBundle{TenantID: "tenant-a", Revision: 2, Payload: candidate}, []decision.Intent{simulationIntent("wallet-intent", "wallet.pay", "merchant:1")})
	if err != nil {
		t.Fatal(err)
	}
	if result.CurrentRevision != 1 || result.CandidateRevision != 2 || len(result.Comparison.Impacts) != 1 || result.Comparison.Impacts[0].AuthorityChange != "narrowed" {
		t.Fatalf("unexpected rollout simulation: %+v", result)
	}
}

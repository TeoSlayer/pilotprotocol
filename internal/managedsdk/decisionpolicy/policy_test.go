// SPDX-License-Identifier: AGPL-3.0-or-later

package decisionpolicy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
)

func policyPayload(t *testing.T) []byte {
	t.Helper()
	document := Document{
		Version: 1, DefaultOutcome: decision.Deny,
		Rules: []Rule{
			{
				ID: "bounded-wallet", Agents: []string{"agent-1"}, Actions: []string{"wallet.*"},
				ResourcePrefixes: []string{"merchant:"}, Risks: []decision.RiskClass{decision.RiskHigh},
				Outcome: decision.Constrain, Reasons: []string{"within mandate"},
				Constraints: []decision.Constraint{{Key: "amount", Operator: "max", Value: "100"}},
			},
			{
				ID: "messages", Agents: []string{"*"}, Actions: []string{"message.send"},
				ResourcePrefixes: []string{"*"}, Risks: []decision.RiskClass{decision.RiskLow},
				Outcome: decision.Allow, Reasons: []string{"low risk"},
			},
		},
	}
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func installedEngine(t *testing.T, now time.Time) (*EngineInstance, authority.PolicyBundle) {
	return installedEngineWithPayload(t, now, policyPayload(t))
}

func installedEngineWithPayload(t *testing.T, now time.Time, payload []byte) (*EngineInstance, authority.PolicyBundle) {
	t.Helper()
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(rand.Reader)
	issuerPublic, issuerPrivate, _ := ed25519.GenerateKey(rand.Reader)
	trustBundle := authority.TrustBundle{
		Version: authority.SchemaVersion, TenantID: "tenant-a", Revision: 1,
		PolicyRevision: 7, RevocationEpoch: 3, IssuedAt: now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(), RootKeyID: "root-1",
		Keys: []authority.AuthorityKey{{
			KeyID: "policy-key-1", PublicKey: base64.StdEncoding.EncodeToString(issuerPublic),
			Usages: []authority.KeyUsage{authority.UsagePolicy}, NotBefore: now.Add(-time.Minute).Unix(),
			ExpiresAt: now.Add(30 * time.Minute).Unix(),
		}},
	}
	if err := trustBundle.Sign(rootPrivate); err != nil {
		t.Fatal(err)
	}
	trust, err := authority.NewStore([]authority.PinnedRoot{{TenantID: "tenant-a", RootKeyID: "root-1", PublicKey: rootPublic}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.Install(trustBundle); err != nil {
		t.Fatal(err)
	}
	manager, err := authority.NewPolicyManager(trust, Validator{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	bundle := authority.NewPolicyBundle(
		"tenant-a", 7, 3, now, now, now.Add(10*time.Minute),
		Engine, EngineVersion, ContentType, "policy-key-1", payload,
	)
	if err := bundle.Sign(issuerPrivate); err != nil {
		t.Fatal(err)
	}
	if err := manager.Install(context.Background(), bundle); err != nil {
		t.Fatal(err)
	}
	engine, err := New(manager)
	if err != nil {
		t.Fatal(err)
	}
	return engine, bundle
}

func TestApprovalPlanIsSignedPolicyScopedAndCurrent(t *testing.T) {
	t.Parallel()
	now := time.Unix(1785500000, 0)
	payload, err := json.Marshal(Document{
		Version: 1, DefaultOutcome: decision.Deny,
		Rules: []Rule{{
			ID: "approved-payment", Agents: []string{"agent-1"}, Actions: []string{"wallet.pay"}, ResourcePrefixes: []string{"merchant:"},
			Risks: []decision.RiskClass{decision.RiskHigh}, Outcome: decision.ApprovalRequired, Reasons: []string{"dual control"},
			Approval: &ApprovalPlan{ApproverKeyIDs: []string{"approval-key-a", "approval-key-b"}, RequiredApprovals: 2, ValiditySeconds: 7200,
				Outcome: decision.Constrain, Constraints: []decision.Constraint{{Key: "amount", Operator: "max", Value: "100"}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, bundle := installedEngineWithPayload(t, now, payload)
	intent := decision.Intent{Version: decision.SchemaVersion, ID: "plan-intent", TenantID: "tenant-a", AgentID: "agent-1", Action: "wallet.pay", Resource: "merchant:42", PayloadHash: decision.HashPayload([]byte("payment")), Risk: decision.RiskHigh, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), Nonce: strings.Repeat("1", 32), KeyID: "agent-key-1"}
	initial, err := engine.Authorize(context.Background(), intent)
	if err != nil || initial.Outcome != decision.ApprovalRequired {
		t.Fatalf("initial=%+v err=%v", initial, err)
	}
	plan, err := engine.ApprovalPlanFor(context.Background(), intent, initial)
	if err != nil || plan.RequiredApprovals != 2 || plan.Outcome != decision.Constrain || plan.ValiditySeconds != 7200 {
		t.Fatalf("approval plan=%+v err=%v", plan, err)
	}
	stale := initial
	stale.PolicyRevision = bundle.Revision - 1
	if _, err := engine.ApprovalPlanFor(context.Background(), intent, stale); err == nil {
		t.Fatal("stale initial decision received an approval plan")
	}
}

func TestDeterministicEvaluatorAndLocalCeiling(t *testing.T) {
	t.Parallel()
	now := time.Unix(1785500000, 0)
	engine, bundle := installedEngine(t, now)
	intent := decision.Intent{
		Version: decision.SchemaVersion, ID: "intent-1", TenantID: "tenant-a", AgentID: "agent-1",
		Action: "wallet.pay", Resource: "merchant:42", PayloadHash: decision.HashPayload([]byte("payment")),
		Risk: decision.RiskHigh, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		Nonce: strings.Repeat("0", 32), KeyID: "agent-key-1",
	}
	local, err := engine.Authorize(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if local.Outcome != decision.Constrain || local.PolicyRevision != bundle.Revision || len(local.Constraints) != 1 {
		t.Fatalf("unexpected local result: %+v", local)
	}
	if err := engine.Check(context.Background(), intent, decision.Decision{Outcome: decision.Allow}); err == nil {
		t.Fatal("remote allow expanded a local constraint")
	}
	if err := engine.Check(context.Background(), intent, decision.Decision{Outcome: decision.Constrain, Constraints: local.Constraints}); err != nil {
		t.Fatalf("matching remote constraint rejected: %v", err)
	}
	intent.Resource = "unapproved:42"
	denied, err := engine.Authorize(context.Background(), intent)
	if err != nil || denied.Outcome != decision.Deny {
		t.Fatalf("default deny result=%+v err=%v", denied, err)
	}
	if err := engine.Check(context.Background(), intent, decision.Decision{Outcome: decision.Allow}); err == nil {
		t.Fatal("remote allow expanded local default deny")
	}
	if err := engine.Check(context.Background(), intent, decision.Decision{Outcome: decision.Deny}); err != nil {
		t.Fatalf("remote deny should always be within ceiling: %v", err)
	}
}

func TestDisclosureRulesControlAuthorizationAndLocalCeiling(t *testing.T) {
	now := time.Unix(1785500000, 0)
	payload, err := json.Marshal(Document{
		Version: 1, DefaultOutcome: decision.Deny,
		Rules: []Rule{{
			ID: "eu-finance-files", Agents: []string{"*"}, Actions: []string{"file.share"}, ResourcePrefixes: []string{"agent:finance/"},
			Risks: []decision.RiskClass{decision.RiskHigh}, Outcome: decision.Allow,
			Disclosure: &DisclosureRule{
				LabelsAll: []string{"finance", "pii"}, ContentTypes: []string{"application/pdf"}, Recipients: []string{"agent:finance"},
				Purposes: []string{"invoice-payment"}, Residencies: []string{"eu-west-1"},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, _ := installedEngineWithPayload(t, now, payload)
	disclosure := decision.DisclosureBinding{
		Version: decision.DisclosureBindingVersion, ContentHash: decision.HashPayload([]byte("invoice")), DeclaredBytes: 7,
		ContentType: "application/pdf", Labels: []string{"finance", "pii"}, Recipient: "agent:finance",
		Purpose: "invoice-payment", Residency: "eu-west-1", Filename: "invoice.pdf",
	}
	intent := disclosurePolicyIntent(t, now, disclosure)
	plain, err := engine.Authorize(context.Background(), intent)
	if err != nil || plain.Outcome != decision.Deny {
		t.Fatalf("bare authorization=%+v err=%v", plain, err)
	}
	allowed, err := engine.AuthorizeDisclosure(context.Background(), intent, disclosure)
	if err != nil || allowed.Outcome != decision.Allow {
		t.Fatalf("typed authorization=%+v err=%v", allowed, err)
	}
	if err := engine.CheckDisclosure(context.Background(), intent, decision.Decision{Outcome: decision.Allow}, disclosure); err != nil {
		t.Fatalf("matching local disclosure ceiling rejected allow: %v", err)
	}

	usDisclosure := disclosure
	usDisclosure.Residency = "us-east-1"
	usIntent := disclosurePolicyIntent(t, now, usDisclosure)
	denied, err := engine.AuthorizeDisclosure(context.Background(), usIntent, usDisclosure)
	if err != nil || denied.Outcome != decision.Deny {
		t.Fatalf("unapproved residency authorization=%+v err=%v", denied, err)
	}
	if err := engine.CheckDisclosure(context.Background(), usIntent, decision.Decision{Outcome: decision.Allow}, usDisclosure); err == nil || !strings.Contains(err.Error(), "expands local deny") {
		t.Fatalf("unapproved residency remote allow accepted: %v", err)
	}
}

func TestDisclosureApprovalPlanUsesTheSameTypedRule(t *testing.T) {
	now := time.Unix(1785500000, 0)
	payload, err := json.Marshal(Document{
		Version: 1, DefaultOutcome: decision.Deny,
		Rules: []Rule{{
			ID: "finance-approval", Agents: []string{"*"}, Actions: []string{"file.share"}, ResourcePrefixes: []string{"agent:finance/"}, Risks: []decision.RiskClass{decision.RiskHigh},
			Outcome: decision.ApprovalRequired, Disclosure: &DisclosureRule{LabelsAll: []string{"finance"}, Recipients: []string{"agent:finance"}, Purposes: []string{"invoice-payment"}, Residencies: []string{"eu-west-1"}},
			Approval: &ApprovalPlan{ApproverKeyIDs: []string{"approval-a", "approval-b"}, RequiredApprovals: 2, ValiditySeconds: 3600, Outcome: decision.Allow},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, _ := installedEngineWithPayload(t, now, payload)
	disclosure := decision.DisclosureBinding{
		Version: decision.DisclosureBindingVersion, ContentHash: decision.HashPayload([]byte("invoice")), DeclaredBytes: 7,
		ContentType: "application/pdf", Labels: []string{"finance"}, Recipient: "agent:finance", Purpose: "invoice-payment", Residency: "eu-west-1", Filename: "invoice.pdf",
	}
	intent := disclosurePolicyIntent(t, now, disclosure)
	initial, err := engine.AuthorizeDisclosure(context.Background(), intent, disclosure)
	if err != nil || initial.Outcome != decision.ApprovalRequired {
		t.Fatalf("typed approval result=%+v err=%v", initial, err)
	}
	plan, err := engine.ApprovalPlanForDisclosure(context.Background(), intent, initial, disclosure)
	if err != nil || plan.RequiredApprovals != 2 || plan.Outcome != decision.Allow {
		t.Fatalf("typed approval plan=%+v err=%v", plan, err)
	}
	if _, err := engine.ApprovalPlanFor(context.Background(), intent, initial); err == nil || !strings.Contains(err.Error(), "no long-running") {
		t.Fatalf("bare approval planner selected disclosure plan: %v", err)
	}
}

func disclosurePolicyIntent(t *testing.T, now time.Time, disclosure decision.DisclosureBinding) decision.Intent {
	t.Helper()
	hash, err := disclosure.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return decision.Intent{
		Version: decision.SchemaVersion, ID: "disclosure-policy-intent", TenantID: "tenant-a", AgentID: "agent-1",
		Action: "file.share", Resource: "agent:finance/inbox", Audience: disclosure.Recipient, Purpose: disclosure.Purpose,
		PayloadHash: hash, Risk: decision.RiskHigh, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		Nonce: strings.Repeat("d", 32), KeyID: "agent-key-1",
	}
}

func TestCompileRejectsUnsafeOrAmbiguousDocuments(t *testing.T) {
	t.Parallel()
	unsafe := []string{
		`{"version":1,"default_outcome":"allow","rules":[]}`,
		`{"version":1,"default_outcome":"deny","rules":[],"unknown":true}`,
		`{"version":1,"default_outcome":"deny","rules":[{"id":"x","agents":["*"],"actions":["wallet.*"],"resource_prefixes":["*"],"risks":["high"],"outcome":"constrain"}]}`,
		`{"version":1,"default_outcome":"deny","rules":[{"id":"x","agents":["*"],"actions":["wallet.**"],"resource_prefixes":["*"],"risks":["high"],"outcome":"allow"}]}`,
		`{"version":1,"default_outcome":"deny","rules":[{"id":"x","agents":["*"],"actions":["wallet.*"],"resource_prefixes":["*"],"risks":["high"],"outcome":"allow","approval":{"approver_key_ids":["a"],"required_approvals":1,"validity_seconds":60,"outcome":"allow"}}]}`,
		`{"version":1,"default_outcome":"deny","rules":[{"id":"x","agents":["*"],"actions":["wallet.*"],"resource_prefixes":["*"],"risks":["high"],"outcome":"approval_required","approval":{"approver_key_ids":["a"],"required_approvals":1,"validity_seconds":0,"outcome":"allow"}}]}`,
		`{"version":1,"default_outcome":"deny","rules":[{"id":"x","agents":["*"],"actions":["file.share"],"resource_prefixes":["*"],"risks":["high"],"outcome":"allow","disclosure":{}}]}`,
		`{"version":1,"default_outcome":"deny","rules":[{"id":"x","agents":["*"],"actions":["file.share"],"resource_prefixes":["*"],"risks":["high"],"outcome":"allow","disclosure":{"labels_all":["PII"]}}]}`,
	}
	for _, payload := range unsafe {
		if _, err := Compile([]byte(payload)); err == nil {
			t.Errorf("unsafe policy accepted: %s", payload)
		}
	}
}

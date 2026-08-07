// SPDX-License-Identifier: AGPL-3.0-or-later

package decisionpolicy

import (
	"testing"
	"time"

	"github.com/pilot-protocol/common/decision"
)

func TestRetentionClassIsAPolicyEnforcedDisclosureField(t *testing.T) {
	rule := Rule{
		ID: "retained-finance", Agents: []string{"agent-1"}, Actions: []string{"file.share"}, ResourcePrefixes: []string{"agent:finance/"},
		Risks: []decision.RiskClass{decision.RiskHigh}, Outcome: decision.Allow,
		Disclosure: &DisclosureRule{RetentionClasses: []string{"finance-7y"}},
	}
	payload := encodeDocument(t, rule)
	policy, err := Compile(payload)
	if err != nil {
		t.Fatal(err)
	}
	disclosure := decision.DisclosureBinding{
		Version: decision.DisclosureBindingRetentionVersion, ContentHash: decision.HashPayload([]byte("invoice")), DeclaredBytes: 7,
		ContentType: "application/pdf", Labels: []string{"finance"}, Recipient: "agent:finance", Purpose: "invoice-payment", Residency: "eu-west-1", Filename: "invoice.pdf", RetentionClass: "finance-7y",
	}
	intent := disclosurePolicyIntent(t, time.Unix(1785500000, 0), disclosure)
	if got := policy.evaluateDisclosure(intent, disclosure); got.Outcome != decision.Allow {
		t.Fatalf("retention class allow=%+v", got)
	}
	disclosure.RetentionClass = "finance-30d"
	if got := policy.evaluateDisclosure(intent, disclosure); got.Outcome != decision.Deny {
		t.Fatalf("retention class mismatch=%+v", got)
	}
}

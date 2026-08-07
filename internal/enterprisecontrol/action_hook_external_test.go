// SPDX-License-Identifier: AGPL-3.0-or-later

package enterprisecontrol

import (
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/actionhook"
	"github.com/pilot-protocol/common/decision"
)

func TestExternalActionAttemptRoundTripsAndRejectsTampering(t *testing.T) {
	fixture := newControlFixture(t)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	runtime.actionAgentID = "sender-a"
	payloadHash := decision.HashPayload([]byte(`{"command":"rm -rf /tmp/example"}`))
	envelope, err := actionhook.NewEnvelope("process.execute", "rm", payloadHash, "harness.claude", map[string]string{"harness": "claude"}, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	intent := decision.Intent{
		Version: decision.SchemaVersion, ID: "intent-external-1", TenantID: "tenant-a", AgentID: "sender-a",
		Action: envelope.Action, Resource: envelope.Resource, PayloadHash: envelope.PayloadHash, Risk: decision.RiskHigh,
		IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(2 * time.Minute).Unix(), Nonce: strings.Repeat("a", 32), KeyID: "sender-key",
	}
	if err := intent.Sign(fixture.intentPrivate); err != nil {
		t.Fatal(err)
	}
	intentHash, err := intent.Hash()
	if err != nil {
		t.Fatal(err)
	}
	result := decision.Decision{
		Version: decision.SchemaVersion, ID: "decision-external-1", IntentHash: intentHash,
		TenantID: "tenant-a", AgentID: "sender-a", Outcome: decision.Allow,
		PolicyRevision: 1, RevocationEpoch: 1, ProviderID: "pilot-managed", IssuedAt: fixture.now.Unix(),
		ExpiresAt: fixture.now.Add(time.Minute).Unix(), KeyID: "authority-key",
	}
	if err := result.Sign(fixture.decisionPrivate); err != nil {
		t.Fatal(err)
	}
	preflight := actionhook.Preflight{
		Outcome:   decision.Allow,
		Reference: actionhook.DecisionReference{IntentID: intent.ID, DecisionID: result.ID, PolicyRevision: 1, ProviderID: result.ProviderID},
		State:     actionHookState{selected: true, managed: true, intent: intent, result: result},
	}
	record, persist, err := runtime.ExportExternalActionAttempt(envelope, preflight)
	if err != nil || !persist {
		t.Fatalf("export persist=%v err=%v", persist, err)
	}
	restoredEnvelope, restoredPreflight, err := runtime.ImportExternalActionAttempt(record)
	if err != nil {
		t.Fatal(err)
	}
	if restoredEnvelope.ID != envelope.ID || restoredPreflight.Outcome != decision.Allow {
		t.Fatalf("restored envelope=%+v preflight=%+v", restoredEnvelope, restoredPreflight)
	}
	state, ok := restoredPreflight.State.(actionHookState)
	if !ok || state.intent.ID != intent.ID || state.result.ID != result.ID {
		t.Fatalf("restored state=%+v", restoredPreflight.State)
	}

	tampered := record
	tampered.Envelope.Resource = "sudo"
	if _, _, err := runtime.ImportExternalActionAttempt(tampered); err == nil || !strings.Contains(err.Error(), "binding mismatch") {
		t.Fatalf("tampered record error=%v", err)
	}
	tampered = record
	tampered.Decision.Outcome = decision.Deny
	if _, _, err := runtime.ImportExternalActionAttempt(tampered); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered decision error=%v", err)
	}
}

func TestExternalActionAttemptDoesNotPersistLocalOrObserveOnlyState(t *testing.T) {
	fixture := newControlFixture(t)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := actionhook.NewEnvelope("file.read", "/tmp/example", decision.HashPayload([]byte("metadata")), "harness.test", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, persist, err := runtime.ExportExternalActionAttempt(envelope, actionhook.Preflight{
		Outcome: decision.Allow, ObserveOnly: true, State: actionHookState{selected: true},
	})
	if err != nil || persist {
		t.Fatalf("persist=%v err=%v", persist, err)
	}
}

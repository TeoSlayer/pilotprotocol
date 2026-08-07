// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/dataexchange"
)

type outboundDecisionCall struct {
	action      string
	resource    string
	payloadHash string
}

type fakeOutboundDecisionRequester struct {
	outcome decision.Outcome
	calls   []outboundDecisionCall
}

func (requester *fakeOutboundDecisionRequester) HasOutboundDecisions() bool { return true }

func (requester *fakeOutboundDecisionRequester) AuthorizeOutbound(_ context.Context, action, resource, payloadHash string) (decision.Intent, decision.Decision, error) {
	requester.calls = append(requester.calls, outboundDecisionCall{action: action, resource: resource, payloadHash: payloadHash})
	now := time.Now().UTC()
	intent := decision.Intent{
		Version: decision.SchemaVersion, ID: "intent-governed-test", TenantID: "tenant-a", AgentID: "sender-a",
		Action: action, Resource: resource, PayloadHash: payloadHash, Risk: decision.RiskHigh,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), Nonce: strings.Repeat("a", 32), KeyID: "sender-key", Signature: "signed",
	}
	intentHash, err := intent.Hash()
	if err != nil {
		return decision.Intent{}, decision.Decision{}, err
	}
	result := decision.Decision{
		Version: decision.SchemaVersion, ID: "decision-governed-test", IntentHash: intentHash,
		TenantID: intent.TenantID, AgentID: intent.AgentID, Outcome: requester.outcome,
		PolicyRevision: 1, RevocationEpoch: 1, ProviderID: "authority-a", IssuedAt: now.Unix(), ExpiresAt: intent.ExpiresAt, KeyID: "authority-key", Signature: "signed",
	}
	if requester.outcome == decision.Deny {
		result.Reasons = []string{"policy:blocked"}
	}
	return intent, result, nil
}

func TestGovernedOutboundFrameRequestsExactActionAndPayload(t *testing.T) {
	requester := &fakeOutboundDecisionRequester{outcome: decision.Allow}
	sender := &governedOutboundSender{requester: requester, resource: "agent:finance/inbox"}
	frame := &dataexchange.Frame{Type: dataexchange.TypeJSON, Payload: []byte(`{"amount":25}`)}
	intent, result, err := sender.authorizeFrame(context.Background(), frame)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != decision.Allow || len(requester.calls) != 1 {
		t.Fatalf("result=%+v calls=%+v", result, requester.calls)
	}
	call := requester.calls[0]
	if call.action != "data.send.json" || call.resource != "agent:finance/inbox" {
		t.Fatalf("call=%+v", call)
	}
	if want := dataexchange.GovernedPayloadHash(frame.Type, frame.Filename, frame.Payload); call.payloadHash != want || intent.PayloadHash != want {
		t.Fatalf("payload hash=%q/%q, want %q", call.payloadHash, intent.PayloadHash, want)
	}
}

func TestGovernedOutboundDenyDoesNotPermitFrame(t *testing.T) {
	requester := &fakeOutboundDecisionRequester{outcome: decision.Deny}
	sender := &governedOutboundSender{requester: requester, resource: "agent:finance/inbox"}
	_, result, err := sender.authorizeFrame(context.Background(), &dataexchange.Frame{Type: dataexchange.TypeText, Payload: []byte("blocked")})
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("err=%v, want deny", err)
	}
	if result.Outcome != decision.Deny || len(requester.calls) != 1 {
		t.Fatalf("result=%+v calls=%+v", result, requester.calls)
	}
}

func TestCmdSendMessageWritesGovernedEnvelope(t *testing.T) {
	requester := &fakeOutboundDecisionRequester{outcome: decision.Allow}
	previous := loadOutboundDecisionRequester
	loadOutboundDecisionRequester = func(path string) (outboundDecisionRequester, error) {
		if path != "control.json" {
			t.Errorf("control path=%q", path)
		}
		return requester, nil
	}
	defer func() { loadOutboundDecisionRequester = previous }()

	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	out := captureStdout(t, func() {
		withJSON(func() {
			cmdSendMessage([]string{
				"0:0000.0000.002A", "--data", "govern this", "--enterprise-control", "control.json", "--governed-resource", "agent:finance/inbox",
			})
		})
	})
	if !strings.Contains(out, `"governed":true`) {
		t.Fatalf("governed result missing: %s", out)
	}
	payload := capturedDataExchangePayload(sd)
	if len(payload) == 0 {
		t.Fatal("no data-exchange frame captured")
	}
	frame, err := dataexchange.ReadFrame(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("read governed frame (%d bytes): %v", len(payload), err)
	}
	governed, err := dataexchange.DecodeGovernedFrame(frame)
	if err != nil {
		t.Fatalf("decode governed frame: %v", err)
	}
	if governed.Intent.Action != "data.send.text" || governed.Intent.Resource != "agent:finance/inbox" || string(governed.Payload) != "govern this" {
		t.Fatalf("governed=%+v", governed)
	}
}

func TestCmdSendFileWritesGovernedEnvelope(t *testing.T) {
	requester := &fakeOutboundDecisionRequester{outcome: decision.Allow}
	previous := loadOutboundDecisionRequester
	loadOutboundDecisionRequester = func(string) (outboundDecisionRequester, error) { return requester, nil }
	defer func() { loadOutboundDecisionRequester = previous }()

	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	path := t.TempDir() + "/budget.csv"
	if err := os.WriteFile(path, []byte("approved,file"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		withJSON(func() {
			cmdSendFile([]string{
				"0:0000.0000.002A", path, "--no-stream", "--enterprise-control", "control.json", "--governed-resource", "agent:finance/inbox",
			})
		})
	})
	if !strings.Contains(out, `"governed":true`) {
		t.Fatalf("governed result missing: %s", out)
	}
	frame, err := dataexchange.ReadFrame(bytes.NewReader(capturedDataExchangePayload(sd)))
	if err != nil {
		t.Fatalf("read governed file frame: %v", err)
	}
	governed, err := dataexchange.DecodeGovernedFrame(frame)
	if err != nil {
		t.Fatalf("decode governed file frame: %v", err)
	}
	if governed.Type != dataexchange.TypeFile || governed.Intent.Action != "file.share" || governed.Filename != "budget.csv" || string(governed.Payload) != "approved,file" {
		t.Fatalf("governed file=%+v", governed)
	}
}

func capturedDataExchangePayload(sd *streamDaemon) []byte {
	sd.capturedMu.Lock()
	defer sd.capturedMu.Unlock()
	for _, frames := range sd.captured {
		if len(frames) > 1 {
			var payload []byte
			for _, part := range frames {
				payload = append(payload, part...)
			}
			return payload
		}
	}
	return nil
}

func TestGovernedOutboundRequiresReceiverResource(t *testing.T) {
	previous := loadOutboundDecisionRequester
	defer func() { loadOutboundDecisionRequester = previous }()
	if _, err := governedOutboundFromFlags(map[string]string{"enterprise-control": "control.json"}); err == nil || !strings.Contains(err.Error(), "governed-resource") {
		t.Fatalf("err=%v, want receiver-resource requirement", err)
	}
}

func TestGovernedOutboundCanBeExplicitlyEnabledByEnvironment(t *testing.T) {
	t.Setenv("PILOT_ENTERPRISE_CONTROL", "control.json")
	t.Setenv("PILOT_GOVERNED_RESOURCE", "agent:finance/inbox")
	requester := &fakeOutboundDecisionRequester{outcome: decision.Allow}
	previous := loadOutboundDecisionRequester
	loadOutboundDecisionRequester = func(path string) (outboundDecisionRequester, error) {
		if path != "control.json" {
			t.Fatalf("path = %q", path)
		}
		return requester, nil
	}
	t.Cleanup(func() { loadOutboundDecisionRequester = previous })
	sender, err := governedOutboundFromFlags(map[string]string{})
	if err != nil || sender == nil || sender.resource != "agent:finance/inbox" {
		t.Fatalf("sender=%+v err=%v", sender, err)
	}
}

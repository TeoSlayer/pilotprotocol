// SPDX-License-Identifier: AGPL-3.0-or-later

package enterprisecontrol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/common/actionhook"
	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/dataexchange"
	"github.com/pilot-protocol/eventstream"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/actionregistry"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authorityhttp"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/decisionhttp"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/decisionpolicy"
)

type controlFixture struct {
	path            string
	rootPrivate     ed25519.PrivateKey
	intentPrivate   ed25519.PrivateKey
	decisionPrivate ed25519.PrivateKey
	now             time.Time
}

type testApprovalAuthority struct {
	mu              sync.Mutex
	decisionPrivate ed25519.PrivateKey
	decisionPublic  ed25519.PublicKey
	approvalPublic  ed25519.PublicKey
	record          decisionhttp.WorkflowRecord
}

func (authority *testApprovalAuthority) authorize(writer http.ResponseWriter, request *http.Request) {
	var intent decision.Intent
	if request.Method != http.MethodPost || json.NewDecoder(request.Body).Decode(&intent) != nil || intent.Validate() != nil {
		http.Error(writer, "invalid intent", http.StatusBadRequest)
		return
	}
	intentHash, err := intent.Hash()
	if err != nil {
		http.Error(writer, "invalid intent", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	expiresAt := now.Add(time.Minute).Unix()
	if intent.ExpiresAt < expiresAt {
		expiresAt = intent.ExpiresAt
	}
	result := decision.Decision{
		Version: decision.SchemaVersion, ID: "approval-" + intentHash[:32], IntentHash: intentHash,
		TenantID: intent.TenantID, AgentID: intent.AgentID, Outcome: decision.ApprovalRequired,
		Reasons: []string{"approval-plan:trust-review:1"}, PolicyRevision: 1, RevocationEpoch: 1,
		ProviderID: "test-authority", IssuedAt: now.Unix(), ExpiresAt: expiresAt, KeyID: "authority-key",
	}
	if err := result.Sign(authority.decisionPrivate); err != nil {
		http.Error(writer, "sign decision", http.StatusInternalServerError)
		return
	}
	writeApprovalTestJSON(writer, result)
}

func (authority *testApprovalAuthority) begin(writer http.ResponseWriter, request *http.Request) {
	var envelope decisionhttp.WorkflowBeginEnvelope
	if request.Method != http.MethodPost || json.NewDecoder(request.Body).Decode(&envelope) != nil {
		http.Error(writer, "invalid workflow", http.StatusBadRequest)
		return
	}
	createdAt := time.Unix(envelope.Initial.IssuedAt, 0)
	transaction, err := decision.NewApprovalTransaction(
		envelope.Intent, envelope.Initial, decision.Allow, nil, []string{"approval-key"}, 1,
		createdAt, createdAt.Add(time.Hour), "test-authority", "authority-key",
	)
	if err == nil {
		err = transaction.Sign(authority.decisionPrivate)
	}
	if err != nil {
		http.Error(writer, "invalid workflow", http.StatusUnprocessableEntity)
		return
	}
	authority.mu.Lock()
	authority.record = decisionhttp.WorkflowRecord{Transaction: transaction}
	record := authority.record
	authority.mu.Unlock()
	writeApprovalTestJSON(writer, record)
}

func (authority *testApprovalAuthority) status(transactionID string) (decisionhttp.WorkflowRecord, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.record.Transaction.ID == "" || authority.record.Transaction.ID != transactionID {
		return decisionhttp.WorkflowRecord{}, fmt.Errorf("workflow %s not found", transactionID)
	}
	return authority.record, nil
}

func (authority *testApprovalAuthority) statusHTTP(writer http.ResponseWriter, request *http.Request) {
	record, err := authority.status(request.URL.Query().Get("transaction_id"))
	if err != nil {
		http.Error(writer, "workflow not found", http.StatusNotFound)
		return
	}
	writeApprovalTestJSON(writer, record)
}

func (authority *testApprovalAuthority) vote(transactionID string, vote decision.ApprovalVote) (decisionhttp.WorkflowRecord, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.record.Transaction.ID == "" || authority.record.Transaction.ID != transactionID {
		return decisionhttp.WorkflowRecord{}, fmt.Errorf("workflow %s not found", transactionID)
	}
	certificate, err := decision.NewApprovalCertificate(
		authority.record.Transaction, []decision.ApprovalVote{vote},
		map[string]ed25519.PublicKey{"approval-key": authority.approvalPublic}, authority.decisionPublic,
		time.Now().UTC(), "test-authority", "authority-key",
	)
	if err == nil {
		err = certificate.Sign(authority.decisionPrivate)
	}
	if err != nil {
		return decisionhttp.WorkflowRecord{}, err
	}
	authority.record.Votes = []decision.ApprovalVote{vote}
	authority.record.Certificate = &certificate
	return authority.record, nil
}

func (authority *testApprovalAuthority) execute(writer http.ResponseWriter, request *http.Request) {
	var envelope decisionhttp.WorkflowExecuteEnvelope
	if request.Method != http.MethodPost || json.NewDecoder(request.Body).Decode(&envelope) != nil {
		http.Error(writer, "invalid execution", http.StatusBadRequest)
		return
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.record.Transaction.ID != envelope.TransactionID || authority.record.Certificate == nil {
		http.Error(writer, "workflow not approved", http.StatusConflict)
		return
	}
	if err := decision.VerifyApprovedExecution(
		envelope.Intent, authority.record.Transaction, *authority.record.Certificate, authority.record.Votes,
		map[string]ed25519.PublicKey{"approval-key": authority.approvalPublic}, authority.decisionPublic, time.Now().UTC(),
	); err != nil {
		http.Error(writer, "invalid approved execution", http.StatusConflict)
		return
	}
	intentHash, err := envelope.Intent.Hash()
	if err != nil {
		http.Error(writer, "invalid execution intent", http.StatusBadRequest)
		return
	}
	certificateHash, err := authority.record.Certificate.Hash()
	if err != nil {
		http.Error(writer, "invalid approval certificate", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	expiresAt := now.Add(time.Minute).Unix()
	if envelope.Intent.ExpiresAt < expiresAt {
		expiresAt = envelope.Intent.ExpiresAt
	}
	if authority.record.Certificate.ExpiresAt < expiresAt {
		expiresAt = authority.record.Certificate.ExpiresAt
	}
	result := decision.Decision{
		Version: decision.SchemaVersion, ID: "approved-" + intentHash[:32], IntentHash: intentHash,
		TenantID: envelope.Intent.TenantID, AgentID: envelope.Intent.AgentID, Outcome: authority.record.Certificate.Outcome,
		Reasons: []string{"workflow:" + certificateHash}, Constraints: append([]decision.Constraint(nil), authority.record.Certificate.Constraints...),
		PolicyRevision: authority.record.Certificate.PolicyRevision, RevocationEpoch: authority.record.Certificate.RevocationEpoch,
		ProviderID: "test-authority", IssuedAt: now.Unix(), ExpiresAt: expiresAt, KeyID: "authority-key",
	}
	if err := result.Sign(authority.decisionPrivate); err != nil {
		http.Error(writer, "sign approved decision", http.StatusInternalServerError)
		return
	}
	authority.record.ConsumedIntentID = intentHash
	authority.record.ConsumedDecision = &result
	writeApprovalTestJSON(writer, result)
}

func writeApprovalTestJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}

func newControlFixture(t *testing.T) controlFixture {
	t.Helper()
	directory := t.TempDir()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	intentPublic, intentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate intent key: %v", err)
	}
	decisionPublic, decisionPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate authority key: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	trust := authority.TrustBundle{
		Version: authority.SchemaVersion, TenantID: "tenant-a", Revision: 1, PolicyRevision: 1, RevocationEpoch: 1,
		IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(), RootKeyID: "root-key",
		Keys: []authority.AuthorityKey{
			{KeyID: "sender-key", AgentID: "sender-a", PublicKey: base64.StdEncoding.EncodeToString(intentPublic), Usages: []authority.KeyUsage{authority.UsageIntent}, NotBefore: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix()},
			{KeyID: "receiver-receipt-key", AgentID: "receiver-a", PublicKey: base64.StdEncoding.EncodeToString(intentPublic), Usages: []authority.KeyUsage{authority.UsageReceipt}, NotBefore: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix()},
			{KeyID: "authority-key", PublicKey: base64.StdEncoding.EncodeToString(decisionPublic), Usages: []authority.KeyUsage{authority.UsageDecision, authority.UsagePolicy, authority.UsageMandate}, NotBefore: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix()},
		},
	}
	if err := trust.Sign(rootPrivate); err != nil {
		t.Fatalf("sign trust: %v", err)
	}
	policyPayload, err := json.Marshal(decisionpolicy.Document{
		Version: 1, DefaultOutcome: decision.Deny,
		Rules: []decisionpolicy.Rule{
			{ID: "text-to-inbox", Agents: []string{"*"}, Actions: []string{"data.send.text"}, ResourcePrefixes: []string{"agent:receiver/inbox"}, Risks: allRisks(), Outcome: decision.Allow},
			{ID: "event-publication", Agents: []string{"*"}, Actions: []string{"event.publish"}, ResourcePrefixes: []string{"eventstream:"}, Risks: allRisks(), Outcome: decision.Allow},
		},
	})
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	policy := authority.NewPolicyBundle("tenant-a", 1, 1, now.Add(-time.Minute), now.Add(-time.Minute), now.Add(time.Hour), decisionpolicy.Engine, decisionpolicy.EngineVersion, decisionpolicy.ContentType, "authority-key", policyPayload)
	if err := policy.Sign(decisionPrivate); err != nil {
		t.Fatalf("sign policy: %v", err)
	}
	writeControlJSON(t, filepath.Join(directory, "trust.json"), trust)
	writeControlJSON(t, filepath.Join(directory, "policy.json"), policy)
	config := Config{
		TenantID: "tenant-a", RootKeyID: "root-key", RootPublicKey: base64.StdEncoding.EncodeToString(rootPublic),
		TrustBundlePath: "trust.json", PolicyBundlePath: "policy.json",
		DataExchange: &DataExchangeRule{RequireGoverned: true, Resource: "agent:receiver/inbox"},
		EventStream:  &EventStreamRule{RequireGoverned: true, ResourceTemplate: "eventstream:{topic}"},
	}
	path := filepath.Join(directory, "control.json")
	writeControlJSON(t, path, config)
	return controlFixture{path: path, rootPrivate: rootPrivate, intentPrivate: intentPrivate, decisionPrivate: decisionPrivate, now: now}
}

func allRisks() []decision.RiskClass {
	return []decision.RiskClass{decision.RiskLow, decision.RiskMedium, decision.RiskHigh, decision.RiskCritical}
}

func TestLocalActionControlIsExplicitAndEnforcesSignedPolicy(t *testing.T) {
	fixture := newControlFixture(t)
	config, err := readSecureJSON[Config](fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	config.ActionControl = &ActionControlConfig{
		Profile: actionregistry.Profile{Version: actionregistry.SchemaVersion, Mode: actionregistry.ModeLocalEnforce, Actions: []string{"trust.accept", "trust.auto_accept"}},
		AgentID: "sender-a", Risk: decision.RiskHigh,
	}
	writeControlJSON(t, fixture.path, config)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	hook := runtime.ActionHook()
	if hook == nil {
		t.Fatal("explicit local action profile did not attach a hook")
	}
	envelope, err := actionhook.NewEnvelope("trust.accept", "agent:42", actionhook.HashMetadata(map[string]string{"peer_node_id": "42"}), "pilot.handshake", map[string]string{"peer_node_id": "42"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	preflight, err := hook.BeforeAction(context.Background(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	if preflight.Outcome != decision.Deny || preflight.ObserveOnly {
		t.Fatalf("signed default-deny policy was not enforced: %+v", preflight)
	}

	unselected, err := actionhook.NewEnvelope("trust.request", "agent:42", envelope.PayloadHash, "pilot.handshake", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pass, err := hook.BeforeAction(context.Background(), unselected)
	if err != nil || !pass.ObserveOnly || pass.Outcome != decision.Allow {
		t.Fatalf("unselected action must remain unmanaged: preflight=%+v err=%v", pass, err)
	}
}

func TestAbsentOrOffActionControlDoesNotAttachHook(t *testing.T) {
	fixture := newControlFixture(t)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.ActionHook() != nil {
		t.Fatal("legacy attachment unexpectedly enabled action hooks")
	}
	config, err := readSecureJSON[Config](fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	config.ActionControl = &ActionControlConfig{Profile: actionregistry.Profile{Mode: actionregistry.ModeOff}}
	writeControlJSON(t, fixture.path, config)
	runtime, err = Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.ActionHook() != nil {
		t.Fatal("off action profile unexpectedly enabled hooks")
	}
}

func TestManagedActionApprovalSuspendsAndResumesExactlyOnce(t *testing.T) {
	fixture := newControlFixture(t)
	directory := filepath.Dir(fixture.path)
	approvalPublic, approvalPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := readSecureJSON[authority.TrustBundle](filepath.Join(directory, "trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	trust.Keys = append(trust.Keys, authority.AuthorityKey{
		KeyID: "approval-key", PublicKey: base64.StdEncoding.EncodeToString(approvalPublic), Usages: []authority.KeyUsage{authority.UsageApproval},
		NotBefore: fixture.now.Add(-time.Minute).Unix(), ExpiresAt: fixture.now.Add(time.Hour).Unix(),
	})
	if err := trust.Sign(fixture.rootPrivate); err != nil {
		t.Fatal(err)
	}
	writeControlJSON(t, filepath.Join(directory, "trust.json"), trust)

	policy, err := readSecureJSON[authority.PolicyBundle](filepath.Join(directory, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document decisionpolicy.Document
	if err := json.Unmarshal(policy.Payload, &document); err != nil {
		t.Fatal(err)
	}
	document.Rules = append([]decisionpolicy.Rule{{
		ID: "allow-trust-accept", Agents: []string{"sender-a"}, Actions: []string{"trust.accept"},
		ResourcePrefixes: []string{"agent:"}, Risks: allRisks(), Outcome: decision.ApprovalRequired,
		Approval: &decisionpolicy.ApprovalPlan{ApproverKeyIDs: []string{"approval-key"}, RequiredApprovals: 1, ValiditySeconds: 3600, Outcome: decision.Allow},
	}}, document.Rules...)
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	policy = authority.NewPolicyBundle("tenant-a", 1, 1, fixture.now.Add(-time.Minute), fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour), decisionpolicy.Engine, decisionpolicy.EngineVersion, decisionpolicy.ContentType, "authority-key", payload)
	if err := policy.Sign(fixture.decisionPrivate); err != nil {
		t.Fatal(err)
	}
	writeControlJSON(t, filepath.Join(directory, "policy.json"), policy)

	approvalAuthority := &testApprovalAuthority{
		decisionPrivate: fixture.decisionPrivate,
		decisionPublic:  fixture.decisionPrivate.Public().(ed25519.PublicKey),
		approvalPublic:  approvalPublic,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/authorize", approvalAuthority.authorize)
	mux.HandleFunc("/v1/workflow/begin", approvalAuthority.begin)
	mux.HandleFunc("/v1/workflow/execute", approvalAuthority.execute)
	mux.HandleFunc("/v1/workflow-status", approvalAuthority.statusHTTP)
	server := httptest.NewServer(mux)
	defer server.Close()

	seedPath := filepath.Join(directory, "sender-intent.seed")
	if err := os.WriteFile(seedPath, []byte(base64.StdEncoding.EncodeToString(fixture.intentPrivate.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	config := readControlConfig(t, fixture.path)
	config.OutboundDecisions = &OutboundDecisionConfig{
		AuthorityEndpoint: server.URL, AgentID: "sender-a", IntentKeyID: "sender-key", IntentSeedPath: filepath.Base(seedPath), Risk: decision.RiskHigh,
	}
	config.ActionControl = &ActionControlConfig{
		Profile: actionregistry.Profile{Version: actionregistry.SchemaVersion, Mode: actionregistry.ModeManagedEnforce, Actions: []string{"trust.accept"}},
		AgentID: "sender-a", ContinuationDirectory: "continuations",
	}
	writeControlJSON(t, fixture.path, config)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	newEnvelope := func() actionhook.Envelope {
		envelope, envelopeErr := actionhook.NewEnvelope("trust.accept", "agent:42", actionhook.HashMetadata(map[string]string{"peer_node_id": "42"}), "pilot.handshake", map[string]string{"peer_node_id": "42"}, time.Now())
		if envelopeErr != nil {
			t.Fatal(envelopeErr)
		}
		envelope.ResumeToken = "trust.accept:inbound:42"
		return envelope
	}

	initial, err := runtime.BeforeAction(context.Background(), newEnvelope())
	if err != nil || initial.Outcome != decision.ApprovalRequired || initial.Reference.ApprovalTransaction == "" {
		t.Fatalf("initial preflight=%+v err=%v", initial, err)
	}
	workflow, err := approvalAuthority.status(initial.Reference.ApprovalTransaction)
	if err != nil {
		t.Fatal(err)
	}
	vote, err := decision.NewApprovalVote(workflow.Transaction, "security-owner", decision.ApprovalVoteApprove, time.Now(), time.Now().Add(50*time.Minute), "11111111111111111111111111111111", "approval-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := vote.Sign(approvalPrivate); err != nil {
		t.Fatal(err)
	}
	if _, err := approvalAuthority.vote(workflow.Transaction.ID, vote); err != nil {
		t.Fatal(err)
	}

	resumedEnvelope := newEnvelope()
	resumed, err := runtime.BeforeAction(context.Background(), resumedEnvelope)
	if err != nil || resumed.Outcome != decision.Allow || resumed.Reference.ApprovalTransaction != workflow.Transaction.ID {
		t.Fatalf("resumed preflight=%+v err=%v", resumed, err)
	}
	if _, err := runtime.BeforeAction(context.Background(), newEnvelope()); err == nil || !strings.Contains(err.Error(), "already executing") {
		t.Fatalf("concurrent duplicate resume err=%v", err)
	}
	if err := runtime.AfterAction(context.Background(), resumedEnvelope, resumed, actionhook.ObservedResult{Status: actionhook.StatusSucceeded, ObservedAt: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}

	// A later intentional repetition gets a new approval transaction; the
	// successful historical record remains immutable evidence.
	repeated, err := runtime.BeforeAction(context.Background(), newEnvelope())
	if err != nil || repeated.Outcome != decision.ApprovalRequired || repeated.Reference.ApprovalTransaction == workflow.Transaction.ID {
		t.Fatalf("repeated action preflight=%+v err=%v", repeated, err)
	}
}

func readControlConfig(t *testing.T, path string) Config {
	t.Helper()
	config, err := readSecureJSON[Config](path)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestDisclosureRequirementNeedsGovernedBoundary(t *testing.T) {
	base := Config{
		TenantID: "tenant-a", RootKeyID: "root-key", RootPublicKey: "configured", TrustBundlePath: "trust.json", PolicyBundlePath: "policy.json",
		DataExchange: &DataExchangeRule{RequireDisclosure: true, Resource: "agent:receiver/inbox"},
	}
	if err := validateConfig(base); err == nil || !strings.Contains(err.Error(), "require_disclosure requires") {
		t.Fatalf("data disclosure without governed boundary err=%v", err)
	}
	base.DataExchange = &DataExchangeRule{RequireGoverned: true, RequireDisclosure: true, Resource: "agent:receiver/inbox"}
	if err := validateConfig(base); err != nil {
		t.Fatalf("data disclosure governed config err=%v", err)
	}
	base.DataExchange = nil
	base.EventStream = &EventStreamRule{RequireDisclosure: true, ResourceTemplate: "eventstream:{topic}"}
	if err := validateConfig(base); err == nil || !strings.Contains(err.Error(), "require_disclosure requires") {
		t.Fatalf("event disclosure without governed boundary err=%v", err)
	}
}

func TestTypedDisclosurePolicyIsEnforcedAtDataBoundary(t *testing.T) {
	fixture := newControlFixture(t)
	directory := filepath.Dir(fixture.path)
	payload, err := json.Marshal(decisionpolicy.Document{
		Version: 1, DefaultOutcome: decision.Deny,
		Rules: []decisionpolicy.Rule{{
			ID: "eu-finance-message", Agents: []string{"sender-a"}, Actions: []string{"data.send.text"}, ResourcePrefixes: []string{"agent:receiver/inbox"},
			Risks: []decision.RiskClass{decision.RiskHigh}, Outcome: decision.Allow,
			Disclosure: &decisionpolicy.DisclosureRule{
				LabelsAll: []string{"finance", "pii"}, ContentTypes: []string{"text/plain"}, Recipients: []string{"agent:receiver"},
				Purposes: []string{"inbox-delivery"}, Residencies: []string{"eu-west-1"},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := authority.NewPolicyBundle("tenant-a", 1, 1, fixture.now.Add(-time.Minute), fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour), decisionpolicy.Engine, decisionpolicy.EngineVersion, decisionpolicy.ContentType, "authority-key", payload)
	if err := policy.Sign(fixture.decisionPrivate); err != nil {
		t.Fatal(err)
	}
	writeControlJSON(t, filepath.Join(directory, "policy.json"), policy)
	config, err := readSecureJSON[Config](fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	config.DataExchange.RequireDisclosure = true
	writeControlJSON(t, fixture.path, config)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	serviceConfig := dataexchange.ServiceConfig{}
	if err := runtime.ApplyDataExchange(&serviceConfig); err != nil {
		t.Fatal(err)
	}
	frame := &dataexchange.Frame{Type: dataexchange.TypeText, Payload: []byte("classified invoice")}
	build := func(residency, suffix string) dataexchange.GovernedFrame {
		disclosure := decision.DisclosureBinding{
			Version: decision.DisclosureBindingVersion, ContentHash: decision.HashPayload(frame.Payload), DeclaredBytes: uint64(len(frame.Payload)),
			ContentType: "text/plain", Labels: []string{"finance", "pii"}, Recipient: "agent:receiver", Purpose: "inbox-delivery", Residency: residency,
		}
		hash, hashErr := disclosure.Hash()
		if hashErr != nil {
			t.Fatal(hashErr)
		}
		nonce, nonceErr := decision.NewNonce()
		if nonceErr != nil {
			t.Fatal(nonceErr)
		}
		intent := decision.Intent{
			Version: decision.SchemaVersion, ID: "typed-data-intent-" + suffix, TenantID: "tenant-a", AgentID: "sender-a",
			Action: "data.send.text", Resource: "agent:receiver/inbox", Audience: disclosure.Recipient, Purpose: disclosure.Purpose,
			PayloadHash: hash, Risk: decision.RiskHigh, IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(time.Minute).Unix(), Nonce: nonce, KeyID: "sender-key",
		}
		if signErr := intent.Sign(fixture.intentPrivate); signErr != nil {
			t.Fatal(signErr)
		}
		intentHash, hashErr := intent.Hash()
		if hashErr != nil {
			t.Fatal(hashErr)
		}
		result := decision.Decision{
			Version: decision.SchemaVersion, ID: "typed-data-decision-" + suffix, IntentHash: intentHash, TenantID: intent.TenantID, AgentID: intent.AgentID,
			Outcome: decision.Allow, PolicyRevision: 1, RevocationEpoch: 1, ProviderID: "authority-a", IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(time.Minute).Unix(), KeyID: "authority-key",
		}
		if signErr := result.Sign(fixture.decisionPrivate); signErr != nil {
			t.Fatal(signErr)
		}
		governed, buildErr := dataexchange.NewGovernedFrameWithDisclosure(frame, intent, result, disclosure)
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		return governed
	}
	if err := serviceConfig.GovernedVerifier.VerifyGovernedFrame(context.Background(), coreapi.Addr{}, build("eu-west-1", "eu")); err != nil {
		t.Fatalf("approved EU disclosure rejected: %v", err)
	}
	if err := serviceConfig.GovernedVerifier.VerifyGovernedFrame(context.Background(), coreapi.Addr{}, build("us-east-1", "us")); err == nil || !strings.Contains(err.Error(), "expands local deny") {
		t.Fatalf("US disclosure expanded local policy: %v", err)
	}
}

func writeControlJSON(t *testing.T, path string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestLoadAttachesSignedControlsAndEnforcesLocalPolicy(t *testing.T) {
	fixture := newControlFixture(t)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatalf("load control: %v", err)
	}
	dataConfig := dataexchange.ServiceConfig{}
	if err := runtime.ApplyDataExchange(&dataConfig); err != nil {
		t.Fatalf("apply data exchange: %v", err)
	}
	if !dataConfig.RequireGoverned || dataConfig.GovernedVerifier == nil || dataConfig.GovernedStreamVerifier == nil {
		t.Fatalf("data exchange was not configured as a required governed receiver")
	}
	eventService := eventstream.NewService()
	if err := runtime.ApplyEventStream(eventService); err != nil {
		t.Fatalf("apply event stream: %v", err)
	}
	state, err := readSecureJSON[controlState](filepath.Join(filepath.Dir(fixture.path), ".enterprise-control-state.json"))
	if err != nil || state.TenantID != "tenant-a" || state.TrustRevision != 1 || state.TrustPolicyRevision != 1 || state.TrustRevocationEpoch != 1 || state.PolicyRevision != 1 || state.PolicyRevocationEpoch != 1 {
		t.Fatalf("persisted state = %+v, err=%v", state, err)
	}

	allowed := signedFrameForControl(t, fixture, &dataexchange.Frame{Type: dataexchange.TypeText, Payload: []byte("approved")}, 1)
	if err := dataConfig.GovernedVerifier.VerifyGovernedFrame(context.Background(), coreapi.Addr{}, allowed); err != nil {
		t.Fatalf("configured verifier rejected allowed text: %v", err)
	}
	denied := signedFrameForControl(t, fixture, &dataexchange.Frame{Type: dataexchange.TypeBinary, Payload: []byte("blocked")}, 1)
	if err := dataConfig.GovernedVerifier.VerifyGovernedFrame(context.Background(), coreapi.Addr{}, denied); err == nil || !strings.Contains(err.Error(), "local authority ceiling") {
		t.Fatalf("configured verifier error = %v, want local policy denial", err)
	}
	writeControlRevision(t, fixture, 2, true)
	if err := runtime.Reload(); err != nil {
		t.Fatalf("reload signed state: %v", err)
	}
	allowedAfterReload := signedFrameForControl(t, fixture, &dataexchange.Frame{Type: dataexchange.TypeBinary, Payload: []byte("now-approved")}, 2)
	if err := dataConfig.GovernedVerifier.VerifyGovernedFrame(context.Background(), coreapi.Addr{}, allowedAfterReload); err != nil {
		t.Fatalf("configured verifier rejected policy added by reload: %v", err)
	}
}

func TestMandateAttachmentRequiresAValidBoundMandateAtDataBoundary(t *testing.T) {
	fixture := newControlFixture(t)
	mandate := configureControlMandate(t, fixture)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	dataConfig := dataexchange.ServiceConfig{}
	if err := runtime.ApplyDataExchange(&dataConfig); err != nil {
		t.Fatal(err)
	}
	missing := signedFrameForControl(t, fixture, &dataexchange.Frame{Type: dataexchange.TypeText, Payload: []byte("without mandate")}, 1)
	if err := dataConfig.GovernedVerifier.VerifyGovernedFrame(context.Background(), coreapi.Addr{}, missing); err == nil || !strings.Contains(err.Error(), "mandate is required") {
		t.Fatalf("missing mandate error=%v", err)
	}
	allowed := signedMandatedFrameForControl(t, fixture, mandate, &dataexchange.Frame{Type: dataexchange.TypeText, Payload: []byte("with mandate")}, 1)
	if err := dataConfig.GovernedVerifier.VerifyGovernedFrame(context.Background(), coreapi.Addr{}, allowed); err != nil {
		t.Fatalf("valid mandated frame rejected: %v", err)
	}
}

func TestMandateAttachmentRequiresAValidBoundMandateAtEventBoundary(t *testing.T) {
	fixture := newControlFixture(t)
	mandate := configureEventControlMandate(t, fixture)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	service := eventstream.NewService()
	if err := runtime.ApplyEventStream(service); err != nil {
		t.Fatal(err)
	}
	// ApplyEventStream attaches this same runtime enforcer to the broker. Test
	// the public verifier here so the test does not need to expose broker
	// internals merely to demonstrate the mandatory local ceiling.
	verifier := eventstream.DecisionEventVerifier{
		Enforcer: runtime.enforcer,
		Resource: func(_ coreapi.Addr, event *eventstream.Event) string {
			return strings.Replace(runtime.eventTemplate, "{topic}", event.Topic, 1)
		},
	}
	event := &eventstream.Event{Topic: "finance.orders", Payload: []byte("approved")}
	missing := signedEventForControl(t, fixture, nil, event, 1)
	if err := verifier.VerifyGovernedEvent(context.Background(), coreapi.Addr{}, missing); err == nil || !strings.Contains(err.Error(), "mandate is required") {
		t.Fatalf("missing event mandate error=%v", err)
	}
	allowed := signedEventForControl(t, fixture, &mandate, event, 1)
	if err := verifier.VerifyGovernedEvent(context.Background(), coreapi.Addr{}, allowed); err != nil {
		t.Fatalf("valid mandated event rejected: %v", err)
	}
}

func TestMandateBundleRefreshAtomicallyRevokesAndRejectsRollback(t *testing.T) {
	fixture := newControlFixture(t)
	directory := filepath.Dir(fixture.path)
	mandate := decision.Mandate{
		Version: decision.SchemaVersion, ID: "mandate-refresh-1", TenantID: "tenant-a", SubjectAgentID: "sender-a",
		Actions: []string{"data.send.text"}, ResourcePrefixes: []string{"agent:receiver/inbox"}, Audience: "agent:receiver", Purpose: "inbox-delivery",
		RevocationEpoch: 1, IssuedAt: fixture.now.Add(-time.Minute).Unix(), ExpiresAt: fixture.now.Add(time.Hour).Unix(), KeyID: "authority-key",
	}
	if err := mandate.Sign(fixture.decisionPrivate); err != nil {
		t.Fatal(err)
	}
	bootstrap := decision.MandateBundle{
		Version: decision.SchemaVersion, TenantID: "tenant-a", SubjectAgentID: "sender-a", Revision: 1, RevocationEpoch: 1,
		Mandates: []decision.Mandate{mandate}, IssuedAt: fixture.now.Add(-time.Minute).Unix(), ExpiresAt: fixture.now.Add(time.Hour).Unix(), KeyID: "authority-key",
	}
	if err := bootstrap.Sign(fixture.decisionPrivate); err != nil {
		t.Fatal(err)
	}
	removal := decision.MandateBundle{
		Version: decision.SchemaVersion, TenantID: "tenant-a", SubjectAgentID: "sender-a", Revision: 2, RevocationEpoch: 1,
		IssuedAt: fixture.now.Add(-time.Minute).Unix(), ExpiresAt: fixture.now.Add(time.Hour).Unix(), KeyID: "authority-key",
	}
	if err := removal.Sign(fixture.decisionPrivate); err != nil {
		t.Fatal(err)
	}
	remoteBundle := removal
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/trust-current":
			trust, err := readSecureJSON[authority.TrustBundle](filepath.Join(directory, "trust.json"))
			if err != nil {
				t.Errorf("read trust: %v", err)
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(writer).Encode(trust)
		case "/v1/policy-candidate", "/v1/policy-current":
			writer.WriteHeader(http.StatusNoContent)
		case "/v1/mandates-current":
			if request.URL.Query().Get("tenant_id") != "tenant-a" || request.URL.Query().Get("agent_id") != "sender-a" {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(writer).Encode(remoteBundle)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	seed := base64.StdEncoding.EncodeToString(fixture.intentPrivate.Seed())
	if err := os.WriteFile(filepath.Join(directory, "ack.seed"), []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	writeControlJSON(t, filepath.Join(directory, "mandate.bundle.json"), bootstrap)
	config, err := readSecureJSON[Config](fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	config.Mandates = &MandateConfig{BundlePath: "mandate.bundle.json", AgentID: "sender-a"}
	config.Rollout = &RolloutConfig{AuthorityEndpoint: server.URL, AgentID: "sender-a", AcknowledgementKeyID: "sender-key", AcknowledgementSeedPath: "ack.seed"}
	writeControlJSON(t, fixture.path, config)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	dataConfig := dataexchange.ServiceConfig{}
	if err := runtime.ApplyDataExchange(&dataConfig); err != nil {
		t.Fatal(err)
	}
	allowed := signedMandatedFrameForControl(t, fixture, mandate, &dataexchange.Frame{Type: dataexchange.TypeText, Payload: []byte("before revocation")}, 1)
	if err := dataConfig.GovernedVerifier.VerifyGovernedFrame(context.Background(), coreapi.Addr{}, allowed); err != nil {
		t.Fatalf("bootstrap mandate rejected: %v", err)
	}
	if err := runtime.RefreshRollout(context.Background()); err != nil {
		t.Fatalf("refresh remote removal: %v", err)
	}
	if err := dataConfig.GovernedVerifier.VerifyGovernedFrame(context.Background(), coreapi.Addr{}, allowed); err == nil {
		t.Fatal("removed mandate still authorized data exchange")
	}
	state, err := readSecureJSON[controlState](filepath.Join(directory, ".enterprise-control-state.json"))
	if err != nil || state.MandateRevision != removal.Revision {
		t.Fatalf("mandate floor=%+v err=%v", state, err)
	}
	remoteBundle = bootstrap
	if err := runtime.RefreshRollout(context.Background()); err == nil || !strings.Contains(err.Error(), "rollback floor") {
		t.Fatalf("rollback bundle error=%v", err)
	}
	restarted, err := Load(fixture.path)
	if err != nil {
		t.Fatalf("restart after removal: %v", err)
	}
	restartedData := dataexchange.ServiceConfig{}
	if err := restarted.ApplyDataExchange(&restartedData); err != nil {
		t.Fatal(err)
	}
	if err := restartedData.GovernedVerifier.VerifyGovernedFrame(context.Background(), coreapi.Addr{}, allowed); err == nil {
		t.Fatal("restart restored a revoked mandate")
	}
}

func TestOutboundDecisionCreatesFreshSignedIntentAndVerifiesAuthorityResponse(t *testing.T) {
	fixture := newControlFixture(t)
	directory := filepath.Dir(fixture.path)
	seedPath := filepath.Join(directory, "sender-intent.seed")
	if err := os.WriteFile(seedPath, []byte(base64.StdEncoding.EncodeToString(fixture.intentPrivate.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/authorize" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		var intent decision.Intent
		if err := json.NewDecoder(request.Body).Decode(&intent); err != nil {
			t.Errorf("decode intent: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := intent.Verify(fixture.intentPrivate.Public().(ed25519.PublicKey), time.Now()); err != nil {
			t.Errorf("intent signature: %v", err)
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		intentHash, err := intent.Hash()
		if err != nil {
			t.Errorf("hash intent: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		result := decision.Decision{
			Version: decision.SchemaVersion, ID: "decision-outbound-1", IntentHash: intentHash,
			TenantID: intent.TenantID, AgentID: intent.AgentID, Outcome: decision.Allow,
			PolicyRevision: 1, RevocationEpoch: 1, ProviderID: "self-hosted", IssuedAt: time.Now().Unix(), ExpiresAt: intent.ExpiresAt, KeyID: "authority-key",
		}
		if err := result.Sign(fixture.decisionPrivate); err != nil {
			t.Errorf("sign decision: %v", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(writer).Encode(result)
	}))
	defer server.Close()
	configureOutboundDecision(t, fixture, server.URL, filepath.Base(seedPath), decision.RiskHigh)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	frame := &dataexchange.Frame{Type: dataexchange.TypeText, Payload: []byte("approved")}
	intent, result, err := runtime.AuthorizeOutbound(context.Background(), "data.send.text", "agent:receiver/inbox", dataexchange.GovernedPayloadHash(frame.Type, frame.Filename, frame.Payload))
	if err != nil {
		t.Fatalf("authorize outbound: %v", err)
	}
	if intent.AgentID != "sender-a" || intent.KeyID != "sender-key" || intent.Risk != decision.RiskHigh || result.Outcome != decision.Allow {
		t.Fatalf("intent=%+v decision=%+v", intent, result)
	}
}

func TestOutboundDisclosureUsesTypedAuthorityEnvelope(t *testing.T) {
	fixture := newControlFixture(t)
	mandate := configureControlMandate(t, fixture)
	directory := filepath.Dir(fixture.path)
	seedPath := filepath.Join(directory, "sender-intent.seed")
	if err := os.WriteFile(seedPath, []byte(base64.StdEncoding.EncodeToString(fixture.intentPrivate.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	disclosure := decision.DisclosureBinding{
		Version: decision.DisclosureBindingVersion, ContentHash: decision.HashPayload([]byte("approved")), DeclaredBytes: 8,
		ContentType: "text/plain", Labels: []string{"confidential", "pii"}, Recipient: mandate.Audience,
		Purpose: mandate.Purpose, Residency: "eu-west-1",
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var received struct {
			Intent     decision.Intent             `json:"intent"`
			Disclosure *decision.DisclosureBinding `json:"disclosure"`
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil || received.Disclosure == nil {
			t.Errorf("decode disclosure envelope: %v received=%+v", err, received)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := received.Disclosure.VerifyIntent(received.Intent); err != nil || received.Disclosure.Residency != disclosure.Residency {
			t.Errorf("disclosure binding: %v received=%+v", err, received)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		intentHash, _ := received.Intent.Hash()
		result := decision.Decision{
			Version: decision.SchemaVersion, ID: "decision-outbound-disclosure", IntentHash: intentHash,
			TenantID: received.Intent.TenantID, AgentID: received.Intent.AgentID, Outcome: decision.Allow,
			PolicyRevision: 1, RevocationEpoch: 1, ProviderID: "self-hosted", IssuedAt: time.Now().Unix(), ExpiresAt: received.Intent.ExpiresAt, KeyID: "authority-key",
		}
		if err := result.Sign(fixture.decisionPrivate); err != nil {
			t.Errorf("sign decision: %v", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(writer).Encode(result)
	}))
	defer server.Close()
	configureOutboundDecision(t, fixture, server.URL, filepath.Base(seedPath), decision.RiskHigh)
	config, err := readSecureJSON[Config](fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	config.OutboundDecisions.MandateID = mandate.ID
	config.OutboundDecisions.Audience = disclosure.Recipient
	config.OutboundDecisions.Purpose = disclosure.Purpose
	config.OutboundDecisions.EvaluatorResidency = disclosure.Residency
	writeControlJSON(t, fixture.path, config)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	intent, result, err := runtime.AuthorizeOutboundDisclosure(context.Background(), "data.send.text", "agent:receiver/inbox", disclosure)
	if err != nil {
		t.Fatal(err)
	}
	if intent.PayloadHash == decision.HashPayload([]byte("approved")) || result.Outcome != decision.Allow {
		t.Fatalf("outbound disclosure intent=%+v result=%+v", intent, result)
	}
	wrongRecipient := disclosure
	wrongRecipient.Recipient = "agent:other"
	if _, _, err := runtime.AuthorizeOutboundDisclosure(context.Background(), "data.send.text", "agent:receiver/inbox", wrongRecipient); err == nil || !strings.Contains(err.Error(), "must match attachment") {
		t.Fatalf("recipient mismatch accepted: %v", err)
	}
	wrongResidency := disclosure
	wrongResidency.Residency = "us-east-1"
	if _, _, err := runtime.AuthorizeOutboundDisclosure(context.Background(), "data.send.text", "agent:receiver/inbox", wrongResidency); err == nil || !strings.Contains(err.Error(), "does not match configured evaluator") {
		t.Fatalf("evaluator residency mismatch accepted: %v", err)
	}
}

func TestOutboundDisclosureVerifiesIndependentEvaluatorAttestation(t *testing.T) {
	fixture := newControlFixture(t)
	mandate := configureControlMandate(t, fixture)
	directory := filepath.Dir(fixture.path)
	seedPath := filepath.Join(directory, "sender-intent.seed")
	if err := os.WriteFile(seedPath, []byte(base64.StdEncoding.EncodeToString(fixture.intentPrivate.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	attestorPublic, attestorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	disclosure := decision.DisclosureBinding{
		Version: decision.DisclosureBindingVersion, ContentHash: decision.HashPayload([]byte("approved")), DeclaredBytes: 8,
		ContentType: "text/plain", Labels: []string{"confidential", "pii"}, Recipient: mandate.Audience,
		Purpose: mandate.Purpose, Residency: "eu-west-1",
	}
	var attestationRequests atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == decisionhttp.EvaluatorAttestationPath {
			attestationRequests.Add(1)
			now := time.Now().UTC().Truncate(time.Second)
			attestation := decision.EvaluatorAttestation{
				Version: decision.EvaluatorAttestationVersion, Endpoint: server.URL, Residency: disclosure.Residency,
				AttestorID: "regional-attestor", EvidenceHash: strings.Repeat("a", 64), IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), KeyID: "region-key-1",
			}
			if err := attestation.Sign(attestorPrivate); err != nil {
				t.Errorf("sign evaluator attestation: %v", err)
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(writer).Encode(attestation)
			return
		}
		if request.URL.Path != "/v1/authorize" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		var received struct {
			Intent     decision.Intent             `json:"intent"`
			Disclosure *decision.DisclosureBinding `json:"disclosure"`
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil || received.Disclosure == nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		intentHash, _ := received.Intent.Hash()
		result := decision.Decision{
			Version: decision.SchemaVersion, ID: "decision-outbound-attested", IntentHash: intentHash,
			TenantID: received.Intent.TenantID, AgentID: received.Intent.AgentID, Outcome: decision.Allow,
			PolicyRevision: 1, RevocationEpoch: 1, ProviderID: "self-hosted", IssuedAt: time.Now().Unix(), ExpiresAt: received.Intent.ExpiresAt, KeyID: "authority-key",
		}
		if err := result.Sign(fixture.decisionPrivate); err != nil {
			t.Errorf("sign decision: %v", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(writer).Encode(result)
	}))
	defer server.Close()
	configureOutboundDecision(t, fixture, server.URL, filepath.Base(seedPath), decision.RiskHigh)
	config, err := readSecureJSON[Config](fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	config.OutboundDecisions.MandateID = mandate.ID
	config.OutboundDecisions.Audience = disclosure.Recipient
	config.OutboundDecisions.Purpose = disclosure.Purpose
	config.OutboundDecisions.EvaluatorResidency = disclosure.Residency
	config.OutboundDecisions.EvaluatorAttestation = &EvaluatorAttestationConfig{
		AttestorID: "regional-attestor", KeyID: "region-key-1", PublicKey: base64.StdEncoding.EncodeToString(attestorPublic),
	}
	writeControlJSON(t, fixture.path, config)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, result, err := runtime.AuthorizeOutboundDisclosure(context.Background(), "data.send.text", "agent:receiver/inbox", disclosure); err != nil || result.Outcome != decision.Allow {
			t.Fatalf("attested outbound authorization attempt=%d result=%+v err=%v", attempt, result, err)
		}
	}
	if requests := attestationRequests.Load(); requests != 1 {
		t.Fatalf("attestation fetches=%d want 1 cached short-lived assertion", requests)
	}
}

func TestOutboundDecisionReturnsSignedDenyWithoutAuthorizingSideEffect(t *testing.T) {
	fixture := newControlFixture(t)
	directory := filepath.Dir(fixture.path)
	seedPath := filepath.Join(directory, "sender-intent.seed")
	if err := os.WriteFile(seedPath, []byte(base64.StdEncoding.EncodeToString(fixture.intentPrivate.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var intent decision.Intent
		if err := json.NewDecoder(request.Body).Decode(&intent); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		intentHash, _ := intent.Hash()
		result := decision.Decision{
			Version: decision.SchemaVersion, ID: "decision-outbound-deny", IntentHash: intentHash,
			TenantID: intent.TenantID, AgentID: intent.AgentID, Outcome: decision.Deny, Reasons: []string{"policy:blocked"},
			PolicyRevision: 1, RevocationEpoch: 1, ProviderID: "self-hosted", IssuedAt: time.Now().Unix(), ExpiresAt: intent.ExpiresAt, KeyID: "authority-key",
		}
		if err := result.Sign(fixture.decisionPrivate); err != nil {
			t.Errorf("sign decision: %v", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(writer).Encode(result)
	}))
	defer server.Close()
	configureOutboundDecision(t, fixture, server.URL, filepath.Base(seedPath), decision.RiskHigh)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	_, result, err := runtime.AuthorizeOutbound(context.Background(), "data.send.text", "agent:receiver/inbox", decision.HashPayload([]byte("blocked")))
	if err != nil {
		t.Fatalf("verify deny: %v", err)
	}
	if result.Outcome != decision.Deny || len(result.Reasons) != 1 {
		t.Fatalf("deny=%+v", result)
	}
}

func TestOutboundDecisionCarriesAttachmentBoundMandate(t *testing.T) {
	fixture := newControlFixture(t)
	mandate := configureControlMandate(t, fixture)
	directory := filepath.Dir(fixture.path)
	seedPath := filepath.Join(directory, "sender-intent.seed")
	if err := os.WriteFile(seedPath, []byte(base64.StdEncoding.EncodeToString(fixture.intentPrivate.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var intent decision.Intent
		if err := json.NewDecoder(request.Body).Decode(&intent); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if intent.MandateID != mandate.ID || intent.Audience != mandate.Audience || intent.Purpose != mandate.Purpose {
			t.Errorf("delegated intent=%+v", intent)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		intentHash, _ := intent.Hash()
		result := decision.Decision{
			Version: decision.SchemaVersion, ID: "decision-outbound-mandate", IntentHash: intentHash, TenantID: intent.TenantID, AgentID: intent.AgentID,
			Outcome: decision.Allow, PolicyRevision: 1, RevocationEpoch: 1, ProviderID: "self-hosted", IssuedAt: time.Now().Unix(), ExpiresAt: intent.ExpiresAt, KeyID: "authority-key",
		}
		if err := result.Sign(fixture.decisionPrivate); err != nil {
			t.Errorf("sign decision: %v", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(writer).Encode(result)
	}))
	defer server.Close()
	configureOutboundDecision(t, fixture, server.URL, filepath.Base(seedPath), decision.RiskHigh)
	config, err := readSecureJSON[Config](fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	config.OutboundDecisions.MandateID = mandate.ID
	config.OutboundDecisions.Audience = mandate.Audience
	config.OutboundDecisions.Purpose = mandate.Purpose
	writeControlJSON(t, fixture.path, config)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	intent, result, err := runtime.AuthorizeOutbound(context.Background(), "data.send.text", "agent:receiver/inbox", decision.HashPayload([]byte("delegated message")))
	if err != nil {
		t.Fatal(err)
	}
	if intent.MandateID != mandate.ID || result.Outcome != decision.Allow {
		t.Fatalf("intent=%+v result=%+v", intent, result)
	}
}

func configureOutboundDecision(t *testing.T, fixture controlFixture, endpoint, seedPath string, risk decision.RiskClass) {
	t.Helper()
	config, err := readSecureJSON[Config](fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	config.OutboundDecisions = &OutboundDecisionConfig{
		AuthorityEndpoint: endpoint, AgentID: "sender-a", IntentKeyID: "sender-key", IntentSeedPath: seedPath, Risk: risk,
	}
	writeControlJSON(t, fixture.path, config)
}

func TestControlStateRejectsTrustAndPolicyRollback(t *testing.T) {
	state := controlState{TenantID: "tenant-a", TrustRevision: 4, TrustPolicyRevision: 6, TrustRevocationEpoch: 3, PolicyRevision: 8, PolicyRevocationEpoch: 3}
	trust := authority.TrustBundle{Revision: 4, PolicyRevision: 6, RevocationEpoch: 3}
	policy := authority.PolicyBundle{Revision: 8, RevocationEpoch: 3}
	if err := state.accepts("tenant-a", trust, policy); err != nil {
		t.Fatalf("current state rejected: %v", err)
	}
	trust.Revision = 3
	if err := state.accepts("tenant-a", trust, policy); err == nil || !strings.Contains(err.Error(), "rollback floor") {
		t.Fatalf("trust rollback error = %v", err)
	}
	trust.Revision = 4
	policy.Revision = 7
	if err := state.accepts("tenant-a", trust, policy); err == nil || !strings.Contains(err.Error(), "rollback floor") {
		t.Fatalf("policy rollback error = %v", err)
	}
}

func TestControlStateRejectsMandateBundleEpochRollback(t *testing.T) {
	state := controlState{TenantID: "tenant-a", MandateRevision: 2, MandateRevocationEpoch: 3, MandateHash: strings.Repeat("a", 64)}
	bundle := decision.MandateBundle{TenantID: "tenant-a", SubjectAgentID: "sender-a", Revision: 3, RevocationEpoch: 2}
	if err := state.acceptsMandate(bundle, strings.Repeat("b", 64)); err == nil || !strings.Contains(err.Error(), "rollback floor") {
		t.Fatalf("mandate epoch rollback error=%v", err)
	}
}

func TestRequireEnabledServiceGatesRejectsOmittedOrPermissiveRules(t *testing.T) {
	if err := (*Runtime)(nil).RequireEnabledServiceGates(true, false); err == nil || !strings.Contains(err.Error(), "data exchange") {
		t.Fatalf("nil runtime error = %v, want data-exchange gate failure", err)
	}
	runtime := &Runtime{dataEnabled: true, dataRequired: true, eventEnabled: true, eventRequired: false, receipts: &governedReceiptSigner{}}
	if err := runtime.RequireEnabledServiceGates(true, true); err == nil || !strings.Contains(err.Error(), "event stream") {
		t.Fatalf("permissive event rule error = %v, want event-stream gate failure", err)
	}
	if err := runtime.RequireEnabledServiceGates(true, false); err != nil {
		t.Fatalf("required enabled data exchange rejected: %v", err)
	}
}

func TestReceiptAttachmentSignsDurableGovernedTransportEvidence(t *testing.T) {
	fixture := newControlFixture(t)
	directory := filepath.Dir(fixture.path)
	var exported int
	exportServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var receipt decision.Receipt
		if err := json.NewDecoder(request.Body).Decode(&receipt); err != nil || request.Header.Get("Idempotency-Key") != receipt.ID {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		exported++
		_ = json.NewEncoder(writer).Encode(map[string]string{"accepted_receipt_id": receipt.ID})
	}))
	defer exportServer.Close()
	seed := base64.StdEncoding.EncodeToString(fixture.intentPrivate.Seed())
	if err := os.WriteFile(filepath.Join(directory, "receipt.seed"), []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := readSecureJSON[Config](fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	config.Receipts = &ReceiptConfig{
		AgentID: "receiver-a", KeyID: "receiver-receipt-key", SeedPath: "receipt.seed", JournalPath: "receipts.jsonl",
		ExportEndpoint: exportServer.URL, ExportAcknowledgementPath: "receipt-export.acks",
	}
	writeControlJSON(t, fixture.path, config)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatalf("load receipt attachment: %v", err)
	}
	dataConfig := dataexchange.ServiceConfig{}
	if err := runtime.ApplyDataExchange(&dataConfig); err != nil {
		t.Fatal(err)
	}
	if !dataConfig.RequireGovernedReceipts || dataConfig.GovernedReceiptRecorder == nil {
		t.Fatal("enterprise data exchange was not configured with a required receipt recorder")
	}
	governed := signedFrameForControl(t, fixture, &dataexchange.Frame{Type: dataexchange.TypeText, Payload: []byte("receipted")}, 1)
	if err := dataConfig.GovernedReceiptRecorder.RecordGovernedReceipt(context.Background(), governed.Intent, governed.Decision); err != nil {
		t.Fatalf("record governed receipt: %v", err)
	}
	if !runtime.HasReceiptExport() || runtime.ReceiptExportInterval() != 30*time.Second {
		t.Fatalf("receipt export configuration was not retained")
	}
	if err := runtime.ExportReceiptsOnce(context.Background()); err != nil || exported != 1 {
		t.Fatalf("export governed receipt err=%v exported=%d", err, exported)
	}
	contents, err := os.ReadFile(filepath.Join(directory, "receipts.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var receipt decision.Receipt
	if err := json.Unmarshal(contents, &receipt); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if receipt.EnforcementPoint != "dataexchange" || receipt.KeyID != "receiver-receipt-key" || receipt.Result != decision.Enforced {
		t.Fatalf("receipt = %+v", receipt)
	}
	if err := receipt.VerifyForEnforcer(governed.Intent, governed.Decision, "receiver-a", fixture.intentPrivate.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("verify governed receipt: %v", err)
	}
	disclosure := decision.DisclosureBinding{
		Version: decision.DisclosureBindingVersion, ContentHash: decision.HashPayload([]byte("classified")), DeclaredBytes: 10,
		ContentType: "text/plain", Labels: []string{"confidential", "pii"}, Recipient: "agent:receiver", Purpose: "inbox-delivery", Residency: "eu-west-1",
	}
	disclosureHash, err := disclosure.Hash()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := decision.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	disclosureIntent := decision.Intent{
		Version: decision.SchemaVersion, ID: "disclosure-receipt-intent", TenantID: "tenant-a", AgentID: "sender-a", Action: "data.send.text", Resource: "agent:receiver/inbox",
		Audience: disclosure.Recipient, Purpose: disclosure.Purpose, PayloadHash: disclosureHash, Risk: decision.RiskHigh,
		IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(time.Minute).Unix(), Nonce: nonce, KeyID: "sender-key",
	}
	if err := disclosureIntent.Sign(fixture.intentPrivate); err != nil {
		t.Fatal(err)
	}
	intentHash, err := disclosureIntent.Hash()
	if err != nil {
		t.Fatal(err)
	}
	disclosureDecision := decision.Decision{
		Version: decision.SchemaVersion, ID: "disclosure-receipt-decision", IntentHash: intentHash, TenantID: "tenant-a", AgentID: "sender-a", Outcome: decision.Allow,
		PolicyRevision: 1, RevocationEpoch: 1, ProviderID: "authority-a", IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(time.Minute).Unix(), KeyID: "authority-key",
	}
	if err := disclosureDecision.Sign(fixture.decisionPrivate); err != nil {
		t.Fatal(err)
	}
	typedRecorder, supported := dataConfig.GovernedReceiptRecorder.(dataexchange.GovernedDisclosureReceiptRecorder)
	if !supported {
		t.Fatal("enterprise receipt recorder does not support V2 disclosure evidence")
	}
	if err := typedRecorder.RecordGovernedDisclosureReceipt(context.Background(), disclosureIntent, disclosureDecision, disclosure); err != nil {
		t.Fatalf("record V2 disclosure receipt: %v", err)
	}
	receipts := runtime.receipts.journal.Receipts()
	typedReceipt := receipts[len(receipts)-1]
	if err := typedReceipt.VerifyForDisclosure(disclosureIntent, disclosureDecision, disclosure, "receiver-a", fixture.intentPrivate.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("verify V2 governed receipt: %v", err)
	}
	rotated := trustRevisionForControl(t, fixture, 2, 1, 2)
	rotated.Keys = []authority.AuthorityKey{rotated.Keys[0], rotated.Keys[2]}
	rotated.Signature = ""
	if err := rotated.Sign(fixture.rootPrivate); err != nil {
		t.Fatal(err)
	}
	if err := runtime.trust.Install(rotated); err != nil {
		t.Fatalf("install receipt-key revocation: %v", err)
	}
	if err := dataConfig.GovernedReceiptRecorder.RecordGovernedReceipt(context.Background(), governed.Intent, governed.Decision); err == nil || !strings.Contains(err.Error(), "no longer active") {
		t.Fatalf("revoked receipt key error = %v", err)
	}
}

func TestRolloutRefreshStagesCandidateThenInstallsOnlyAuthorityActivePolicy(t *testing.T) {
	fixture := newControlFixture(t)
	directory := filepath.Dir(fixture.path)
	rotatedTrust := trustRevisionForControl(t, fixture, 2, 2, 1)
	candidatePolicy := rolloutPolicyForControl(t, fixture, 2, true)
	candidateHash, err := candidatePolicy.Hash()
	if err != nil {
		t.Fatal(err)
	}
	publication := authority.PolicyPublication{
		Version: authority.SchemaVersion, ID: "rollout-2", TenantID: "tenant-a", PolicyRevision: 2, RevocationEpoch: 1,
		PolicyHash: candidateHash, ExpectedAgents: []string{"sender-a"}, RequiredAcknowledged: 1, IssuedAt: fixture.now.Unix(), KeyID: "authority-key",
	}
	if err := publication.Sign(fixture.decisionPrivate); err != nil {
		t.Fatal(err)
	}
	activation, err := authority.NewPolicyActivation(publication, candidatePolicy, fixture.now, fixture.now, "authority-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := activation.Sign(fixture.decisionPrivate); err != nil {
		t.Fatal(err)
	}
	var (
		candidateAvailable = true
		active             *authorityhttp.ActivePolicyEnvelope
		acknowledgements   []authority.PolicyAckStatus
	)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/trust-current":
			_ = json.NewEncoder(writer).Encode(rotatedTrust)
		case "/v1/policy-candidate":
			if candidateAvailable {
				_ = json.NewEncoder(writer).Encode(authorityhttp.PublicationEnvelope{Publication: publication, Bundle: candidatePolicy})
				return
			}
			writer.WriteHeader(http.StatusNoContent)
		case "/v1/policy-current":
			if active == nil {
				writer.WriteHeader(http.StatusNoContent)
				return
			}
			_ = json.NewEncoder(writer).Encode(*active)
		case "/v1/policy-ack":
			var ack authority.PolicyAcknowledgement
			if err := json.NewDecoder(request.Body).Decode(&ack); err != nil {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			if err := ack.Verify(fixture.intentPrivate.Public().(ed25519.PublicKey), time.Now()); err != nil {
				t.Errorf("ack verification: %v", err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			acknowledgements = append(acknowledgements, ack.Status)
			_ = json.NewEncoder(writer).Encode(authority.RolloutStatus{Publication: publication, Ready: true})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	seed := base64.StdEncoding.EncodeToString(fixture.intentPrivate.Seed())
	if err := os.WriteFile(filepath.Join(directory, "ack.seed"), []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := readSecureJSON[Config](fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	config.Rollout = &RolloutConfig{AuthorityEndpoint: server.URL, AgentID: "sender-a", AcknowledgementKeyID: "sender-key", AcknowledgementSeedPath: "ack.seed"}
	writeControlJSON(t, fixture.path, config)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	dataConfig := dataexchange.ServiceConfig{}
	if err := runtime.ApplyDataExchange(&dataConfig); err != nil {
		t.Fatal(err)
	}
	if err := runtime.RefreshRollout(context.Background()); err != nil {
		t.Fatalf("stage candidate: %v", err)
	}
	if len(acknowledgements) != 1 || acknowledgements[0] != authority.PolicyAckStaged {
		t.Fatalf("acknowledgements after stage = %v", acknowledgements)
	}
	denied := signedFrameForControl(t, fixture, &dataexchange.Frame{Type: dataexchange.TypeBinary, Payload: []byte("not active")}, 2)
	if err := dataConfig.GovernedVerifier.VerifyGovernedFrame(context.Background(), coreapi.Addr{}, denied); err == nil || !strings.Contains(err.Error(), "local authority ceiling") {
		t.Fatalf("staged policy was enforced before authority activation: %v", err)
	}
	candidateAvailable = false
	active = &authorityhttp.ActivePolicyEnvelope{Publication: publication, Bundle: candidatePolicy, Activation: activation}
	if err := runtime.RefreshRollout(context.Background()); err != nil {
		t.Fatalf("install active policy: %v", err)
	}
	if len(acknowledgements) != 2 || acknowledgements[0] != authority.PolicyAckStaged || acknowledgements[1] != authority.PolicyAckEnforced {
		t.Fatalf("activation acknowledgement evidence = %v", acknowledgements)
	}
	if err := runtime.RefreshRollout(context.Background()); err != nil {
		t.Fatalf("idempotent active refresh: %v", err)
	}
	if len(acknowledgements) != 2 {
		t.Fatalf("active refresh resubmitted delivered acknowledgement = %v", acknowledgements)
	}
	allowed := signedFrameForControl(t, fixture, &dataexchange.Frame{Type: dataexchange.TypeBinary, Payload: []byte("active")}, 2)
	if err := dataConfig.GovernedVerifier.VerifyGovernedFrame(context.Background(), coreapi.Addr{}, allowed); err != nil {
		t.Fatalf("authority-active policy was not enforced: %v", err)
	}
	// Remote trust and the authority-active policy are written back to the
	// protected attachment files. A restart therefore restores the same
	// ceiling rather than regressing to the original bootstrap state.
	restarted, err := Load(fixture.path)
	if err != nil {
		t.Fatalf("restart with persisted rollout state: %v", err)
	}
	restartedData := dataexchange.ServiceConfig{}
	if err := restarted.ApplyDataExchange(&restartedData); err != nil {
		t.Fatal(err)
	}
	if err := restartedData.GovernedVerifier.VerifyGovernedFrame(context.Background(), coreapi.Addr{}, allowed); err != nil {
		t.Fatalf("persisted authority-active policy was not restored: %v", err)
	}
	if err := restarted.RefreshRollout(context.Background()); err != nil {
		t.Fatalf("restart active refresh: %v", err)
	}
	if len(acknowledgements) != 2 {
		t.Fatalf("restart resubmitted delivered acknowledgement = %v", acknowledgements)
	}
}

func TestFleetControlReportsBoundedStatusAndVerifiesCommands(t *testing.T) {
	fixture := newControlFixture(t)
	directory := filepath.Dir(fixture.path)
	command := authority.FleetCommand{
		Version: authority.FleetCommandVersion, ID: "fleet-command-1", TenantID: "tenant-a", Targets: []string{"sender-a"},
		Kind: authority.FleetCommandRefreshPolicy, IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(time.Hour).Unix(), KeyID: "authority-key",
	}
	if err := command.Sign(fixture.decisionPrivate); err != nil {
		t.Fatal(err)
	}
	var reports []authority.FleetNodeReport
	var results []authority.FleetCommandResult
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/fleet/report":
			var report authority.FleetNodeReport
			if err := json.NewDecoder(request.Body).Decode(&report); err != nil || report.Verify(fixture.intentPrivate.Public().(ed25519.PublicKey), time.Now()) != nil {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			reports = append(reports, report)
		case "/v1/fleet/commands":
			_ = json.NewEncoder(writer).Encode(map[string]any{"commands": []authority.FleetCommand{command}})
		case "/v1/fleet/result":
			var result authority.FleetCommandResult
			if err := json.NewDecoder(request.Body).Decode(&result); err != nil || result.Verify(fixture.intentPrivate.Public().(ed25519.PublicKey), time.Now()) != nil {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			results = append(results, result)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	if err := os.WriteFile(filepath.Join(directory, "ack.seed"), []byte(base64.StdEncoding.EncodeToString(fixture.intentPrivate.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := readSecureJSON[Config](fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	config.Rollout = &RolloutConfig{AuthorityEndpoint: server.URL, AgentID: "sender-a", AcknowledgementKeyID: "sender-key", AcknowledgementSeedPath: "ack.seed"}
	config.Fleet = &FleetConfig{ReportIntervalSeconds: 30}
	writeControlJSON(t, fixture.path, config)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	if !runtime.HasFleetControl() || runtime.FleetReportInterval() != 30*time.Second {
		t.Fatalf("fleet control unavailable interval=%s", runtime.FleetReportInterval())
	}
	if err := runtime.ReportFleetStatus(context.Background(), FleetNodeStatus{NodeID: 7, AgentVersion: "1.2.3", Connections: 2, BytesSent: 5}); err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || reports[0].AgentID != "sender-a" || reports[0].Connections != 2 {
		t.Fatalf("reports=%+v", reports)
	}
	commands, err := runtime.FleetCommands(context.Background())
	if err != nil || len(commands) != 1 || commands[0].ID != command.ID {
		t.Fatalf("commands=%+v err=%v", commands, err)
	}
	if err := runtime.ReportFleetCommandResult(context.Background(), command.ID, "succeeded", ""); err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].CommandID != command.ID || results[0].Outcome != "succeeded" {
		t.Fatalf("results=%+v", results)
	}
}

func TestFleetDesiredStateIsVerifiedPersistedAndQuarantinesHookedActions(t *testing.T) {
	fixture := newControlFixture(t)
	directory := filepath.Dir(fixture.path)
	control := authority.FleetNodeControl{
		Version: authority.FleetNodeControlVersion, TenantID: "tenant-a", AgentID: "sender-a", Revision: 7,
		Group: "finance", Tags: []string{"production"}, DesiredVersion: "1.2.3", DesiredPolicyRevision: 1,
		Quarantined: true, Reason: "Contain node during incident review", IssuedAt: fixture.now.Unix(), KeyID: "authority-key",
	}
	if err := control.Sign(fixture.decisionPrivate); err != nil {
		t.Fatal(err)
	}
	var serveControl atomic.Bool
	serveControl.Store(true)
	var remoteControl atomic.Value
	remoteControl.Store(control)
	acknowledgements := make(chan authority.FleetControlAcknowledgement, 2)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/fleet/control-ack" {
			var acknowledgement authority.FleetControlAcknowledgement
			if err := json.NewDecoder(request.Body).Decode(&acknowledgement); err != nil || acknowledgement.Verify(fixture.intentPrivate.Public().(ed25519.PublicKey), time.Now()) != nil {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			acknowledgements <- acknowledgement
			return
		}
		if request.URL.Path != "/v1/fleet/control" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		if !serveControl.Load() {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(writer).Encode(remoteControl.Load().(authority.FleetNodeControl))
	}))
	defer server.Close()
	if err := os.WriteFile(filepath.Join(directory, "ack.seed"), []byte(base64.StdEncoding.EncodeToString(fixture.intentPrivate.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := readSecureJSON[Config](fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	config.Rollout = &RolloutConfig{AuthorityEndpoint: server.URL, AgentID: "sender-a", AcknowledgementKeyID: "sender-key", AcknowledgementSeedPath: "ack.seed"}
	config.Fleet = &FleetConfig{ReportIntervalSeconds: 30}
	config.ActionControl = &ActionControlConfig{Profile: actionregistry.Profile{Version: actionregistry.SchemaVersion, Mode: actionregistry.ModeLocalEnforce, Actions: []string{"data.send.text"}}, AgentID: "sender-a"}
	writeControlJSON(t, fixture.path, config)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	reconciliation, err := runtime.ReconcileFleetControl(context.Background(), "1.2.3")
	if err != nil || !reconciliation.Found || reconciliation.Status != "applied" || reconciliation.AppliedPolicyRevision != 1 {
		t.Fatalf("reconciliation=%+v err=%v", reconciliation, err)
	}
	if err := runtime.ReportFleetControlAcknowledgement(context.Background(), reconciliation, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	acknowledgement := <-acknowledgements
	if acknowledgement.ControlRevision != control.Revision || acknowledgement.Status != authority.FleetControlApplied || !acknowledgement.Quarantined {
		t.Fatalf("acknowledgement=%+v", acknowledgement)
	}
	installed, found := runtime.CurrentFleetControl()
	if !found || installed.Revision != 7 || !installed.Quarantined {
		t.Fatalf("installed control=%+v found=%v", installed, found)
	}
	envelope, err := actionhook.NewEnvelope("trust.request", "agent:peer", actionhook.HashMetadata(map[string]string{"peer_node_id": "42"}), "pilot.handshake", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	preflight, err := runtime.ActionHook().BeforeAction(context.Background(), envelope)
	if err != nil || preflight.Outcome != decision.Deny || len(preflight.Reasons) != 1 || preflight.Reasons[0] != "fleet_quarantine" {
		t.Fatalf("quarantine preflight=%+v err=%v", preflight, err)
	}

	// An unauthenticated absence cannot clear the last signed desired state.
	serveControl.Store(false)
	reconciliation, err = runtime.ReconcileFleetControl(context.Background(), "1.2.3")
	if err != nil || !reconciliation.Found || !reconciliation.Control.Quarantined {
		t.Fatalf("absence cleared desired state: %+v err=%v", reconciliation, err)
	}

	// The exact signed revision survives restart and remains the rollback floor.
	restarted, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	persisted, found := restarted.CurrentFleetControl()
	if !found || persisted.Signature != installed.Signature {
		t.Fatalf("persisted control=%+v found=%v", persisted, found)
	}
	serveControl.Store(true)
	conflict := control
	conflict.Reason = "Conflicting content at the same revision"
	if err := conflict.Sign(fixture.decisionPrivate); err != nil {
		t.Fatal(err)
	}
	remoteControl.Store(conflict)
	if _, err := restarted.ReconcileFleetControl(context.Background(), "1.2.3"); err == nil || !strings.Contains(err.Error(), "conflicting desired fleet state") {
		t.Fatalf("same-revision conflict error=%v", err)
	}
}

func TestLoadRejectsUnsafeResourceTemplateBeforeReadingBundles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.json")
	writeControlJSON(t, path, Config{
		TenantID: "tenant-a", RootKeyID: "root-key", RootPublicKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		TrustBundlePath: "missing-trust.json", PolicyBundlePath: "missing-policy.json",
		EventStream: &EventStreamRule{ResourceTemplate: "eventstream:all"},
	})
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "exactly one {topic}") {
		t.Fatalf("load error = %v, want template rejection", err)
	}
}

func TestLoadRejectsContentInspectionWithoutTypedGovernance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.json")
	base := Config{
		TenantID: "tenant-a", RootKeyID: "root-key", RootPublicKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		TrustBundlePath: "missing-trust.json", PolicyBundlePath: "missing-policy.json",
		DataExchange: &DataExchangeRule{RequireGoverned: true, RequireContentInspection: true, Resource: "agent:receiver/inbox"},
	}
	writeControlJSON(t, path, base)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "replaced by Pilot-hosted federation") {
		t.Fatalf("data inspection profile error=%v", err)
	}
	base.DataExchange = nil
	base.EventStream = &EventStreamRule{RequireGoverned: true, RequireContentInspection: true, ResourceTemplate: "eventstream:{topic}"}
	writeControlJSON(t, path, base)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "replaced by Pilot-hosted federation") {
		t.Fatalf("event inspection profile error=%v", err)
	}
}

func TestLocalContentInspectionAttachmentIsRejected(t *testing.T) {
	fixture := newControlFixture(t)
	config, err := readSecureJSON[Config](fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	config.DataExchange = &DataExchangeRule{RequireGoverned: true, RequireDisclosure: true, Resource: "agent:receiver/inbox"}
	config.ContentInspection = &ContentInspectionConfig{PresidioEndpoint: "http://127.0.0.1:55002", Entities: []string{"EMAIL_ADDRESS"}, ProcessingResidency: "eu-west-1"}
	writeControlJSON(t, fixture.path, config)
	if _, err := Load(fixture.path); err == nil || !strings.Contains(err.Error(), "content_inspection is no longer supported") {
		t.Fatalf("local inspector attachment error=%v", err)
	}
}

func TestTransferQuotaAttachmentUsesGovernedDataExchange(t *testing.T) {
	fixture := newControlFixture(t)
	config, err := readSecureJSON[Config](fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	config.DataExchange = &DataExchangeRule{
		RequireGoverned: true, Resource: "agent:receiver/inbox",
		TransferQuota: &TransferQuotaConfig{WindowSeconds: 60, MaxBytes: 5, MaxSenders: 2},
	}
	writeControlJSON(t, fixture.path, config)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	dataConfig := dataexchange.ServiceConfig{}
	if err := runtime.ApplyDataExchange(&dataConfig); err != nil {
		t.Fatal(err)
	}
	if !dataConfig.RequireGoverned || dataConfig.GovernedTransferQuota == nil {
		t.Fatalf("data-exchange quota gate = %+v", dataConfig)
	}
	if err := dataConfig.GovernedTransferQuota.Allow("sender-a", 5); err != nil {
		t.Fatal(err)
	}
	if err := dataConfig.GovernedTransferQuota.Allow("sender-a", 1); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("quota limit error=%v", err)
	}

	config.DataExchange = &DataExchangeRule{Resource: "agent:receiver/inbox", TransferQuota: &TransferQuotaConfig{WindowSeconds: 60, MaxBytes: 5, MaxSenders: 2}}
	writeControlJSON(t, fixture.path, config)
	if _, err := Load(fixture.path); err == nil || !strings.Contains(err.Error(), "transfer_quota requires require_governed") {
		t.Fatalf("ungoverned quota attachment error=%v", err)
	}
}

func TestRetentionAttachmentRequiresTypedGovernanceAndConfiguresExpiry(t *testing.T) {
	fixture := newControlFixture(t)
	config, err := readSecureJSON[Config](fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	retention := &DataRetentionConfig{Classes: []DataRetentionClass{{Class: "finance-7y", RetainForSeconds: 3600}}, SweepIntervalSeconds: 60}
	config.DataExchange = &DataExchangeRule{RequireGoverned: true, RequireDisclosure: true, Retention: retention, Resource: "agent:receiver/inbox"}
	writeControlJSON(t, fixture.path, config)
	runtime, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	dataConfig := dataexchange.ServiceConfig{}
	if err := runtime.ApplyDataExchange(&dataConfig); err != nil {
		t.Fatal(err)
	}
	if len(dataConfig.GovernedRetentionPolicies) != 1 || dataConfig.GovernedRetentionPolicies[0].Class != "finance-7y" || dataConfig.GovernedRetentionPolicies[0].RetainFor != time.Hour || dataConfig.RetentionSweepInterval != time.Minute {
		t.Fatalf("retention attachment = %+v interval=%s", dataConfig.GovernedRetentionPolicies, dataConfig.RetentionSweepInterval)
	}
	config.DataExchange = &DataExchangeRule{RequireGoverned: true, Retention: retention, Resource: "agent:receiver/inbox"}
	writeControlJSON(t, fixture.path, config)
	if _, err := Load(fixture.path); err == nil || !strings.Contains(err.Error(), "retention requires require_governed and require_disclosure") {
		t.Fatalf("untyped retention attachment error=%v", err)
	}
}

func TestLoadRejectsBundlePathEscapingControlDirectory(t *testing.T) {
	fixture := newControlFixture(t)
	config := Config{
		TenantID: "tenant-a", RootKeyID: "root-key", RootPublicKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)), TrustBundlePath: "../trust.json", PolicyBundlePath: "policy.json",
		DataExchange: &DataExchangeRule{Resource: "agent:receiver/inbox"},
	}
	writeControlJSON(t, fixture.path, config)
	if _, err := Load(fixture.path); err == nil || !strings.Contains(err.Error(), "escapes control configuration directory") {
		t.Fatalf("load error = %v, want path escape rejection", err)
	}
}

func writeControlRevision(t *testing.T, fixture controlFixture, revision uint64, allowBinary bool) {
	t.Helper()
	trust := trustRevisionForControl(t, fixture, revision, revision, 1)
	rules := []decisionpolicy.Rule{
		{ID: "text-to-inbox", Agents: []string{"*"}, Actions: []string{"data.send.text"}, ResourcePrefixes: []string{"agent:receiver/inbox"}, Risks: allRisks(), Outcome: decision.Allow},
		{ID: "event-publication", Agents: []string{"*"}, Actions: []string{"event.publish"}, ResourcePrefixes: []string{"eventstream:"}, Risks: allRisks(), Outcome: decision.Allow},
	}
	if allowBinary {
		rules = append(rules, decisionpolicy.Rule{ID: "binary-to-inbox", Agents: []string{"*"}, Actions: []string{"data.send.binary"}, ResourcePrefixes: []string{"agent:receiver/inbox"}, Risks: allRisks(), Outcome: decision.Allow})
	}
	payload, err := json.Marshal(decisionpolicy.Document{Version: 1, DefaultOutcome: decision.Deny, Rules: rules})
	if err != nil {
		t.Fatalf("marshal policy revision: %v", err)
	}
	policy := authority.NewPolicyBundle("tenant-a", revision, 1, fixture.now.Add(-time.Minute), fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour), decisionpolicy.Engine, decisionpolicy.EngineVersion, decisionpolicy.ContentType, "authority-key", payload)
	if err := policy.Sign(fixture.decisionPrivate); err != nil {
		t.Fatalf("sign policy revision: %v", err)
	}
	directory := filepath.Dir(fixture.path)
	writeControlJSON(t, filepath.Join(directory, "trust.json"), trust)
	writeControlJSON(t, filepath.Join(directory, "policy.json"), policy)
}

func trustRevisionForControl(t *testing.T, fixture controlFixture, revision, policyRevision, revocationEpoch uint64) authority.TrustBundle {
	t.Helper()
	intentPublic := fixture.intentPrivate.Public().(ed25519.PublicKey)
	decisionPublic := fixture.decisionPrivate.Public().(ed25519.PublicKey)
	trust := authority.TrustBundle{
		Version: authority.SchemaVersion, TenantID: "tenant-a", Revision: revision, PolicyRevision: policyRevision, RevocationEpoch: revocationEpoch,
		IssuedAt: fixture.now.Add(-time.Minute).Unix(), ExpiresAt: fixture.now.Add(time.Hour).Unix(), RootKeyID: "root-key",
		Keys: []authority.AuthorityKey{
			{KeyID: "sender-key", AgentID: "sender-a", PublicKey: base64.StdEncoding.EncodeToString(intentPublic), Usages: []authority.KeyUsage{authority.UsageIntent}, NotBefore: fixture.now.Add(-time.Minute).Unix(), ExpiresAt: fixture.now.Add(time.Hour).Unix()},
			{KeyID: "receiver-receipt-key", AgentID: "receiver-a", PublicKey: base64.StdEncoding.EncodeToString(intentPublic), Usages: []authority.KeyUsage{authority.UsageReceipt}, NotBefore: fixture.now.Add(-time.Minute).Unix(), ExpiresAt: fixture.now.Add(time.Hour).Unix()},
			{KeyID: "authority-key", PublicKey: base64.StdEncoding.EncodeToString(decisionPublic), Usages: []authority.KeyUsage{authority.UsageDecision, authority.UsagePolicy, authority.UsageMandate}, NotBefore: fixture.now.Add(-time.Minute).Unix(), ExpiresAt: fixture.now.Add(time.Hour).Unix()},
		},
	}
	if err := trust.Sign(fixture.rootPrivate); err != nil {
		t.Fatalf("sign trust revision: %v", err)
	}
	return trust
}

func rolloutPolicyForControl(t *testing.T, fixture controlFixture, revision uint64, allowBinary bool) authority.PolicyBundle {
	t.Helper()
	rules := []decisionpolicy.Rule{
		{ID: "text-to-inbox", Agents: []string{"*"}, Actions: []string{"data.send.text"}, ResourcePrefixes: []string{"agent:receiver/inbox"}, Risks: allRisks(), Outcome: decision.Allow},
		{ID: "event-publication", Agents: []string{"*"}, Actions: []string{"event.publish"}, ResourcePrefixes: []string{"eventstream:"}, Risks: allRisks(), Outcome: decision.Allow},
	}
	if allowBinary {
		rules = append(rules, decisionpolicy.Rule{ID: "binary-to-inbox", Agents: []string{"*"}, Actions: []string{"data.send.binary"}, ResourcePrefixes: []string{"agent:receiver/inbox"}, Risks: allRisks(), Outcome: decision.Allow})
	}
	payload, err := json.Marshal(decisionpolicy.Document{Version: 1, DefaultOutcome: decision.Deny, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	policy := authority.NewPolicyBundle("tenant-a", revision, 1, fixture.now.Add(-time.Minute), fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour), decisionpolicy.Engine, decisionpolicy.EngineVersion, decisionpolicy.ContentType, "authority-key", payload)
	if err := policy.Sign(fixture.decisionPrivate); err != nil {
		t.Fatal(err)
	}
	return policy
}

func signedFrameForControl(t *testing.T, fixture controlFixture, frame *dataexchange.Frame, revision uint64) dataexchange.GovernedFrame {
	t.Helper()
	nonce, err := decision.NewNonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	action := "data.send.text"
	if frame.Type == dataexchange.TypeBinary {
		action = "data.send.binary"
	}
	intent := decision.Intent{
		Version: decision.SchemaVersion, ID: "transport-intent", TenantID: "tenant-a", AgentID: "sender-a", Action: action,
		Resource: "agent:receiver/inbox", PayloadHash: dataexchange.GovernedPayloadHash(frame.Type, frame.Filename, frame.Payload), Risk: decision.RiskMedium,
		IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(2 * time.Minute).Unix(), Nonce: nonce, KeyID: "sender-key",
	}
	if err := intent.Sign(fixture.intentPrivate); err != nil {
		t.Fatalf("sign intent: %v", err)
	}
	intentHash, err := intent.Hash()
	if err != nil {
		t.Fatalf("hash intent: %v", err)
	}
	result := decision.Decision{
		Version: decision.SchemaVersion, ID: "transport-decision", IntentHash: intentHash, TenantID: intent.TenantID, AgentID: intent.AgentID,
		Outcome: decision.Allow, PolicyRevision: revision, RevocationEpoch: 1, ProviderID: "authority-a", IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(time.Minute).Unix(), KeyID: "authority-key",
	}
	if err := result.Sign(fixture.decisionPrivate); err != nil {
		t.Fatalf("sign decision: %v", err)
	}
	governed, err := dataexchange.NewGovernedFrame(frame, intent, result)
	if err != nil {
		t.Fatalf("new governed frame: %v", err)
	}
	return governed
}

func configureControlMandate(t *testing.T, fixture controlFixture) decision.Mandate {
	t.Helper()
	mandate := decision.Mandate{
		Version: decision.SchemaVersion, ID: "mandate-inbox-1", TenantID: "tenant-a", SubjectAgentID: "sender-a",
		Actions: []string{"data.send.text"}, ResourcePrefixes: []string{"agent:receiver/inbox"}, Audience: "agent:receiver", Purpose: "inbox-delivery",
		RevocationEpoch: 1, IssuedAt: fixture.now.Add(-time.Minute).Unix(), ExpiresAt: fixture.now.Add(time.Hour).Unix(), KeyID: "authority-key",
	}
	if err := mandate.Sign(fixture.decisionPrivate); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(fixture.path)
	writeControlJSON(t, filepath.Join(directory, "mandates.json"), []decision.Mandate{mandate})
	config, err := readSecureJSON[Config](fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	config.Mandates = &MandateConfig{Path: "mandates.json"}
	writeControlJSON(t, fixture.path, config)
	return mandate
}

func configureEventControlMandate(t *testing.T, fixture controlFixture) decision.Mandate {
	t.Helper()
	mandate := decision.Mandate{
		Version: decision.SchemaVersion, ID: "mandate-events-1", TenantID: "tenant-a", SubjectAgentID: "sender-a",
		Actions: []string{"event.publish"}, ResourcePrefixes: []string{"eventstream:finance."}, Audience: "broker-a", Purpose: "finance-order-publication",
		RevocationEpoch: 1, IssuedAt: fixture.now.Add(-time.Minute).Unix(), ExpiresAt: fixture.now.Add(time.Hour).Unix(), KeyID: "authority-key",
	}
	if err := mandate.Sign(fixture.decisionPrivate); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(fixture.path)
	writeControlJSON(t, filepath.Join(directory, "mandates.json"), []decision.Mandate{mandate})
	config, err := readSecureJSON[Config](fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	config.Mandates = &MandateConfig{Path: "mandates.json"}
	writeControlJSON(t, fixture.path, config)
	return mandate
}

func signedMandatedFrameForControl(t *testing.T, fixture controlFixture, mandate decision.Mandate, frame *dataexchange.Frame, revision uint64) dataexchange.GovernedFrame {
	t.Helper()
	nonce, err := decision.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	intent := decision.Intent{
		Version: decision.SchemaVersion, ID: "transport-mandated-intent", TenantID: "tenant-a", AgentID: "sender-a", Action: "data.send.text",
		Resource: "agent:receiver/inbox", MandateID: mandate.ID, Audience: mandate.Audience, Purpose: mandate.Purpose,
		PayloadHash: dataexchange.GovernedPayloadHash(frame.Type, frame.Filename, frame.Payload), Risk: decision.RiskMedium,
		IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(2 * time.Minute).Unix(), Nonce: nonce, KeyID: "sender-key",
	}
	if err := intent.Sign(fixture.intentPrivate); err != nil {
		t.Fatal(err)
	}
	intentHash, err := intent.Hash()
	if err != nil {
		t.Fatal(err)
	}
	result := decision.Decision{
		Version: decision.SchemaVersion, ID: "transport-mandated-decision", IntentHash: intentHash, TenantID: intent.TenantID, AgentID: intent.AgentID,
		Outcome: decision.Allow, PolicyRevision: revision, RevocationEpoch: 1, ProviderID: "authority-a", IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(time.Minute).Unix(), KeyID: "authority-key",
	}
	if err := result.Sign(fixture.decisionPrivate); err != nil {
		t.Fatal(err)
	}
	governed, err := dataexchange.NewGovernedFrame(frame, intent, result)
	if err != nil {
		t.Fatal(err)
	}
	return governed
}

func signedEventForControl(t *testing.T, fixture controlFixture, mandate *decision.Mandate, event *eventstream.Event, revision uint64) eventstream.GovernedEvent {
	t.Helper()
	nonce, err := decision.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	intent := decision.Intent{
		Version: decision.SchemaVersion, ID: "event-intent", TenantID: "tenant-a", AgentID: "sender-a", Action: "event.publish",
		Resource: "eventstream:" + event.Topic, PayloadHash: eventstream.GovernedEventPayloadHash(event.Topic, event.Payload), Risk: decision.RiskMedium,
		IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(2 * time.Minute).Unix(), Nonce: nonce, KeyID: "sender-key",
	}
	if mandate != nil {
		intent.MandateID = mandate.ID
		intent.Audience = mandate.Audience
		intent.Purpose = mandate.Purpose
	}
	if err := intent.Sign(fixture.intentPrivate); err != nil {
		t.Fatal(err)
	}
	intentHash, err := intent.Hash()
	if err != nil {
		t.Fatal(err)
	}
	result := decision.Decision{
		Version: decision.SchemaVersion, ID: "event-decision", IntentHash: intentHash, TenantID: intent.TenantID, AgentID: intent.AgentID,
		Outcome: decision.Allow, PolicyRevision: revision, RevocationEpoch: 1, ProviderID: "authority-a", IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(time.Minute).Unix(), KeyID: "authority-key",
	}
	if err := result.Sign(fixture.decisionPrivate); err != nil {
		t.Fatal(err)
	}
	governed, err := eventstream.NewGovernedEvent(event, intent, result)
	if err != nil {
		t.Fatal(err)
	}
	return governed
}

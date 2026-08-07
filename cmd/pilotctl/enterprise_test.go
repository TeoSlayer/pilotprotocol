// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authorityhttp"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/decisionhttp"
)

func TestCLIEnterpriseDashboardURL(t *testing.T) {
	t.Parallel()
	stdout, stderr, code := runCLI(t, []string{
		"--json", "enterprise", "dashboard-url",
		"--endpoint", "https://authority.example", "--tenant", "acme",
	}, nil)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	var envelope struct {
		Status string                 `json:"status"`
		Data   map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout)
	}
	if envelope.Status != "ok" {
		t.Fatalf("status=%q", envelope.Status)
	}
	if got, want := envelope.Data["dashboard_url"], "https://authority.example/v1/manage/dashboard?tenant_id=acme"; got != want {
		t.Errorf("dashboard_url=%v, want %q", got, want)
	}
}

func TestCLIEnterpriseHelp(t *testing.T) {
	t.Parallel()
	stdout, stderr, code := runCLI(t, []string{"enterprise", "--help"}, nil)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout+stderr, "dashboard-url") {
		t.Errorf("enterprise help missing dashboard command: %s%s", stdout, stderr)
	}
}

func TestCLIEnterpriseStatus(t *testing.T) {
	state := enterpriseStateForTest(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/manage/control-state" || request.URL.Query().Get("tenant_id") != "acme" {
			t.Errorf("request=%s", request.URL.String())
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(state); err != nil {
			t.Errorf("encode state: %v", err)
		}
	}))
	defer server.Close()

	stdout, stderr, code := runCLI(t, []string{
		"--json", "enterprise", "status", "--endpoint", server.URL, "--tenant", "acme",
	}, nil)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	var envelope struct {
		Status string                 `json:"status"`
		Data   map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout)
	}
	if envelope.Status != "ok" || envelope.Data["tenant_id"] != "acme" {
		t.Fatalf("response=%s", stdout)
	}
	if got := envelope.Data["trust_revision"]; got != float64(7) {
		t.Errorf("trust_revision=%v, want 7", got)
	}
	if got := envelope.Data["policy_revision"]; got != float64(9) {
		t.Errorf("policy_revision=%v, want 9", got)
	}
	if _, found := envelope.Data["recent_workflows"]; !found {
		t.Errorf("status response omits recent workflows: %s", stdout)
	}
	if _, found := envelope.Data["usage_export"]; !found {
		t.Errorf("status response omits usage export: %s", stdout)
	}
}

func TestCLIEnterpriseStatusOIDCBearerEnvironment(t *testing.T) {
	state := enterpriseStateForTest(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer keycloak-access-token" {
			t.Errorf("authorization=%q", request.Header.Get("Authorization"))
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		if request.URL.Path != "/v1/manage/control-state" || request.URL.Query().Get("tenant_id") != "acme" {
			t.Errorf("request=%s", request.URL.String())
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(state)
	}))
	defer server.Close()
	stdout, stderr, code := runCLI(t, []string{
		"--json", "enterprise", "status", "--endpoint", server.URL, "--tenant", "acme", "--bearer-token-env", "PILOT_OIDC_TOKEN",
	}, map[string]string{"PILOT_OIDC_TOKEN": "keycloak-access-token"})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, `"tenant_id":"acme"`) {
		t.Fatalf("status output=%s", stdout)
	}
}

func TestCLIEnterprisePolicyStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/manage/policy-status" || request.URL.Query().Get("id") != "rollout-42" {
			t.Errorf("request=%s", request.URL.String())
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"publication":{"id":"rollout-42","tenant_id":"acme"},"staged":1,"pending":[]}`))
	}))
	defer server.Close()

	stdout, stderr, code := runCLI(t, []string{
		"--json", "enterprise", "policy", "status", "--endpoint", server.URL, "--tenant", "acme", "--id", "rollout-42",
	}, nil)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	var envelope struct {
		Status string                 `json:"status"`
		Data   map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout)
	}
	rollout, _ := envelope.Data["rollout"].(map[string]interface{})
	publication, _ := rollout["publication"].(map[string]interface{})
	if envelope.Status != "ok" || publication["id"] != "rollout-42" {
		t.Fatalf("response=%s", stdout)
	}
}

func TestCLIEnterpriseMandatePublish(t *testing.T) {
	now := time.Now().UTC()
	bundle := decision.MandateBundle{
		Version: decision.SchemaVersion, TenantID: "acme", SubjectAgentID: "agent-1", Revision: 1, RevocationEpoch: 1,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), KeyID: "issuer-key", Signature: "signed",
	}
	path := filepath.Join(t.TempDir(), "mandate-bundle.json")
	body, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/manage/mandates" || request.Method != http.MethodPost {
			t.Errorf("request=%s %s", request.Method, request.URL.String())
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		hash, _ := bundle.Hash()
		if request.Header.Get("Idempotency-Key") != hash {
			t.Errorf("idempotency key=%q", request.Header.Get("Idempotency-Key"))
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(writer).Encode(bundle)
	}))
	defer server.Close()
	stdout, stderr, code := runCLI(t, []string{
		"--json", "enterprise", "mandate", "publish", "--endpoint", server.URL, "--tenant", "acme", "--bundle", path,
	}, nil)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, `"mandate_bundle"`) || !strings.Contains(stdout, `"subject_agent_id":"agent-1"`) {
		t.Fatalf("publish output=%s", stdout)
	}
}

func TestCLIEnterpriseTrustPublish(t *testing.T) {
	bundle := enterpriseStateForTest(t).Trust
	path := filepath.Join(t.TempDir(), "trust-bundle.json")
	body, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	hash, err := bundle.Hash()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/manage/trust" || request.Method != http.MethodPost || request.Header.Get("Idempotency-Key") != hash {
			t.Errorf("request=%s %s idempotency=%q", request.Method, request.URL.String(), request.Header.Get("Idempotency-Key"))
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(writer).Encode(authorityhttp.TrustPublicationResult{TenantID: bundle.TenantID, Revision: bundle.Revision, BundleHash: hash})
	}))
	defer server.Close()
	stdout, stderr, code := runCLI(t, []string{
		"--json", "enterprise", "trust", "publish", "--endpoint", server.URL, "--tenant", "acme", "--bundle", path,
	}, nil)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, `"trust"`) || !strings.Contains(stdout, `"revision":7`) || !strings.Contains(stdout, hash) {
		t.Fatalf("trust publish output=%s", stdout)
	}
}

func TestCLIEnterpriseReceiptList(t *testing.T) {
	receiptID, err := decision.ReceiptID("decision-1", "wallet")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/manage/receipts" || request.URL.Query().Get("tenant_id") != "acme" || request.URL.Query().Get("limit") != "5" {
			t.Errorf("request=%s", request.URL.String())
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"receipts": []decision.Receipt{{
			Version: decision.SchemaVersion, ID: receiptID, DecisionID: "decision-1", DecisionHash: strings.Repeat("a", 64), IntentHash: strings.Repeat("b", 64),
			TenantID: "acme", AgentID: "agent-1", Outcome: decision.Allow, Result: decision.Enforced, EnforcementPoint: "wallet", ObservedAt: time.Now().Unix(), KeyID: "receipt-key", Signature: "signed",
		}}})
	}))
	defer server.Close()
	stdout, stderr, code := runCLI(t, []string{
		"--json", "enterprise", "receipt", "list", "--endpoint", server.URL, "--tenant", "acme", "--limit", "5",
	}, nil)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, `"receipts"`) || !strings.Contains(stdout, receiptID) {
		t.Fatalf("receipt output=%s", stdout)
	}
}

func TestCLIEnterpriseWorkflowStatusAndCancellation(t *testing.T) {
	record, authorityPrivate := enterpriseWorkflowRecordForTest(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/manage/workflows":
			if request.Method != http.MethodGet || request.URL.Query().Get("tenant_id") != "acme" || request.URL.Query().Get("limit") != "5" {
				t.Errorf("list request=%s %s", request.Method, request.URL.String())
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(writer).Encode(decisionhttp.WorkflowListResponse{Workflows: []decisionhttp.WorkflowRecord{record}})
		case "/v1/manage/workflow-status":
			if request.Method != http.MethodGet || request.URL.Query().Get("transaction_id") != record.Transaction.ID {
				t.Errorf("status request=%s %s", request.Method, request.URL.String())
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(writer).Encode(record)
		case "/v1/manage/workflow-cancel":
			var cancellationRequest decisionhttp.WorkflowCancelRequest
			if err := json.NewDecoder(request.Body).Decode(&cancellationRequest); err != nil {
				t.Errorf("decode cancellation: %v", err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			sum := sha256.Sum256([]byte(cancellationRequest.TransactionID + "\x00" + cancellationRequest.Reason))
			if request.Method != http.MethodPost || cancellationRequest.TransactionID != record.Transaction.ID || request.Header.Get("Idempotency-Key") != hex.EncodeToString(sum[:]) {
				t.Errorf("cancel request=%s body=%+v idempotency=%q", request.Method, cancellationRequest, request.Header.Get("Idempotency-Key"))
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			cancellation, err := decision.NewApprovalCancellation(record.Transaction, cancellationRequest.Reason, time.Now(), record.Transaction.ProviderID, record.Transaction.KeyID)
			if err != nil {
				t.Errorf("new cancellation: %v", err)
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			if err := cancellation.Sign(authorityPrivate); err != nil {
				t.Errorf("sign cancellation: %v", err)
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			cancelled := record
			cancelled.Cancellation = &cancellation
			_ = json.NewEncoder(writer).Encode(cancelled)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	listOutput, stderr, code := runCLI(t, []string{
		"--json", "enterprise", "workflow", "list", "--endpoint", server.URL, "--tenant", "acme", "--limit", "5",
	}, nil)
	if code != 0 {
		t.Fatalf("list exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(listOutput, `"workflows"`) || !strings.Contains(listOutput, record.Transaction.ID) {
		t.Fatalf("list output=%s", listOutput)
	}
	statusOutput, stderr, code := runCLI(t, []string{
		"--json", "enterprise", "workflow", "status", "--endpoint", server.URL, "--tenant", "acme", "--id", record.Transaction.ID,
	}, nil)
	if code != 0 {
		t.Fatalf("status exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(statusOutput, `"workflow"`) || !strings.Contains(statusOutput, record.Transaction.ID) {
		t.Fatalf("status output=%s", statusOutput)
	}
	cancelOutput, stderr, code := runCLI(t, []string{
		"--json", "enterprise", "workflow", "cancel", "--endpoint", server.URL, "--tenant", "acme", "--id", record.Transaction.ID, "--reason", "operator stop",
	}, nil)
	if code != 0 {
		t.Fatalf("cancel exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(cancelOutput, `"cancellation"`) || !strings.Contains(cancelOutput, "operator stop") {
		t.Fatalf("cancel output=%s", cancelOutput)
	}
}

func enterpriseWorkflowRecordForTest(t *testing.T) (decisionhttp.WorkflowRecord, ed25519.PrivateKey) {
	t.Helper()
	_, agentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	intent := decision.Intent{
		Version: decision.SchemaVersion, ID: "workflow-intent", TenantID: "acme", AgentID: "agent-1", Action: "message.send", Resource: "agent:finance",
		PayloadHash: decision.HashPayload([]byte("invoice")), Risk: decision.RiskHigh, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), Nonce: strings.Repeat("1", 32), KeyID: "agent-key-1",
	}
	if err := intent.Sign(agentPrivate); err != nil {
		t.Fatal(err)
	}
	intentHash, err := intent.Hash()
	if err != nil {
		t.Fatal(err)
	}
	initial := decision.Decision{
		Version: decision.SchemaVersion, ID: "workflow-initial", IntentHash: intentHash, TenantID: intent.TenantID, AgentID: intent.AgentID,
		Outcome: decision.ApprovalRequired, PolicyRevision: 1, RevocationEpoch: 1, ProviderID: "authority-1", IssuedAt: now.Unix(), ExpiresAt: intent.ExpiresAt, KeyID: "authority-key-1",
	}
	if err := initial.Sign(authorityPrivate); err != nil {
		t.Fatal(err)
	}
	transaction, err := decision.NewApprovalTransaction(intent, initial, decision.Allow, nil, []string{"approval-key-1"}, 1, now, now.Add(time.Hour), "authority-1", "authority-key-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Sign(authorityPrivate); err != nil {
		t.Fatal(err)
	}
	return decisionhttp.WorkflowRecord{Transaction: transaction}, authorityPrivate
}

func TestCLIEnterpriseStatusRequiresCompleteMTLSIdentity(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{
		"enterprise", "status", "--endpoint", "http://127.0.0.1:1", "--tenant", "acme",
		"--client-cert", "operator.pem",
	}, nil)
	if code == 0 {
		t.Fatal("expected non-zero exit")
	}
	if !strings.Contains(stderr, "--client-cert and --client-key together") {
		t.Errorf("missing mTLS identity explanation: %s", stderr)
	}
}

func TestCLIEnterpriseDashboardURLRejectsRemotePlaintext(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{
		"enterprise", "dashboard-url", "--endpoint", "http://authority.example", "--tenant", "acme",
	}, nil)
	if code == 0 {
		t.Fatal("expected non-zero exit")
	}
	if !strings.Contains(stderr, "must use HTTPS") {
		t.Errorf("missing HTTPS explanation: %s", stderr)
	}
}

func TestEnterpriseSecretFileRejectsWorldReadableKey(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "operator-key.pem")
	if err := os.WriteFile(path, []byte("not a key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := enterpriseSecretFile(path); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("err=%v, want owner-only file rejection", err)
	}
}

func TestEnterpriseCertificateFileRejectsSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "operator.pem")
	if err := os.WriteFile(target, []byte("certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "operator-link.pem")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := enterpriseCertificateFile(link); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("err=%v, want symlink rejection", err)
	}
}

func enterpriseStateForTest(t *testing.T) authorityhttp.ManagementState {
	t.Helper()
	now := time.Now().UTC()
	issuerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := authority.TrustBundle{
		Version: authority.SchemaVersion, TenantID: "acme", Revision: 7, PolicyRevision: 9, RevocationEpoch: 2,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), RootKeyID: "root-key",
		Keys: []authority.AuthorityKey{{
			KeyID: "issuer-key", PublicKey: base64.StdEncoding.EncodeToString(issuerPublic),
			Usages: []authority.KeyUsage{authority.UsagePolicy}, NotBefore: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		}},
	}
	if err := trust.Sign(rootPrivate); err != nil {
		t.Fatal(err)
	}
	policy := authority.NewPolicyBundle(
		"acme", 9, 2, now, now, now.Add(time.Minute), "policy-engine", "1", "application/json", "issuer-key", []byte(`{"default":"deny"}`),
	)
	return authorityhttp.ManagementState{Trust: trust, ActivePolicy: policy}
}

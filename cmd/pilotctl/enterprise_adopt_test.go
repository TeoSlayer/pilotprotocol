// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

	"github.com/pilot-protocol/common/authority"
	"github.com/pilot-protocol/common/authorityhttp"
	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/common/decisionpolicy"
	"github.com/pilot-protocol/pilotprotocol/internal/enterprisecontrol"
)

func TestAdoptEnterpriseNodeClaimsAndInstallsVerifiedAttachment(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agentPublic, agentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := authority.TrustBundle{
		Version: authority.SchemaVersion, TenantID: "tenant-a", Revision: 1, PolicyRevision: 1, RevocationEpoch: 1,
		IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(), RootKeyID: "root-key",
		Keys: []authority.AuthorityKey{
			{KeyID: "agent-key", AgentID: "agent-003", PublicKey: base64.StdEncoding.EncodeToString(agentPublic), Usages: []authority.KeyUsage{authority.UsageIntent, authority.UsageReceipt}, NotBefore: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix()},
			{KeyID: "authority-key", PublicKey: base64.StdEncoding.EncodeToString(authorityPublic), Usages: []authority.KeyUsage{authority.UsagePolicy, authority.UsageDecision}, NotBefore: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix()},
		},
	}
	if err := trust.Sign(rootPrivate); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(decisionpolicy.Document{Version: 1, DefaultOutcome: decision.Deny})
	if err != nil {
		t.Fatal(err)
	}
	policy := authority.NewPolicyBundle("tenant-a", 1, 1, now.Add(-time.Minute), now.Add(-time.Minute), now.Add(time.Hour), decisionpolicy.Engine, decisionpolicy.EngineVersion, decisionpolicy.ContentType, "authority-key", payload)
	if err := policy.Sign(authorityPrivate); err != nil {
		t.Fatal(err)
	}
	credential, err := json.Marshal(enrolledNodeCredential{
		Version: 1, TenantID: "tenant-a", Agent: enrolledNodeMaterial{AgentID: "agent-003", KeyID: "agent-key", Seed: hex.EncodeToString(agentPrivate.Seed())},
		RootKeyID: "root-key", RootPublicKey: hex.EncodeToString(rootPublic), Trust: trust,
	})
	if err != nil {
		t.Fatal(err)
	}

	const token = "one-time-test-token"
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/enroll/claim":
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body["token"] != token {
				http.Error(writer, "bad token", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(writer).Encode(authorityhttp.NodeEnrollmentClaimResponse{
				Version: authorityhttp.NodeEnrollmentVersion, EnrollmentID: "enrollment-123", TenantID: "tenant-a", AgentID: "agent-003",
				HarnessID: "gemini", DisplayName: "Finance agent", RunID: "run-123456", PublicOrigin: server.URL, FederationEndpoint: server.URL,
				Options: authorityhttp.NodeEnrollmentOptions{ActionControl: true, FleetControl: true, StateSync: true}, Credential: credential, ClaimedAt: now.Unix(),
			})
		case "/v1/policy-current":
			if request.URL.Query().Get("tenant_id") != "tenant-a" || request.URL.Query().Get("agent_id") != "agent-003" {
				http.Error(writer, "bad scope", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(writer).Encode(authorityhttp.ActivePolicyEnvelope{Bundle: policy})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	const tokenEnv = "PILOT_TEST_ENROLLMENT_TOKEN"
	t.Setenv(tokenEnv, token)
	outputDirectory := filepath.Join(t.TempDir(), "managed")
	result, err := adoptEnterpriseNode(context.Background(), enterpriseAdoptOptions{
		Endpoint: server.URL, OutputDirectory: outputDirectory, TokenEnvironment: tokenEnv, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.AgentID != "agent-003" || result.HarnessID != "gemini" || !result.ActionControl || !result.FleetControl || !result.StateSync {
		t.Fatalf("adoption result = %+v", result)
	}
	if os.Getenv(tokenEnv) != "" {
		t.Fatal("enrollment token remained in the process environment")
	}
	if _, err := enterprisecontrol.Load(result.ControlPath); err != nil {
		t.Fatalf("installed attachment did not verify: %v", err)
	}
	if err := filepath.Walk(outputDirectory, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr == nil && !info.IsDir() {
			body, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if strings.Contains(string(body), token) {
				t.Fatalf("one-time token persisted in %s", path)
			}
		}
		return walkErr
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizedManagedEndpointRejectsNonOriginInputs(t *testing.T) {
	for _, input := range []string{"http://management.example", "https://user@management.example", "https://management.example/path", "https://management.example?tenant=a"} {
		if _, err := normalizedManagedEndpoint(input); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package authorityhttp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientSignsEveryConfidentialAgentRead(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		agentID := request.Header.Get(agentRequestAgentIDHeader)
		keyID := request.Header.Get(agentRequestKeyIDHeader)
		timestamp := request.Header.Get(agentRequestTimestampHeader)
		nonce := request.Header.Get(agentRequestNonceHeader)
		query, queryErr := strictAgentRequestQuery(request.URL, "tenant-a", "agent-a")
		canonical, canonicalErr := canonicalAgentRequest(request.Method, request.URL, query, "tenant-a", agentID, keyID, timestamp, nonce)
		signature, signatureErr := base64.RawURLEncoding.DecodeString(request.Header.Get(agentRequestSignatureHeader))
		if queryErr != nil || canonicalErr != nil || signatureErr != nil || agentID != "agent-a" || keyID != "agent-key-a" || !ed25519.Verify(publicKey, canonical, signature) {
			t.Errorf("invalid authenticated request for %s", request.URL.String())
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		seen[request.URL.Path]++
		switch request.URL.Path {
		case "/v1/fleet/commands":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"commands":[]}`))
		case "/v1/fleet/state/mutations":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"mutations":[]}`))
		case "/v1/trust-current":
			writer.WriteHeader(http.StatusNotFound)
		default:
			writer.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ConfigureAgentRequestSigning("agent-a", "agent-key-a", privateKey); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if _, _, err := client.CurrentTrust(ctx, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.Candidate(ctx, "tenant-a", "agent-a"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.CurrentPolicy(ctx, "tenant-a", "agent-a"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.CurrentMandateBundle(ctx, "tenant-a", "agent-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.FleetCommands(ctx, "tenant-a", "agent-a"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.FleetStateSnapshot(ctx, "tenant-a", "agent-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.FleetStateMutations(ctx, "tenant-a", "agent-a"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.FleetControl(ctx, "tenant-a", "agent-a"); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		"/v1/trust-current", "/v1/policy-candidate", "/v1/policy-current", "/v1/mandates-current",
		"/v1/fleet/commands", "/v1/fleet/state/current", "/v1/fleet/state/mutations", "/v1/fleet/control",
	} {
		if seen[path] != 1 {
			t.Errorf("%s signed requests = %d", path, seen[path])
		}
	}
}

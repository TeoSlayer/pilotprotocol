// SPDX-License-Identifier: AGPL-3.0-or-later

package decisionhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWorkflowStatusUsesConfiguredAgentRequestSigner(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("tenant_id") != "tenant-a" || request.URL.Query().Get("agent_id") != "agent-a" || request.Header.Get("X-Test-Agent-Signature") != "present" {
			t.Errorf("unbound status request: %s headers=%v", request.URL.String(), request.Header)
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{}`))
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err := client.ConfigureWorkflowAgentRequestSigning("tenant-a", "agent-a", func(request *http.Request, tenantID, agentID string) error {
		called = true
		if tenantID != "tenant-a" || agentID != "agent-a" {
			t.Fatalf("signer identity = %s/%s", tenantID, agentID)
		}
		request.Header.Set("X-Test-Agent-Signature", "present")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, _ = client.WorkflowStatus(context.Background(), "transaction-a")
	if !called {
		t.Fatal("configured workflow status signer was not called")
	}
}

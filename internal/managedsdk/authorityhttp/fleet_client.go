// SPDX-License-Identifier: AGPL-3.0-or-later

package authorityhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
)

// FleetCommands retrieves the short-lived signed commands addressed to one
// agent. The caller must independently verify each command before execution.
func (client *Client) FleetCommands(ctx context.Context, tenantID, agentID string) ([]authority.FleetCommand, error) {
	if client == nil || client.endpoint == nil || client.httpClient == nil {
		return nil, fmt.Errorf("authorityhttp: client is not initialized")
	}
	if !clientIdentifier(tenantID) || !clientIdentifier(agentID) {
		return nil, fmt.Errorf("authorityhttp: tenant and agent identifiers are required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.route("/v1/fleet/commands", url.Values{"tenant_id": {tenantID}, "agent_id": {agentID}}), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	if err := client.signAgentRequest(request, tenantID, agentID); err != nil {
		return nil, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("authorityhttp: fleet commands: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authorityhttp: fleet commands returned HTTP %d", response.StatusCode)
	}
	var envelope struct {
		Commands []authority.FleetCommand `json:"commands"`
	}
	if err := decodeResponse(response.Body, &envelope); err != nil {
		return nil, err
	}
	for _, command := range envelope.Commands {
		if err := command.Validate(); err != nil || command.TenantID != tenantID || !command.TargetsAgent(agentID) {
			return nil, fmt.Errorf("authorityhttp: invalid fleet command")
		}
	}
	return envelope.Commands, nil
}

func (client *Client) ReportFleetNode(ctx context.Context, report authority.FleetNodeReport) error {
	if err := report.Validate(); err != nil {
		return err
	}
	return client.postFleet(ctx, "/v1/fleet/report", report)
}

func (client *Client) ReportFleetResult(ctx context.Context, result authority.FleetCommandResult) error {
	if err := result.Validate(); err != nil {
		return err
	}
	return client.postFleet(ctx, "/v1/fleet/result", result)
}

func (client *Client) ReportFleetControlAcknowledgement(ctx context.Context, acknowledgement authority.FleetControlAcknowledgement) error {
	if err := acknowledgement.Validate(); err != nil {
		return err
	}
	return client.postFleet(ctx, "/v1/fleet/control-ack", acknowledgement)
}

func (client *Client) ReportFleetActivity(ctx context.Context, activity authority.FleetActivity) error {
	if err := activity.Validate(); err != nil {
		return err
	}
	return client.postFleetIdempotent(ctx, "/v1/fleet/activity", activity, activity.ID)
}

func (client *Client) ReportFleetStateSnapshot(ctx context.Context, snapshot authority.FleetStateSnapshot) error {
	if err := snapshot.Validate(); err != nil {
		return err
	}
	return client.postFleetIdempotent(ctx, "/v1/fleet/state/report", snapshot, snapshot.ID)
}

func (client *Client) FleetStateSnapshot(ctx context.Context, tenantID, agentID string) (authority.FleetStateSnapshot, bool, error) {
	if client == nil || client.endpoint == nil || client.httpClient == nil || !clientIdentifier(tenantID) || !clientIdentifier(agentID) {
		return authority.FleetStateSnapshot{}, false, fmt.Errorf("authorityhttp: tenant and agent identifiers are required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.route("/v1/fleet/state/current", url.Values{"tenant_id": {tenantID}, "agent_id": {agentID}}), nil)
	if err != nil {
		return authority.FleetStateSnapshot{}, false, err
	}
	request.Header.Set("Accept", "application/json")
	if err := client.signAgentRequest(request, tenantID, agentID); err != nil {
		return authority.FleetStateSnapshot{}, false, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return authority.FleetStateSnapshot{}, false, fmt.Errorf("authorityhttp: fleet state snapshot: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		return authority.FleetStateSnapshot{}, false, nil
	}
	if response.StatusCode != http.StatusOK {
		return authority.FleetStateSnapshot{}, false, fmt.Errorf("authorityhttp: fleet state snapshot returned HTTP %d", response.StatusCode)
	}
	var snapshot authority.FleetStateSnapshot
	if err := decodeResponse(response.Body, &snapshot); err != nil {
		return authority.FleetStateSnapshot{}, false, err
	}
	if err := snapshot.Validate(); err != nil || snapshot.TenantID != tenantID || snapshot.AgentID != agentID {
		return authority.FleetStateSnapshot{}, false, fmt.Errorf("authorityhttp: invalid fleet state snapshot")
	}
	return snapshot, true, nil
}

func (client *Client) FleetStateMutations(ctx context.Context, tenantID, agentID string) ([]authority.FleetStateMutation, error) {
	if client == nil || client.endpoint == nil || client.httpClient == nil || !clientIdentifier(tenantID) || !clientIdentifier(agentID) {
		return nil, fmt.Errorf("authorityhttp: tenant and agent identifiers are required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.route("/v1/fleet/state/mutations", url.Values{"tenant_id": {tenantID}, "agent_id": {agentID}}), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	if err := client.signAgentRequest(request, tenantID, agentID); err != nil {
		return nil, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("authorityhttp: fleet state mutations: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authorityhttp: fleet state mutations returned HTTP %d", response.StatusCode)
	}
	var envelope struct {
		Mutations []authority.FleetStateMutation `json:"mutations"`
	}
	if err := decodeResponse(response.Body, &envelope); err != nil {
		return nil, err
	}
	for _, mutation := range envelope.Mutations {
		if err := mutation.Validate(); err != nil || mutation.TenantID != tenantID || mutation.AgentID != agentID {
			return nil, fmt.Errorf("authorityhttp: invalid fleet state mutation")
		}
	}
	return envelope.Mutations, nil
}

func (client *Client) ReportFleetStateMutationResult(ctx context.Context, result authority.FleetStateMutationResult) error {
	if err := result.Validate(); err != nil {
		return err
	}
	return client.postFleet(ctx, "/v1/fleet/state/result", result)
}

func (client *Client) FleetControl(ctx context.Context, tenantID, agentID string) (authority.FleetNodeControl, bool, error) {
	if client == nil || client.endpoint == nil || client.httpClient == nil {
		return authority.FleetNodeControl{}, false, fmt.Errorf("authorityhttp: client is not initialized")
	}
	if !clientIdentifier(tenantID) || !clientIdentifier(agentID) {
		return authority.FleetNodeControl{}, false, fmt.Errorf("authorityhttp: tenant and agent identifiers are required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.route("/v1/fleet/control", url.Values{"tenant_id": {tenantID}, "agent_id": {agentID}}), nil)
	if err != nil {
		return authority.FleetNodeControl{}, false, err
	}
	request.Header.Set("Accept", "application/json")
	if err := client.signAgentRequest(request, tenantID, agentID); err != nil {
		return authority.FleetNodeControl{}, false, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return authority.FleetNodeControl{}, false, fmt.Errorf("authorityhttp: fleet control: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		return authority.FleetNodeControl{}, false, nil
	}
	if response.StatusCode != http.StatusOK {
		return authority.FleetNodeControl{}, false, fmt.Errorf("authorityhttp: fleet control returned HTTP %d", response.StatusCode)
	}
	var control authority.FleetNodeControl
	if err := decodeResponse(response.Body, &control); err != nil {
		return authority.FleetNodeControl{}, false, err
	}
	if err := control.Validate(); err != nil || control.TenantID != tenantID || control.AgentID != agentID {
		return authority.FleetNodeControl{}, false, fmt.Errorf("authorityhttp: invalid fleet control")
	}
	return control, true, nil
}

func (client *Client) postFleet(ctx context.Context, path string, value any) error {
	return client.postFleetIdempotent(ctx, path, value, "")
}

func (client *Client) postFleetIdempotent(ctx context.Context, path string, value any, idempotencyKey string) error {
	if client == nil || client.endpoint == nil || client.httpClient == nil {
		return fmt.Errorf("authorityhttp: client is not initialized")
	}
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.route(path, nil), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("authorityhttp: fleet post: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("authorityhttp: fleet post returned HTTP %d", response.StatusCode)
	}
	return nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package authorityhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/decisionhttp"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/decisionpolicy"
)

type Client struct {
	endpoint           *url.URL
	httpClient         *http.Client
	agentRequestSigner *AgentRequestSigner
}

// TrustPublicationResult is the durable identity returned after the authority
// accepts a root-signed trust/revocation update through its management plane.
type TrustPublicationResult struct {
	TenantID   string `json:"tenant_id"`
	Revision   uint64 `json:"revision"`
	BundleHash string `json:"bundle_hash"`
}

func New(endpoint string, httpClient *http.Client) (*Client, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("authorityhttp: invalid endpoint")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && authorityLoopback(parsed.Hostname())) {
		return nil, fmt.Errorf("authorityhttp: endpoint must use HTTPS")
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/v1/policy-ack"
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{endpoint: parsed, httpClient: httpClient}, nil
}

func (client *Client) Acknowledge(ctx context.Context, ack authority.PolicyAcknowledgement) (authority.RolloutStatus, error) {
	if client == nil || client.endpoint == nil || client.httpClient == nil {
		return authority.RolloutStatus{}, fmt.Errorf("authorityhttp: client is not initialized")
	}
	if err := ack.Validate(); err != nil {
		return authority.RolloutStatus{}, err
	}
	body, err := json.Marshal(ack)
	if err != nil {
		return authority.RolloutStatus{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return authority.RolloutStatus{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", ack.ID)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return authority.RolloutStatus{}, fmt.Errorf("authorityhttp: acknowledge: %w", err)
	}
	defer response.Body.Close()
	body, err = io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil {
		return authority.RolloutStatus{}, err
	}
	if len(body) > 1<<20 {
		return authority.RolloutStatus{}, fmt.Errorf("authorityhttp: acknowledgement response is too large")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return authority.RolloutStatus{}, fmt.Errorf("authorityhttp: acknowledgement returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var status authority.RolloutStatus
	if err := decoder.Decode(&status); err != nil {
		return authority.RolloutStatus{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return authority.RolloutStatus{}, fmt.Errorf("authorityhttp: trailing response data")
	}
	if status.Publication.ID != ack.PublicationID {
		return authority.RolloutStatus{}, fmt.Errorf("authorityhttp: acknowledgement status publication mismatch")
	}
	return status, nil
}

// Candidate retrieves the newest unactivated signed policy publication that
// explicitly targets agentID. A false found result is normal: it means the
// authority has no staged change for that workload, not that the current
// policy permits an action.
func (client *Client) Candidate(ctx context.Context, tenantID, agentID string) (PublicationEnvelope, bool, error) {
	if client == nil || client.endpoint == nil || client.httpClient == nil {
		return PublicationEnvelope{}, false, fmt.Errorf("authorityhttp: client is not initialized")
	}
	if !clientIdentifier(tenantID) || !clientIdentifier(agentID) {
		return PublicationEnvelope{}, false, fmt.Errorf("authorityhttp: tenant and agent identifiers are required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.route("/v1/policy-candidate", url.Values{"tenant_id": {tenantID}, "agent_id": {agentID}}), nil)
	if err != nil {
		return PublicationEnvelope{}, false, err
	}
	request.Header.Set("Accept", "application/json")
	if err := client.signAgentRequest(request, tenantID, agentID); err != nil {
		return PublicationEnvelope{}, false, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return PublicationEnvelope{}, false, fmt.Errorf("authorityhttp: candidate: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		return PublicationEnvelope{}, false, nil
	}
	if response.StatusCode != http.StatusOK {
		return PublicationEnvelope{}, false, fmt.Errorf("authorityhttp: candidate returned HTTP %d", response.StatusCode)
	}
	var envelope PublicationEnvelope
	if err := decodeResponse(response.Body, &envelope); err != nil {
		return PublicationEnvelope{}, false, err
	}
	if err := envelope.Publication.Validate(); err != nil {
		return PublicationEnvelope{}, false, fmt.Errorf("authorityhttp: invalid candidate publication: %w", err)
	}
	if err := envelope.Bundle.Validate(); err != nil {
		return PublicationEnvelope{}, false, fmt.Errorf("authorityhttp: invalid candidate bundle: %w", err)
	}
	return envelope, true, nil
}

// CurrentTrust retrieves the authority's current root-signed trust bundle for
// a tenant. The caller verifies it against an out-of-band pinned root before
// making it active.
func (client *Client) CurrentTrust(ctx context.Context, tenantID string) (authority.TrustBundle, bool, error) {
	if client == nil || client.endpoint == nil || client.httpClient == nil {
		return authority.TrustBundle{}, false, fmt.Errorf("authorityhttp: client is not initialized")
	}
	if !clientIdentifier(tenantID) {
		return authority.TrustBundle{}, false, fmt.Errorf("authorityhttp: tenant identifier is required")
	}
	query := url.Values{"tenant_id": {tenantID}}
	if client.agentRequestSigner != nil {
		query.Set("agent_id", client.agentRequestSigner.agentID)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.route("/v1/trust-current", query), nil)
	if err != nil {
		return authority.TrustBundle{}, false, err
	}
	request.Header.Set("Accept", "application/json")
	if client.agentRequestSigner != nil {
		if err := client.signAgentRequest(request, tenantID, client.agentRequestSigner.agentID); err != nil {
			return authority.TrustBundle{}, false, err
		}
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return authority.TrustBundle{}, false, fmt.Errorf("authorityhttp: current trust: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return authority.TrustBundle{}, false, nil
	}
	if response.StatusCode != http.StatusOK {
		return authority.TrustBundle{}, false, fmt.Errorf("authorityhttp: current trust returned HTTP %d", response.StatusCode)
	}
	var bundle authority.TrustBundle
	if err := decodeResponse(response.Body, &bundle); err != nil {
		return authority.TrustBundle{}, false, err
	}
	if err := bundle.Validate(); err != nil {
		return authority.TrustBundle{}, false, fmt.Errorf("authorityhttp: invalid current trust: %w", err)
	}
	return bundle, true, nil
}

// CurrentPolicy retrieves the authority's signed publication, bundle, and
// activation proof for one targeted agent. The caller must still verify all
// three objects against its locally pinned trust state.
func (client *Client) CurrentPolicy(ctx context.Context, tenantID, agentID string) (ActivePolicyEnvelope, bool, error) {
	if client == nil || client.endpoint == nil || client.httpClient == nil {
		return ActivePolicyEnvelope{}, false, fmt.Errorf("authorityhttp: client is not initialized")
	}
	if !clientIdentifier(tenantID) || !clientIdentifier(agentID) {
		return ActivePolicyEnvelope{}, false, fmt.Errorf("authorityhttp: tenant and agent identifiers are required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.route("/v1/policy-current", url.Values{"tenant_id": {tenantID}, "agent_id": {agentID}}), nil)
	if err != nil {
		return ActivePolicyEnvelope{}, false, err
	}
	request.Header.Set("Accept", "application/json")
	if err := client.signAgentRequest(request, tenantID, agentID); err != nil {
		return ActivePolicyEnvelope{}, false, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return ActivePolicyEnvelope{}, false, fmt.Errorf("authorityhttp: current policy: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent || response.StatusCode == http.StatusNotFound {
		return ActivePolicyEnvelope{}, false, nil
	}
	if response.StatusCode != http.StatusOK {
		return ActivePolicyEnvelope{}, false, fmt.Errorf("authorityhttp: current policy returned HTTP %d", response.StatusCode)
	}
	var envelope ActivePolicyEnvelope
	if err := decodeResponse(response.Body, &envelope); err != nil {
		return ActivePolicyEnvelope{}, false, err
	}
	if err := envelope.Publication.Validate(); err != nil {
		return ActivePolicyEnvelope{}, false, fmt.Errorf("authorityhttp: invalid active policy publication: %w", err)
	}
	if err := envelope.Bundle.Validate(); err != nil {
		return ActivePolicyEnvelope{}, false, fmt.Errorf("authorityhttp: invalid active policy bundle: %w", err)
	}
	if err := envelope.Activation.Validate(); err != nil {
		return ActivePolicyEnvelope{}, false, fmt.Errorf("authorityhttp: invalid active policy activation: %w", err)
	}
	return envelope, true, nil
}

// CurrentMandateBundle retrieves the complete, revisioned mandate snapshot
// for one workload. A false found result is a normal no-delegation state; it
// must never be treated as an authorization allow.
func (client *Client) CurrentMandateBundle(ctx context.Context, tenantID, agentID string) (decision.MandateBundle, bool, error) {
	if client == nil || client.endpoint == nil || client.httpClient == nil {
		return decision.MandateBundle{}, false, fmt.Errorf("authorityhttp: client is not initialized")
	}
	if !clientIdentifier(tenantID) || !clientIdentifier(agentID) {
		return decision.MandateBundle{}, false, fmt.Errorf("authorityhttp: tenant and agent identifiers are required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.route("/v1/mandates-current", url.Values{"tenant_id": {tenantID}, "agent_id": {agentID}}), nil)
	if err != nil {
		return decision.MandateBundle{}, false, err
	}
	request.Header.Set("Accept", "application/json")
	if err := client.signAgentRequest(request, tenantID, agentID); err != nil {
		return decision.MandateBundle{}, false, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return decision.MandateBundle{}, false, fmt.Errorf("authorityhttp: current mandates: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent || response.StatusCode == http.StatusNotFound {
		return decision.MandateBundle{}, false, nil
	}
	if response.StatusCode != http.StatusOK {
		return decision.MandateBundle{}, false, fmt.Errorf("authorityhttp: current mandates returned HTTP %d", response.StatusCode)
	}
	var bundle decision.MandateBundle
	if err := decodeResponse(response.Body, &bundle); err != nil {
		return decision.MandateBundle{}, false, err
	}
	if err := bundle.Validate(); err != nil {
		return decision.MandateBundle{}, false, fmt.Errorf("authorityhttp: invalid current mandate bundle: %w", err)
	}
	return bundle, true, nil
}

// ManagementState retrieves the read-only control-plane snapshot used by an
// authenticated operator CLI or UI. The reference authority keeps this route
// loopback-only; callers using a remotely exposed management gateway supply
// its authenticated HTTP client. This helper validates structure only—local
// enforcement must still verify signed objects against its pinned root.
func (client *Client) ManagementState(ctx context.Context, tenantID string) (ManagementState, error) {
	if client == nil || client.endpoint == nil || client.httpClient == nil {
		return ManagementState{}, fmt.Errorf("authorityhttp: client is not initialized")
	}
	if !clientIdentifier(tenantID) {
		return ManagementState{}, fmt.Errorf("authorityhttp: tenant identifier is required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.route("/v1/manage/control-state", url.Values{"tenant_id": {tenantID}}), nil)
	if err != nil {
		return ManagementState{}, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return ManagementState{}, fmt.Errorf("authorityhttp: management state: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ManagementState{}, fmt.Errorf("authorityhttp: management state returned HTTP %d", response.StatusCode)
	}
	var state ManagementState
	if err := decodeResponse(response.Body, &state); err != nil {
		return ManagementState{}, err
	}
	if err := validateManagementState(state, tenantID); err != nil {
		return ManagementState{}, err
	}
	return state, nil
}

// PublishTrust transports a pre-signed root trust bundle through the protected
// management boundary. It cannot create a root signature; the returned hash
// proves exactly which signed state the authority durably accepted.
func (client *Client) PublishTrust(ctx context.Context, bundle authority.TrustBundle) (TrustPublicationResult, error) {
	if err := bundle.Validate(); err != nil || strings.TrimSpace(bundle.Signature) == "" {
		return TrustPublicationResult{}, fmt.Errorf("authorityhttp: invalid signed trust bundle")
	}
	hash, err := bundle.Hash()
	if err != nil {
		return TrustPublicationResult{}, err
	}
	var result TrustPublicationResult
	if err := client.managementPost(ctx, "/v1/manage/trust", bundle, hash, &result); err != nil {
		return TrustPublicationResult{}, fmt.Errorf("authorityhttp: publish trust: %w", err)
	}
	if result.TenantID != bundle.TenantID || result.Revision != bundle.Revision || result.BundleHash != hash {
		return TrustPublicationResult{}, fmt.Errorf("authorityhttp: published trust bundle binding mismatch")
	}
	return result, nil
}

// Publish submits a pre-signed policy publication and its exact pre-signed
// bundle through the authenticated management boundary. This client never
// signs policy state; an operator CLI is only a transport for tenant-owned
// authority artifacts.
func (client *Client) Publish(ctx context.Context, publication authority.PolicyPublication, bundle authority.PolicyBundle) (authority.RolloutStatus, error) {
	if err := publication.Validate(); err != nil || strings.TrimSpace(publication.Signature) == "" {
		return authority.RolloutStatus{}, fmt.Errorf("authorityhttp: invalid signed policy publication")
	}
	if err := bundle.Validate(); err != nil || strings.TrimSpace(bundle.Signature) == "" {
		return authority.RolloutStatus{}, fmt.Errorf("authorityhttp: invalid signed policy bundle")
	}
	idempotencyKey, err := publication.Hash()
	if err != nil {
		return authority.RolloutStatus{}, err
	}
	var status authority.RolloutStatus
	if err := client.managementPost(ctx, "/v1/manage/policy", PublicationEnvelope{Publication: publication, Bundle: bundle}, idempotencyKey, &status); err != nil {
		return authority.RolloutStatus{}, fmt.Errorf("authorityhttp: publish policy: %w", err)
	}
	return status, nil
}

// PublishMandateBundle submits a pre-signed full delegation snapshot. It is
// deliberately unable to create or modify tenant signatures.
func (client *Client) PublishMandateBundle(ctx context.Context, bundle decision.MandateBundle) (decision.MandateBundle, error) {
	if err := bundle.Validate(); err != nil || strings.TrimSpace(bundle.Signature) == "" {
		return decision.MandateBundle{}, fmt.Errorf("authorityhttp: invalid signed mandate bundle")
	}
	hash, err := bundle.Hash()
	if err != nil {
		return decision.MandateBundle{}, err
	}
	var published decision.MandateBundle
	if err := client.managementPost(ctx, "/v1/manage/mandates", bundle, hash, &published); err != nil {
		return decision.MandateBundle{}, fmt.Errorf("authorityhttp: publish mandate bundle: %w", err)
	}
	if published.TenantID != bundle.TenantID || published.SubjectAgentID != bundle.SubjectAgentID || published.Revision != bundle.Revision || published.Signature != bundle.Signature {
		return decision.MandateBundle{}, fmt.Errorf("authorityhttp: published mandate bundle binding mismatch")
	}
	return published, nil
}

// Receipts reads the bounded authenticated evidence view. Returned objects
// retain their original enforcement signatures for independent verification.
func (client *Client) Receipts(ctx context.Context, tenantID string, limit int) ([]decision.Receipt, error) {
	if client == nil || client.endpoint == nil || client.httpClient == nil {
		return nil, fmt.Errorf("authorityhttp: client is not initialized")
	}
	if !clientIdentifier(tenantID) || limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("authorityhttp: tenant identifier and receipt limit are required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.route("/v1/manage/receipts", url.Values{"tenant_id": {tenantID}, "limit": {strconv.Itoa(limit)}}), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("authorityhttp: receipts: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authorityhttp: receipts returned HTTP %d", response.StatusCode)
	}
	var payload struct {
		Receipts []decision.Receipt `json:"receipts"`
	}
	if err := decodeResponse(response.Body, &payload); err != nil {
		return nil, err
	}
	for _, receipt := range payload.Receipts {
		if receipt.TenantID != tenantID {
			return nil, fmt.Errorf("authorityhttp: receipt tenant binding mismatch")
		}
		if err := receipt.Validate(); err != nil {
			return nil, fmt.Errorf("authorityhttp: invalid receipt: %w", err)
		}
	}
	return payload.Receipts, nil
}

// Activate submits a pre-signed activation after the authority has verified
// the durable acknowledgement threshold. It cannot promote a bundle by time
// or client-side state alone.
func (client *Client) Activate(ctx context.Context, activation authority.PolicyActivation) (authority.RolloutStatus, error) {
	if err := activation.Validate(); err != nil || strings.TrimSpace(activation.Signature) == "" {
		return authority.RolloutStatus{}, fmt.Errorf("authorityhttp: invalid signed policy activation")
	}
	var status authority.RolloutStatus
	if err := client.managementPost(ctx, "/v1/manage/policy-activate", activation, activation.ID, &status); err != nil {
		return authority.RolloutStatus{}, fmt.Errorf("authorityhttp: activate policy: %w", err)
	}
	return status, nil
}

// Simulate evaluates a signed candidate without publishing or activating it.
func (client *Client) Simulate(ctx context.Context, request SimulationRequest) (decisionpolicy.RolloutSimulation, error) {
	if err := request.Publication.Validate(); err != nil || strings.TrimSpace(request.Publication.Signature) == "" {
		return decisionpolicy.RolloutSimulation{}, fmt.Errorf("authorityhttp: invalid signed simulation publication")
	}
	if err := request.Bundle.Validate(); err != nil || strings.TrimSpace(request.Bundle.Signature) == "" {
		return decisionpolicy.RolloutSimulation{}, fmt.Errorf("authorityhttp: invalid signed simulation bundle")
	}
	if len(request.Intents) != 0 && len(request.Inputs) != 0 {
		return decisionpolicy.RolloutSimulation{}, fmt.Errorf("authorityhttp: simulation must use intents or inputs, not both")
	}
	for _, intent := range request.Intents {
		if err := intent.Validate(); err != nil || strings.TrimSpace(intent.Signature) == "" {
			return decisionpolicy.RolloutSimulation{}, fmt.Errorf("authorityhttp: invalid signed simulation intent")
		}
	}
	for _, input := range request.Inputs {
		if err := input.Validate(); err != nil || strings.TrimSpace(input.Intent.Signature) == "" {
			return decisionpolicy.RolloutSimulation{}, fmt.Errorf("authorityhttp: invalid signed simulation input")
		}
	}
	idempotencyKey, err := request.Publication.Hash()
	if err != nil {
		return decisionpolicy.RolloutSimulation{}, err
	}
	var simulation decisionpolicy.RolloutSimulation
	if err := client.managementPost(ctx, "/v1/manage/policy-simulate", request, idempotencyKey, &simulation); err != nil {
		return decisionpolicy.RolloutSimulation{}, fmt.Errorf("authorityhttp: simulate policy: %w", err)
	}
	return simulation, nil
}

// Status returns the authority's durable rollout view for one publication.
func (client *Client) Status(ctx context.Context, publicationID string) (authority.RolloutStatus, error) {
	if client == nil || client.endpoint == nil || client.httpClient == nil {
		return authority.RolloutStatus{}, fmt.Errorf("authorityhttp: client is not initialized")
	}
	if strings.TrimSpace(publicationID) == "" || len(publicationID) > 128 {
		return authority.RolloutStatus{}, fmt.Errorf("authorityhttp: publication identifier is required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.route("/v1/manage/policy-status", url.Values{"id": {publicationID}}), nil)
	if err != nil {
		return authority.RolloutStatus{}, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return authority.RolloutStatus{}, fmt.Errorf("authorityhttp: policy status: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return authority.RolloutStatus{}, fmt.Errorf("authorityhttp: policy status returned HTTP %d", response.StatusCode)
	}
	var status authority.RolloutStatus
	if err := decodeResponse(response.Body, &status); err != nil {
		return authority.RolloutStatus{}, err
	}
	return status, nil
}

func (client *Client) managementPost(ctx context.Context, path string, payload any, idempotencyKey string, result any) error {
	if client == nil || client.endpoint == nil || client.httpClient == nil {
		return fmt.Errorf("client is not initialized")
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		return fmt.Errorf("idempotency key is required")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.route(path, nil), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("management endpoint returned HTTP %d", response.StatusCode)
	}
	return decodeResponse(response.Body, result)
}

func validateManagementState(state ManagementState, tenantID string) error {
	if state.Trust.TenantID != tenantID || state.ActivePolicy.TenantID != tenantID {
		return fmt.Errorf("authorityhttp: management state tenant binding mismatch")
	}
	if err := state.Trust.Validate(); err != nil {
		return fmt.Errorf("authorityhttp: invalid management trust: %w", err)
	}
	if err := state.ActivePolicy.Validate(); err != nil {
		return fmt.Errorf("authorityhttp: invalid management active policy: %w", err)
	}
	if state.ActivePolicy.Revision < state.Trust.PolicyRevision || state.ActivePolicy.RevocationEpoch < state.Trust.RevocationEpoch {
		return fmt.Errorf("authorityhttp: management active policy is below trust state floor")
	}
	for _, status := range state.Rollouts {
		if status.Publication.TenantID != tenantID {
			return fmt.Errorf("authorityhttp: management rollout tenant binding mismatch")
		}
		if err := status.Publication.Validate(); err != nil {
			return fmt.Errorf("authorityhttp: invalid management publication: %w", err)
		}
		if status.Activation != nil {
			if status.Activation.TenantID != tenantID || status.Activation.PublicationID != status.Publication.ID {
				return fmt.Errorf("authorityhttp: management activation binding mismatch")
			}
			if err := status.Activation.Validate(); err != nil {
				return fmt.Errorf("authorityhttp: invalid management activation: %w", err)
			}
		}
	}
	for _, bundle := range state.MandateBundles {
		if bundle.TenantID != tenantID {
			return fmt.Errorf("authorityhttp: management mandate bundle tenant binding mismatch")
		}
		if err := bundle.Validate(); err != nil {
			return fmt.Errorf("authorityhttp: invalid management mandate bundle: %w", err)
		}
	}
	for _, receipt := range state.RecentReceipts {
		if receipt.TenantID != tenantID {
			return fmt.Errorf("authorityhttp: management receipt tenant binding mismatch")
		}
		if err := receipt.Validate(); err != nil {
			return fmt.Errorf("authorityhttp: invalid management receipt: %w", err)
		}
	}
	for _, workflow := range state.RecentWorkflows {
		if workflow.Transaction.TenantID != tenantID {
			return fmt.Errorf("authorityhttp: management workflow tenant binding mismatch")
		}
		if err := decisionhttp.ValidateWorkflowRecord(workflow); err != nil {
			return fmt.Errorf("authorityhttp: invalid management workflow: %w", err)
		}
	}
	if state.UsageExport != nil {
		if err := state.UsageExport.Validate(); err != nil {
			return fmt.Errorf("authorityhttp: invalid management usage export status: %w", err)
		}
	}
	return nil
}

func (client *Client) route(path string, query url.Values) string {
	target := *client.endpoint
	target.Path = path
	target.RawQuery = query.Encode()
	return target.String()
}

func decodeResponse(body io.Reader, target any) error {
	contents, err := io.ReadAll(io.LimitReader(body, (1<<20)+1))
	if err != nil {
		return err
	}
	if len(contents) > 1<<20 {
		return fmt.Errorf("authorityhttp: response is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("authorityhttp: trailing response data")
	}
	return nil
}

func clientIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func authorityLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

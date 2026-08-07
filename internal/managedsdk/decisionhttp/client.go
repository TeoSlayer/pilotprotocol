// SPDX-License-Identifier: AGPL-3.0-or-later

// Package decisionhttp implements the managed/self-hosted HTTP transport for
// decision.Authorizer. Signature and policy verification remain at the local
// enforcement point.
package decisionhttp

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
)

const DefaultMaxResponseBytes int64 = 1 << 20

const (
	modelCallsHeader        = "X-Pilot-Model-Calls"
	modelInputTokensHeader  = "X-Pilot-Model-Input-Tokens"  // #nosec G101 -- HTTP usage-metering header name, not a credential.
	modelOutputTokensHeader = "X-Pilot-Model-Output-Tokens" // #nosec G101 -- HTTP usage-metering header name, not a credential.
)

type Client struct {
	endpoint                   *url.URL
	httpClient                 *http.Client
	maxResponseBytes           int64
	bearerToken                string
	workflowTenantID           string
	workflowAgentID            string
	workflowAgentRequestSigner func(*http.Request, string, string) error
}

// AuthorizationRequest is the additive authorization wire envelope for a
// disclosure-bound V1 Intent. Plain V1 clients continue posting an Intent
// directly, preserving their signed bytes and endpoint compatibility.
type AuthorizationRequest struct {
	Intent     decision.Intent             `json:"intent"`
	Disclosure *decision.DisclosureBinding `json:"disclosure,omitempty"`
}

// SemanticAuthorizationRequest is sent only to a configured semantic
// evaluator. The primary workload authorization handler deliberately rejects
// this envelope so a workload cannot choose or replace its active policy.
type SemanticAuthorizationRequest struct {
	Intent     decision.Intent                `json:"intent"`
	Disclosure *decision.DisclosureBinding    `json:"disclosure,omitempty"`
	Policy     decision.SemanticPolicyContext `json:"semantic_policy"`
}

// FederatedContentAuthorizationRequest is used only between Pilot's hosted
// authority and its hosted semantic runtime. It is never accepted by the
// workload /v1/authorize handler.
type FederatedContentAuthorizationRequest struct {
	Intent  decision.Intent           `json:"intent"`
	Content decision.FederatedContent `json:"federated_content"`
}

// SemanticFederatedContentAuthorizationRequest additionally carries the
// reviewed policy clauses selected by the authority. A workload cannot choose
// or replace this context.
type SemanticFederatedContentAuthorizationRequest struct {
	Intent  decision.Intent                `json:"intent"`
	Content decision.FederatedContent      `json:"federated_content"`
	Policy  decision.SemanticPolicyContext `json:"semantic_policy"`
}

type Option func(*Client)

func WithHTTPClient(httpClient *http.Client) Option {
	return func(client *Client) {
		if httpClient != nil {
			client.httpClient = httpClient
		}
	}
}

func WithMaxResponseBytes(limit int64) Option {
	return func(client *Client) {
		if limit > 0 {
			client.maxResponseBytes = limit
		}
	}
}

func WithBearerToken(token string) Option {
	return func(client *Client) {
		client.bearerToken = strings.TrimSpace(token)
	}
}

func New(endpoint string, options ...Option) (*Client, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("decisionhttp: parse endpoint: %w", err)
	}
	if parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return nil, fmt.Errorf("decisionhttp: endpoint must not contain credentials, query, or fragment")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("decisionhttp: endpoint host is required")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopbackHost(parsed.Hostname())) {
		return nil, fmt.Errorf("decisionhttp: endpoint must use HTTPS (loopback HTTP is allowed for tests)")
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/v1/authorize"
	}
	client := &Client{
		endpoint: parsed,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		maxResponseBytes: DefaultMaxResponseBytes,
	}
	for _, option := range options {
		option(client)
	}
	if len(client.bearerToken) > 16<<10 || strings.ContainsAny(client.bearerToken, "\r\n\x00") {
		return nil, fmt.Errorf("decisionhttp: invalid bearer token")
	}
	return client, nil
}

func (c *Client) Authorize(ctx context.Context, intent decision.Intent) (decision.Decision, error) {
	return c.authorize(ctx, intent, intent)
}

// AuthorizeDisclosure submits typed metadata alongside an Intent that already
// binds its canonical hash. Authorities whose evaluator cannot inspect
// disclosure metadata fail closed.
func (c *Client) AuthorizeDisclosure(ctx context.Context, intent decision.Intent, disclosure decision.DisclosureBinding) (decision.Decision, error) {
	if err := disclosure.VerifyIntent(intent); err != nil {
		return decision.Decision{}, err
	}
	return c.authorize(ctx, intent, AuthorizationRequest{Intent: intent, Disclosure: &disclosure})
}

func (c *Client) AuthorizeSemantic(ctx context.Context, intent decision.Intent, policy decision.SemanticPolicyContext) (decision.Decision, error) {
	if err := policy.ValidateIntent(intent, intent.IssuedAt); err != nil {
		return decision.Decision{}, err
	}
	return c.authorize(ctx, intent, SemanticAuthorizationRequest{Intent: intent, Policy: policy})
}

func (c *Client) AuthorizeSemanticDisclosure(ctx context.Context, intent decision.Intent, disclosure decision.DisclosureBinding, policy decision.SemanticPolicyContext) (decision.Decision, error) {
	if err := disclosure.VerifyIntent(intent); err != nil {
		return decision.Decision{}, err
	}
	if err := policy.ValidateIntent(intent, intent.IssuedAt); err != nil {
		return decision.Decision{}, err
	}
	return c.authorize(ctx, intent, SemanticAuthorizationRequest{Intent: intent, Disclosure: &disclosure, Policy: policy})
}

func (c *Client) AuthorizeFederatedContent(ctx context.Context, intent decision.Intent, content decision.FederatedContent) (decision.Decision, error) {
	if err := content.VerifyIntent(intent); err != nil {
		return decision.Decision{}, err
	}
	return c.authorize(ctx, intent, FederatedContentAuthorizationRequest{Intent: intent, Content: content.Clone()})
}

func (c *Client) AuthorizeSemanticFederatedContent(ctx context.Context, intent decision.Intent, content decision.FederatedContent, policy decision.SemanticPolicyContext) (decision.Decision, error) {
	if err := content.VerifyIntent(intent); err != nil {
		return decision.Decision{}, err
	}
	if err := policy.ValidateIntent(intent, intent.IssuedAt); err != nil {
		return decision.Decision{}, err
	}
	return c.authorize(ctx, intent, SemanticFederatedContentAuthorizationRequest{Intent: intent, Content: content.Clone(), Policy: policy})
}

func (c *Client) authorize(ctx context.Context, intent decision.Intent, payload any) (decision.Decision, error) {
	if c == nil || c.endpoint == nil || c.httpClient == nil {
		return decision.Decision{}, fmt.Errorf("decisionhttp: client is not initialized")
	}
	if err := intent.Validate(); err != nil {
		return decision.Decision{}, err
	}
	if strings.TrimSpace(intent.Signature) == "" {
		return decision.Decision{}, fmt.Errorf("decisionhttp: remote intents must be signed")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return decision.Decision{}, fmt.Errorf("decisionhttp: encode intent: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return decision.Decision{}, fmt.Errorf("decisionhttp: build request: %w", err)
	}
	intentHash, err := intent.Hash()
	if err != nil {
		return decision.Decision{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", intentHash)
	if c.bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+c.bearerToken)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return decision.Decision{}, fmt.Errorf("decisionhttp: authorize request: %w", err)
	}
	defer response.Body.Close()
	if err := recordModelUsage(ctx, response.Header); err != nil {
		return decision.Decision{}, err
	}
	limited := io.LimitReader(response.Body, c.maxResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return decision.Decision{}, fmt.Errorf("decisionhttp: read response: %w", err)
	}
	if int64(len(responseBody)) > c.maxResponseBytes {
		return decision.Decision{}, fmt.Errorf("decisionhttp: response exceeds %d bytes", c.maxResponseBytes)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return decision.Decision{}, fmt.Errorf("decisionhttp: authority returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	var result decision.Decision
	if err := decoder.Decode(&result); err != nil {
		return decision.Decision{}, fmt.Errorf("decisionhttp: decode decision: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return decision.Decision{}, err
	}
	if err := result.Validate(); err != nil {
		return decision.Decision{}, fmt.Errorf("decisionhttp: invalid decision: %w", err)
	}
	return result, nil
}

func recordModelUsage(ctx context.Context, headers http.Header) error {
	rawCalls, rawInput, rawOutput := headers.Get(modelCallsHeader), headers.Get(modelInputTokensHeader), headers.Get(modelOutputTokensHeader)
	if rawCalls == "" && rawInput == "" && rawOutput == "" {
		return nil
	}
	if rawCalls == "" || rawInput == "" || rawOutput == "" {
		return fmt.Errorf("decisionhttp: incomplete model usage headers")
	}
	calls, err := strconv.ParseUint(rawCalls, 10, 64)
	if err != nil {
		return fmt.Errorf("decisionhttp: invalid model call usage")
	}
	input, err := strconv.ParseUint(rawInput, 10, 64)
	if err != nil {
		return fmt.Errorf("decisionhttp: invalid model input usage")
	}
	output, err := strconv.ParseUint(rawOutput, 10, 64)
	if err != nil {
		return fmt.Errorf("decisionhttp: invalid model output usage")
	}
	if err := decision.ReportModelUsage(ctx, decision.ModelUsage{ModelCalls: calls, InputTokens: input, OutputTokens: output}); err != nil {
		return fmt.Errorf("decisionhttp: record model usage: %w", err)
	}
	return nil
}

var _ decision.SemanticContextAuthorizer = (*Client)(nil)
var _ decision.SemanticContextDisclosureAuthorizer = (*Client)(nil)

func ensureEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decisionhttp: trailing JSON value")
		}
		return fmt.Errorf("decisionhttp: trailing response data: %w", err)
	}
	return nil
}

func loopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

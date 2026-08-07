// SPDX-License-Identifier: AGPL-3.0-or-later

package decisionhttp

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/pilot-protocol/common/decision"
)

const FederationExchangeVersion uint16 = 1

type FederationExchangeState string

const (
	FederationExchangeDenied          FederationExchangeState = "denied"
	FederationExchangeApprovalPending FederationExchangeState = "approval_pending"
	FederationExchangeAuthorized      FederationExchangeState = "authorized"
	FederationExchangeCompleted       FederationExchangeState = "completed"
	FederationExchangeFailed          FederationExchangeState = "failed"
)

type FederationExchangeRequest struct {
	Version uint16                    `json:"version"`
	Intent  decision.Intent           `json:"intent"`
	Content decision.FederatedContent `json:"content"`
}

type FederationExchangeResponse struct {
	Version               uint16                  `json:"version"`
	ExchangeID            string                  `json:"exchange_id"`
	AccountSlug           string                  `json:"account_slug"`
	State                 FederationExchangeState `json:"state"`
	Decision              decision.Decision       `json:"decision"`
	ApprovalTransactionID string                  `json:"approval_transaction_id,omitempty"`
	ApprovalExpiresAt     int64                   `json:"approval_expires_at,omitempty"`
	RetentionUntil        int64                   `json:"retention_until"`
}

type FederationExchangeResultRequest struct {
	Version         uint16                     `json:"version"`
	ExecutionIntent decision.Intent            `json:"execution_intent"`
	Decision        decision.Decision          `json:"decision"`
	Result          decision.FederationResult  `json:"result"`
	Content         *decision.FederatedContent `json:"content,omitempty"`
}

type FederationExchangeResultResponse struct {
	Version    uint16                  `json:"version"`
	ExchangeID string                  `json:"exchange_id"`
	State      FederationExchangeState `json:"state"`
	UpdatedAt  int64                   `json:"updated_at"`
}

func (client *Client) SubmitFederationExchange(ctx context.Context, envelope FederationExchangeRequest) (FederationExchangeResponse, error) {
	if client == nil || client.endpoint == nil || client.httpClient == nil {
		return FederationExchangeResponse{}, fmt.Errorf("decisionhttp: client is not initialized")
	}
	if envelope.Version != FederationExchangeVersion {
		return FederationExchangeResponse{}, fmt.Errorf("decisionhttp: invalid federation exchange version")
	}
	if err := envelope.Content.VerifyIntent(envelope.Intent); err != nil {
		return FederationExchangeResponse{}, err
	}
	key, err := envelope.Intent.Hash()
	if err != nil {
		return FederationExchangeResponse{}, err
	}
	var response FederationExchangeResponse
	if err := client.workflowJSON(ctx, http.MethodPost, "/v1/federation/exchanges", envelope, key, &response); err != nil {
		return FederationExchangeResponse{}, err
	}
	if response.Version != FederationExchangeVersion || !validFederationIdentifier(response.ExchangeID) || !validAccountSlug(response.AccountSlug) {
		return FederationExchangeResponse{}, fmt.Errorf("decisionhttp: invalid federation exchange response")
	}
	if err := response.Decision.Validate(); err != nil {
		return FederationExchangeResponse{}, err
	}
	if response.Decision.IntentHash != key || response.Decision.TenantID != envelope.Intent.TenantID || response.Decision.AgentID != envelope.Intent.AgentID {
		return FederationExchangeResponse{}, fmt.Errorf("decisionhttp: federation exchange response binding mismatch")
	}
	switch response.State {
	case FederationExchangeDenied, FederationExchangeAuthorized:
	case FederationExchangeApprovalPending:
		if !validFederationIdentifier(response.ApprovalTransactionID) || response.ApprovalExpiresAt <= 0 {
			return FederationExchangeResponse{}, fmt.Errorf("decisionhttp: invalid federation approval response")
		}
	default:
		return FederationExchangeResponse{}, fmt.Errorf("decisionhttp: invalid federation exchange response state %q", response.State)
	}
	return response, nil
}

func (client *Client) SubmitFederationExchangeResult(ctx context.Context, envelope FederationExchangeResultRequest) (FederationExchangeResultResponse, error) {
	if client == nil || client.endpoint == nil || client.httpClient == nil {
		return FederationExchangeResultResponse{}, fmt.Errorf("decisionhttp: client is not initialized")
	}
	if err := validateFederationResultEnvelope(envelope); err != nil {
		return FederationExchangeResultResponse{}, err
	}
	var response FederationExchangeResultResponse
	if err := client.workflowJSON(ctx, http.MethodPost, "/v1/federation/exchanges/result", envelope, envelope.Result.ID, &response); err != nil {
		return FederationExchangeResultResponse{}, err
	}
	if response.Version != FederationExchangeVersion || response.ExchangeID != envelope.Result.ExchangeID || response.UpdatedAt <= 0 {
		return FederationExchangeResultResponse{}, fmt.Errorf("decisionhttp: invalid federation result response")
	}
	switch response.State {
	case FederationExchangeCompleted, FederationExchangeFailed, FederationExchangeDenied, FederationExchangeApprovalPending:
	default:
		return FederationExchangeResultResponse{}, fmt.Errorf("decisionhttp: invalid federation result state %q", response.State)
	}
	return response, nil
}

func validateFederationResultEnvelope(envelope FederationExchangeResultRequest) error {
	if envelope.Version != FederationExchangeVersion {
		return fmt.Errorf("decisionhttp: invalid federation result version")
	}
	if err := envelope.ExecutionIntent.Validate(); err != nil {
		return err
	}
	if err := envelope.Decision.Validate(); err != nil {
		return err
	}
	if err := envelope.Result.Validate(); err != nil {
		return err
	}
	intentHash, err := envelope.ExecutionIntent.Hash()
	if err != nil || envelope.Decision.IntentHash != intentHash || envelope.Result.IntentHash != intentHash || envelope.Result.DecisionID != envelope.Decision.ID || envelope.Result.TenantID != envelope.ExecutionIntent.TenantID || envelope.Result.AgentID != envelope.ExecutionIntent.AgentID {
		return fmt.Errorf("decisionhttp: federation result authorization mismatch")
	}
	if envelope.Content == nil {
		if envelope.Result.ResponseDisclosureHash != "" {
			return fmt.Errorf("decisionhttp: federation result response content is missing")
		}
		return nil
	}
	if err := envelope.Content.Validate(); err != nil {
		return err
	}
	disclosureHash, err := envelope.Content.Disclosure.Hash()
	if err != nil || disclosureHash != envelope.Result.ResponseDisclosureHash {
		return fmt.Errorf("decisionhttp: federation result response binding mismatch")
	}
	return nil
}

func validAccountSlug(value string) bool {
	if len(value) < 1 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validFederationIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || (index > 0 && strings.ContainsRune("._:-", character)) {
			continue
		}
		return false
	}
	return true
}

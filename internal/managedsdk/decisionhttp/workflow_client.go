// SPDX-License-Identifier: AGPL-3.0-or-later

package decisionhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/pilot-protocol/common/decision"
)

// BeginWorkflow creates or retrieves the deterministic approval transaction
// bound to an already-issued approval_required decision.
func (client *Client) BeginWorkflow(ctx context.Context, envelope WorkflowBeginEnvelope) (WorkflowRecord, error) {
	if err := envelope.Intent.Validate(); err != nil {
		return WorkflowRecord{}, err
	}
	if err := envelope.Initial.Validate(); err != nil {
		return WorkflowRecord{}, err
	}
	if envelope.Disclosure != nil {
		if err := envelope.Disclosure.VerifyIntent(envelope.Intent); err != nil {
			return WorkflowRecord{}, err
		}
	}
	key, err := envelope.Initial.Hash()
	if err != nil {
		return WorkflowRecord{}, err
	}
	var record WorkflowRecord
	if err := client.workflowJSON(ctx, http.MethodPost, "/v1/workflow/begin", envelope, key, &record); err != nil {
		return WorkflowRecord{}, err
	}
	if err := validateWorkflowRecord(record); err != nil {
		return WorkflowRecord{}, fmt.Errorf("decisionhttp: invalid workflow record: %w", err)
	}
	return record, nil
}

// VoteWorkflow submits one signed vote. Replaying the same vote returns the
// durable record; a different vote from the same key is rejected by the
// authority.
func (client *Client) VoteWorkflow(ctx context.Context, transactionID string, vote decision.ApprovalVote) (WorkflowRecord, error) {
	if err := vote.Validate(); err != nil {
		return WorkflowRecord{}, err
	}
	key, err := vote.Hash()
	if err != nil {
		return WorkflowRecord{}, err
	}
	var record WorkflowRecord
	if err := client.workflowJSON(ctx, http.MethodPost, "/v1/workflow/vote", WorkflowVoteEnvelope{TransactionID: transactionID, Vote: vote}, key, &record); err != nil {
		return WorkflowRecord{}, err
	}
	if err := validateWorkflowRecord(record); err != nil {
		return WorkflowRecord{}, fmt.Errorf("decisionhttp: invalid workflow record: %w", err)
	}
	return record, nil
}

// ExecuteWorkflow submits a new workload-signed execution intent and returns
// the one canonical decision consumed for that approval transaction. Callers
// must still locally verify this signed decision before performing a side
// effect.
func (client *Client) ExecuteWorkflow(ctx context.Context, transactionID string, intent decision.Intent) (decision.Decision, error) {
	if err := intent.Validate(); err != nil {
		return decision.Decision{}, err
	}
	if intent.Signature == "" {
		return decision.Decision{}, fmt.Errorf("decisionhttp: workflow execution intent must be signed")
	}
	key, err := intent.Hash()
	if err != nil {
		return decision.Decision{}, err
	}
	var result decision.Decision
	if err := client.workflowJSON(ctx, http.MethodPost, "/v1/workflow/execute", WorkflowExecuteEnvelope{TransactionID: transactionID, Intent: intent}, key, &result); err != nil {
		return decision.Decision{}, err
	}
	if err := result.Validate(); err != nil {
		return decision.Decision{}, fmt.Errorf("decisionhttp: invalid workflow execution decision: %w", err)
	}
	return result, nil
}

func (client *Client) WorkflowStatus(ctx context.Context, transactionID string) (WorkflowRecord, error) {
	return client.workflowStatus(ctx, "/v1/workflow-status", transactionID)
}

// ManagementWorkflowStatus returns a workflow record through the separately
// protected operator route. It is intended for a client configured with the
// authority's management mTLS identity; it does not grant an uncredentialed
// caller any management authority itself.
func (client *Client) ManagementWorkflowStatus(ctx context.Context, transactionID string) (WorkflowRecord, error) {
	return client.workflowStatus(ctx, "/v1/manage/workflow-status", transactionID)
}

// ManagementWorkflows retrieves a bounded tenant-scoped list through the
// separately protected operator route. The caller supplies management mTLS;
// this method validates each returned workflow before exposing it to a UI or
// CLI.
func (client *Client) ManagementWorkflows(ctx context.Context, tenantID string, limit int) ([]WorkflowRecord, error) {
	if client == nil || client.endpoint == nil || client.httpClient == nil {
		return nil, fmt.Errorf("decisionhttp: client is not initialized")
	}
	if !validWorkflowTenant(tenantID) || limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("decisionhttp: workflow tenant and limit are required")
	}
	endpoint := *client.endpoint
	endpoint.Path = "/v1/manage/workflows"
	query := url.Values{}
	query.Set("tenant_id", tenantID)
	query.Set("limit", strconv.Itoa(limit))
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	var response WorkflowListResponse
	if err := client.workflowResponse(request, &response); err != nil {
		return nil, err
	}
	if len(response.Workflows) > limit {
		return nil, fmt.Errorf("decisionhttp: workflow response exceeds requested limit")
	}
	for _, record := range response.Workflows {
		if record.Transaction.TenantID != tenantID {
			return nil, fmt.Errorf("decisionhttp: workflow tenant binding mismatch")
		}
		if err := validateWorkflowRecord(record); err != nil {
			return nil, fmt.Errorf("decisionhttp: invalid workflow record: %w", err)
		}
	}
	return append([]WorkflowRecord(nil), response.Workflows...), nil
}

func (client *Client) workflowStatus(ctx context.Context, path, transactionID string) (WorkflowRecord, error) {
	if client == nil || client.endpoint == nil || client.httpClient == nil {
		return WorkflowRecord{}, fmt.Errorf("decisionhttp: client is not initialized")
	}
	if strings.TrimSpace(transactionID) == "" {
		return WorkflowRecord{}, fmt.Errorf("decisionhttp: workflow transaction identifier is required")
	}
	endpoint := *client.endpoint
	endpoint.Path = path
	query := url.Values{}
	query.Set("transaction_id", transactionID)
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return WorkflowRecord{}, err
	}
	request.Header.Set("Accept", "application/json")
	var record WorkflowRecord
	if err := client.workflowResponse(request, &record); err != nil {
		return WorkflowRecord{}, err
	}
	if err := validateWorkflowRecord(record); err != nil {
		return WorkflowRecord{}, fmt.Errorf("decisionhttp: invalid workflow record: %w", err)
	}
	return record, nil
}

// CancelWorkflow requests an authority-signed terminal cancellation through
// the separately protected management route. It binds retries to the exact
// transaction and reason, so a retry cannot accidentally mutate a different
// management action.
func (client *Client) CancelWorkflow(ctx context.Context, transactionID, reason string) (WorkflowRecord, error) {
	transactionID = strings.TrimSpace(transactionID)
	reason = strings.TrimSpace(reason)
	if transactionID == "" || reason == "" {
		return WorkflowRecord{}, fmt.Errorf("decisionhttp: workflow transaction identifier and cancellation reason are required")
	}
	sum := sha256.Sum256([]byte(transactionID + "\x00" + reason))
	var record WorkflowRecord
	if err := client.workflowJSON(ctx, http.MethodPost, "/v1/manage/workflow-cancel", WorkflowCancelRequest{
		TransactionID: transactionID,
		Reason:        reason,
	}, hex.EncodeToString(sum[:]), &record); err != nil {
		return WorkflowRecord{}, err
	}
	if err := validateWorkflowRecord(record); err != nil {
		return WorkflowRecord{}, fmt.Errorf("decisionhttp: invalid workflow record: %w", err)
	}
	return record, nil
}

func (client *Client) workflowJSON(ctx context.Context, method, path string, value any, idempotencyKey string, target any) error {
	if client == nil || client.endpoint == nil || client.httpClient == nil {
		return fmt.Errorf("decisionhttp: client is not initialized")
	}
	body, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("decisionhttp: encode workflow request: %w", err)
	}
	endpoint := *client.endpoint
	endpoint.Path = path
	endpoint.RawQuery = ""
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("decisionhttp: build workflow request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	return client.workflowResponse(request, target)
}

func (client *Client) workflowResponse(request *http.Request, target any) error {
	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("decisionhttp: workflow request: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, client.maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("decisionhttp: read workflow response: %w", err)
	}
	if int64(len(body)) > client.maxResponseBytes {
		return fmt.Errorf("decisionhttp: workflow response exceeds %d bytes", client.maxResponseBytes)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("decisionhttp: workflow authority returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decisionhttp: decode workflow response: %w", err)
	}
	return ensureEOF(decoder)
}

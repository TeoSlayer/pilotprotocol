// SPDX-License-Identifier: AGPL-3.0-or-later

package enterprisecontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/pilot-protocol/common/actioncontinuation"
	"github.com/pilot-protocol/common/actionhook"
	"github.com/pilot-protocol/common/actionregistry"
	"github.com/pilot-protocol/common/authority"
	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/common/decisionhttp"
)

type actionHookState struct {
	selected          bool
	managed           bool
	federated         bool
	exchangeID        string
	intent            decision.Intent
	result            decision.Decision
	continuationID    string
	continuationLease string
}

// ActionHook returns this attachment as a universal hook only when an
// operator explicitly selected a non-off profile. A nil return is the hard
// compatibility boundary used by unmanaged nodes.
func (runtime *Runtime) ActionHook() actionhook.Hook {
	if runtime == nil || runtime.actionRegistry == nil || runtime.actionProfile.Mode.Normalize() == actionregistry.ModeOff {
		return nil
	}
	return runtime
}

// ActionArtifacts returns the locally verified signed wire objects behind a
// managed preflight. Governed transport adapters need these exact objects for
// receiver-side verification; local/observe-only hooks intentionally expose
// none.
func (runtime *Runtime) ActionArtifacts(preflight actionhook.Preflight) (decision.Intent, decision.Decision, bool) {
	state, ok := preflight.State.(actionHookState)
	if !ok || !state.selected || !state.managed || state.intent.ID == "" || state.result.ID == "" {
		return decision.Intent{}, decision.Decision{}, false
	}
	return state.intent, state.result, true
}

// BeforeAction evaluates only explicitly selected actions. Local enforcement
// uses the signed policy bundle already installed on the node; managed
// enforcement obtains and verifies a fresh signed authority Decision. Observe
// mode evaluates locally but cannot block the adapter.
func (runtime *Runtime) BeforeAction(ctx context.Context, envelope actionhook.Envelope) (actionhook.Preflight, error) {
	if err := envelope.Validate(); err != nil {
		return actionhook.Preflight{}, err
	}
	runtime.mu.Lock()
	registry := runtime.actionRegistry
	profile := runtime.actionProfile
	agentID := runtime.actionAgentID
	risk := runtime.actionRisk
	localPolicy := runtime.localPolicy
	tenantID := runtime.tenantID
	continuations := runtime.continuations
	fleetControl, fleetControlled := runtime.fleetControl, runtime.fleetControlFound
	runtime.mu.Unlock()
	if fleetControlled && fleetControl.Quarantined {
		if profile.Mode.Normalize() == actionregistry.ModeObserve {
			return actionhook.Preflight{Outcome: decision.Allow, Reasons: []string{"observe:fleet_quarantine"}, ObserveOnly: true, State: actionHookState{selected: true}}, nil
		}
		return actionhook.Preflight{Outcome: decision.Deny, Reasons: []string{"fleet_quarantine"}, State: actionHookState{selected: true}}, nil
	}
	if registry == nil || !profile.AppliesTo(registry, envelope.Action) {
		return actionhook.Preflight{Outcome: decision.Allow, ObserveOnly: true, State: actionHookState{}}, nil
	}
	definition, found := registry.Resolve(envelope.Action)
	if !found {
		return actionhook.Preflight{}, fmt.Errorf("enterprise control: action %q is not registered", envelope.Action)
	}
	canonical := definition.Name

	var intent decision.Intent
	var result decision.Decision
	managed := profile.Mode.Normalize() == actionregistry.ModeManagedEnforce
	if managed {
		if definition.Privacy == actionregistry.PrivacyFederatedContent && envelope.FederatedContent == nil {
			return actionhook.Preflight{}, fmt.Errorf("enterprise control: managed action %q requires hosted federation content", canonical)
		}
		if definition.Resumable && continuations != nil {
			resumed, exists, resumeErr := runtime.resumeAction(ctx, envelope, canonical)
			if resumeErr != nil || exists {
				return resumed, resumeErr
			}
		}
		var err error
		if envelope.FederatedContent != nil {
			var exchange decisionhttp.FederationExchangeResponse
			intent, exchange, err = runtime.AuthorizeOutboundFederatedContent(ctx, canonical, envelope.Resource, envelope.FederatedContent.Clone())
			result = exchange.Decision
			if err == nil {
				envelope.PayloadHash = intent.PayloadHash
			}
			if err != nil {
				return actionhook.Preflight{}, err
			}
			preflight := actionhook.Preflight{
				Outcome: result.Outcome, Reasons: append([]string(nil), result.Reasons...),
				Constraints: append([]decision.Constraint(nil), result.Constraints...),
				Reference: actionhook.DecisionReference{
					IntentID: intent.ID, DecisionID: result.ID, PolicyRevision: result.PolicyRevision, ProviderID: result.ProviderID,
					ExchangeID:          exchange.ExchangeID,
					ApprovalTransaction: exchange.ApprovalTransactionID, ApprovalExpiresAt: exchange.ApprovalExpiresAt,
				},
				State: actionHookState{selected: true, managed: true, federated: true, exchangeID: exchange.ExchangeID, intent: intent, result: result},
			}
			if result.Outcome == decision.ApprovalRequired && definition.Resumable && continuations != nil {
				pending, pendingErr := actioncontinuation.NewPending(tenantID, agentID, envelope, preflight.Reference, exchange.ApprovalTransactionID, time.Unix(exchange.ApprovalExpiresAt, 0))
				if pendingErr != nil {
					return actionhook.Preflight{}, pendingErr
				}
				stored, storeErr := continuations.PutPending(ctx, pending)
				if storeErr != nil {
					return actionhook.Preflight{}, fmt.Errorf("enterprise control: persist hosted approval continuation: %w", storeErr)
				}
				preflight.Reference.ApprovalTransaction = stored.ApprovalTransaction
				preflight.Reference.ApprovalExpiresAt = stored.ExpiresAt
			}
			return preflight, nil
		}
		intent, result, err = runtime.AuthorizeOutbound(ctx, canonical, envelope.Resource, envelope.PayloadHash)
		if err != nil {
			return actionhook.Preflight{}, err
		}
	} else {
		if localPolicy == nil {
			return actionhook.Preflight{}, fmt.Errorf("enterprise control: local action policy is unavailable")
		}
		intent = decision.Intent{
			Version: decision.SchemaVersion, ID: envelope.ID, TenantID: tenantID, AgentID: agentID,
			Action: canonical, Resource: envelope.Resource, PayloadHash: envelope.PayloadHash, Risk: risk,
		}
		var err error
		result, err = localPolicy.Authorize(ctx, intent)
		if err != nil {
			if profile.Mode.Normalize() == actionregistry.ModeObserve {
				return actionhook.Preflight{
					Outcome: decision.Allow, Reasons: []string{"observe:evaluation_unavailable"}, ObserveOnly: true,
					State: actionHookState{selected: true},
				}, nil
			}
			return actionhook.Preflight{}, fmt.Errorf("enterprise control: evaluate local action policy: %w", err)
		}
	}
	preflight := actionhook.Preflight{
		Outcome: result.Outcome, Reasons: append([]string(nil), result.Reasons...),
		Constraints: append([]decision.Constraint(nil), result.Constraints...),
		Reference: actionhook.DecisionReference{
			IntentID: intent.ID, DecisionID: result.ID, PolicyRevision: result.PolicyRevision, ProviderID: result.ProviderID,
		},
		ObserveOnly: profile.Mode.Normalize() == actionregistry.ModeObserve,
		State:       actionHookState{selected: true, managed: managed, intent: intent, result: result},
	}
	if managed && result.Outcome == decision.ApprovalRequired && definition.Resumable && continuations != nil {
		record, err := runtime.outboundClient.BeginWorkflow(ctx, decisionhttp.WorkflowBeginEnvelope{Intent: intent, Initial: result})
		if err != nil {
			return actionhook.Preflight{}, fmt.Errorf("enterprise control: begin approval workflow: %w", err)
		}
		pending, err := actioncontinuation.NewPending(tenantID, agentID, envelope, preflight.Reference, record.Transaction.ID, time.Unix(record.Transaction.ExpiresAt, 0))
		if err != nil {
			return actionhook.Preflight{}, err
		}
		stored, err := continuations.PutPending(ctx, pending)
		if err != nil {
			return actionhook.Preflight{}, fmt.Errorf("enterprise control: persist approval continuation: %w", err)
		}
		preflight.Reference.ApprovalTransaction = stored.ApprovalTransaction
		preflight.Reference.ApprovalExpiresAt = stored.ExpiresAt
	}
	return preflight, nil
}

func (runtime *Runtime) resumeAction(ctx context.Context, envelope actionhook.Envelope, canonicalAction string) (actionhook.Preflight, bool, error) {
	runtime.mu.Lock()
	store := runtime.continuations
	client := runtime.outboundClient
	tenantID, agentID := runtime.tenantID, runtime.actionAgentID
	runtime.mu.Unlock()
	if store == nil || client == nil {
		return actionhook.Preflight{}, false, nil
	}
	fingerprint := actioncontinuation.Fingerprint(tenantID, agentID, canonicalAction, envelope.Resource, envelope.PayloadHash, envelope.AdapterID, envelope.ResumeToken)
	continuation, err := store.FindActive(ctx, fingerprint)
	if errors.Is(err, actioncontinuation.ErrNotFound) {
		return actionhook.Preflight{}, false, nil
	}
	if err != nil {
		return actionhook.Preflight{}, true, err
	}
	reference := continuation.InitialDecision
	reference.ApprovalTransaction = continuation.ApprovalTransaction
	reference.ApprovalExpiresAt = continuation.ExpiresAt
	switch continuation.State {
	case actioncontinuation.StateExecuting:
		return actionhook.Preflight{}, true, fmt.Errorf("enterprise control: approval continuation %s is already executing", continuation.ID)
	case actioncontinuation.StateFailed:
		return actionhook.Preflight{}, true, fmt.Errorf("enterprise control: approval continuation %s is fail-closed after %s", continuation.ID, continuation.FailureCode)
	case actioncontinuation.StatePending:
	default:
		return actionhook.Preflight{}, true, fmt.Errorf("enterprise control: approval continuation %s is not resumable", continuation.ID)
	}
	workflow, err := client.WorkflowStatus(ctx, continuation.ApprovalTransaction)
	if err != nil {
		return actionhook.Preflight{}, true, fmt.Errorf("enterprise control: approval status: %w", err)
	}
	if !workflowMatchesContinuation(workflow, continuation) {
		return actionhook.Preflight{}, true, fmt.Errorf("enterprise control: approval workflow no longer matches local continuation")
	}
	if workflow.Cancellation != nil {
		return actionhook.Preflight{
			Outcome: decision.Deny, Reasons: []string{"approval:cancelled"}, Reference: reference,
			State: actionHookState{selected: true},
		}, true, nil
	}
	if workflow.Certificate == nil {
		return actionhook.Preflight{
			Outcome: decision.ApprovalRequired, Reasons: []string{"approval:pending"}, Reference: reference,
			State: actionHookState{selected: true},
		}, true, nil
	}
	claimed, lease, err := store.ClaimResume(ctx, continuation.ID)
	if err != nil {
		return actionhook.Preflight{}, true, fmt.Errorf("enterprise control: claim approval continuation: %w", err)
	}
	intent, err := runtime.newWorkflowExecutionIntent(ctx, workflow.Transaction, workflow.Certificate.ExpiresAt)
	if err != nil {
		_, _ = store.Finish(context.Background(), claimed.ID, lease, false, "intent_creation_failed")
		return actionhook.Preflight{}, true, err
	}
	result, err := client.ExecuteWorkflow(ctx, workflow.Transaction.ID, intent)
	if err != nil {
		_, _ = store.Finish(context.Background(), claimed.ID, lease, false, "workflow_execution_failed")
		return actionhook.Preflight{}, true, fmt.Errorf("enterprise control: execute approved workflow: %w", err)
	}
	if err := runtime.enforcer.Verify(ctx, intent, result); err != nil {
		_, _ = store.Finish(context.Background(), claimed.ID, lease, false, "decision_verification_failed")
		return actionhook.Preflight{}, true, fmt.Errorf("enterprise control: verify approved workflow decision: %w", err)
	}
	return actionhook.Preflight{
		Outcome: result.Outcome, Reasons: append([]string(nil), result.Reasons...), Constraints: append([]decision.Constraint(nil), result.Constraints...),
		Reference: actionhook.DecisionReference{
			IntentID: intent.ID, DecisionID: result.ID, PolicyRevision: result.PolicyRevision, ProviderID: result.ProviderID,
			ApprovalTransaction: continuation.ApprovalTransaction, ApprovalExpiresAt: continuation.ExpiresAt,
		},
		State: actionHookState{
			selected: true, managed: true, federated: reference.ExchangeID != "", exchangeID: reference.ExchangeID, intent: intent, result: result,
			continuationID: claimed.ID, continuationLease: lease,
		},
	}, true, nil
}

func workflowMatchesContinuation(workflow decisionhttp.WorkflowRecord, continuation actioncontinuation.Record) bool {
	transaction := workflow.Transaction
	return transaction.ID == continuation.ApprovalTransaction && transaction.TenantID == continuation.TenantID &&
		transaction.AgentID == continuation.AgentID && transaction.Action == continuation.Action &&
		transaction.Resource == continuation.Resource && transaction.PayloadHash == continuation.PayloadHash &&
		transaction.PolicyRevision == continuation.InitialDecision.PolicyRevision
}

func (runtime *Runtime) newWorkflowExecutionIntent(ctx context.Context, transaction decision.ApprovalTransaction, certificateExpiresAt int64) (decision.Intent, error) {
	if !runtime.HasOutboundDecisions() {
		return decision.Intent{}, fmt.Errorf("enterprise control: outbound decisions are not configured")
	}
	nonce, err := decision.NewNonce()
	if err != nil {
		return decision.Intent{}, err
	}
	runtime.mu.Lock()
	keyID := runtime.outboundKeyID
	privateKey := append(ed25519.PrivateKey(nil), runtime.outboundPrivate...)
	mandateID, audience, purpose := runtime.outboundMandateID, runtime.outboundAudience, runtime.outboundPurpose
	runtime.mu.Unlock()
	publicKey, keyErr := runtime.trust.IntentKey(ctx, transaction.TenantID, transaction.AgentID, keyID)
	if keyErr != nil || !bytes.Equal(publicKey, privateKey.Public().(ed25519.PublicKey)) {
		return decision.Intent{}, fmt.Errorf("enterprise control: workflow intent key is no longer active")
	}
	now := time.Now().UTC()
	expiresAt := now.Add(2 * time.Minute).Unix()
	if certificateExpiresAt < expiresAt {
		expiresAt = certificateExpiresAt
	}
	if expiresAt <= now.Unix() {
		return decision.Intent{}, fmt.Errorf("enterprise control: approval certificate has expired")
	}
	intent := decision.Intent{
		Version: decision.SchemaVersion, ID: "resume-" + nonce,
		TenantID: transaction.TenantID, AgentID: transaction.AgentID,
		Action: transaction.Action, Resource: transaction.Resource, PayloadHash: transaction.PayloadHash, Risk: transaction.Risk,
		MandateID: mandateID, Audience: audience, Purpose: purpose,
		IssuedAt: now.Unix(), ExpiresAt: expiresAt, Nonce: nonce, KeyID: keyID,
	}
	if err := intent.Sign(privateKey); err != nil {
		return decision.Intent{}, err
	}
	return intent, nil
}

// AfterAction writes signed enforcement evidence when receipt signing is
// configured. It intentionally does nothing for unselected/local-only
// actions. A caller must never retry a side effect because this method fails.
func (runtime *Runtime) AfterAction(ctx context.Context, envelope actionhook.Envelope, preflight actionhook.Preflight, observed actionhook.ObservedResult) error {
	if err := envelope.Validate(); err != nil {
		return err
	}
	if err := observed.Validate(); err != nil {
		return err
	}
	state, ok := preflight.State.(actionHookState)
	if !ok || !state.selected {
		return nil
	}
	var continuationErr error
	if state.continuationID != "" {
		succeeded := observed.Status == actionhook.StatusSucceeded
		failureCode := observed.ErrorCode
		if failureCode == "" && !succeeded {
			failureCode = "adapter_did_not_execute"
		}
		_, continuationErr = runtime.continuations.Finish(ctx, state.continuationID, state.continuationLease, succeeded, failureCode)
	}
	if !state.managed {
		return continuationErr
	}
	var federationErr error
	if state.federated {
		federationErr = runtime.reportFederationResult(ctx, state, observed)
	}
	var enforcementResult decision.EnforcementResult
	switch state.result.Outcome {
	case decision.Deny:
		enforcementResult = decision.Denied
	case decision.ApprovalRequired:
		enforcementResult = decision.ApprovalPending
	case decision.Allow, decision.Constrain:
		if observed.Status == actionhook.StatusSucceeded {
			enforcementResult = decision.Enforced
		} else {
			enforcementResult = decision.Failed
		}
	default:
		return fmt.Errorf("enterprise control: cannot receipt invalid outcome %q", state.result.Outcome)
	}
	var receiptErr error
	if runtime.receipts != nil {
		recorder := transportReceiptRecorder{signer: runtime.receipts, enforcementPoint: envelope.AdapterID}
		receiptErr = recorder.RecordGovernedResultReceipt(ctx, state.intent, state.result, enforcementResult, time.Unix(observed.ObservedAt, 0))
	}
	activityErr := runtime.recordActionActivity(ctx, envelope, state, enforcementResult, observed.ObservedAt)
	return errors.Join(continuationErr, federationErr, receiptErr, activityErr)
}

func (runtime *Runtime) reportFederationResult(ctx context.Context, state actionHookState, observed actionhook.ObservedResult) error {
	if state.exchangeID == "" || state.intent.ID == "" || state.result.ID == "" {
		return fmt.Errorf("enterprise control: hosted federation result is missing execution state")
	}
	var status decision.FederationResultStatus
	errorCode := observed.ErrorCode
	switch observed.Status {
	case actionhook.StatusSucceeded:
		status = decision.FederationResultSucceeded
	case actionhook.StatusFailed:
		status = decision.FederationResultFailed
		if errorCode == "" {
			errorCode = "adapter_failed"
		}
	case actionhook.StatusSkipped:
		status = decision.FederationResultSkipped
	case actionhook.StatusDenied:
		status = decision.FederationResultDenied
	case actionhook.StatusApprovalPending:
		status = decision.FederationResultApprovalPending
	default:
		return fmt.Errorf("enterprise control: unsupported hosted federation result %q", observed.Status)
	}
	runtime.mu.Lock()
	client := runtime.outboundClient
	keyID := runtime.outboundKeyID
	privateKey := append(ed25519.PrivateKey(nil), runtime.outboundPrivate...)
	timeout := runtime.outboundTimeout
	runtime.mu.Unlock()
	if client == nil || keyID == "" || len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("enterprise control: hosted federation result client is unavailable")
	}
	var responseDisclosure *decision.DisclosureBinding
	var responseContent *decision.FederatedContent
	if observed.FederatedContent != nil {
		cloned := observed.FederatedContent.Clone()
		responseDisclosure = &cloned.Disclosure
		responseContent = &cloned
	}
	result, err := decision.NewFederationResult(state.exchangeID, state.intent, state.result, status, errorCode, responseDisclosure, time.Unix(observed.ObservedAt, 0), keyID)
	if err != nil {
		return err
	}
	if err := result.Sign(privateKey); err != nil {
		return err
	}
	reportContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, err = client.SubmitFederationExchangeResult(reportContext, decisionhttp.FederationExchangeResultRequest{
		Version: decisionhttp.FederationExchangeVersion, ExecutionIntent: state.intent,
		Decision: state.result, Result: result, Content: responseContent,
	})
	if err != nil {
		return fmt.Errorf("enterprise control: report hosted federation result: %w", err)
	}
	return nil
}

func (runtime *Runtime) recordActionActivity(ctx context.Context, envelope actionhook.Envelope, state actionHookState, enforcementResult decision.EnforcementResult, observedAt int64) error {
	runtime.mu.Lock()
	client := runtime.rolloutClient
	keyID := runtime.outboundKeyID
	privateKey := append(ed25519.PrivateKey(nil), runtime.outboundPrivate...)
	runtime.mu.Unlock()
	if client == nil || keyID == "" || len(privateKey) != ed25519.PrivateKeySize || state.intent.ID == "" || state.result.ID == "" {
		return nil
	}
	duration := time.Duration(0)
	if observedAt > envelope.CreatedAt {
		duration = time.Duration(observedAt-envelope.CreatedAt) * time.Second
	}
	activity, err := authority.NewFleetActivity(state.intent, state.result, enforcementResult, duration, keyID, observedAt)
	if err != nil {
		return err
	}
	if err := activity.Sign(privateKey); err != nil {
		return err
	}
	return client.ReportFleetActivity(ctx, activity)
}

var _ actionhook.Hook = (*Runtime)(nil)

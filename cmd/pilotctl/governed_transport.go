// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pilot-protocol/common/actionhook"
	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/dataexchange"
	"github.com/pilot-protocol/pilotprotocol/internal/enterprisecontrol"
)

const maxInlineHostedFederationBytes int64 = 16 << 20

// outboundDecisionRequester is intentionally narrow so the transport command
// code never gains access to a configured private key. The enterprise-control
// runtime owns signing, request construction, and local verification.
type outboundDecisionRequester interface {
	HasOutboundDecisions() bool
	AuthorizeOutbound(context.Context, string, string, string) (decision.Intent, decision.Decision, error)
}

var loadOutboundDecisionRequester = func(path string) (outboundDecisionRequester, error) {
	return enterprisecontrol.Load(path)
}

type governedOutboundSender struct {
	requester outboundDecisionRequester
	resource  string
	hook      actionhook.Hook
	artifacts interface {
		ActionArtifacts(actionhook.Preflight) (decision.Intent, decision.Decision, bool)
	}
	contentBuilder interface {
		NewOutboundFederatedContent(string, string, []byte) (decision.FederatedContent, error)
		NewOutboundFederatedResponseContent(string, string, []byte) (decision.FederatedContent, error)
	}
	mu          sync.Mutex
	attempts    map[string]governedActionAttempt
	disclosures map[string]decision.DisclosureBinding
}

type governedActionAttempt struct {
	envelope  actionhook.Envelope
	preflight actionhook.Preflight
}

type outboundActionHookProvider interface {
	ActionHook() actionhook.Hook
	ActionArtifacts(actionhook.Preflight) (decision.Intent, decision.Decision, bool)
}

type outboundFederationContentProvider interface {
	NewOutboundFederatedContent(string, string, []byte) (decision.FederatedContent, error)
	NewOutboundFederatedResponseContent(string, string, []byte) (decision.FederatedContent, error)
}

// governedOutboundFromFlags is opt-in. Without the attachment argument (or
// environment equivalent), ordinary open-agent transport behavior is
// unchanged. The resource is explicit because it is owned by the receiver;
// inferring one from a sender address would create an authorization bypass.
func governedOutboundFromFlags(flags map[string]string) (*governedOutboundSender, error) {
	path := strings.TrimSpace(flagString(flags, "enterprise-control", ""))
	if path == "" {
		path = strings.TrimSpace(os.Getenv("PILOT_ENTERPRISE_CONTROL"))
	}
	if path == "" {
		return nil, nil
	}
	resource := strings.TrimSpace(flagString(flags, "governed-resource", ""))
	if resource == "" {
		resource = strings.TrimSpace(os.Getenv("PILOT_GOVERNED_RESOURCE"))
	}
	if resource == "" {
		return nil, fmt.Errorf("--governed-resource is required with --enterprise-control")
	}
	requester, err := loadOutboundDecisionRequester(path)
	if err != nil {
		return nil, fmt.Errorf("load enterprise control: %w", err)
	}
	if !requester.HasOutboundDecisions() {
		return nil, fmt.Errorf("enterprise control does not configure outbound_decisions")
	}
	sender := &governedOutboundSender{requester: requester, resource: resource, attempts: make(map[string]governedActionAttempt), disclosures: make(map[string]decision.DisclosureBinding)}
	if provider, ok := requester.(outboundActionHookProvider); ok {
		sender.hook = provider.ActionHook()
		sender.artifacts = provider
	}
	if provider, ok := requester.(outboundFederationContentProvider); ok {
		sender.contentBuilder = provider
	}
	return sender, nil
}

func (sender *governedOutboundSender) authorizeFrame(ctx context.Context, frame *dataexchange.Frame) (decision.Intent, decision.Decision, error) {
	if sender == nil || sender.requester == nil || frame == nil {
		return decision.Intent{}, decision.Decision{}, fmt.Errorf("governed outbound sender is not initialized")
	}
	action := dataexchange.GovernedAction(frame.Type)
	if action == "" {
		return decision.Intent{}, decision.Decision{}, fmt.Errorf("frame type %s cannot be sent as governed data", dataexchange.TypeName(frame.Type))
	}
	payloadHash := dataexchange.GovernedPayloadHash(frame.Type, frame.Filename, frame.Payload)
	var content *decision.FederatedContent
	if sender.hook != nil && sender.contentBuilder != nil {
		if int64(len(frame.Payload)) > maxInlineHostedFederationBytes {
			return decision.Intent{}, decision.Decision{}, fmt.Errorf("hosted federation inline content exceeds %d bytes", maxInlineHostedFederationBytes)
		}
		created, contentErr := sender.contentBuilder.NewOutboundFederatedContent(frameContentType(frame.Type), frame.Filename, frame.Payload)
		if contentErr != nil {
			return decision.Intent{}, decision.Decision{}, contentErr
		}
		content = &created
		payloadHash, _ = created.Disclosure.Hash()
	}
	intent, result, err := sender.authorizeAction(ctx, action, payloadHash, "frame:"+action+":"+payloadHash, content)
	if err != nil {
		return decision.Intent{}, decision.Decision{}, err
	}
	if err := outboundDecisionPermits(result); err != nil {
		return intent, result, err
	}
	if content != nil {
		sender.mu.Lock()
		if sender.disclosures == nil {
			sender.disclosures = make(map[string]decision.DisclosureBinding)
		}
		sender.disclosures[intent.ID] = content.Disclosure
		sender.mu.Unlock()
	}
	return intent, result, nil
}

func (sender *governedOutboundSender) authorizeStream(ctx context.Context, initPayload []byte) (decision.Intent, decision.Decision, error) {
	if sender == nil || sender.requester == nil {
		return decision.Intent{}, decision.Decision{}, fmt.Errorf("governed outbound sender is not initialized")
	}
	payloadHash := dataexchange.GovernedStreamPayloadHash(initPayload)
	intent, result, err := sender.authorizeAction(ctx, "file.share", payloadHash, "stream:file.share:"+payloadHash, nil)
	if err != nil {
		return decision.Intent{}, decision.Decision{}, err
	}
	if err := outboundDecisionPermits(result); err != nil {
		return intent, result, err
	}
	return intent, result, nil
}

func (sender *governedOutboundSender) authorizeFederatedStream(ctx context.Context, initPayload, body []byte) (decision.Intent, decision.Decision, decision.DisclosureBinding, error) {
	if sender == nil || sender.hook == nil || sender.contentBuilder == nil {
		intent, result, err := sender.authorizeStream(ctx, initPayload)
		return intent, result, decision.DisclosureBinding{}, err
	}
	transferID, declaredBytes, contentHash, filename, err := dataexchange.GovernedStreamDisclosureMetadata(initPayload)
	if err != nil {
		return decision.Intent{}, decision.Decision{}, decision.DisclosureBinding{}, err
	}
	if declaredBytes != uint64(len(body)) || contentHash != decision.HashPayload(body) {
		return decision.Intent{}, decision.Decision{}, decision.DisclosureBinding{}, fmt.Errorf("governed stream body does not match final INIT")
	}
	content, err := sender.contentBuilder.NewOutboundFederatedContent("application/octet-stream", filename, body)
	if err != nil {
		return decision.Intent{}, decision.Decision{}, decision.DisclosureBinding{}, err
	}
	content.Disclosure.TransferID = transferID
	content, err = decision.NewFederatedContent(content.Disclosure, body)
	if err != nil {
		return decision.Intent{}, decision.Decision{}, decision.DisclosureBinding{}, err
	}
	payloadHash, _ := content.Disclosure.Hash()
	intent, result, err := sender.authorizeAction(ctx, "file.share", payloadHash, "stream:file.share:"+payloadHash, &content)
	if err != nil {
		return decision.Intent{}, decision.Decision{}, decision.DisclosureBinding{}, err
	}
	if err := outboundDecisionPermits(result); err != nil {
		return intent, result, decision.DisclosureBinding{}, err
	}
	sender.mu.Lock()
	if sender.disclosures == nil {
		sender.disclosures = make(map[string]decision.DisclosureBinding)
	}
	sender.disclosures[intent.ID] = content.Disclosure
	sender.mu.Unlock()
	return intent, result, content.Disclosure, nil
}

func (sender *governedOutboundSender) authorizeAction(ctx context.Context, action, payloadHash, resumeToken string, content *decision.FederatedContent) (decision.Intent, decision.Decision, error) {
	if sender.hook == nil {
		return sender.requester.AuthorizeOutbound(ctx, action, sender.resource, payloadHash)
	}
	var envelope actionhook.Envelope
	var err error
	if content != nil {
		envelope, err = actionhook.NewFederatedEnvelope(action, sender.resource, "pilot.dataexchange", *content, map[string]string{"transport": "dataexchange"}, time.Now())
	} else {
		envelope, err = actionhook.NewEnvelope(action, sender.resource, payloadHash, "pilot.dataexchange", map[string]string{"transport": "dataexchange"}, time.Now())
	}
	if err != nil {
		return decision.Intent{}, decision.Decision{}, err
	}
	envelope.ResumeToken = resumeToken
	if err := envelope.Validate(); err != nil {
		return decision.Intent{}, decision.Decision{}, err
	}
	preflight, err := sender.hook.BeforeAction(ctx, envelope)
	if err != nil {
		return decision.Intent{}, decision.Decision{}, err
	}
	intent, result, hasArtifacts := sender.artifacts.ActionArtifacts(preflight)
	if executeErr := preflight.RequireUnconstrained(); executeErr != nil {
		status := actionhook.StatusFailed
		var blocked *actionhook.BlockedError
		if errors.As(executeErr, &blocked) {
			switch blocked.Outcome {
			case decision.Deny:
				status = actionhook.StatusDenied
			case decision.ApprovalRequired:
				status = actionhook.StatusApprovalPending
			}
		}
		_ = sender.hook.AfterAction(ctx, envelope, preflight, actionhook.ObservedResult{Status: status, ObservedAt: time.Now().Unix(), ErrorCode: "preflight_blocked"})
		return intent, result, executeErr
	}
	if !hasArtifacts {
		intent, result, err = sender.requester.AuthorizeOutbound(ctx, action, sender.resource, payloadHash)
		if err != nil {
			_ = sender.hook.AfterAction(ctx, envelope, preflight, actionhook.ObservedResult{Status: actionhook.StatusFailed, ObservedAt: time.Now().Unix(), ErrorCode: "wire_authorization_failed"})
			return decision.Intent{}, decision.Decision{}, err
		}
	}
	if err := outboundDecisionPermits(result); err != nil {
		_ = sender.hook.AfterAction(ctx, envelope, preflight, actionhook.ObservedResult{Status: actionhook.StatusDenied, ObservedAt: time.Now().Unix(), ErrorCode: "wire_decision_blocked"})
		return intent, result, err
	}
	sender.mu.Lock()
	if sender.attempts == nil {
		sender.attempts = make(map[string]governedActionAttempt)
	}
	sender.attempts[intent.ID] = governedActionAttempt{envelope: envelope, preflight: preflight}
	sender.mu.Unlock()
	return intent, result, nil
}

// complete records the actual transport result exactly once. A post-hook
// failure is evidence loss, never authority to repeat a send.
func (sender *governedOutboundSender) complete(ctx context.Context, intentID string, succeeded bool, failureCode string) {
	sender.completeWithResponse(ctx, intentID, succeeded, failureCode, "", nil)
}

func (sender *governedOutboundSender) completeWithResponse(ctx context.Context, intentID string, succeeded bool, failureCode, contentType string, response []byte) {
	if sender == nil || sender.hook == nil || intentID == "" {
		return
	}
	sender.mu.Lock()
	attempt, exists := sender.attempts[intentID]
	delete(sender.attempts, intentID)
	delete(sender.disclosures, intentID)
	sender.mu.Unlock()
	if !exists {
		return
	}
	status := actionhook.StatusSucceeded
	if !succeeded {
		status = actionhook.StatusFailed
		if failureCode == "" {
			failureCode = "transport_failed"
		}
	}
	observed := actionhook.ObservedResult{Status: status, ObservedAt: time.Now().Unix(), ErrorCode: failureCode}
	if len(response) > 0 && contentType != "" && sender.contentBuilder != nil {
		content, err := sender.contentBuilder.NewOutboundFederatedResponseContent(contentType, "", response)
		if err != nil {
			slog.Error("governed transport response attachment failed", "intent_id", intentID, "error", err)
		} else {
			observed.FederatedContent = &content
		}
	}
	if err := sender.hook.AfterAction(ctx, attempt.envelope, attempt.preflight, observed); err != nil {
		slog.Error("governed transport post-hook failed", "intent_id", intentID, "error", err)
	}
}

func (sender *governedOutboundSender) disclosure(intentID string) (decision.DisclosureBinding, bool) {
	if sender == nil || intentID == "" {
		return decision.DisclosureBinding{}, false
	}
	sender.mu.Lock()
	defer sender.mu.Unlock()
	disclosure, found := sender.disclosures[intentID]
	disclosure.Labels = append([]string(nil), disclosure.Labels...)
	return disclosure, found
}

func frameContentType(frameType uint32) string {
	switch frameType {
	case dataexchange.TypeText:
		return "text/plain"
	case dataexchange.TypeJSON:
		return "application/json"
	case dataexchange.TypeFile, dataexchange.TypeBinary:
		return "application/octet-stream"
	default:
		return "application/octet-stream"
	}
}

func outboundDecisionPermits(result decision.Decision) error {
	switch result.Outcome {
	case decision.Allow, decision.Constrain:
		return nil
	case decision.Deny:
		return fmt.Errorf("enterprise decision denied%s", decisionReasonSuffix(result.Reasons))
	case decision.ApprovalRequired:
		return fmt.Errorf("enterprise decision requires approval%s", decisionReasonSuffix(result.Reasons))
	default:
		return fmt.Errorf("enterprise decision has unsupported outcome %q", result.Outcome)
	}
}

func decisionReasonSuffix(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	return ": " + strings.Join(reasons, "; ")
}

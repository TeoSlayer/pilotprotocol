// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pilot-protocol/common/actionhook"
	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/pilotprotocol/internal/enterprisecontrol"
)

const (
	externalHookVersion        uint16 = 1
	maxExternalHookContent            = 16 << 20
	externalHookAttemptVersion uint16 = 1
)

// enterpriseHookRequest is the harness-neutral process boundary. Harness
// adapters translate their native event into this schema; the configured
// action/resource mapping remains visible in traces and policy evaluation.
// ContentBase64 is the exact JSON or byte representation of the tool request
// or result. Labels, retention, purpose, and evaluator residency are not
// caller-controlled: Runtime.NewOutboundFederated* supplies those values from
// the protected attachment.
type enterpriseHookRequest struct {
	Version       uint16            `json:"version"`
	AttemptKey    string            `json:"attempt_key"`
	Action        string            `json:"action,omitempty"`
	Resource      string            `json:"resource,omitempty"`
	AdapterID     string            `json:"adapter_id,omitempty"`
	ContentType   string            `json:"content_type,omitempty"`
	Filename      string            `json:"filename,omitempty"`
	ContentBase64 string            `json:"content_base64,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
	ResumeToken   string            `json:"resume_token,omitempty"`
	Status        string            `json:"status,omitempty"`
	ErrorCode     string            `json:"error_code,omitempty"`
}

type enterpriseHookResponse struct {
	Version     uint16                       `json:"version"`
	Attached    bool                         `json:"attached"`
	Execute     bool                         `json:"execute"`
	Outcome     decision.Outcome             `json:"outcome"`
	Reasons     []string                     `json:"reasons,omitempty"`
	Reference   actionhook.DecisionReference `json:"reference,omitempty"`
	ObserveOnly bool                         `json:"observe_only,omitempty"`
	AttemptID   string                       `json:"attempt_id,omitempty"`
	Reported    bool                         `json:"reported,omitempty"`
	Warning     string                       `json:"warning,omitempty"`
}

type persistedExternalHookAttempt struct {
	Version   uint16                                  `json:"version"`
	AttemptID string                                  `json:"attempt_id"`
	CreatedAt int64                                   `json:"created_at"`
	Attempt   enterprisecontrol.ExternalActionAttempt `json:"attempt"`
	Observed  *actionhook.ObservedResult              `json:"observed,omitempty"`
}

func cmdEnterpriseHook(args []string) {
	if len(args) == 0 || (args[0] != "pre" && args[0] != "post") {
		fatalHint("invalid_argument", "available: pilotctl --json enterprise hook pre | post", "missing or invalid enterprise hook phase")
	}
	phase := args[0]
	flags := flag.NewFlagSet("enterprise hook "+phase, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	controlPath := ""
	flags.StringVar(&controlPath, "control", "", "enterprise-control attachment path")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		fatalCode("invalid_argument", "enterprise hook %s accepts only --control", phase)
	}
	if strings.TrimSpace(controlPath) == "" {
		controlPath = strings.TrimSpace(os.Getenv("PILOT_ENTERPRISE_CONTROL"))
	}
	request, err := decodeEnterpriseHookRequest(os.Stdin)
	if err != nil {
		fatalCode("invalid_argument", "enterprise hook %s request: %v", phase, err)
	}
	if controlPath == "" {
		// The compatibility invariant: installing a harness adapter does not
		// opt an existing/open agent into governance.
		output(enterpriseHookResponse{Version: externalHookVersion, Execute: true, Outcome: decision.Allow})
		return
	}
	runtime, err := enterprisecontrol.Load(controlPath)
	if err != nil {
		fatalCode("unavailable", "enterprise hook %s control attachment: %v", phase, err)
	}
	if phase == "pre" {
		response, err := executeEnterprisePreHook(context.Background(), controlPath, runtime, request)
		if err != nil {
			fatalCode("unavailable", "enterprise hook pre: %v", err)
		}
		output(response)
		return
	}
	response, err := executeEnterprisePostHook(context.Background(), controlPath, runtime, request)
	if err != nil {
		fatalCode("unavailable", "enterprise hook post: %v", err)
	}
	output(response)
}

func decodeEnterpriseHookRequest(reader io.Reader) (enterpriseHookRequest, error) {
	limited := io.LimitReader(reader, maxExternalHookContent+(1<<20))
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var request enterpriseHookRequest
	if err := decoder.Decode(&request); err != nil {
		return enterpriseHookRequest{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return enterpriseHookRequest{}, fmt.Errorf("multiple JSON values are not allowed")
		}
		return enterpriseHookRequest{}, err
	}
	if request.Version != externalHookVersion {
		return enterpriseHookRequest{}, fmt.Errorf("unsupported version %d", request.Version)
	}
	if strings.TrimSpace(request.AttemptKey) == "" || len(request.AttemptKey) > 1024 || !utf8.ValidString(request.AttemptKey) {
		return enterpriseHookRequest{}, fmt.Errorf("attempt_key is required and must be at most 1024 UTF-8 bytes")
	}
	return request, nil
}

func executeEnterprisePreHook(ctx context.Context, controlPath string, runtime *enterprisecontrol.Runtime, request enterpriseHookRequest) (enterpriseHookResponse, error) {
	hook := runtime.ActionHook()
	if hook == nil {
		return enterpriseHookResponse{Version: externalHookVersion, Execute: true, Outcome: decision.Allow}, nil
	}
	if request.Action == "" || request.Resource == "" || request.AdapterID == "" {
		return enterpriseHookResponse{}, fmt.Errorf("action, resource, and adapter_id are required")
	}
	body, err := decodeEnterpriseHookContent(request.ContentBase64)
	if err != nil {
		return enterpriseHookResponse{}, err
	}
	contentType := strings.TrimSpace(request.ContentType)
	if contentType == "" {
		contentType = "application/json"
	}
	now := time.Now().UTC()
	var envelope actionhook.Envelope
	content, contentErr := runtime.NewOutboundFederatedContent(contentType, request.Filename, body)
	if contentErr == nil {
		envelope, err = actionhook.NewFederatedEnvelope(request.Action, request.Resource, request.AdapterID, content, request.Attributes, now)
	} else {
		envelope, err = actionhook.NewEnvelope(request.Action, request.Resource, decision.HashPayload(body), request.AdapterID, request.Attributes, now)
	}
	if err != nil {
		return enterpriseHookResponse{}, err
	}
	envelope.ResumeToken = request.ResumeToken
	preflight, err := hook.BeforeAction(ctx, envelope)
	if err != nil {
		return enterpriseHookResponse{}, err
	}
	response := enterpriseHookResponse{
		Version: externalHookVersion, Attached: true, Execute: preflight.RequireUnconstrained() == nil,
		Outcome: preflight.Outcome, Reasons: append([]string(nil), preflight.Reasons...),
		Reference: preflight.Reference, ObserveOnly: preflight.ObserveOnly,
	}
	record, persist, err := runtime.ExportExternalActionAttempt(envelope, preflight)
	if err != nil {
		// An approved continuation is claimed before its execution decision is
		// returned. If the process boundary cannot durably retain that state,
		// finish the claim as failed and report evidence instead of leaving an
		// indefinitely executing continuation. The side effect has not run.
		if response.Execute {
			_ = hook.AfterAction(ctx, envelope, preflight, actionhook.ObservedResult{
				Status: actionhook.StatusFailed, ObservedAt: now.Unix(), ErrorCode: "hook_state_persistence_failed",
				Attributes: map[string]string{"hook_phase": "pre"},
			})
		}
		return enterpriseHookResponse{}, err
	}
	if !persist {
		return response, nil
	}
	persisted := persistedExternalHookAttempt{
		Version: externalHookAttemptVersion, AttemptID: externalHookAttemptID(request.AttemptKey),
		CreatedAt: now.Unix(), Attempt: record,
	}
	response.AttemptID = persisted.AttemptID
	if !response.Execute {
		observed := actionhook.ObservedResult{ObservedAt: now.Unix(), Attributes: map[string]string{"hook_phase": "pre"}}
		switch preflight.Outcome {
		case decision.ApprovalRequired:
			observed.Status = actionhook.StatusApprovalPending
		case decision.Deny, decision.Constrain:
			observed.Status = actionhook.StatusDenied
		default:
			observed.Status = actionhook.StatusSkipped
		}
		persisted.Observed = &observed
	}
	if err := writeExternalHookAttempt(controlPath, persisted); err != nil {
		return enterpriseHookResponse{}, err
	}
	if persisted.Observed != nil {
		restoredEnvelope, restoredPreflight, err := runtime.ImportExternalActionAttempt(record)
		if err != nil {
			return enterpriseHookResponse{}, err
		}
		if err := hook.AfterAction(ctx, restoredEnvelope, restoredPreflight, *persisted.Observed); err != nil {
			response.Warning = "decision enforced; evidence report is queued for retry"
			return response, nil
		}
		if err := removeExternalHookAttempt(controlPath, persisted.AttemptID); err != nil {
			response.Warning = "decision enforced and reported; local attempt cleanup failed"
			return response, nil
		}
		response.Reported = true
	}
	return response, nil
}

func executeEnterprisePostHook(ctx context.Context, controlPath string, runtime *enterprisecontrol.Runtime, request enterpriseHookRequest) (enterpriseHookResponse, error) {
	attemptID := externalHookAttemptID(request.AttemptKey)
	persisted, err := readExternalHookAttempt(controlPath, attemptID)
	if err != nil {
		return enterpriseHookResponse{}, err
	}
	envelope, preflight, err := runtime.ImportExternalActionAttempt(persisted.Attempt)
	if err != nil {
		return enterpriseHookResponse{}, err
	}
	var observed actionhook.ObservedResult
	if persisted.Observed != nil {
		// The first post-hook invocation durably fixes the signed observation.
		// Reuse it byte-for-byte on outbox retries so result IDs, receipts, and
		// usage units remain idempotent even after process or authority restarts.
		observed = *persisted.Observed
		switch observed.Status {
		case actionhook.StatusSucceeded, actionhook.StatusFailed, actionhook.StatusSkipped:
		default:
			return enterpriseHookResponse{}, fmt.Errorf("hook attempt did not execute and cannot accept a post-hook")
		}
	} else {
		observedStatus, err := externalObservedStatus(request.Status)
		if err != nil {
			return enterpriseHookResponse{}, err
		}
		observed = actionhook.ObservedResult{
			Status: observedStatus, ObservedAt: time.Now().UTC().Unix(), ErrorCode: request.ErrorCode,
			Attributes: request.Attributes,
		}
		responseBody, err := decodeEnterpriseHookContent(request.ContentBase64)
		if err != nil {
			return enterpriseHookResponse{}, err
		}
		if request.ContentBase64 != "" {
			contentType := strings.TrimSpace(request.ContentType)
			if contentType == "" {
				contentType = "application/json"
			}
			content, err := runtime.NewOutboundFederatedResponseContent(contentType, request.Filename, responseBody)
			if err != nil {
				return enterpriseHookResponse{}, err
			}
			observed.FederatedContent = &content
		}
		persisted.Observed = &observed
		if err := writeExternalHookAttempt(controlPath, persisted); err != nil {
			return enterpriseHookResponse{}, fmt.Errorf("persist post-hook observation before reporting: %w", err)
		}
	}
	if err := runtime.AfterAction(ctx, envelope, preflight, observed); err != nil {
		return enterpriseHookResponse{}, err
	}
	if err := removeExternalHookAttempt(controlPath, attemptID); err != nil {
		return enterpriseHookResponse{}, err
	}
	return enterpriseHookResponse{
		Version: externalHookVersion, Attached: true, Execute: true, Outcome: preflight.Outcome,
		Reference: preflight.Reference, AttemptID: attemptID, Reported: true,
	}, nil
}

func decodeEnterpriseHookContent(encoded string) ([]byte, error) {
	if encoded == "" {
		return []byte{}, nil
	}
	body, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("content_base64 is invalid")
	}
	if len(body) > maxExternalHookContent {
		return nil, fmt.Errorf("hook content exceeds %d bytes", maxExternalHookContent)
	}
	return body, nil
}

func externalObservedStatus(value string) (actionhook.ObservedStatus, error) {
	switch strings.TrimSpace(value) {
	case "", "succeeded":
		return actionhook.StatusSucceeded, nil
	case "failed":
		return actionhook.StatusFailed, nil
	case "skipped":
		return actionhook.StatusSkipped, nil
	default:
		return "", fmt.Errorf("status must be succeeded, failed, or skipped")
	}
}

func externalHookAttemptID(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

func externalHookAttemptDirectory(controlPath string) string {
	return filepath.Join(filepath.Dir(controlPath), ".external-hook-attempts")
}

func externalHookAttemptPath(controlPath, attemptID string) string {
	return filepath.Join(externalHookAttemptDirectory(controlPath), attemptID+".json")
}

func writeExternalHookAttempt(controlPath string, attempt persistedExternalHookAttempt) error {
	directory := externalHookAttemptDirectory(controlPath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create hook attempt directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&0o077 != 0 {
		return fmt.Errorf("hook attempt directory must be an owner-only directory")
	}
	body, err := json.Marshal(attempt)
	if err != nil {
		return fmt.Errorf("encode hook attempt: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".attempt-*")
	if err != nil {
		return fmt.Errorf("create hook attempt: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, externalHookAttemptPath(controlPath, attempt.AttemptID)); err != nil {
		return fmt.Errorf("commit hook attempt: %w", err)
	}
	return nil
}

func readExternalHookAttempt(controlPath, attemptID string) (persistedExternalHookAttempt, error) {
	path := externalHookAttemptPath(controlPath, attemptID)
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return persistedExternalHookAttempt{}, fmt.Errorf("hook attempt %s was not found", attemptID)
		}
		return persistedExternalHookAttempt{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&0o077 != 0 {
		return persistedExternalHookAttempt{}, fmt.Errorf("hook attempt must be an owner-only regular file")
	}
	// #nosec G304 -- path is derived from a validated attempt ID beneath the private managed-hook directory and checked above.
	file, err := os.Open(path)
	if err != nil {
		return persistedExternalHookAttempt{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 2<<20))
	decoder.DisallowUnknownFields()
	var attempt persistedExternalHookAttempt
	if err := decoder.Decode(&attempt); err != nil {
		return persistedExternalHookAttempt{}, fmt.Errorf("decode hook attempt: %w", err)
	}
	if attempt.Version != externalHookAttemptVersion || attempt.AttemptID != attemptID || attempt.CreatedAt <= 0 {
		return persistedExternalHookAttempt{}, fmt.Errorf("hook attempt record is invalid")
	}
	return attempt, nil
}

func removeExternalHookAttempt(controlPath, attemptID string) error {
	if err := os.Remove(externalHookAttemptPath(controlPath, attemptID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

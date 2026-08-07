// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/pilotprotocol/internal/enterprisecontrol"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/actionregistry"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authorityhttp"
)

const defaultEnrollmentTokenEnvironment = "PILOT_ENROLLMENT_TOKEN"
const managedCoreConnectorVersion = "pilot-core-managed-0.1.4"

type enterpriseAdoptOptions struct {
	Endpoint         string
	OutputDirectory  string
	TokenEnvironment string
	HTTPClient       *http.Client
}

type enterpriseAdoptResult struct {
	TenantID      string `json:"tenant_id"`
	AgentID       string `json:"agent_id"`
	HarnessID     string `json:"harness_id"`
	RunID         string `json:"run_id"`
	ControlPath   string `json:"control_path"`
	EnrollmentID  string `json:"enrollment_id"`
	ActionControl bool   `json:"action_control"`
	FleetControl  bool   `json:"fleet_control"`
	StateSync     bool   `json:"state_sync"`
}

type enrolledNodeCredential struct {
	Version       uint16                `json:"version"`
	TenantID      string                `json:"tenant_id"`
	Agent         enrolledNodeMaterial  `json:"agent"`
	RootKeyID     string                `json:"root_key_id"`
	RootPublicKey string                `json:"root_public_key"`
	Trust         authority.TrustBundle `json:"trust"`
}

type enrolledNodeMaterial struct {
	AgentID string `json:"agent_id"`
	KeyID   string `json:"key_id"`
	Seed    string `json:"seed"`
}

func cmdEnterpriseAdopt(args []string) {
	home, err := os.UserHomeDir()
	if err != nil {
		fatalCode("unavailable", "resolve home directory: %v", err)
	}
	flags := flag.NewFlagSet("enterprise adopt", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	options := enterpriseAdoptOptions{OutputDirectory: filepath.Join(home, ".pilot", "managed"), TokenEnvironment: defaultEnrollmentTokenEnvironment}
	flags.StringVar(&options.Endpoint, "endpoint", "", "hosted Pilot management origin")
	flags.StringVar(&options.OutputDirectory, "output", options.OutputDirectory, "owner-only managed attachment directory")
	flags.StringVar(&options.TokenEnvironment, "token-env", options.TokenEnvironment, "environment variable holding the one-time token")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fatalCode("invalid_argument", "enterprise adopt accepts --endpoint, --output, and --token-env")
	}
	if !enterpriseEnvironmentName(options.TokenEnvironment) {
		fatalCode("invalid_argument", "enterprise adopt token environment name is invalid")
	}
	result, err := adoptEnterpriseNode(context.Background(), options)
	if err != nil {
		fatalCode("unavailable", "enterprise adopt: %v", err)
	}
	output(result)
}

func adoptEnterpriseNode(ctx context.Context, options enterpriseAdoptOptions) (enterpriseAdoptResult, error) {
	endpoint, err := normalizedManagedEndpoint(options.Endpoint)
	if err != nil {
		return enterpriseAdoptResult{}, err
	}
	token := strings.TrimSpace(os.Getenv(options.TokenEnvironment))
	if token == "" || len(token) > 4096 || strings.ContainsAny(token, "\r\n\x00") {
		return enterpriseAdoptResult{}, fmt.Errorf("%s is empty or invalid", options.TokenEnvironment)
	}
	// The token must not leak into the daemon, harness hooks, or subprocesses
	// after the one request that consumes it.
	defer os.Unsetenv(options.TokenEnvironment)
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	claim, err := claimNodeEnrollment(ctx, client, endpoint, token)
	if err != nil {
		return enterpriseAdoptResult{}, err
	}
	credential, root, seed, err := validateEnrolledCredential(claim)
	if err != nil {
		return enterpriseAdoptResult{}, err
	}
	policy, err := decodeEnrollmentPolicy(claim.Policy)
	if err != nil {
		return enterpriseAdoptResult{}, err
	}
	if policy.TenantID != claim.TenantID || policy.Revision < credential.Trust.PolicyRevision || policy.RevocationEpoch < credential.Trust.RevocationEpoch {
		return enterpriseAdoptResult{}, fmt.Errorf("bootstrap policy does not satisfy the enrolled trust floor")
	}
	if err := policy.Validate(); err != nil {
		return enterpriseAdoptResult{}, fmt.Errorf("validate bootstrap policy: %w", err)
	}
	controlPath, err := installEnrolledAttachment(options.OutputDirectory, claim, credential, root, seed, policy)
	if err != nil {
		return enterpriseAdoptResult{}, err
	}
	return enterpriseAdoptResult{
		TenantID: claim.TenantID, AgentID: claim.AgentID, HarnessID: claim.HarnessID, RunID: claim.RunID,
		ControlPath: controlPath, EnrollmentID: claim.EnrollmentID,
		ActionControl: claim.Options.ActionControl, FleetControl: claim.Options.FleetControl, StateSync: claim.Options.StateSync,
	}, nil
}

func normalizedManagedEndpoint(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("endpoint must be an HTTPS origin without credentials, path, query, or fragment")
	}
	return parsed.String(), nil
}

func claimNodeEnrollment(ctx context.Context, client *http.Client, endpoint, token string) (authorityhttp.NodeEnrollmentClaimResponse, error) {
	body, _ := json.Marshal(map[string]string{"token": token})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/enroll/claim", bytes.NewReader(body))
	if err != nil {
		return authorityhttp.NodeEnrollmentClaimResponse{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return authorityhttp.NodeEnrollmentClaimResponse{}, fmt.Errorf("claim node identity: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return authorityhttp.NodeEnrollmentClaimResponse{}, fmt.Errorf("claim node identity returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	decoder.DisallowUnknownFields()
	var claim authorityhttp.NodeEnrollmentClaimResponse
	if err := decoder.Decode(&claim); err != nil {
		return authorityhttp.NodeEnrollmentClaimResponse{}, fmt.Errorf("decode node enrollment: %w", err)
	}
	if claim.Version != authorityhttp.NodeEnrollmentVersion || claim.EnrollmentID == "" || claim.TenantID == "" || claim.AgentID == "" || claim.HarnessID == "" || claim.RunID == "" || claim.ClaimedAt <= 0 || len(claim.Credential) == 0 || len(claim.Policy) == 0 || claim.PublicOrigin != endpoint || !claim.Options.FleetControl {
		return authorityhttp.NodeEnrollmentClaimResponse{}, fmt.Errorf("node enrollment response is incomplete or mismatched")
	}
	if _, err := normalizedManagedEndpoint(claim.FederationEndpoint); err != nil {
		return authorityhttp.NodeEnrollmentClaimResponse{}, fmt.Errorf("node enrollment federation endpoint: %w", err)
	}
	return claim, nil
}

func validateEnrolledCredential(claim authorityhttp.NodeEnrollmentClaimResponse) (enrolledNodeCredential, ed25519.PublicKey, []byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(claim.Credential))
	decoder.DisallowUnknownFields()
	var credential enrolledNodeCredential
	if err := decoder.Decode(&credential); err != nil {
		return enrolledNodeCredential{}, nil, nil, fmt.Errorf("decode delegated node credential: %w", err)
	}
	if credential.Version != 1 || credential.TenantID != claim.TenantID || credential.Agent.AgentID != claim.AgentID || credential.RootKeyID != credential.Trust.RootKeyID || credential.Trust.TenantID != claim.TenantID {
		return enrolledNodeCredential{}, nil, nil, fmt.Errorf("delegated node credential binding mismatch")
	}
	rootBytes, err := hex.DecodeString(credential.RootPublicKey)
	if err != nil || len(rootBytes) != ed25519.PublicKeySize {
		return enrolledNodeCredential{}, nil, nil, fmt.Errorf("delegated root pin is invalid")
	}
	root := ed25519.PublicKey(rootBytes)
	if err := credential.Trust.Verify(root, time.Now().UTC()); err != nil {
		return enrolledNodeCredential{}, nil, nil, fmt.Errorf("verify delegated trust: %w", err)
	}
	seed, err := hex.DecodeString(credential.Agent.Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return enrolledNodeCredential{}, nil, nil, fmt.Errorf("delegated node seed is invalid")
	}
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	matched := false
	for _, key := range credential.Trust.Keys {
		if key.AgentID == claim.AgentID && key.KeyID == credential.Agent.KeyID {
			decoded, decodeErr := base64.StdEncoding.DecodeString(key.PublicKey)
			matched = decodeErr == nil && bytes.Equal(decoded, public)
			break
		}
	}
	if !matched {
		return enrolledNodeCredential{}, nil, nil, fmt.Errorf("delegated node key is not active in signed trust")
	}
	return credential, root, seed, nil
}

func decodeEnrollmentPolicy(raw json.RawMessage) (authority.PolicyBundle, error) {
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(raw), 2<<20))
	decoder.DisallowUnknownFields()
	var policy authority.PolicyBundle
	if err := decoder.Decode(&policy); err != nil {
		return authority.PolicyBundle{}, fmt.Errorf("decode bootstrap policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return authority.PolicyBundle{}, fmt.Errorf("decode bootstrap policy: trailing data")
	}
	return policy, nil
}

func installEnrolledAttachment(outputDirectory string, claim authorityhttp.NodeEnrollmentClaimResponse, credential enrolledNodeCredential, root ed25519.PublicKey, seed []byte, policy authority.PolicyBundle) (string, error) {
	outputDirectory = filepath.Clean(strings.TrimSpace(outputDirectory))
	if outputDirectory == "" || !filepath.IsAbs(outputDirectory) {
		return "", fmt.Errorf("output directory must be absolute")
	}
	if _, err := os.Lstat(outputDirectory); err == nil {
		return "", fmt.Errorf("managed attachment already exists at %s", outputDirectory)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(outputDirectory)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return "", err
	}
	stage, err := os.MkdirTemp(parent, ".managed-adopt-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stage)
	for _, directory := range []string{"runtime/continuations", "state/workflows"} {
		if err := os.MkdirAll(filepath.Join(stage, filepath.FromSlash(directory)), 0o700); err != nil {
			return "", err
		}
	}
	if err := writeAdoptionJSON(filepath.Join(stage, "trust.json"), credential.Trust); err != nil {
		return "", err
	}
	if err := writeAdoptionJSON(filepath.Join(stage, "policy.json"), policy); err != nil {
		return "", err
	}
	if err := writeAdoptionFile(filepath.Join(stage, "agent.seed"), []byte(base64.StdEncoding.EncodeToString(seed)+"\n")); err != nil {
		return "", err
	}
	if err := writeAdoptionJSON(filepath.Join(stage, "state", "settings.json"), map[string]any{
		"agent_id": claim.AgentID, "display_name": claim.DisplayName, "harness": claim.HarnessID,
		"mode": "managed", "source": "hosted-enrollment", "enrollment_id": claim.EnrollmentID, "created_at": claim.ClaimedAt,
	}); err != nil {
		return "", err
	}
	config := enterprisecontrol.Config{
		TenantID: claim.TenantID, RootKeyID: credential.RootKeyID, RootPublicKey: base64.StdEncoding.EncodeToString(root),
		TrustBundlePath: "trust.json", PolicyBundlePath: "policy.json",
	}
	if claim.Options.ActionControl {
		config.Receipts = &enterprisecontrol.ReceiptConfig{
			AgentID: claim.AgentID, KeyID: credential.Agent.KeyID, SeedPath: "agent.seed", JournalPath: "runtime/receipts.jsonl",
			ExportEndpoint: claim.PublicOrigin + "/v1/receipts", ExportAcknowledgementPath: "runtime/receipt-acks.log", ExportIntervalSeconds: 30, ExportBatchSize: 100,
		}
		config.OutboundDecisions = &enterprisecontrol.OutboundDecisionConfig{
			AuthorityEndpoint: claim.FederationEndpoint, AgentID: claim.AgentID, IntentKeyID: credential.Agent.KeyID, IntentSeedPath: "agent.seed",
			Risk: decision.RiskMedium, RequestTimeoutSeconds: 20, Audience: "account:" + claim.TenantID, Purpose: "Govern complete agent tool calls",
			ContentLabels: []string{"agent-tool-call", claim.HarnessID}, RetentionClass: "account-default", EvaluatorResidency: "eu-west-1",
		}
		config.ActionControl = &enterprisecontrol.ActionControlConfig{
			Profile: actionregistry.Profile{Version: actionregistry.SchemaVersion, Mode: actionregistry.ModeManagedEnforce, Actions: managedAdoptionActions()},
			AgentID: claim.AgentID, Risk: decision.RiskMedium, ContinuationDirectory: "runtime/continuations",
		}
	}
	if claim.Options.FleetControl || claim.Options.ActionControl {
		config.Rollout = &enterprisecontrol.RolloutConfig{
			AuthorityEndpoint: claim.PublicOrigin, AgentID: claim.AgentID, AcknowledgementKeyID: credential.Agent.KeyID,
			AcknowledgementSeedPath: "agent.seed", PollIntervalSeconds: 5,
		}
	}
	if claim.Options.FleetControl {
		config.Fleet = &enterprisecontrol.FleetConfig{
			ReportIntervalSeconds: 5, AgentVersion: "pilot-onboarding/" + claim.HarnessID + "/" + claim.RunID,
			HarnessID: claim.HarnessID, HarnessVersion: "managed", ConnectorVersion: managedCoreConnectorVersion,
			StateSyncEnabled: claim.Options.StateSync, StateSyncIntervalSeconds: 2,
		}
		if claim.Options.StateSync {
			config.Fleet.StateDirectory = "state"
		}
	}
	controlPath := filepath.Join(stage, "enterprise-control.json")
	if err := writeAdoptionJSON(controlPath, config); err != nil {
		return "", err
	}
	if _, err := enterprisecontrol.Load(controlPath); err != nil {
		return "", fmt.Errorf("verify managed attachment: %w", err)
	}
	if err := os.Rename(stage, outputDirectory); err != nil {
		return "", err
	}
	return filepath.Join(outputDirectory, "enterprise-control.json"), nil
}

func managedAdoptionActions() []string {
	return []string{
		"browser.navigate", "data.export", "data.read", "data.send.binary", "data.send.json", "data.send.text",
		"event.publish", "file.delete", "file.read", "file.share", "file.write", "http.request", "process.execute",
		"tool.invoke", "trust.accept", "trust.auto_accept", "trust.reject", "trust.request", "trust.revoke",
		"wallet.pay", "webhook.send",
	}
}

func writeAdoptionJSON(path string, value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return writeAdoptionFile(path, body)
}

func writeAdoptionFile(path string, body []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".adopt-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
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
	return os.Rename(name, path)
}

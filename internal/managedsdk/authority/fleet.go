// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/actionregistry"
)

const (
	FleetCommandVersion   uint16 = 1 // accepted legacy wire format
	FleetCommandVersionV2 uint16 = 2
	FleetReportVersion    uint16 = 1
	FleetReportVersionV2  uint16 = 2
	FleetCommandDomain           = "pilot-fleet-command-v1"
	FleetCommandDomainV2         = "pilot-fleet-command-v2"
	FleetReportDomain            = "pilot-fleet-report-v1"
	FleetReportDomainV2          = "pilot-fleet-report-v2"
	FleetResultDomain            = "pilot-fleet-result-v1"
	MaxFleetCommandTTL           = 24 * time.Hour
	MaxFleetTargets              = 10_000
)

// FleetCommandKind is deliberately a small, non-shell command vocabulary. A
// node executes a command only after checking this separately signed object
// against its root-pinned authority trust.
type FleetCommandKind string

const (
	FleetCommandRefreshPolicy   FleetCommandKind = "refresh_policy"
	FleetCommandExportReceipts  FleetCommandKind = "export_receipts"
	FleetCommandReloadControl   FleetCommandKind = "reload_control"
	FleetCommandSyncState       FleetCommandKind = "sync_state"
	FleetCommandDiagnostics     FleetCommandKind = "collect_diagnostics"
	FleetCommandRestartRuntime  FleetCommandKind = "restart_runtime"
	FleetCommandShutdownRuntime FleetCommandKind = "shutdown_runtime"
)

// FleetCommand is a short-lived command addressed to one or more enrolled
// agent identities. The authority stores and distributes it but does not infer
// authority from transport or UI identity: the operator supplies a separately
// signed artifact.
type FleetCommand struct {
	Version   uint16           `json:"version"`
	ID        string           `json:"id"`
	TenantID  string           `json:"tenant_id"`
	Targets   []string         `json:"targets"`
	Kind      FleetCommandKind `json:"kind"`
	Reason    string           `json:"reason,omitempty"`
	IssuedAt  int64            `json:"issued_at"`
	ExpiresAt int64            `json:"expires_at"`
	KeyID     string           `json:"key_id"`
	Signature string           `json:"signature"`
}

func (command FleetCommand) Validate() error {
	if command.Version != FleetCommandVersion && command.Version != FleetCommandVersionV2 {
		return fmt.Errorf("authority: unsupported fleet command version")
	}
	for name, value := range map[string]string{"id": command.ID, "tenant_id": command.TenantID, "key_id": command.KeyID} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if len(command.Targets) == 0 || len(command.Targets) > MaxFleetTargets {
		return fmt.Errorf("authority: fleet command requires 1-%d targets", MaxFleetTargets)
	}
	seen := make(map[string]struct{}, len(command.Targets))
	for _, target := range command.Targets {
		if err := validateIdentifier("fleet target", target); err != nil {
			return err
		}
		if _, exists := seen[target]; exists {
			return fmt.Errorf("authority: duplicate fleet command target %q", target)
		}
		seen[target] = struct{}{}
	}
	switch command.Kind {
	case FleetCommandRefreshPolicy, FleetCommandExportReceipts, FleetCommandReloadControl, FleetCommandSyncState, FleetCommandDiagnostics, FleetCommandRestartRuntime, FleetCommandShutdownRuntime:
	default:
		return fmt.Errorf("authority: unsupported fleet command kind %q", command.Kind)
	}
	if command.IssuedAt <= 0 || command.ExpiresAt <= command.IssuedAt || command.ExpiresAt-command.IssuedAt > int64(MaxFleetCommandTTL/time.Second) {
		return fmt.Errorf("authority: invalid fleet command validity")
	}
	if command.Version == FleetCommandVersion && command.Reason != "" {
		return fmt.Errorf("authority: legacy fleet command cannot carry a reason")
	}
	if command.Version == FleetCommandVersionV2 && (!boundedFleetText(command.Reason, 256, false) || len(strings.TrimSpace(command.Reason)) < 8) {
		return fmt.Errorf("authority: fleet command v2 requires an auditable reason")
	}
	return nil
}

func (command FleetCommand) Canonical() ([]byte, error) {
	if err := command.Validate(); err != nil {
		return nil, err
	}
	targets := append([]string(nil), command.Targets...)
	sort.Strings(targets)
	writer := canonicalWriter{}
	domain := FleetCommandDomain
	if command.Version == FleetCommandVersionV2 {
		domain = FleetCommandDomainV2
	}
	writer.string(domain)
	writer.u16(command.Version)
	writer.string(command.ID)
	writer.string(command.TenantID)
	writer.u16(uint16(len(targets)))
	for _, target := range targets {
		writer.string(target)
	}
	writer.string(string(command.Kind))
	if command.Version == FleetCommandVersionV2 {
		writer.string(command.Reason)
	}
	writer.i64(command.IssuedAt)
	writer.i64(command.ExpiresAt)
	writer.string(command.KeyID)
	if writer.err != nil {
		return nil, writer.err
	}
	return writer.Buffer.Bytes(), nil
}

func (command *FleetCommand) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("authority: invalid fleet command signing key")
	}
	canonical, err := command.Canonical()
	if err != nil {
		return err
	}
	command.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return nil
}

func (command FleetCommand) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	if err := command.Validate(); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("authority: invalid fleet command public key")
	}
	if now.Unix() < command.IssuedAt-int64(MaxBundleClockSkew/time.Second) || now.Unix() > command.ExpiresAt+int64(MaxBundleClockSkew/time.Second) {
		return fmt.Errorf("authority: fleet command is outside its validity window")
	}
	canonical, err := command.Canonical()
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(command.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("authority: invalid fleet command signature")
	}
	return nil
}

func (command FleetCommand) TargetsAgent(agentID string) bool {
	for _, target := range command.Targets {
		if target == agentID {
			return true
		}
	}
	return false
}

// FleetNodeReport contains the bounded, non-sensitive liveness information a
// daemon elects to make visible to its tenant operators. It never contains
// prompts, payloads, peer addresses, local paths, or environment values.
type FleetNodeReport struct {
	Version          uint16                             `json:"version"`
	TenantID         string                             `json:"tenant_id"`
	AgentID          string                             `json:"agent_id"`
	NodeID           uint32                             `json:"node_id"`
	AgentVersion     string                             `json:"agent_version,omitempty"`
	HarnessID        string                             `json:"harness_id,omitempty"`
	HarnessVersion   string                             `json:"harness_version,omitempty"`
	ConnectorVersion string                             `json:"connector_version,omitempty"`
	Capabilities     []actionregistry.AdapterCapability `json:"capabilities,omitempty"`
	ObservedAt       int64                              `json:"observed_at"`
	UptimeSeconds    uint64                             `json:"uptime_seconds"`
	Connections      uint32                             `json:"connections"`
	Peers            uint32                             `json:"peers"`
	EncryptedPeers   uint32                             `json:"encrypted_peers"`
	BytesSent        uint64                             `json:"bytes_sent"`
	BytesReceived    uint64                             `json:"bytes_received"`
	PolicyRevision   uint64                             `json:"policy_revision"`
	KeyID            string                             `json:"key_id"`
	Signature        string                             `json:"signature"`
}

func (report FleetNodeReport) Validate() error {
	if report.Version != FleetReportVersion && report.Version != FleetReportVersionV2 {
		return fmt.Errorf("authority: unsupported fleet report version")
	}
	for name, value := range map[string]string{"tenant_id": report.TenantID, "agent_id": report.AgentID, "key_id": report.KeyID} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if report.ObservedAt <= 0 || len(report.AgentVersion) > 128 || strings.ContainsAny(report.AgentVersion, "\r\n\x00") {
		return fmt.Errorf("authority: invalid fleet node report")
	}
	if report.Version == FleetReportVersion {
		if report.HarnessID != "" || report.HarnessVersion != "" || report.ConnectorVersion != "" || len(report.Capabilities) != 0 {
			return fmt.Errorf("authority: legacy fleet report cannot carry capability data")
		}
		return nil
	}
	for name, value := range map[string]string{"harness_id": report.HarnessID, "connector_version": report.ConnectorVersion} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if report.HarnessVersion == "" || len(report.HarnessVersion) > 128 || strings.ContainsAny(report.HarnessVersion, "\r\n\x00") {
		return fmt.Errorf("authority: invalid harness version")
	}
	if len(report.Capabilities) == 0 || len(report.Capabilities) > len(actionregistry.Builtins().Definitions()) {
		return fmt.Errorf("authority: capability-aware report requires a bounded capability set")
	}
	registry := actionregistry.Builtins()
	seen := make(map[string]struct{}, len(report.Capabilities))
	for _, capability := range report.Capabilities {
		if err := capability.Validate(registry); err != nil {
			return fmt.Errorf("authority: invalid adapter capability: %w", err)
		}
		canonical, _ := registry.CanonicalName(capability.Action)
		if _, duplicate := seen[canonical]; duplicate {
			return fmt.Errorf("authority: duplicate adapter capability for %q", canonical)
		}
		seen[canonical] = struct{}{}
	}
	return nil
}

func (report FleetNodeReport) Canonical() ([]byte, error) {
	if err := report.Validate(); err != nil {
		return nil, err
	}
	writer := canonicalWriter{}
	domain := FleetReportDomain
	if report.Version == FleetReportVersionV2 {
		domain = FleetReportDomainV2
	}
	writer.string(domain)
	writer.u16(report.Version)
	writer.string(report.TenantID)
	writer.string(report.AgentID)
	writer.u64(uint64(report.NodeID))
	writer.string(report.AgentVersion)
	writer.i64(report.ObservedAt)
	writer.u64(report.UptimeSeconds)
	writer.u64(uint64(report.Connections))
	writer.u64(uint64(report.Peers))
	writer.u64(uint64(report.EncryptedPeers))
	writer.u64(report.BytesSent)
	writer.u64(report.BytesReceived)
	writer.u64(report.PolicyRevision)
	if report.Version == FleetReportVersionV2 {
		writer.string(report.HarnessID)
		writer.string(report.HarnessVersion)
		writer.string(report.ConnectorVersion)
		capabilities := append([]actionregistry.AdapterCapability(nil), report.Capabilities...)
		registry := actionregistry.Builtins()
		sort.Slice(capabilities, func(i, j int) bool {
			left, _ := registry.CanonicalName(capabilities[i].Action)
			right, _ := registry.CanonicalName(capabilities[j].Action)
			return left < right
		})
		writer.u16(uint16(len(capabilities)))
		for _, capability := range capabilities {
			canonical, _ := registry.CanonicalName(capability.Action)
			writer.string(canonical)
			writer.string(capability.AdapterID)
			writer.string(capability.AdapterVersion)
			writer.boolean(capability.Observe)
			writer.boolean(capability.Enforce)
			writer.boolean(capability.Suspend)
			writer.boolean(capability.Resume)
			writer.boolean(capability.Receipt)
		}
	}
	writer.string(report.KeyID)
	if writer.err != nil {
		return nil, writer.err
	}
	return writer.Buffer.Bytes(), nil
}

func (report *FleetNodeReport) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("authority: invalid fleet report signing key")
	}
	canonical, err := report.Canonical()
	if err != nil {
		return err
	}
	report.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return nil
}

func (report FleetNodeReport) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	if err := report.Validate(); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("authority: invalid fleet report public key")
	}
	if report.ObservedAt > now.Unix()+int64(MaxBundleClockSkew/time.Second) || report.ObservedAt < now.Add(-24*time.Hour).Unix() {
		return fmt.Errorf("authority: fleet report is outside its accepted observation window")
	}
	canonical, err := report.Canonical()
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(report.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("authority: invalid fleet report signature")
	}
	return nil
}

// FleetCommandResult records the bounded result of one allowlisted command.
// DetailCode is intentionally an identifier rather than a remote error string.
type FleetCommandResult struct {
	Version    uint16 `json:"version"`
	TenantID   string `json:"tenant_id"`
	AgentID    string `json:"agent_id"`
	CommandID  string `json:"command_id"`
	Outcome    string `json:"outcome"`
	DetailCode string `json:"detail_code,omitempty"`
	ObservedAt int64  `json:"observed_at"`
	KeyID      string `json:"key_id"`
	Signature  string `json:"signature"`
}

func (result FleetCommandResult) Validate() error {
	if result.Version != FleetReportVersion {
		return fmt.Errorf("authority: unsupported fleet command result version")
	}
	for name, value := range map[string]string{"tenant_id": result.TenantID, "agent_id": result.AgentID, "command_id": result.CommandID, "key_id": result.KeyID} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if result.DetailCode != "" {
		if err := validateIdentifier("detail_code", result.DetailCode); err != nil {
			return err
		}
	}
	switch result.Outcome {
	case "succeeded", "failed", "rejected":
	default:
		return fmt.Errorf("authority: invalid fleet command result outcome")
	}
	if result.ObservedAt <= 0 {
		return fmt.Errorf("authority: invalid fleet command result observation time")
	}
	return nil
}

func (result FleetCommandResult) Canonical() ([]byte, error) {
	if err := result.Validate(); err != nil {
		return nil, err
	}
	writer := canonicalWriter{}
	writer.string(FleetResultDomain)
	writer.u16(result.Version)
	writer.string(result.TenantID)
	writer.string(result.AgentID)
	writer.string(result.CommandID)
	writer.string(result.Outcome)
	writer.string(result.DetailCode)
	writer.i64(result.ObservedAt)
	writer.string(result.KeyID)
	if writer.err != nil {
		return nil, writer.err
	}
	return writer.Buffer.Bytes(), nil
}

func (result *FleetCommandResult) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("authority: invalid fleet result signing key")
	}
	canonical, err := result.Canonical()
	if err != nil {
		return err
	}
	result.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return nil
}

func (result FleetCommandResult) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	if err := result.Validate(); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("authority: invalid fleet result public key")
	}
	if result.ObservedAt > now.Unix()+int64(MaxBundleClockSkew/time.Second) || result.ObservedAt < now.Add(-24*time.Hour).Unix() {
		return fmt.Errorf("authority: fleet result is outside its accepted observation window")
	}
	canonical, err := result.Canonical()
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(result.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("authority: invalid fleet result signature")
	}
	return nil
}

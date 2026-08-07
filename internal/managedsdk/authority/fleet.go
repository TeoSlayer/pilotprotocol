// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
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

// FleetPersistence keeps the control queue and latest bounded node state
// outside the authorization decision path.
type FleetPersistence interface {
	SaveFleetCommand(context.Context, FleetCommand) error
	ListFleetCommands(context.Context, string) ([]FleetCommand, error)
	SaveFleetNodeReport(context.Context, FleetNodeReport) error
	ListFleetNodeReports(context.Context, string) ([]FleetNodeReport, error)
	SaveFleetCommandResult(context.Context, FleetCommandResult) error
	ListFleetCommandResults(context.Context, string) ([]FleetCommandResult, error)
	SaveFleetNodeControl(context.Context, FleetNodeControl) error
	ListFleetNodeControls(context.Context, string) ([]FleetNodeControl, error)
	SaveFleetActivity(context.Context, FleetActivity) error
	ListFleetActivities(context.Context, string, int) ([]FleetActivity, error)
}

type FleetControlAcknowledgementPersistence interface {
	SaveFleetControlAcknowledgement(context.Context, FleetControlAcknowledgement) error
	ListFleetControlAcknowledgements(context.Context, string, int) ([]FleetControlAcknowledgement, error)
}

// IndexedFleetPersistence is an optional high-volume read path. Shared stores
// implement it so node polling and management snapshots never scan historical
// command or result collections in application memory.
type IndexedFleetPersistence interface {
	CountActiveFleetAgents(context.Context, string, int64, int64, []string) (int, error)
	ListPendingFleetCommands(context.Context, string, string, int64, int) ([]FleetCommand, error)
	LoadFleetCommand(context.Context, string, string) (FleetCommand, bool, error)
	FleetNodeReportExists(context.Context, string, string) (bool, error)
	ListRecentFleetCommands(context.Context, string, int) ([]FleetCommand, error)
	ListRecentFleetCommandResults(context.Context, string, int) ([]FleetCommandResult, error)
	ListRecentFleetCommandCancellations(context.Context, string, int) ([]FleetCommandCancellation, error)
}

// AgentFleetActivityPersistence is an optional indexed read path for stable
// per-node views. A tenant-global recency window is not sufficient: under a
// busy fleet, activity from noisy nodes can otherwise evict a quieter node's
// newest records before its detail page is rendered.
type AgentFleetActivityPersistence interface {
	ListRecentFleetActivities(context.Context, string, string, int) ([]FleetActivity, error)
	LoadFleetActivity(context.Context, string, string) (FleetActivity, bool, error)
}

type FleetTrustStore interface {
	DecisionKey(context.Context, string, string) (ed25519.PublicKey, error)
	IntentKeyAt(string, string, string, time.Time) (ed25519.PublicKey, error)
}

// FleetManager is the authority-side verifier and queue façade. Persistence
// failure never changes a workload decision, while command/report operations
// themselves fail closed and remain auditable.
type FleetManager struct {
	trust          FleetTrustStore
	persistence    FleetPersistence
	entitlements   EntitlementProvider
	now            func() time.Time
	controlCache   fleetControlCache
	lifecycleCache fleetLifecycleCache
	enrollmentMu   sync.RWMutex
	enrollmentMode string
}

func NewFleetManager(trust FleetTrustStore, persistence FleetPersistence, now func() time.Time) (*FleetManager, error) {
	if trust == nil || persistence == nil {
		return nil, fmt.Errorf("authority: fleet trust and persistence are required")
	}
	if now == nil {
		now = time.Now
	}
	return &FleetManager{trust: trust, persistence: persistence, now: now, enrollmentMode: FleetEnrollmentOpen}, nil
}

// SetEntitlementProvider installs the authority-owned commercial gate before
// the manager serves requests. A nil provider leaves the free single-node
// profile available and rejects multi-node fleet control.
func (manager *FleetManager) SetEntitlementProvider(provider EntitlementProvider) {
	if manager != nil {
		manager.entitlements = provider
	}
}

func (manager *FleetManager) Queue(ctx context.Context, command FleetCommand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	publicKey, err := manager.trust.DecisionKey(ctx, command.TenantID, command.KeyID)
	if err != nil {
		return err
	}
	if err := command.Verify(publicKey, manager.now()); err != nil {
		return err
	}
	for _, target := range command.Targets {
		if !manager.nodeOperational(command.TenantID, target) {
			return fmt.Errorf("authority: fleet command target is not actively enrolled")
		}
	}
	requiresEntitlement, err := manager.requiresFleetEntitlement(ctx, command.TenantID, command.Targets)
	if err != nil {
		return err
	}
	if requiresEntitlement {
		if manager.entitlements == nil || !manager.entitlements.Allows(ctx, command.TenantID, CommercialFleet) {
			return ErrEntitlementRequired
		}
	}
	if err := manager.persistence.SaveFleetCommand(ctx, command); err != nil {
		return persistenceError("save fleet command", err)
	}
	return nil
}

func (manager *FleetManager) requiresFleetEntitlement(ctx context.Context, tenantID string, targets []string) (bool, error) {
	now := manager.now().Unix()
	if indexed, ok := manager.persistence.(IndexedFleetPersistence); ok {
		count, err := indexed.CountActiveFleetAgents(ctx, tenantID, now-int64(24*time.Hour/time.Second), now-int64(MaxBundleClockSkew/time.Second), targets)
		if err != nil {
			return false, persistenceError("count active fleet agents", err)
		}
		return count > 1, nil
	}
	agents := make(map[string]struct{}, len(targets)+1)
	for _, target := range targets {
		agents[target] = struct{}{}
	}
	reports, err := manager.persistence.ListFleetNodeReports(ctx, tenantID)
	if err != nil {
		return false, persistenceError("load fleet node reports", err)
	}
	for _, report := range reports {
		if report.ObservedAt >= now-int64(24*time.Hour/time.Second) {
			agents[report.AgentID] = struct{}{}
		}
	}
	commands, err := manager.persistence.ListFleetCommands(ctx, tenantID)
	if err != nil {
		return false, persistenceError("load fleet commands", err)
	}
	for _, existing := range commands {
		if existing.ExpiresAt+int64(MaxBundleClockSkew/time.Second) < now {
			continue
		}
		for _, target := range existing.Targets {
			agents[target] = struct{}{}
		}
	}
	return len(agents) > 1, nil
}

func (manager *FleetManager) Commands(ctx context.Context, tenantID, agentID string) ([]FleetCommand, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateIdentifier("tenant_id", tenantID); err != nil {
		return nil, err
	}
	if err := validateIdentifier("agent_id", agentID); err != nil {
		return nil, err
	}
	if !manager.nodeOperational(tenantID, agentID) {
		return nil, nil
	}
	requiresEntitlement, err := manager.requiresFleetEntitlement(ctx, tenantID, nil)
	if err != nil {
		return nil, err
	}
	if requiresEntitlement && (manager.entitlements == nil || !manager.entitlements.Allows(ctx, tenantID, CommercialFleet)) {
		return nil, ErrEntitlementRequired
	}
	now := manager.now()
	var commands []FleetCommand
	if indexed, ok := manager.persistence.(IndexedFleetPersistence); ok {
		commands, err = indexed.ListPendingFleetCommands(ctx, tenantID, agentID, now.Unix()-int64(MaxBundleClockSkew/time.Second), 100)
		if err != nil {
			return nil, persistenceError("load pending fleet commands", err)
		}
	} else {
		commands, err = manager.persistence.ListFleetCommands(ctx, tenantID)
		if err != nil {
			return nil, persistenceError("load fleet commands", err)
		}
		results, resultErr := manager.persistence.ListFleetCommandResults(ctx, tenantID)
		if resultErr != nil {
			return nil, persistenceError("load fleet command results", resultErr)
		}
		completed := make(map[string]struct{}, len(results))
		for _, result := range results {
			if result.AgentID == agentID {
				completed[result.CommandID] = struct{}{}
			}
		}
		cancelled := make(map[string]struct{})
		if cancellations, cancelErr := manager.Cancellations(ctx, tenantID); cancelErr != nil {
			return nil, cancelErr
		} else {
			for _, cancellation := range cancellations {
				cancelled[cancellation.CommandID] = struct{}{}
			}
		}
		filtered := commands[:0]
		for _, command := range commands {
			if _, done := completed[command.ID]; done {
				continue
			}
			if _, stopped := cancelled[command.ID]; stopped {
				continue
			}
			filtered = append(filtered, command)
		}
		commands = filtered
	}
	allowed := make([]FleetCommand, 0, len(commands))
	for _, command := range commands {
		if command.TenantID != tenantID || !command.TargetsAgent(agentID) {
			continue
		}
		publicKey, keyErr := manager.trust.DecisionKey(ctx, tenantID, command.KeyID)
		if keyErr != nil || command.Verify(publicKey, now) != nil {
			continue
		}
		allowed = append(allowed, command)
	}
	sort.Slice(allowed, func(i, j int) bool { return allowed[i].IssuedAt < allowed[j].IssuedAt })
	return allowed, nil
}

func (manager *FleetManager) Report(ctx context.Context, report FleetNodeReport) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	publicKey, err := manager.trust.IntentKeyAt(report.TenantID, report.AgentID, report.KeyID, time.Unix(report.ObservedAt, 0))
	if err != nil {
		return err
	}
	if err := report.Verify(publicKey, manager.now()); err != nil {
		return err
	}
	if state, found := manager.lifecycleCache.state(report.TenantID, report.AgentID); found && state == FleetNodeRetired {
		return fmt.Errorf("authority: retired fleet node cannot report")
	}
	requiresEntitlement, err := manager.requiresFleetEntitlement(ctx, report.TenantID, []string{report.AgentID})
	if err != nil {
		return err
	}
	if requiresEntitlement && (manager.entitlements == nil || !manager.entitlements.Allows(ctx, report.TenantID, CommercialFleet)) {
		return ErrEntitlementRequired
	}
	if err := manager.persistence.SaveFleetNodeReport(ctx, report); err != nil {
		return persistenceError("save fleet node report", err)
	}
	return nil
}

func (manager *FleetManager) Result(ctx context.Context, result FleetCommandResult) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	publicKey, err := manager.trust.IntentKeyAt(result.TenantID, result.AgentID, result.KeyID, time.Unix(result.ObservedAt, 0))
	if err != nil {
		return err
	}
	if err := result.Verify(publicKey, manager.now()); err != nil {
		return err
	}
	var command FleetCommand
	found := false
	if indexed, ok := manager.persistence.(IndexedFleetPersistence); ok {
		command, found, err = indexed.LoadFleetCommand(ctx, result.TenantID, result.CommandID)
		if err != nil {
			return persistenceError("load fleet command", err)
		}
	} else {
		commands, loadErr := manager.persistence.ListFleetCommands(ctx, result.TenantID)
		if loadErr != nil {
			return persistenceError("load fleet commands", loadErr)
		}
		for _, candidate := range commands {
			if candidate.ID == result.CommandID {
				command, found = candidate, true
				break
			}
		}
	}
	if found && command.TargetsAgent(result.AgentID) && (result.ObservedAt < command.IssuedAt-int64(MaxBundleClockSkew/time.Second) || result.ObservedAt > command.ExpiresAt+int64(MaxBundleClockSkew/time.Second)) {
		return fmt.Errorf("authority: fleet command result is outside command validity")
	}
	found = found && command.TargetsAgent(result.AgentID)
	if !found {
		return fmt.Errorf("authority: fleet command result does not target agent")
	}
	if err := manager.persistence.SaveFleetCommandResult(ctx, result); err != nil {
		return persistenceError("save fleet command result", err)
	}
	return nil
}

// PublishControl verifies and monotonically installs the signed desired state
// for one enrolled node. The cache is updated only after durable persistence.
func (manager *FleetManager) PublishControl(ctx context.Context, control FleetNodeControl) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	publicKey, err := manager.trust.DecisionKey(ctx, control.TenantID, control.KeyID)
	if err != nil {
		return err
	}
	if err := control.Verify(publicKey, manager.now()); err != nil {
		return err
	}
	if !manager.nodeOperational(control.TenantID, control.AgentID) {
		return fmt.Errorf("authority: fleet control target is not actively enrolled")
	}
	found := false
	if indexed, ok := manager.persistence.(IndexedFleetPersistence); ok {
		found, err = indexed.FleetNodeReportExists(ctx, control.TenantID, control.AgentID)
		if err != nil {
			return persistenceError("load fleet node report", err)
		}
	} else {
		reports, loadErr := manager.persistence.ListFleetNodeReports(ctx, control.TenantID)
		if loadErr != nil {
			return persistenceError("load fleet node reports", loadErr)
		}
		for _, report := range reports {
			if report.AgentID == control.AgentID {
				found = true
				break
			}
		}
	}
	if !found {
		return fmt.Errorf("authority: fleet control target is not enrolled")
	}
	requiresEntitlement, err := manager.requiresFleetEntitlement(ctx, control.TenantID, []string{control.AgentID})
	if err != nil {
		return err
	}
	if requiresEntitlement && (manager.entitlements == nil || !manager.entitlements.Allows(ctx, control.TenantID, CommercialFleet)) {
		return ErrEntitlementRequired
	}
	if err := manager.persistence.SaveFleetNodeControl(ctx, control); err != nil {
		return persistenceError("save fleet node control", err)
	}
	manager.controlCache.put(control)
	return nil
}

func (manager *FleetManager) Control(ctx context.Context, tenantID, agentID string) (FleetNodeControl, bool, error) {
	if err := validateIdentifier("tenant_id", tenantID); err != nil {
		return FleetNodeControl{}, false, err
	}
	if err := validateIdentifier("agent_id", agentID); err != nil {
		return FleetNodeControl{}, false, err
	}
	controls, err := manager.persistence.ListFleetNodeControls(ctx, tenantID)
	if err != nil {
		return FleetNodeControl{}, false, persistenceError("load fleet node controls", err)
	}
	for _, control := range controls {
		if control.AgentID != agentID {
			continue
		}
		publicKey, keyErr := manager.trust.DecisionKey(ctx, tenantID, control.KeyID)
		if keyErr != nil || control.Verify(publicKey, manager.now()) != nil {
			return FleetNodeControl{}, false, fmt.Errorf("authority: invalid stored fleet node control")
		}
		return control, true, nil
	}
	return FleetNodeControl{}, false, nil
}

func (manager *FleetManager) RecordControlAcknowledgement(ctx context.Context, acknowledgement FleetControlAcknowledgement) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	persistence, ok := manager.persistence.(FleetControlAcknowledgementPersistence)
	if !ok {
		return fmt.Errorf("authority: fleet control acknowledgement persistence is unavailable")
	}
	publicKey, err := manager.trust.IntentKeyAt(acknowledgement.TenantID, acknowledgement.AgentID, acknowledgement.KeyID, time.Unix(acknowledgement.ObservedAt, 0))
	if err != nil {
		return err
	}
	if err := acknowledgement.Verify(publicKey, manager.now()); err != nil {
		return err
	}
	control, found, err := manager.Control(ctx, acknowledgement.TenantID, acknowledgement.AgentID)
	if err != nil {
		return err
	}
	if !found || control.Revision != acknowledgement.ControlRevision || control.Quarantined != acknowledgement.Quarantined {
		return fmt.Errorf("authority: fleet control acknowledgement does not match desired state")
	}
	if acknowledgement.Status == FleetControlApplied {
		if control.DesiredPolicyRevision != 0 && acknowledgement.AppliedPolicyRevision != control.DesiredPolicyRevision {
			return fmt.Errorf("authority: applied fleet control acknowledgement has policy drift")
		}
		if control.DesiredVersion != "" && acknowledgement.RunningVersion != control.DesiredVersion {
			return fmt.Errorf("authority: applied fleet control acknowledgement has runtime drift")
		}
	}
	if !manager.nodeOperational(acknowledgement.TenantID, acknowledgement.AgentID) {
		return fmt.Errorf("authority: fleet control acknowledgement source is not actively enrolled")
	}
	if err := persistence.SaveFleetControlAcknowledgement(ctx, acknowledgement); err != nil {
		return persistenceError("save fleet control acknowledgement", err)
	}
	return nil
}

func (manager *FleetManager) ControlAcknowledgements(ctx context.Context, tenantID string, limit int) ([]FleetControlAcknowledgement, error) {
	persistence, ok := manager.persistence.(FleetControlAcknowledgementPersistence)
	if !ok {
		return nil, nil
	}
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("authority: fleet control acknowledgement limit must be 1-1000")
	}
	values, err := persistence.ListFleetControlAcknowledgements(ctx, tenantID, limit)
	if err != nil {
		return nil, persistenceError("load fleet control acknowledgements", err)
	}
	for _, acknowledgement := range values {
		publicKey, keyErr := manager.trust.IntentKeyAt(acknowledgement.TenantID, acknowledgement.AgentID, acknowledgement.KeyID, time.Unix(acknowledgement.ObservedAt, 0))
		if keyErr != nil || acknowledgement.Verify(publicKey, manager.now()) != nil || acknowledgement.TenantID != tenantID {
			return nil, fmt.Errorf("authority: invalid stored fleet control acknowledgement")
		}
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].ObservedAt != values[j].ObservedAt {
			return values[i].ObservedAt > values[j].ObservedAt
		}
		return values[i].AgentID < values[j].AgentID
	})
	if len(values) > limit {
		values = values[:limit]
	}
	return values, nil
}

// RefreshControls rebuilds the non-expanding quarantine cache from verified
// durable state. Call it at startup and after shared-store reconciliation.
func (manager *FleetManager) RefreshControls(ctx context.Context, tenantID string) error {
	controls, err := manager.persistence.ListFleetNodeControls(ctx, tenantID)
	if err != nil {
		return persistenceError("load fleet node controls", err)
	}
	for _, control := range controls {
		publicKey, keyErr := manager.trust.DecisionKey(ctx, tenantID, control.KeyID)
		if keyErr != nil || control.Verify(publicKey, manager.now()) != nil {
			return fmt.Errorf("authority: invalid stored fleet node control")
		}
	}
	manager.controlCache.replace(controls)
	if persistence, ok := manager.persistence.(FleetNodeLifecyclePersistence); ok {
		lifecycles, loadErr := persistence.ListFleetNodeLifecycles(ctx, tenantID)
		if loadErr != nil {
			return persistenceError("load fleet node lifecycles", loadErr)
		}
		for _, lifecycle := range lifecycles {
			publicKey, keyErr := manager.trust.DecisionKey(ctx, tenantID, lifecycle.KeyID)
			if keyErr != nil || lifecycle.Verify(publicKey, manager.now()) != nil {
				return fmt.Errorf("authority: invalid stored fleet node lifecycle")
			}
		}
		manager.lifecycleCache.replace(lifecycles)
	}
	if persistence, ok := manager.persistence.(FleetEnrollmentControlPersistence); ok {
		control, found, loadErr := persistence.LoadFleetEnrollmentControl(ctx, tenantID)
		if loadErr != nil {
			return persistenceError("load fleet enrollment control", loadErr)
		}
		if found {
			key, keyErr := manager.trust.DecisionKey(ctx, tenantID, control.KeyID)
			if keyErr != nil || control.Verify(key, manager.now()) != nil {
				return fmt.Errorf("authority: invalid stored fleet enrollment control")
			}
			if modeErr := manager.SetEnrollmentMode(control.Mode); modeErr != nil {
				return modeErr
			}
		}
	}
	return nil
}

func (manager *FleetManager) Quarantined(tenantID, agentID string) bool {
	if manager == nil {
		return false
	}
	return manager.controlCache.quarantined(tenantID, agentID) || !manager.nodeOperational(tenantID, agentID)
}

func (manager *FleetManager) RecordActivity(ctx context.Context, activity FleetActivity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	publicKey, err := manager.trust.IntentKeyAt(activity.TenantID, activity.AgentID, activity.KeyID, time.Unix(activity.ObservedAt, 0))
	if err != nil {
		return err
	}
	if err := activity.Verify(publicKey, manager.now()); err != nil {
		return err
	}
	if !manager.nodeOperational(activity.TenantID, activity.AgentID) {
		return fmt.Errorf("authority: fleet activity source is not actively enrolled")
	}
	requiresEntitlement, err := manager.requiresFleetEntitlement(ctx, activity.TenantID, []string{activity.AgentID})
	if err != nil {
		return err
	}
	if requiresEntitlement && (manager.entitlements == nil || !manager.entitlements.Allows(ctx, activity.TenantID, CommercialFleet)) {
		return ErrEntitlementRequired
	}
	if err := manager.persistence.SaveFleetActivity(ctx, activity); err != nil {
		return persistenceError("save fleet activity", err)
	}
	return nil
}

func (manager *FleetManager) Activities(ctx context.Context, tenantID string, limit int) ([]FleetActivity, error) {
	if err := validateIdentifier("tenant_id", tenantID); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("authority: fleet activity limit must be 1-1000")
	}
	activities, err := manager.persistence.ListFleetActivities(ctx, tenantID, limit)
	if err != nil {
		return nil, persistenceError("load fleet activities", err)
	}
	for _, activity := range activities {
		publicKey, keyErr := manager.trust.IntentKeyAt(activity.TenantID, activity.AgentID, activity.KeyID, time.Unix(activity.ObservedAt, 0))
		if keyErr != nil || activity.Verify(publicKey, manager.now()) != nil {
			return nil, fmt.Errorf("authority: invalid stored fleet activity")
		}
	}
	sort.Slice(activities, func(i, j int) bool {
		if activities[i].ObservedAt != activities[j].ObservedAt {
			return activities[i].ObservedAt > activities[j].ObservedAt
		}
		return activities[i].ID > activities[j].ID
	})
	if len(activities) > limit {
		activities = activities[:limit]
	}
	return activities, nil
}

// ActivitiesForAgent returns a bounded, indexed activity feed for one node.
// It intentionally fails when the persistence implementation does not expose
// the high-volume contract rather than silently falling back to a tenant-wide
// window that can produce incomplete node detail.
func (manager *FleetManager) ActivitiesForAgent(ctx context.Context, tenantID, agentID string, limit int) ([]FleetActivity, error) {
	if err := validateIdentifier("tenant_id", tenantID); err != nil {
		return nil, err
	}
	if err := validateIdentifier("agent_id", agentID); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("authority: fleet activity limit must be 1-1000")
	}
	persistence, ok := manager.persistence.(AgentFleetActivityPersistence)
	if !ok {
		return nil, fmt.Errorf("authority: indexed per-agent fleet activity is unavailable")
	}
	activities, err := persistence.ListRecentFleetActivities(ctx, tenantID, agentID, limit)
	if err != nil {
		return nil, persistenceError("load agent fleet activities", err)
	}
	if err := manager.verifyActivities(activities, tenantID, agentID); err != nil {
		return nil, err
	}
	return activities, nil
}

// Activity loads one retained activity by stable identity, independent of the
// management snapshot's bounded recency window.
func (manager *FleetManager) Activity(ctx context.Context, tenantID, activityID string) (FleetActivity, bool, error) {
	if err := validateIdentifier("tenant_id", tenantID); err != nil {
		return FleetActivity{}, false, err
	}
	if !lowerHexIdentifier(activityID, 64) {
		return FleetActivity{}, false, fmt.Errorf("authority: invalid fleet activity id")
	}
	persistence, ok := manager.persistence.(AgentFleetActivityPersistence)
	if !ok {
		return FleetActivity{}, false, fmt.Errorf("authority: indexed fleet activity lookup is unavailable")
	}
	activity, found, err := persistence.LoadFleetActivity(ctx, tenantID, activityID)
	if err != nil || !found {
		return FleetActivity{}, found, err
	}
	if err := manager.verifyActivities([]FleetActivity{activity}, tenantID, ""); err != nil {
		return FleetActivity{}, false, err
	}
	return activity, true, nil
}

func (manager *FleetManager) verifyActivities(activities []FleetActivity, tenantID, agentID string) error {
	for _, activity := range activities {
		if activity.TenantID != tenantID || agentID != "" && activity.AgentID != agentID {
			return fmt.Errorf("authority: stored fleet activity scope mismatch")
		}
		publicKey, keyErr := manager.trust.IntentKeyAt(activity.TenantID, activity.AgentID, activity.KeyID, time.Unix(activity.ObservedAt, 0))
		if keyErr != nil || activity.Verify(publicKey, manager.now()) != nil {
			return fmt.Errorf("authority: invalid stored fleet activity")
		}
	}
	sort.Slice(activities, func(i, j int) bool {
		if activities[i].ObservedAt != activities[j].ObservedAt {
			return activities[i].ObservedAt > activities[j].ObservedAt
		}
		return activities[i].ID > activities[j].ID
	})
	return nil
}

type FleetSnapshot struct {
	Commands                []FleetCommand                `json:"commands"`
	Reports                 []FleetNodeReport             `json:"reports"`
	Results                 []FleetCommandResult          `json:"results"`
	Controls                []FleetNodeControl            `json:"controls"`
	Activity                []FleetActivity               `json:"activity"`
	Cancellations           []FleetCommandCancellation    `json:"cancellations,omitempty"`
	Lifecycles              []FleetNodeLifecycle          `json:"lifecycles,omitempty"`
	Groups                  []FleetGroup                  `json:"groups,omitempty"`
	EnrollmentMode          string                        `json:"enrollment_mode"`
	EnrollmentControl       *FleetEnrollmentControl       `json:"enrollment_control,omitempty"`
	ControlAcknowledgements []FleetControlAcknowledgement `json:"control_acknowledgements,omitempty"`
}

func (manager *FleetManager) Snapshot(ctx context.Context, tenantID string) (FleetSnapshot, error) {
	if err := validateIdentifier("tenant_id", tenantID); err != nil {
		return FleetSnapshot{}, err
	}
	var commands []FleetCommand
	var results []FleetCommandResult
	var recentCancellations []FleetCommandCancellation
	indexed, hasIndexed := manager.persistence.(IndexedFleetPersistence)
	var err error
	if hasIndexed {
		commands, err = indexed.ListRecentFleetCommands(ctx, tenantID, 100)
	} else {
		commands, err = manager.persistence.ListFleetCommands(ctx, tenantID)
	}
	if err != nil {
		return FleetSnapshot{}, persistenceError("load fleet commands", err)
	}
	reports, err := manager.persistence.ListFleetNodeReports(ctx, tenantID)
	if err != nil {
		return FleetSnapshot{}, persistenceError("load fleet reports", err)
	}
	if hasIndexed {
		results, err = indexed.ListRecentFleetCommandResults(ctx, tenantID, 50)
	} else {
		results, err = manager.persistence.ListFleetCommandResults(ctx, tenantID)
	}
	if err != nil {
		return FleetSnapshot{}, persistenceError("load fleet results", err)
	}
	controls, err := manager.persistence.ListFleetNodeControls(ctx, tenantID)
	if err != nil {
		return FleetSnapshot{}, persistenceError("load fleet node controls", err)
	}
	activity, err := manager.Activities(ctx, tenantID, 100)
	if err != nil {
		return FleetSnapshot{}, err
	}
	var cancellations []FleetCommandCancellation
	if hasIndexed {
		recentCancellations, err = indexed.ListRecentFleetCommandCancellations(ctx, tenantID, 100)
		if err == nil {
			for _, cancellation := range recentCancellations {
				key, keyErr := manager.trust.DecisionKey(ctx, tenantID, cancellation.KeyID)
				if keyErr != nil || cancellation.Verify(key, manager.now()) != nil {
					err = fmt.Errorf("authority: invalid stored fleet command cancellation")
					break
				}
			}
		}
		cancellations = recentCancellations
	} else {
		cancellations, err = manager.Cancellations(ctx, tenantID)
	}
	if err != nil {
		return FleetSnapshot{}, err
	}
	lifecycles, err := manager.NodeLifecycles(ctx, tenantID)
	if err != nil {
		return FleetSnapshot{}, err
	}
	groups, err := manager.Groups(ctx, tenantID)
	if err != nil {
		return FleetSnapshot{}, err
	}
	enrollmentControl, found, err := manager.EnrollmentControl(ctx, tenantID)
	if err != nil {
		return FleetSnapshot{}, err
	}
	var enrollmentPointer *FleetEnrollmentControl
	if found {
		enrollmentPointer = &enrollmentControl
	}
	controlAcknowledgements, err := manager.ControlAcknowledgements(ctx, tenantID, 1000)
	if err != nil {
		return FleetSnapshot{}, err
	}
	return FleetSnapshot{Commands: commands, Reports: reports, Results: results, Controls: controls, Activity: activity, Cancellations: cancellations, Lifecycles: lifecycles, Groups: groups, EnrollmentMode: manager.EnrollmentMode(), EnrollmentControl: enrollmentPointer, ControlAcknowledgements: controlAcknowledgements}, nil
}

func fleetRepositoryPathID(domain, value string) string {
	sum := sha256.Sum256([]byte(domain + "\x00" + value))
	return hex.EncodeToString(sum[:])
}

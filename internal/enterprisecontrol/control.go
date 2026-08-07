// SPDX-License-Identifier: AGPL-3.0-or-later

// Package enterprisecontrol loads the daemon-side attachment between a
// tenant's signed authority state and the governed data-service boundaries.
// It deliberately verifies static bootstrap files locally; distributing newer
// signed state is a separate rollout transport concern.
package enterprisecontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/dataexchange"
	"github.com/pilot-protocol/eventstream"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/actioncontinuation"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/actionregistry"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authorityhttp"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/decisionhttp"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/decisionpolicy"
)

// Config is the daemon's local, signed-state bootstrap attachment. Root keys
// are pinned out of band; trust and policy files are authenticated before
// they become usable at any resource boundary.
type Config struct {
	TenantID          string                   `json:"tenant_id"`
	RootKeyID         string                   `json:"root_key_id"`
	RootPublicKey     string                   `json:"root_public_key"`
	TrustBundlePath   string                   `json:"trust_bundle_path"`
	PolicyBundlePath  string                   `json:"policy_bundle_path"`
	DataExchange      *DataExchangeRule        `json:"data_exchange,omitempty"`
	EventStream       *EventStreamRule         `json:"event_stream,omitempty"`
	Mandates          *MandateConfig           `json:"mandates,omitempty"`
	Receipts          *ReceiptConfig           `json:"receipts,omitempty"`
	Rollout           *RolloutConfig           `json:"rollout,omitempty"`
	Fleet             *FleetConfig             `json:"fleet,omitempty"`
	OutboundDecisions *OutboundDecisionConfig  `json:"outbound_decisions,omitempty"`
	ActionControl     *ActionControlConfig     `json:"action_control,omitempty"`
	ContentInspection *ContentInspectionConfig `json:"content_inspection,omitempty"`
}

// ActionControl opts concrete node adapters into the universal before/after
// action hook. Omitting this block (or using mode off) preserves unmanaged
// behavior even when the same attachment is used for governed transports.
type ActionControlConfig struct {
	Profile               actionregistry.Profile `json:"profile"`
	AgentID               string                 `json:"agent_id,omitempty"`
	Risk                  decision.RiskClass     `json:"risk,omitempty"`
	ContinuationDirectory string                 `json:"continuation_directory,omitempty"`
}

// DataExchangeRule binds all inbound data-exchange receipts to one exact
// local resource. Deploy separate daemons or attachments for separate tenant
// destinations rather than accepting a sender-selected destination.
type DataExchangeRule struct {
	RequireGoverned          bool                 `json:"require_governed"`
	RequireDisclosure        bool                 `json:"require_disclosure,omitempty"`
	RequireContentInspection bool                 `json:"require_content_inspection,omitempty"`
	TransferQuota            *TransferQuotaConfig `json:"transfer_quota,omitempty"`
	Retention                *DataRetentionConfig `json:"retention,omitempty"`
	Resource                 string               `json:"resource"`
}

// DataRetentionConfig maps signed V2 retention classes to a receiver-local
// expiry duration. The state journal is owned by the data-exchange service;
// no sender-provided path or duration is accepted.
type DataRetentionConfig struct {
	Classes              []DataRetentionClass `json:"classes"`
	SweepIntervalSeconds int64                `json:"sweep_interval_seconds,omitempty"`
}

type DataRetentionClass struct {
	Class            string `json:"class"`
	RetainForSeconds int64  `json:"retain_for_seconds"`
}

// EventStreamRule requires topic-bound resources. ResourceTemplate must
// contain the literal {topic} once, ensuring authority for one topic cannot
// be replayed to another broker topic.
type EventStreamRule struct {
	RequireGoverned          bool                 `json:"require_governed"`
	RequireDisclosure        bool                 `json:"require_disclosure,omitempty"`
	RequireContentInspection bool                 `json:"require_content_inspection,omitempty"`
	TransferQuota            *TransferQuotaConfig `json:"transfer_quota,omitempty"`
	ResourceTemplate         string               `json:"resource_template"`
}

// TransferQuotaConfig is a per-signed-agent local admission budget. It is
// charged only for a verified governed message, event, or stream INIT; no
// transport address or caller-supplied identity participates in accounting.
type TransferQuotaConfig struct {
	WindowSeconds int64  `json:"window_seconds"`
	MaxBytes      uint64 `json:"max_bytes,omitempty"`
	MaxActions    uint64 `json:"max_actions,omitempty"`
	MaxSenders    int    `json:"max_senders"`
}

// MandateConfig installs a protected local set of tenant-issuer-signed
// mandates. When configured, governed Decisions pass through this ceiling in
// addition to the local deterministic policy bundle.
type MandateConfig struct {
	// Path is the legacy static array of individually signed mandates. It is
	// suitable for local/self-hosted bootstrap, but cannot carry a monotonic
	// removal revision.
	Path string `json:"path,omitempty"`
	// BundlePath is a protected bootstrap copy of a signed, revisioned mandate
	// bundle. When Rollout is also configured, RefreshRollout replaces it only
	// with a newer bundle obtained from the authority for AgentID.
	BundlePath string `json:"bundle_path,omitempty"`
	AgentID    string `json:"agent_id,omitempty"`
}

// ReceiptConfig gives the local enforcement daemon a tenant-delegated receipt
// signing key and an owner-only append-only journal. The agent ID is the
// signer identity, which may differ from the sender named by an incoming
// Intent; the enforcement point identifies the receiver/broker that acted.
type ReceiptConfig struct {
	AgentID                   string `json:"agent_id"`
	KeyID                     string `json:"key_id"`
	SeedPath                  string `json:"seed_path"`
	JournalPath               string `json:"journal_path"`
	ExportEndpoint            string `json:"export_endpoint,omitempty"`
	ExportAcknowledgementPath string `json:"export_acknowledgement_path,omitempty"`
	ExportBearerTokenEnv      string `json:"export_bearer_token_env,omitempty"`
	ExportIntervalSeconds     int64  `json:"export_interval_seconds,omitempty"`
	ExportBatchSize           int    `json:"export_batch_size,omitempty"`
}

// RolloutConfig opts a workload into the authority's staged policy lifecycle.
// The acknowledgement key must be the agent-scoped intent key named in the
// tenant trust bundle; its seed is read only from the protected attachment
// directory and never sent to the authority.
type RolloutConfig struct {
	AuthorityEndpoint       string `json:"authority_endpoint"`
	AgentID                 string `json:"agent_id"`
	AcknowledgementKeyID    string `json:"acknowledgement_key_id"`
	AcknowledgementSeedPath string `json:"acknowledgement_seed_path"`
	PollIntervalSeconds     int64  `json:"poll_interval_seconds,omitempty"`
}

// FleetConfig enables a daemon's signed pull-based remote-operations channel.
// It reports bounded health/activity and accepts only short-lived, authority-
// signed allowlisted commands; it never opens an inbound remote shell.
type FleetConfig struct {
	ReportIntervalSeconds    int64  `json:"report_interval_seconds,omitempty"`
	AgentVersion             string `json:"agent_version,omitempty"`
	HarnessID                string `json:"harness_id,omitempty"`
	HarnessVersion           string `json:"harness_version,omitempty"`
	ConnectorVersion         string `json:"connector_version,omitempty"`
	StateSyncEnabled         bool   `json:"state_sync_enabled,omitempty"`
	StateDirectory           string `json:"state_directory,omitempty"`
	StateSyncIntervalSeconds int64  `json:"state_sync_interval_seconds,omitempty"`
}

// FleetNodeStatus is intentionally bounded node telemetry suitable for an
// operator console. It excludes endpoint addresses, identities, payloads,
// prompts, local paths, and environment values.
type FleetNodeStatus struct {
	NodeID           uint32
	AgentVersion     string
	HarnessID        string
	HarnessVersion   string
	ConnectorVersion string
	UptimeSeconds    uint64
	Connections      uint32
	Peers            uint32
	EncryptedPeers   uint32
	BytesSent        uint64
	BytesReceived    uint64
	PolicyRevision   uint64
}

// OutboundDecisionConfig lets a local sender request a short-lived signed
// Decision before it transmits governed data. It is deliberately separate
// from rollout acknowledgement: an acknowledgement key proves a deployment
// reached a staged revision, whereas this key is delegated to propose actual
// business actions. The configured risk is attachment-controlled so a caller
// cannot downgrade an action to select a weaker evaluator failure policy.
type OutboundDecisionConfig struct {
	AuthorityEndpoint     string             `json:"authority_endpoint"`
	AgentID               string             `json:"agent_id"`
	IntentKeyID           string             `json:"intent_key_id"`
	IntentSeedPath        string             `json:"intent_seed_path"`
	Risk                  decision.RiskClass `json:"risk,omitempty"`
	RequestTimeoutSeconds int64              `json:"request_timeout_seconds,omitempty"`
	MandateID             string             `json:"mandate_id,omitempty"`
	Audience              string             `json:"audience,omitempty"`
	Purpose               string             `json:"purpose,omitempty"`
	// ContentLabels and RetentionClass are attachment-owned defaults for the
	// complete request/response bodies uploaded to Pilot's hosted federation
	// ingress. Application code cannot silently downgrade either field.
	ContentLabels  []string `json:"content_labels,omitempty"`
	RetentionClass string   `json:"retention_class,omitempty"`
	// EvaluatorResidency is an attachment-controlled routing constraint for
	// typed metadata. It does not attest an endpoint's physical geography.
	EvaluatorResidency   string                      `json:"evaluator_residency,omitempty"`
	EvaluatorAttestation *EvaluatorAttestationConfig `json:"evaluator_attestation,omitempty"`
}

// EvaluatorAttestationConfig pins a key independent from the authority's
// decision signer. Before a residency-bound disclosure request is sent, the
// runtime fetches a short-lived signed assertion and verifies this key.
type EvaluatorAttestationConfig struct {
	AttestorID string `json:"attestor_id"`
	KeyID      string `json:"key_id"`
	PublicKey  string `json:"public_key"`
}

// ContentInspectionConfig is retained only so older attachment files fail
// with a precise migration error. Pilot no longer supports a tenant-local
// semantic/content inspector; managed content travels to the Pilot-hosted
// account federation ingress before any side effect is released.
type ContentInspectionConfig struct {
	PresidioEndpoint string   `json:"presidio_endpoint"`
	Language         string   `json:"language,omitempty"`
	Entities         []string `json:"entities,omitempty"`
	ScoreThreshold   float64  `json:"score_threshold,omitempty"`
	MaxBytes         int64    `json:"max_bytes,omitempty"`
	// ProcessingResidency rejects disclosures intended for another region
	// before plaintext is sent to this local inspection endpoint.
	ProcessingResidency string `json:"processing_residency,omitempty"`
}

// Runtime contains the verified local enforcement attachment.
type Runtime struct {
	mu                             sync.Mutex
	fleetStateSyncMu               sync.Mutex
	enforcer                       *decision.Enforcer
	root                           authority.PinnedRoot
	trust                          *authority.Store
	policies                       *authority.PolicyManager
	localPolicy                    *decisionpolicy.EngineInstance
	actionRegistry                 *actionregistry.Registry
	actionProfile                  actionregistry.Profile
	actionAgentID                  string
	actionRisk                     decision.RiskClass
	continuations                  *actioncontinuation.Store
	tenantID                       string
	trustPath                      string
	policyPath                     string
	statePath                      string
	mandates                       *replaceableMandateStore
	mandateBundlePath              string
	mandateAgentID                 string
	rolloutClient                  *authorityhttp.Client
	rolloutAgentID                 string
	rolloutKeyID                   string
	rolloutPrivate                 ed25519.PrivateKey
	rolloutInterval                time.Duration
	fleetInterval                  time.Duration
	fleetAgentVersion              string
	fleetHarnessID                 string
	fleetHarnessVersion            string
	fleetConnectorVersion          string
	fleetControlPath               string
	lifecycleGuardPath             string
	fleetControl                   authority.FleetNodeControl
	fleetControlFound              bool
	fleetStateEnabled              bool
	fleetStateInterval             time.Duration
	fleetStateRoot                 string
	fleetStateCursorPath           string
	fleetStateRevision             uint64
	fleetStateRootHash             string
	fleetStatePendingResults       []authority.FleetStateMutationResult
	outboundClient                 *decisionhttp.Client
	outboundAgentID                string
	outboundKeyID                  string
	outboundPrivate                ed25519.PrivateKey
	outboundRisk                   decision.RiskClass
	outboundTimeout                time.Duration
	outboundMandateID              string
	outboundAudience               string
	outboundPurpose                string
	outboundContentLabels          []string
	outboundRetentionClass         string
	outboundEvaluatorResidency     string
	outboundAttestorID             string
	outboundAttestorKeyID          string
	outboundAttestorPublicKey      ed25519.PublicKey
	outboundAttestationExpiresAt   int64
	receipts                       *governedReceiptSigner
	receiptExporter                *decision.ReceiptExporter
	receiptInterval                time.Duration
	contentInspector               decision.DisclosureContentInspector
	dataResource                   string
	eventTemplate                  string
	dataEnabled                    bool
	eventEnabled                   bool
	dataRequired                   bool
	dataDisclosureRequired         bool
	dataContentInspectionRequired  bool
	dataTransferQuota              *TransferQuotaConfig
	dataRetention                  *DataRetentionConfig
	eventRequired                  bool
	eventDisclosureRequired        bool
	eventContentInspectionRequired bool
	eventTransferQuota             *TransferQuotaConfig
}

type governedReceiptSigner struct {
	journal  *decision.ReceiptJournal
	trust    *authority.Store
	tenantID string
	agentID  string
	keyID    string
	private  ed25519.PrivateKey
}

type residencyBoundInspector struct {
	residency string
	next      decision.DisclosureContentInspector
}

func (inspector residencyBoundInspector) InspectDisclosureContent(ctx context.Context, intent decision.Intent, disclosure *decision.DisclosureBinding, contentType, filename string, content io.Reader) error {
	if disclosure == nil || disclosure.Residency != inspector.residency {
		return fmt.Errorf("enterprise control: local inspector residency does not match disclosure")
	}
	return inspector.next.InspectDisclosureContent(ctx, intent, disclosure, contentType, filename, content)
}

// transportReceiptRecorder binds a shared local signer to one enforcement
// point. Different governed boundaries therefore produce distinct,
// deterministic receipt IDs for the same authority decision.
type transportReceiptRecorder struct {
	signer           *governedReceiptSigner
	enforcementPoint string
}

func (recorder transportReceiptRecorder) RecordGovernedReceipt(ctx context.Context, intent decision.Intent, result decision.Decision) error {
	return recorder.RecordGovernedResultReceipt(ctx, intent, result, decision.Enforced, time.Now())
}

func (recorder transportReceiptRecorder) RecordGovernedResultReceipt(ctx context.Context, intent decision.Intent, result decision.Decision, enforcementResult decision.EnforcementResult, observedAt time.Time) error {
	receipt, err := recorder.newResultReceipt(intent, result, nil, enforcementResult, observedAt)
	if err != nil {
		return err
	}
	if err := receipt.Sign(recorder.signer.private); err != nil {
		return fmt.Errorf("enterprise control: sign governed receipt: %w", err)
	}
	if err := recorder.signer.journal.AppendReceipt(ctx, receipt); err != nil {
		return fmt.Errorf("enterprise control: persist governed receipt: %w", err)
	}
	return nil
}

func (recorder transportReceiptRecorder) RecordGovernedDisclosureReceipt(ctx context.Context, intent decision.Intent, result decision.Decision, disclosure decision.DisclosureBinding) error {
	receipt, err := recorder.newResultReceipt(intent, result, &disclosure, decision.Enforced, time.Now())
	if err != nil {
		return err
	}
	if err := receipt.Sign(recorder.signer.private); err != nil {
		return fmt.Errorf("enterprise control: sign governed disclosure receipt: %w", err)
	}
	if err := recorder.signer.journal.AppendReceipt(ctx, receipt); err != nil {
		return fmt.Errorf("enterprise control: persist governed disclosure receipt: %w", err)
	}
	return nil
}

func (recorder transportReceiptRecorder) newResultReceipt(intent decision.Intent, result decision.Decision, disclosure *decision.DisclosureBinding, enforcementResult decision.EnforcementResult, observedAt time.Time) (decision.Receipt, error) {
	if recorder.signer == nil || recorder.signer.journal == nil || recorder.enforcementPoint == "" {
		return decision.Receipt{}, fmt.Errorf("enterprise control: governed receipt recorder is not initialized")
	}
	publicKey, err := recorder.signer.trust.ReceiptKey(recorder.signer.tenantID, recorder.signer.agentID, recorder.signer.keyID)
	if err != nil || !bytes.Equal(publicKey, recorder.signer.private.Public().(ed25519.PublicKey)) {
		return decision.Receipt{}, fmt.Errorf("enterprise control: receipt signing key is no longer active")
	}
	if disclosure != nil {
		receipt, err := decision.NewDisclosureReceiptForEnforcer(intent, result, *disclosure, recorder.signer.agentID, recorder.enforcementPoint, recorder.signer.keyID, observedAt.Unix(), enforcementResult)
		if err != nil {
			return decision.Receipt{}, fmt.Errorf("enterprise control: create governed disclosure receipt: %w", err)
		}
		return receipt, nil
	}
	receipt, err := decision.NewReceiptForEnforcer(intent, result, recorder.signer.agentID, recorder.enforcementPoint, recorder.signer.keyID, observedAt.Unix(), enforcementResult)
	if err != nil {
		return decision.Receipt{}, fmt.Errorf("enterprise control: create governed receipt: %w", err)
	}
	return receipt, nil
}

// controlState is the restart-durable anti-rollback floor for this local
// attachment. The root pin is configured out of band; this state prevents a
// later daemon restart from accepting an older, still-valid signed bundle.
type controlState struct {
	TenantID                string `json:"tenant_id"`
	TrustRevision           uint64 `json:"trust_revision"`
	TrustPolicyRevision     uint64 `json:"trust_policy_revision"`
	TrustRevocationEpoch    uint64 `json:"trust_revocation_epoch"`
	PolicyRevision          uint64 `json:"policy_revision"`
	PolicyRevocationEpoch   uint64 `json:"policy_revocation_epoch"`
	MandateRevision         uint64 `json:"mandate_revision,omitempty"`
	MandateRevocationEpoch  uint64 `json:"mandate_revocation_epoch,omitempty"`
	MandateHash             string `json:"mandate_hash,omitempty"`
	EnforcementPublication  string `json:"enforcement_publication,omitempty"`
	EnforcementObservedAt   int64  `json:"enforcement_observed_at,omitempty"`
	EnforcementAckDelivered bool   `json:"enforcement_ack_delivered,omitempty"`
}

// Load parses the strict JSON attachment at path, resolves its relative
// bundle paths, verifies every signature and state floor, and constructs an
// enforcer with no remote provider. The enforcer is used only to verify a
// sender-supplied signed Decision below the local signed policy ceiling.
func Load(path string) (*Runtime, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("enterprise control: configuration path is required")
	}
	config, err := readSecureJSON[Config](path)
	if err != nil {
		return nil, fmt.Errorf("enterprise control: read configuration: %w", err)
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	root, err := decodeRoot(config.RootPublicKey)
	if err != nil {
		return nil, err
	}
	directory := filepath.Dir(path)
	if err := secureDirectory(directory); err != nil {
		return nil, fmt.Errorf("enterprise control: configuration directory: %w", err)
	}
	trustPath, err := resolveBundlePath(directory, config.TrustBundlePath)
	if err != nil {
		return nil, fmt.Errorf("enterprise control: trust bundle: %w", err)
	}
	policyPath, err := resolveBundlePath(directory, config.PolicyBundlePath)
	if err != nil {
		return nil, fmt.Errorf("enterprise control: policy bundle: %w", err)
	}
	statePath := filepath.Join(directory, ".enterprise-control-state.json")
	rootPin := authority.PinnedRoot{
		TenantID: config.TenantID, RootKeyID: config.RootKeyID, PublicKey: root,
	}
	store, err := authority.NewStore([]authority.PinnedRoot{rootPin}, time.Now)
	if err != nil {
		return nil, fmt.Errorf("enterprise control: initialize pinned trust: %w", err)
	}
	policies, err := authority.NewPolicyManager(store, decisionpolicy.Validator{}, time.Now)
	if err != nil {
		return nil, fmt.Errorf("enterprise control: initialize policy manager: %w", err)
	}
	ceiling, err := decisionpolicy.New(policies)
	if err != nil {
		return nil, fmt.Errorf("enterprise control: initialize policy ceiling: %w", err)
	}
	runtime := &Runtime{
		enforcer: &decision.Enforcer{Trust: store, Ceiling: ceiling}, root: rootPin, trust: store, policies: policies,
		localPolicy: ceiling, tenantID: config.TenantID, trustPath: trustPath, policyPath: policyPath, statePath: statePath,
	}
	if err := runtime.Reload(); err != nil {
		return nil, err
	}
	if config.Mandates != nil && config.Mandates.Path != "" {
		mandatePath, resolveErr := resolveBundlePath(directory, config.Mandates.Path)
		if resolveErr != nil {
			return nil, fmt.Errorf("enterprise control: mandates: %w", resolveErr)
		}
		mandates, mandateErr := loadMandateStore(mandatePath, config.TenantID, store)
		if mandateErr != nil {
			return nil, fmt.Errorf("enterprise control: mandates: %w", mandateErr)
		}
		runtime.mandates = newReplaceableMandateStore(mandates)
		runtime.enforcer.Ceiling = decision.MandateCeiling{Store: runtime.mandates, Keys: store, Next: ceiling}
	} else if config.Mandates != nil {
		bundlePath, resolveErr := resolveBundlePath(directory, config.Mandates.BundlePath)
		if resolveErr != nil {
			return nil, fmt.Errorf("enterprise control: mandate bundle: %w", resolveErr)
		}
		bundle, mandates, mandateErr := loadMandateBundleStore(bundlePath, config.TenantID, config.Mandates.AgentID, store)
		if mandateErr != nil {
			return nil, fmt.Errorf("enterprise control: mandate bundle: %w", mandateErr)
		}
		runtime.mandates = newReplaceableMandateStore(mandates)
		runtime.mandateBundlePath = bundlePath
		runtime.mandateAgentID = config.Mandates.AgentID
		if mandateErr := runtime.installMandateBundleLocked(bundle, mandates); mandateErr != nil {
			return nil, mandateErr
		}
		runtime.enforcer.Ceiling = decision.MandateCeiling{Store: runtime.mandates, Keys: store, Next: ceiling}
	}
	if config.Receipts != nil {
		seedPath, resolveErr := resolveBundlePath(directory, config.Receipts.SeedPath)
		if resolveErr != nil {
			return nil, fmt.Errorf("enterprise control: receipt signing seed: %w", resolveErr)
		}
		journalPath, resolveErr := resolveBundlePath(directory, config.Receipts.JournalPath)
		if resolveErr != nil {
			return nil, fmt.Errorf("enterprise control: receipt journal: %w", resolveErr)
		}
		privateKey, seedErr := readEd25519Seed(seedPath)
		if seedErr != nil {
			return nil, fmt.Errorf("enterprise control: receipt signing seed: %w", seedErr)
		}
		publicKey, keyErr := runtime.trust.ReceiptKey(config.TenantID, config.Receipts.AgentID, config.Receipts.KeyID)
		if keyErr != nil || !bytes.Equal(publicKey, privateKey.Public().(ed25519.PublicKey)) {
			return nil, fmt.Errorf("enterprise control: receipt signing seed does not match active agent receipt key")
		}
		journal, journalErr := decision.OpenReceiptJournal(journalPath)
		if journalErr != nil {
			return nil, fmt.Errorf("enterprise control: receipt journal: %w", journalErr)
		}
		runtime.receipts = &governedReceiptSigner{
			journal: journal, trust: runtime.trust, tenantID: config.TenantID,
			agentID: config.Receipts.AgentID, keyID: config.Receipts.KeyID, private: privateKey,
		}
		if config.Receipts.ExportEndpoint != "" {
			ackPath, ackResolveErr := resolveBundlePath(directory, config.Receipts.ExportAcknowledgementPath)
			if ackResolveErr != nil {
				return nil, fmt.Errorf("enterprise control: receipt export acknowledgement path: %w", ackResolveErr)
			}
			exporter, exportErr := decision.NewReceiptExporter(decision.ReceiptExporterConfig{
				Journal: journal, Endpoint: config.Receipts.ExportEndpoint, AckPath: ackPath,
				BearerToken: os.Getenv(config.Receipts.ExportBearerTokenEnv),
				Interval:    time.Duration(config.Receipts.ExportIntervalSeconds) * time.Second,
				BatchSize:   config.Receipts.ExportBatchSize,
			})
			if exportErr != nil {
				return nil, fmt.Errorf("enterprise control: receipt exporter: %w", exportErr)
			}
			runtime.receiptExporter = exporter
			runtime.receiptInterval = time.Duration(config.Receipts.ExportIntervalSeconds) * time.Second
			if runtime.receiptInterval == 0 {
				runtime.receiptInterval = 30 * time.Second
			}
		}
	}
	if config.OutboundDecisions != nil {
		seedPath, resolveErr := resolveBundlePath(directory, config.OutboundDecisions.IntentSeedPath)
		if resolveErr != nil {
			return nil, fmt.Errorf("enterprise control: outbound decision seed: %w", resolveErr)
		}
		privateKey, seedErr := readEd25519Seed(seedPath)
		if seedErr != nil {
			return nil, fmt.Errorf("enterprise control: outbound decision seed: %w", seedErr)
		}
		client, clientErr := decisionhttp.New(config.OutboundDecisions.AuthorityEndpoint)
		if clientErr != nil {
			return nil, fmt.Errorf("enterprise control: outbound decision authority endpoint: %w", clientErr)
		}
		publicKey, keyErr := runtime.trust.IntentKey(context.Background(), config.TenantID, config.OutboundDecisions.AgentID, config.OutboundDecisions.IntentKeyID)
		if keyErr != nil || !bytes.Equal(publicKey, privateKey.Public().(ed25519.PublicKey)) {
			return nil, fmt.Errorf("enterprise control: outbound decision seed does not match active agent intent key")
		}
		runtime.outboundClient = client
		runtime.outboundAgentID = config.OutboundDecisions.AgentID
		runtime.outboundKeyID = config.OutboundDecisions.IntentKeyID
		runtime.outboundPrivate = privateKey
		runtime.outboundRisk = config.OutboundDecisions.Risk
		if runtime.outboundRisk == "" {
			runtime.outboundRisk = decision.RiskHigh
		}
		runtime.outboundTimeout = time.Duration(config.OutboundDecisions.RequestTimeoutSeconds) * time.Second
		if runtime.outboundTimeout == 0 {
			runtime.outboundTimeout = 10 * time.Second
		}
		runtime.outboundMandateID = config.OutboundDecisions.MandateID
		runtime.outboundAudience = config.OutboundDecisions.Audience
		runtime.outboundPurpose = config.OutboundDecisions.Purpose
		runtime.outboundContentLabels = append([]string(nil), config.OutboundDecisions.ContentLabels...)
		runtime.outboundRetentionClass = config.OutboundDecisions.RetentionClass
		runtime.outboundEvaluatorResidency = config.OutboundDecisions.EvaluatorResidency
		if config.OutboundDecisions.EvaluatorAttestation != nil {
			attestor := config.OutboundDecisions.EvaluatorAttestation
			publicKey, keyErr := decodeEvaluatorAttestorKey(attestor.PublicKey)
			if keyErr != nil {
				return nil, keyErr
			}
			runtime.outboundAttestorID = attestor.AttestorID
			runtime.outboundAttestorKeyID = attestor.KeyID
			runtime.outboundAttestorPublicKey = publicKey
		}
	}
	if config.Fleet != nil {
		runtime.fleetInterval = time.Duration(config.Fleet.ReportIntervalSeconds) * time.Second
		if runtime.fleetInterval == 0 {
			runtime.fleetInterval = 30 * time.Second
		}
		runtime.fleetAgentVersion = config.Fleet.AgentVersion
		runtime.fleetHarnessID = config.Fleet.HarnessID
		runtime.fleetHarnessVersion = config.Fleet.HarnessVersion
		runtime.fleetConnectorVersion = config.Fleet.ConnectorVersion
		runtime.fleetControlPath = filepath.Join(directory, ".enterprise-fleet-control.json")
		runtime.lifecycleGuardPath = filepath.Join(directory, ".enterprise-lifecycle-applied.json")
		if config.Fleet.StateSyncEnabled {
			// state_directory must be explicit and distinct from the config
			// directory. The prior empty->"." default pointed the scan root at
			// the directory holding enterprise-control.json, so scanFleetState
			// would ship 256KB previews of any operator-added text file there
			// as signed telemetry. Fail closed rather than expose them.
			stateDirectory := strings.TrimSpace(config.Fleet.StateDirectory)
			if stateDirectory == "" {
				return nil, fmt.Errorf("enterprise control: fleet state sync is enabled but state_directory is empty; set it to a dedicated directory distinct from the enterprise-control config directory")
			}
			stateRoot, resolveErr := resolveBundlePath(directory, stateDirectory)
			if resolveErr != nil {
				return nil, fmt.Errorf("enterprise control: fleet state directory: %w", resolveErr)
			}
			if absState, absErr := filepath.Abs(stateRoot); absErr == nil {
				if absConfig, cfgErr := filepath.Abs(directory); cfgErr == nil && absState == absConfig {
					return nil, fmt.Errorf("enterprise control: fleet state_directory must be distinct from the enterprise-control config directory (%s)", directory)
				}
			}
			if err := secureDirectory(stateRoot); err != nil {
				return nil, fmt.Errorf("enterprise control: fleet state directory: %w", err)
			}
			runtime.fleetStateEnabled = true
			runtime.fleetStateRoot = stateRoot
			runtime.fleetStateCursorPath = filepath.Join(stateRoot, ".enterprise-fleet-state-cursor.json")
			runtime.fleetStateInterval = time.Duration(config.Fleet.StateSyncIntervalSeconds) * time.Second
			if runtime.fleetStateInterval == 0 {
				runtime.fleetStateInterval = 5 * time.Second
			}
		}
	}
	if config.DataExchange != nil {
		runtime.dataEnabled = true
		runtime.dataRequired = config.DataExchange.RequireGoverned
		runtime.dataDisclosureRequired = config.DataExchange.RequireDisclosure
		runtime.dataTransferQuota = config.DataExchange.TransferQuota
		runtime.dataRetention = config.DataExchange.Retention
		runtime.dataResource = config.DataExchange.Resource
	}
	if config.EventStream != nil {
		runtime.eventEnabled = true
		runtime.eventRequired = config.EventStream.RequireGoverned
		runtime.eventDisclosureRequired = config.EventStream.RequireDisclosure
		runtime.eventTransferQuota = config.EventStream.TransferQuota
		runtime.eventTemplate = config.EventStream.ResourceTemplate
	}
	if config.Rollout != nil {
		seedPath, resolveErr := resolveBundlePath(directory, config.Rollout.AcknowledgementSeedPath)
		if resolveErr != nil {
			return nil, fmt.Errorf("enterprise control: rollout acknowledgement seed: %w", resolveErr)
		}
		privateKey, seedErr := readEd25519Seed(seedPath)
		if seedErr != nil {
			return nil, fmt.Errorf("enterprise control: rollout acknowledgement seed: %w", seedErr)
		}
		client, clientErr := authorityhttp.New(config.Rollout.AuthorityEndpoint, nil)
		if clientErr != nil {
			return nil, fmt.Errorf("enterprise control: rollout authority endpoint: %w", clientErr)
		}
		publicKey, keyErr := runtime.trust.IntentKey(context.Background(), config.TenantID, config.Rollout.AgentID, config.Rollout.AcknowledgementKeyID)
		if keyErr != nil || !bytes.Equal(publicKey, privateKey.Public().(ed25519.PublicKey)) {
			return nil, fmt.Errorf("enterprise control: rollout acknowledgement seed does not match active agent intent key")
		}
		runtime.rolloutClient = client
		runtime.rolloutAgentID = config.Rollout.AgentID
		runtime.rolloutKeyID = config.Rollout.AcknowledgementKeyID
		runtime.rolloutPrivate = privateKey
		runtime.rolloutInterval = time.Duration(config.Rollout.PollIntervalSeconds) * time.Second
		if runtime.rolloutInterval == 0 {
			runtime.rolloutInterval = 30 * time.Second
		}
	}
	if config.ActionControl != nil {
		runtime.actionRegistry = actionregistry.Builtins()
		runtime.actionProfile = config.ActionControl.Profile
		runtime.actionAgentID = config.ActionControl.AgentID
		if runtime.actionAgentID == "" && config.OutboundDecisions != nil {
			runtime.actionAgentID = config.OutboundDecisions.AgentID
		}
		runtime.actionRisk = config.ActionControl.Risk
		if runtime.actionRisk == "" {
			runtime.actionRisk = decision.RiskHigh
		}
		if runtime.actionProfile.Mode.Normalize() == actionregistry.ModeManagedEnforce {
			continuationDirectory := strings.TrimSpace(config.ActionControl.ContinuationDirectory)
			if continuationDirectory == "" {
				continuationDirectory = "continuations"
			}
			continuationPath, resolveErr := resolveBundlePath(directory, continuationDirectory)
			if resolveErr != nil {
				return nil, fmt.Errorf("enterprise control: action continuation directory: %w", resolveErr)
			}
			continuations, continuationErr := actioncontinuation.Open(continuationPath)
			if continuationErr != nil {
				return nil, fmt.Errorf("enterprise control: action continuation directory: %w", continuationErr)
			}
			runtime.continuations = continuations
		}
	}
	if config.Fleet != nil {
		if err := runtime.loadPersistedFleetControl(); err != nil {
			return nil, err
		}
		if err := runtime.loadFleetStateCursor(); err != nil {
			return nil, err
		}
	}
	return runtime, nil
}

// Reload atomically validates a newer pair of local signed bundles against a
// temporary authority state, then installs it below the already-attached
// enforcer. Resource mappings and the root pin are immutable until restart;
// SIGHUP therefore advances only signed authority state, not configuration.
func (runtime *Runtime) Reload() error {
	if runtime == nil || runtime.trust == nil || runtime.policies == nil || runtime.enforcer == nil {
		return fmt.Errorf("enterprise control: runtime is not initialized")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.reloadLocked()
}

func (runtime *Runtime) reloadLocked() error {
	trustBundle, err := readSecureJSON[authority.TrustBundle](runtime.trustPath)
	if err != nil {
		return fmt.Errorf("enterprise control: read trust bundle: %w", err)
	}
	policyBundle, err := readSecureJSON[authority.PolicyBundle](runtime.policyPath)
	if err != nil {
		return fmt.Errorf("enterprise control: read policy bundle: %w", err)
	}
	if trustBundle.TenantID != runtime.tenantID || policyBundle.TenantID != runtime.tenantID {
		return fmt.Errorf("enterprise control: trust and policy bundles must match configured tenant")
	}
	state, err := loadControlState(runtime.statePath)
	if err != nil {
		return err
	}
	if err := state.accepts(runtime.tenantID, trustBundle, policyBundle); err != nil {
		return err
	}
	// Validate both objects against a new store first. This ensures malformed
	// or mismatched input cannot partially mutate the active enforcement state.
	probeTrust, err := authority.NewStore([]authority.PinnedRoot{runtime.root}, time.Now)
	if err != nil {
		return fmt.Errorf("enterprise control: initialize reload trust: %w", err)
	}
	if err := probeTrust.Install(trustBundle); err != nil {
		return fmt.Errorf("enterprise control: verify trust bundle: %w", err)
	}
	probePolicies, err := authority.NewPolicyManager(probeTrust, decisionpolicy.Validator{}, time.Now)
	if err != nil {
		return fmt.Errorf("enterprise control: initialize reload policy: %w", err)
	}
	// A trust rotation can intentionally raise the policy or revocation floor
	// before the corresponding active policy is available locally. Keep the
	// root-verified trust state and start fail-closed in that case; the rollout
	// loop can subsequently fetch the signed, authority-activated policy. Any
	// other malformed or unauthenticated policy remains a startup error.
	policyUnavailable := policyBundle.Revision < trustBundle.PolicyRevision || policyBundle.RevocationEpoch < trustBundle.RevocationEpoch
	if policyUnavailable {
		if err := policyBundle.Validate(); err != nil {
			return fmt.Errorf("enterprise control: verify stale policy bundle: %w", err)
		}
	} else if err := probePolicies.Install(context.Background(), policyBundle); err != nil {
		return fmt.Errorf("enterprise control: verify policy bundle: %w", err)
	}
	// Persist the anti-rollback floor before exposing the newer state. A disk
	// failure therefore leaves the old live enforcer untouched rather than
	// making a successful-looking reload disappear after the next restart.
	nextState := state
	nextState.TenantID = runtime.tenantID
	nextState.TrustRevision = trustBundle.Revision
	nextState.TrustPolicyRevision = trustBundle.PolicyRevision
	nextState.TrustRevocationEpoch = trustBundle.RevocationEpoch
	if nextState.PolicyRevision != policyBundle.Revision {
		nextState.EnforcementPublication = ""
		nextState.EnforcementObservedAt = 0
		nextState.EnforcementAckDelivered = false
	}
	nextState.PolicyRevision = policyBundle.Revision
	nextState.PolicyRevocationEpoch = policyBundle.RevocationEpoch
	if err := saveControlState(runtime.statePath, nextState); err != nil {
		return err
	}
	if err := runtime.trust.Install(trustBundle); err != nil {
		return fmt.Errorf("enterprise control: install trust bundle: %w", err)
	}
	if policyUnavailable {
		return nil
	}
	if err := runtime.policies.Install(context.Background(), policyBundle); err != nil {
		return fmt.Errorf("enterprise control: install policy bundle: %w", err)
	}
	return nil
}

// HasRollout reports whether this attachment is configured to participate in
// the authority's staged policy acknowledgement lifecycle.
func (runtime *Runtime) HasRollout() bool {
	return runtime != nil && runtime.rolloutClient != nil && runtime.rolloutAgentID != "" && runtime.rolloutKeyID != "" && len(runtime.rolloutPrivate) == ed25519.PrivateKeySize
}

// HasFleetControl reports whether the daemon participates in the signed
// pull-based fleet operations channel.
func (runtime *Runtime) HasFleetControl() bool {
	return runtime != nil && runtime.fleetInterval > 0 && runtime.HasRollout()
}

func (runtime *Runtime) FleetReportInterval() time.Duration {
	if !runtime.HasFleetControl() {
		return 0
	}
	return runtime.fleetInterval
}

// FleetReconciliation is the bounded local result of applying one signed
// desired-state revision. Runtime and policy changes remain explicit: Pilot
// can refresh an already signed policy, while a binary-version drift requires
// the deployment mechanism to restart the node.
type FleetReconciliation struct {
	Control               authority.FleetNodeControl
	Found                 bool
	Status                string
	DetailCode            string
	AppliedPolicyRevision uint64
	VersionMatches        bool
}

// ReconcileFleetControl fetches, verifies, anti-rolls back, and durably
// installs the authority's desired state. A missing remote object retains the
// last signed local state; clearing desired state therefore requires a newer
// signed revision instead of an unauthenticated absence.
func (runtime *Runtime) ReconcileFleetControl(ctx context.Context, runningVersion string) (FleetReconciliation, error) {
	if !runtime.HasFleetControl() {
		return FleetReconciliation{}, fmt.Errorf("enterprise control: fleet control is not configured")
	}
	runtime.mu.Lock()
	client, tenantID, agentID := runtime.rolloutClient, runtime.tenantID, runtime.rolloutAgentID
	runtime.mu.Unlock()
	remote, found, err := client.FleetControl(ctx, tenantID, agentID)
	if err != nil {
		return FleetReconciliation{}, fmt.Errorf("enterprise control: fetch desired fleet state: %w", err)
	}
	if found {
		publicKey, keyErr := runtime.trust.DecisionKey(ctx, tenantID, remote.KeyID)
		if keyErr != nil || remote.Verify(publicKey, time.Now()) != nil {
			return FleetReconciliation{}, fmt.Errorf("enterprise control: invalid desired fleet state")
		}
		runtime.mu.Lock()
		err = runtime.installFleetControlLocked(remote)
		runtime.mu.Unlock()
		if err != nil {
			return FleetReconciliation{}, err
		}
	}
	runtime.mu.Lock()
	control, installed := runtime.fleetControl, runtime.fleetControlFound
	runtime.mu.Unlock()
	if !installed {
		return FleetReconciliation{Status: "no_desired_state", VersionMatches: true}, nil
	}
	policy, err := runtime.policies.Active(ctx, tenantID)
	if err != nil {
		return FleetReconciliation{}, fmt.Errorf("enterprise control: read active policy for reconciliation: %w", err)
	}
	if control.DesiredPolicyRevision > policy.Revision {
		if refreshErr := runtime.RefreshRollout(ctx); refreshErr != nil {
			return FleetReconciliation{Control: control, Found: true, Status: "partially_applied", DetailCode: "policy_refresh_failed", AppliedPolicyRevision: policy.Revision, VersionMatches: control.DesiredVersion == "" || control.DesiredVersion == runningVersion}, refreshErr
		}
		policy, err = runtime.policies.Active(ctx, tenantID)
		if err != nil {
			return FleetReconciliation{}, err
		}
	}
	result := FleetReconciliation{Control: control, Found: true, Status: "applied", AppliedPolicyRevision: policy.Revision, VersionMatches: control.DesiredVersion == "" || control.DesiredVersion == runningVersion}
	if control.DesiredPolicyRevision != 0 && policy.Revision != control.DesiredPolicyRevision {
		result.Status, result.DetailCode = "partially_applied", "policy_revision_mismatch"
	}
	if !result.VersionMatches {
		result.Status, result.DetailCode = "partially_applied", "version_restart_required"
	}
	return result, nil
}

func (runtime *Runtime) CurrentPolicyRevision(ctx context.Context) uint64 {
	if runtime == nil || runtime.policies == nil {
		return 0
	}
	policy, err := runtime.policies.Active(ctx, runtime.tenantID)
	if err != nil {
		return 0
	}
	return policy.Revision
}

func (runtime *Runtime) CurrentFleetControl() (authority.FleetNodeControl, bool) {
	if runtime == nil {
		return authority.FleetNodeControl{}, false
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.fleetControl, runtime.fleetControlFound
}

func (runtime *Runtime) loadPersistedFleetControl() error {
	if runtime.fleetControlPath == "" {
		return nil
	}
	if _, err := os.Lstat(runtime.fleetControlPath); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("enterprise control: inspect persisted fleet control: %w", err)
	}
	control, err := readSecureJSON[authority.FleetNodeControl](runtime.fleetControlPath)
	if err != nil {
		return fmt.Errorf("enterprise control: read persisted fleet control: %w", err)
	}
	publicKey, err := runtime.trust.DecisionKey(context.Background(), runtime.tenantID, control.KeyID)
	if err != nil || control.Verify(publicKey, time.Now()) != nil || control.AgentID != runtime.rolloutAgentID {
		return fmt.Errorf("enterprise control: invalid persisted fleet control")
	}
	runtime.fleetControl, runtime.fleetControlFound = control, true
	return nil
}

func (runtime *Runtime) installFleetControlLocked(control authority.FleetNodeControl) error {
	if control.TenantID != runtime.tenantID || control.AgentID != runtime.rolloutAgentID {
		return fmt.Errorf("enterprise control: desired fleet state binding mismatch")
	}
	if runtime.fleetControlFound {
		if control.Revision < runtime.fleetControl.Revision {
			return fmt.Errorf("enterprise control: desired fleet state is below local rollback floor")
		}
		if control.Revision == runtime.fleetControl.Revision {
			if control.Signature != runtime.fleetControl.Signature {
				return fmt.Errorf("enterprise control: conflicting desired fleet state revision")
			}
			return nil
		}
	}
	if err := writeSecureJSON(runtime.fleetControlPath, control); err != nil {
		return fmt.Errorf("enterprise control: persist desired fleet state: %w", err)
	}
	runtime.fleetControl, runtime.fleetControlFound = control, true
	return nil
}

// ReportFleetStatus signs and publishes bounded operational telemetry using
// the enrolled rollout intent key. A reporting failure does not alter local
// authorization or governed delivery.
func (runtime *Runtime) ReportFleetStatus(ctx context.Context, status FleetNodeStatus) error {
	if !runtime.HasFleetControl() {
		return fmt.Errorf("enterprise control: fleet control is not configured")
	}
	runtime.mu.Lock()
	client := runtime.rolloutClient
	tenantID, agentID, keyID := runtime.tenantID, runtime.rolloutAgentID, runtime.rolloutKeyID
	privateKey := append(ed25519.PrivateKey(nil), runtime.rolloutPrivate...)
	profile, registry, receiptCapable := runtime.actionProfile, runtime.actionRegistry, runtime.receipts != nil
	reportedAgentVersion, reportedHarnessID := runtime.fleetAgentVersion, runtime.fleetHarnessID
	reportedHarnessVersion, reportedConnectorVersion := runtime.fleetHarnessVersion, runtime.fleetConnectorVersion
	runtime.mu.Unlock()
	now := time.Now().UTC()
	if reportedAgentVersion != "" {
		status.AgentVersion = reportedAgentVersion
	}
	if reportedHarnessID != "" {
		status.HarnessID = reportedHarnessID
	}
	if reportedHarnessVersion != "" {
		status.HarnessVersion = reportedHarnessVersion
	}
	if reportedConnectorVersion != "" {
		status.ConnectorVersion = reportedConnectorVersion
	}
	harnessID := strings.TrimSpace(status.HarnessID)
	if harnessID == "" {
		harnessID = "pilot-native"
	}
	harnessVersion := strings.TrimSpace(status.HarnessVersion)
	if harnessVersion == "" {
		harnessVersion = status.AgentVersion
		if harnessVersion == "" {
			harnessVersion = "unknown"
		}
	}
	connectorVersion := strings.TrimSpace(status.ConnectorVersion)
	if connectorVersion == "" {
		connectorVersion = "unknown"
	}
	capabilities := make([]actionregistry.AdapterCapability, 0)
	if registry != nil && profile.Mode.Normalize() != actionregistry.ModeOff {
		for _, definition := range registry.Definitions() {
			if !profile.AppliesTo(registry, definition.Name) {
				continue
			}
			enforce := profile.Mode.Enforces()
			managed := profile.Mode.Managed()
			capabilities = append(capabilities, actionregistry.AdapterCapability{
				Action: definition.Name, AdapterID: "pilot-action-hook", AdapterVersion: connectorVersion,
				Observe: true, Enforce: enforce, Suspend: enforce && managed && definition.Suspendable,
				Resume: enforce && managed && definition.Resumable, Receipt: receiptCapable,
			})
		}
	}
	version := authority.FleetReportVersion
	if len(capabilities) > 0 {
		version = authority.FleetReportVersionV2
	}
	report := authority.FleetNodeReport{
		Version: version, TenantID: tenantID, AgentID: agentID, NodeID: status.NodeID,
		AgentVersion: status.AgentVersion, ObservedAt: now.Unix(), UptimeSeconds: status.UptimeSeconds,
		Connections: status.Connections, Peers: status.Peers, EncryptedPeers: status.EncryptedPeers,
		BytesSent: status.BytesSent, BytesReceived: status.BytesReceived, PolicyRevision: status.PolicyRevision, KeyID: keyID,
	}
	if version == authority.FleetReportVersionV2 {
		report.HarnessID, report.HarnessVersion, report.ConnectorVersion, report.Capabilities = harnessID, harnessVersion, connectorVersion, capabilities
	}
	if err := report.Sign(privateKey); err != nil {
		return err
	}
	if err := client.ReportFleetNode(ctx, report); err != nil {
		return fmt.Errorf("enterprise control: report fleet status: %w", err)
	}
	return nil
}

// FleetCommands returns only commands which verify against the daemon's
// locally pinned authority trust and target this enrolled agent.
func (runtime *Runtime) FleetCommands(ctx context.Context) ([]authority.FleetCommand, error) {
	if !runtime.HasFleetControl() {
		return nil, fmt.Errorf("enterprise control: fleet control is not configured")
	}
	runtime.mu.Lock()
	client := runtime.rolloutClient
	tenantID, agentID := runtime.tenantID, runtime.rolloutAgentID
	runtime.mu.Unlock()
	commands, err := client.FleetCommands(ctx, tenantID, agentID)
	if err != nil {
		return nil, fmt.Errorf("enterprise control: fetch fleet commands: %w", err)
	}
	verified := make([]authority.FleetCommand, 0, len(commands))
	for _, command := range commands {
		publicKey, keyErr := runtime.trust.DecisionKey(ctx, tenantID, command.KeyID)
		if keyErr != nil || command.Verify(publicKey, time.Now()) != nil || !command.TargetsAgent(agentID) {
			return nil, fmt.Errorf("enterprise control: invalid fleet command")
		}
		verified = append(verified, command)
	}
	return verified, nil
}

// lifecycleGuardState records the last authority-signed lifecycle command that
// was applied. It defeats replay of a captured restart/shutdown command: a
// compromised or MITM'd authority connection could otherwise re-present a
// still-valid signed command every poll (and after the restart it caused) for
// up to its 24h TTL, since the daemon's result report is dropped by the
// attacker so server-side de-duplication never engages. IssuedAt is a
// monotonic high-water; LastID guards an exact same-second re-send.
type lifecycleGuardState struct {
	IssuedAt int64  `json:"issued_at"`
	LastID   string `json:"last_id"`
}

// LifecycleCommandAlreadyApplied reports whether a signed lifecycle command has
// already been acted on (by monotonic issue time or exact id). Missing or
// unreadable state reads as "not applied" (first boot); durability rests on the
// fail-closed MarkLifecycleCommandApplied step.
func (runtime *Runtime) LifecycleCommandAlreadyApplied(command authority.FleetCommand) bool {
	if runtime == nil || runtime.lifecycleGuardPath == "" {
		return false
	}
	state, err := readSecureJSON[lifecycleGuardState](runtime.lifecycleGuardPath)
	if err != nil {
		return false
	}
	return command.IssuedAt <= state.IssuedAt || (command.ID != "" && command.ID == state.LastID)
}

// MarkLifecycleCommandApplied durably records a lifecycle command as applied
// BEFORE the daemon acts on it, so the action cannot loop across polls or the
// restart it triggers. The caller must treat an error as fatal to the action
// (fail closed) rather than proceed unrecorded.
func (runtime *Runtime) MarkLifecycleCommandApplied(command authority.FleetCommand) error {
	if runtime == nil || runtime.lifecycleGuardPath == "" {
		return fmt.Errorf("enterprise control: lifecycle guard not configured")
	}
	state, err := readSecureJSON[lifecycleGuardState](runtime.lifecycleGuardPath)
	if err != nil {
		state = lifecycleGuardState{}
	}
	if command.IssuedAt > state.IssuedAt {
		state.IssuedAt = command.IssuedAt
	}
	state.LastID = command.ID
	return writeSecureJSON(runtime.lifecycleGuardPath, state)
}

// ReportFleetCommandResult signs an allowlisted-command outcome. The remote
// service keeps the short result code, never daemon logs or raw errors.
func (runtime *Runtime) ReportFleetCommandResult(ctx context.Context, commandID, outcome, detailCode string) error {
	if !runtime.HasFleetControl() {
		return fmt.Errorf("enterprise control: fleet control is not configured")
	}
	runtime.mu.Lock()
	client := runtime.rolloutClient
	tenantID, agentID, keyID := runtime.tenantID, runtime.rolloutAgentID, runtime.rolloutKeyID
	privateKey := append(ed25519.PrivateKey(nil), runtime.rolloutPrivate...)
	runtime.mu.Unlock()
	result := authority.FleetCommandResult{
		Version: authority.FleetReportVersion, TenantID: tenantID, AgentID: agentID, CommandID: commandID,
		Outcome: outcome, DetailCode: detailCode, ObservedAt: time.Now().UTC().Unix(), KeyID: keyID,
	}
	if err := result.Sign(privateKey); err != nil {
		return err
	}
	if err := client.ReportFleetResult(ctx, result); err != nil {
		return fmt.Errorf("enterprise control: report fleet command result: %w", err)
	}
	return nil
}

// ReportFleetControlAcknowledgement gives the management plane signed proof
// of the exact desired-state revision the node reached. The record contains
// only coarse applied state and never local paths, endpoints, or payloads.
func (runtime *Runtime) ReportFleetControlAcknowledgement(ctx context.Context, reconciliation FleetReconciliation, runningVersion string) error {
	if !runtime.HasFleetControl() || !reconciliation.Found {
		return fmt.Errorf("enterprise control: no fleet desired state to acknowledge")
	}
	runtime.mu.Lock()
	client := runtime.rolloutClient
	tenantID, agentID, keyID := runtime.tenantID, runtime.rolloutAgentID, runtime.rolloutKeyID
	privateKey := append(ed25519.PrivateKey(nil), runtime.rolloutPrivate...)
	runtime.mu.Unlock()
	status := reconciliation.Status
	switch status {
	case authority.FleetControlApplied, authority.FleetControlPartiallyApplied, authority.FleetControlRejected:
	default:
		status = authority.FleetControlRejected
		if reconciliation.DetailCode == "" {
			reconciliation.DetailCode = "reconciliation_failed"
		}
	}
	acknowledgement := authority.FleetControlAcknowledgement{
		Version: authority.FleetControlAckVersion, TenantID: tenantID, AgentID: agentID,
		ControlRevision: reconciliation.Control.Revision, Status: status, DetailCode: reconciliation.DetailCode,
		AppliedPolicyRevision: reconciliation.AppliedPolicyRevision, RunningVersion: runningVersion,
		Quarantined: reconciliation.Control.Quarantined, ObservedAt: time.Now().UTC().Unix(), KeyID: keyID,
	}
	if err := acknowledgement.Sign(privateKey); err != nil {
		return err
	}
	if err := client.ReportFleetControlAcknowledgement(ctx, acknowledgement); err != nil {
		return fmt.Errorf("enterprise control: report fleet control acknowledgement: %w", err)
	}
	return nil
}

// HasOutboundDecisions reports whether this attachment can request signed
// Decisions for a local sender. It is opt-in so open-agent installations keep
// their existing direct message and file behavior.
func (runtime *Runtime) HasOutboundDecisions() bool {
	return runtime != nil && runtime.outboundClient != nil && runtime.outboundAgentID != "" && runtime.outboundKeyID != "" && len(runtime.outboundPrivate) == ed25519.PrivateKeySize
}

// AuthorizeOutbound creates a fresh, signed Intent and asks the configured
// authority for a Decision. It verifies the response against the locally
// pinned trust and deterministic policy ceiling before returning it. A deny or
// approval-required result is returned as a valid Decision; the caller must
// not perform the side effect unless the outcome permits it.
func (runtime *Runtime) AuthorizeOutbound(ctx context.Context, action, resource, payloadHash string) (decision.Intent, decision.Decision, error) {
	return runtime.authorizeOutbound(ctx, action, resource, payloadHash, nil)
}

// AuthorizeOutboundDisclosure creates an outbound Intent whose payload hash
// binds typed disclosure metadata, then sends that metadata through the
// disclosure-aware authority envelope. The attachment-owned audience and
// purpose must match the binding so an application cannot select a different
// recipient or stated purpose at request time.
func (runtime *Runtime) AuthorizeOutboundDisclosure(ctx context.Context, action, resource string, disclosure decision.DisclosureBinding) (decision.Intent, decision.Decision, error) {
	payloadHash, err := disclosure.Hash()
	if err != nil {
		return decision.Intent{}, decision.Decision{}, err
	}
	return runtime.authorizeOutbound(ctx, action, resource, payloadHash, &disclosure)
}

// AuthorizeOutboundFederatedContent sends the exact exchange body to the
// Pilot-hosted account ingress configured as AuthorityEndpoint. The hosted
// response remains below the locally pinned policy ceiling and is bound to the
// disclosure hash; a customer-local semantic inspector is never invoked.
func (runtime *Runtime) AuthorizeOutboundFederatedContent(ctx context.Context, action, resource string, content decision.FederatedContent) (decision.Intent, decisionhttp.FederationExchangeResponse, error) {
	if !runtime.HasOutboundDecisions() {
		return decision.Intent{}, decisionhttp.FederationExchangeResponse{}, fmt.Errorf("enterprise control: outbound decisions are not configured")
	}
	if err := content.Validate(); err != nil {
		return decision.Intent{}, decisionhttp.FederationExchangeResponse{}, err
	}
	runtime.mu.Lock()
	client := runtime.outboundClient
	agentID, keyID := runtime.outboundAgentID, runtime.outboundKeyID
	privateKey := append(ed25519.PrivateKey(nil), runtime.outboundPrivate...)
	risk, timeout := runtime.outboundRisk, runtime.outboundTimeout
	mandateID, audience, purpose := runtime.outboundMandateID, runtime.outboundAudience, runtime.outboundPurpose
	evaluatorResidency := runtime.outboundEvaluatorResidency
	attestorConfigured := len(runtime.outboundAttestorPublicKey) == ed25519.PublicKeySize
	runtime.mu.Unlock()
	disclosure := content.Disclosure
	if audience != disclosure.Recipient || purpose != disclosure.Purpose {
		return decision.Intent{}, decisionhttp.FederationExchangeResponse{}, fmt.Errorf("enterprise control: federated content recipient and purpose must match attachment")
	}
	if evaluatorResidency != "" && disclosure.Residency != evaluatorResidency {
		return decision.Intent{}, decisionhttp.FederationExchangeResponse{}, fmt.Errorf("enterprise control: federated content residency does not match hosted evaluator routing")
	}
	if attestorConfigured {
		attestationContext, cancel := context.WithTimeout(ctx, timeout)
		err := runtime.verifyEvaluatorAttestation(attestationContext, client, evaluatorResidency)
		cancel()
		if err != nil {
			return decision.Intent{}, decisionhttp.FederationExchangeResponse{}, err
		}
	}
	publicKey, keyErr := runtime.trust.IntentKey(ctx, runtime.tenantID, agentID, keyID)
	if keyErr != nil || !bytes.Equal(publicKey, privateKey.Public().(ed25519.PublicKey)) {
		return decision.Intent{}, decisionhttp.FederationExchangeResponse{}, fmt.Errorf("enterprise control: outbound intent key is no longer active")
	}
	payloadHash, err := disclosure.Hash()
	if err != nil {
		return decision.Intent{}, decisionhttp.FederationExchangeResponse{}, err
	}
	nonce, err := decision.NewNonce()
	if err != nil {
		return decision.Intent{}, decisionhttp.FederationExchangeResponse{}, err
	}
	now := time.Now().UTC()
	intent := decision.Intent{
		Version: decision.SchemaVersion, ID: "federation-" + nonce,
		TenantID: runtime.tenantID, AgentID: agentID, Action: action, Resource: resource,
		MandateID: mandateID, Audience: audience, Purpose: purpose, PayloadHash: payloadHash, Risk: risk,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(2 * time.Minute).Unix(), Nonce: nonce, KeyID: keyID,
	}
	if err := intent.Sign(privateKey); err != nil {
		return decision.Intent{}, decisionhttp.FederationExchangeResponse{}, err
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	response, err := client.SubmitFederationExchange(requestContext, decisionhttp.FederationExchangeRequest{
		Version: decisionhttp.FederationExchangeVersion, Intent: intent, Content: content.Clone(),
	})
	if err != nil {
		return decision.Intent{}, decisionhttp.FederationExchangeResponse{}, fmt.Errorf("enterprise control: hosted federation exchange: %w", err)
	}
	if err := runtime.enforcer.VerifyDisclosure(ctx, intent, response.Decision, disclosure); err != nil {
		return decision.Intent{}, decisionhttp.FederationExchangeResponse{}, fmt.Errorf("enterprise control: verify hosted federation decision: %w", err)
	}
	return intent, response, nil
}

// NewOutboundFederatedContent creates the exact hosted request attachment
// from immutable node configuration and the adapter's real bytes. It is the
// only supported construction path for built-in managed adapters, preventing
// application-selected labels, purpose, recipient, retention, or residency.
func (runtime *Runtime) NewOutboundFederatedContent(contentType, filename string, body []byte) (decision.FederatedContent, error) {
	if runtime == nil || !runtime.HasOutboundDecisions() {
		return decision.FederatedContent{}, fmt.Errorf("enterprise control: outbound decisions are not configured")
	}
	runtime.mu.Lock()
	labels := append([]string(nil), runtime.outboundContentLabels...)
	recipient, purpose := runtime.outboundAudience, runtime.outboundPurpose
	residency, retention := runtime.outboundEvaluatorResidency, runtime.outboundRetentionClass
	runtime.mu.Unlock()
	if len(labels) == 0 {
		labels = []string{"unclassified"}
	}
	if retention == "" {
		retention = "exchange-7d"
	}
	disclosure := decision.DisclosureBinding{
		Version: decision.DisclosureBindingRetentionVersion, ContentHash: decision.HashPayload(body),
		DeclaredBytes: uint64(len(body)), ContentType: strings.ToLower(strings.TrimSpace(contentType)),
		Labels: labels, Recipient: recipient, Purpose: purpose, Residency: residency,
		Filename: filename, RetentionClass: retention,
	}
	return decision.NewFederatedContent(disclosure, body)
}

// NewOutboundFederatedResponseContent creates the post-hook counterpart for
// bytes returned to this node. Response metadata is still node-owned and
// cannot be supplied by the remote peer or application harness.
func (runtime *Runtime) NewOutboundFederatedResponseContent(contentType, filename string, body []byte) (decision.FederatedContent, error) {
	if runtime == nil || !runtime.HasOutboundDecisions() {
		return decision.FederatedContent{}, fmt.Errorf("enterprise control: outbound decisions are not configured")
	}
	runtime.mu.Lock()
	labels := append([]string(nil), runtime.outboundContentLabels...)
	agentID, purpose := runtime.outboundAgentID, runtime.outboundPurpose
	residency, retention := runtime.outboundEvaluatorResidency, runtime.outboundRetentionClass
	runtime.mu.Unlock()
	if len(labels) == 0 {
		labels = []string{"unclassified"}
	}
	if retention == "" {
		retention = "exchange-7d"
	}
	if len(purpose) > 247 {
		purpose = purpose[:247]
	}
	disclosure := decision.DisclosureBinding{
		Version: decision.DisclosureBindingRetentionVersion, ContentHash: decision.HashPayload(body),
		DeclaredBytes: uint64(len(body)), ContentType: strings.ToLower(strings.TrimSpace(contentType)),
		Labels: labels, Recipient: "agent:" + agentID, Purpose: purpose + ".response",
		Residency: residency, Filename: filename, RetentionClass: retention,
	}
	return decision.NewFederatedContent(disclosure, body)
}

func (runtime *Runtime) authorizeOutbound(ctx context.Context, action, resource, payloadHash string, disclosure *decision.DisclosureBinding) (decision.Intent, decision.Decision, error) {
	if !runtime.HasOutboundDecisions() {
		return decision.Intent{}, decision.Decision{}, fmt.Errorf("enterprise control: outbound decisions are not configured")
	}
	nonce, err := decision.NewNonce()
	if err != nil {
		return decision.Intent{}, decision.Decision{}, err
	}
	runtime.mu.Lock()
	client := runtime.outboundClient
	agentID := runtime.outboundAgentID
	keyID := runtime.outboundKeyID
	privateKey := append(ed25519.PrivateKey(nil), runtime.outboundPrivate...)
	risk := runtime.outboundRisk
	timeout := runtime.outboundTimeout
	mandateID := runtime.outboundMandateID
	audience := runtime.outboundAudience
	purpose := runtime.outboundPurpose
	evaluatorResidency := runtime.outboundEvaluatorResidency
	attestorConfigured := len(runtime.outboundAttestorPublicKey) == ed25519.PublicKeySize
	runtime.mu.Unlock()
	if disclosure != nil && (audience != disclosure.Recipient || purpose != disclosure.Purpose) {
		return decision.Intent{}, decision.Decision{}, fmt.Errorf("enterprise control: outbound disclosure recipient and purpose must match attachment")
	}
	if disclosure != nil && evaluatorResidency != "" && disclosure.Residency != evaluatorResidency {
		return decision.Intent{}, decision.Decision{}, fmt.Errorf("enterprise control: outbound disclosure residency does not match configured evaluator")
	}
	if disclosure != nil && attestorConfigured {
		attestationContext, cancel := context.WithTimeout(ctx, timeout)
		err := runtime.verifyEvaluatorAttestation(attestationContext, client, evaluatorResidency)
		cancel()
		if err != nil {
			return decision.Intent{}, decision.Decision{}, err
		}
	}
	if publicKey, keyErr := runtime.trust.IntentKey(ctx, runtime.tenantID, agentID, keyID); keyErr != nil || !bytes.Equal(publicKey, privateKey.Public().(ed25519.PublicKey)) {
		return decision.Intent{}, decision.Decision{}, fmt.Errorf("enterprise control: outbound intent key is no longer active")
	}
	now := time.Now().UTC()
	intent := decision.Intent{
		Version: decision.SchemaVersion, ID: "outbound-" + nonce,
		TenantID: runtime.tenantID, AgentID: agentID, Action: action, Resource: resource,
		MandateID: mandateID, Audience: audience, Purpose: purpose,
		PayloadHash: payloadHash, Risk: risk,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(2 * time.Minute).Unix(), Nonce: nonce, KeyID: keyID,
	}
	if err := intent.Sign(privateKey); err != nil {
		return decision.Intent{}, decision.Decision{}, err
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var result decision.Decision
	if disclosure != nil {
		result, err = client.AuthorizeDisclosure(requestContext, intent, *disclosure)
	} else {
		result, err = client.Authorize(requestContext, intent)
	}
	if err != nil {
		return decision.Intent{}, decision.Decision{}, fmt.Errorf("enterprise control: request outbound decision: %w", err)
	}
	if err := runtime.enforcer.Verify(ctx, intent, result); err != nil {
		return decision.Intent{}, decision.Decision{}, fmt.Errorf("enterprise control: verify outbound decision: %w", err)
	}
	return intent, result, nil
}

// verifyEvaluatorAttestation ensures that a residency-bound disclosure is not
// sent until a separately pinned attestor has vouched for the authority's
// evaluator origin. The assertion itself intentionally contains no disclosure
// metadata or payload; it is a short-lived deployment-evidence reference.
func (runtime *Runtime) verifyEvaluatorAttestation(ctx context.Context, client *decisionhttp.Client, residency string) error {
	now := time.Now().UTC()
	runtime.mu.Lock()
	if runtime.outboundAttestationExpiresAt > now.Unix() {
		runtime.mu.Unlock()
		return nil
	}
	attestorID := runtime.outboundAttestorID
	keyID := runtime.outboundAttestorKeyID
	publicKey := append(ed25519.PublicKey(nil), runtime.outboundAttestorPublicKey...)
	runtime.mu.Unlock()

	origin, err := client.EvaluatorOrigin()
	if err != nil {
		return fmt.Errorf("enterprise control: evaluator attestation origin: %w", err)
	}
	attestation, err := client.EvaluatorAttestation(ctx)
	if err != nil {
		return fmt.Errorf("enterprise control: fetch evaluator attestation: %w", err)
	}
	if err := attestation.VerifyForEndpoint(origin, residency, attestorID, keyID, publicKey, now); err != nil {
		return fmt.Errorf("enterprise control: verify evaluator attestation: %w", err)
	}
	runtime.mu.Lock()
	if attestation.ExpiresAt > runtime.outboundAttestationExpiresAt {
		runtime.outboundAttestationExpiresAt = attestation.ExpiresAt
	}
	runtime.mu.Unlock()
	return nil
}

// RolloutInterval returns the bounded authority poll cadence. It is zero when
// the attachment does not participate in rollout acknowledgement.
func (runtime *Runtime) RolloutInterval() time.Duration {
	if runtime == nil || runtime.rolloutInterval <= 0 {
		return 0
	}
	return runtime.rolloutInterval
}

// HasReceiptExport reports whether signed enforcement receipts should be
// asynchronously exported. Export availability never changes local action
// authorization or receipt persistence.
func (runtime *Runtime) HasReceiptExport() bool {
	return runtime != nil && runtime.receiptExporter != nil && runtime.receiptInterval > 0
}

// ReceiptExportInterval returns the configured bounded export cadence.
func (runtime *Runtime) ReceiptExportInterval() time.Duration {
	if runtime == nil || runtime.receiptInterval <= 0 {
		return 0
	}
	return runtime.receiptInterval
}

// ExportReceiptsOnce attempts idempotent export of locally durable receipts.
// It is deliberately separate from every governed action path.
func (runtime *Runtime) ExportReceiptsOnce(ctx context.Context) error {
	if !runtime.HasReceiptExport() {
		return fmt.Errorf("enterprise control: receipt export is not configured")
	}
	return runtime.receiptExporter.ExportOnce(ctx)
}

// RefreshRollout fetches a targeted staged candidate and the signed active
// policy from the configured authority. Candidate validation and the staged
// acknowledgement happen before activation; only the authority's current
// policy endpoint can advance the live local ceiling.
func (runtime *Runtime) RefreshRollout(ctx context.Context) error {
	if !runtime.HasRollout() {
		return fmt.Errorf("enterprise control: rollout participation is not configured")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	trust, foundTrust, err := runtime.rolloutClient.CurrentTrust(ctx, runtime.tenantID)
	if err != nil {
		return err
	}
	candidate, foundCandidate, err := runtime.rolloutClient.Candidate(ctx, runtime.tenantID, runtime.rolloutAgentID)
	if err != nil {
		return err
	}
	current, foundCurrent, err := runtime.rolloutClient.CurrentPolicy(ctx, runtime.tenantID, runtime.rolloutAgentID)
	if err != nil {
		return err
	}
	var mandateBundle decision.MandateBundle
	foundMandateBundle := false
	if runtime.mandateBundlePath != "" {
		mandateBundle, foundMandateBundle, err = runtime.rolloutClient.CurrentMandateBundle(ctx, runtime.tenantID, runtime.mandateAgentID)
		if err != nil {
			return err
		}
		if !foundMandateBundle {
			return fmt.Errorf("enterprise control: authority has no mandate bundle for configured agent")
		}
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if foundTrust {
		if err := runtime.installTrustLocked(trust); err != nil {
			return err
		}
	}
	if foundCurrent {
		if err := runtime.installActivePolicyLocked(ctx, current); err != nil {
			return err
		}
	}
	if foundMandateBundle {
		if err := runtime.installRemoteMandateBundleLocked(mandateBundle); err != nil {
			return err
		}
	}
	if foundCandidate && (!foundCurrent || candidate.Bundle.Revision > current.Bundle.Revision) {
		if err := runtime.stageCandidateLocked(ctx, candidate); err != nil {
			return err
		}
	}
	return nil
}

// installTrustLocked root-verifies and persists a remotely supplied trust
// bundle before making it visible to the local enforcer. The Store's durable
// commit hook preserves its strict in-memory monotonicity check, so another
// root-signed bundle at the same revision cannot replace existing trust.
//
// The bundle file is committed before the anti-rollback state. If the process
// stops between those two writes, the next startup sees newer signed trust and
// advances the floor; the reverse order could make recovery impossible.
func (runtime *Runtime) installTrustLocked(bundle authority.TrustBundle) error {
	if bundle.TenantID != runtime.tenantID {
		return fmt.Errorf("enterprise control: current trust tenant binding mismatch")
	}
	state, err := loadControlState(runtime.statePath)
	if err != nil {
		return err
	}
	if state.TenantID == "" {
		return fmt.Errorf("enterprise control: persisted control state is required before installing remote trust")
	}
	if err := state.acceptsTrust(runtime.tenantID, bundle); err != nil {
		return err
	}
	nextState := state
	nextState.TenantID = runtime.tenantID
	nextState.TrustRevision = bundle.Revision
	nextState.TrustPolicyRevision = bundle.PolicyRevision
	nextState.TrustRevocationEpoch = bundle.RevocationEpoch
	if err := runtime.trust.InstallWithCommit(bundle, func() error {
		if err := writeSecureJSON(runtime.trustPath, bundle); err != nil {
			return fmt.Errorf("enterprise control: persist current trust: %w", err)
		}
		return saveControlState(runtime.statePath, nextState)
	}); err != nil {
		return fmt.Errorf("enterprise control: install current trust: %w", err)
	}
	return nil
}

func (runtime *Runtime) stageCandidateLocked(ctx context.Context, candidate authorityhttp.PublicationEnvelope) error {
	if candidate.Publication.TenantID != runtime.tenantID || !publicationTargetsAgent(candidate.Publication, runtime.rolloutAgentID) || candidate.Publication.PolicyRevision != candidate.Bundle.Revision || candidate.Publication.RevocationEpoch != candidate.Bundle.RevocationEpoch {
		return fmt.Errorf("enterprise control: rollout candidate tenant or revision binding mismatch")
	}
	issuer, err := runtime.trust.PolicyKey(runtime.tenantID, candidate.Publication.KeyID)
	if err != nil {
		return fmt.Errorf("enterprise control: resolve candidate policy key: %w", err)
	}
	if err := candidate.Publication.VerifyFor(candidate.Bundle, issuer, time.Now()); err != nil {
		return fmt.Errorf("enterprise control: verify candidate publication: %w", err)
	}
	if err := runtime.policies.ValidateInstall(ctx, candidate.Bundle); err != nil {
		return fmt.Errorf("enterprise control: validate candidate policy: %w", err)
	}
	ack, err := authority.NewPolicyAcknowledgement(candidate.Publication, runtime.rolloutAgentID, authority.PolicyAckStaged, time.Unix(candidate.Publication.IssuedAt, 0), runtime.rolloutKeyID)
	if err != nil {
		return fmt.Errorf("enterprise control: create staged acknowledgement: %w", err)
	}
	if err := ack.Sign(runtime.rolloutPrivate); err != nil {
		return fmt.Errorf("enterprise control: sign staged acknowledgement: %w", err)
	}
	if _, err := runtime.rolloutClient.Acknowledge(ctx, ack); err != nil {
		return fmt.Errorf("enterprise control: submit staged acknowledgement: %w", err)
	}
	return nil
}

func (runtime *Runtime) installActivePolicyLocked(ctx context.Context, active authorityhttp.ActivePolicyEnvelope) error {
	publication, policy, activation := active.Publication, active.Bundle, active.Activation
	observedAt := time.Now()
	if policy.TenantID != runtime.tenantID || publication.TenantID != runtime.tenantID || !publicationTargetsAgent(publication, runtime.rolloutAgentID) {
		return fmt.Errorf("enterprise control: active policy tenant binding mismatch")
	}
	issuer, err := runtime.trust.PolicyKey(runtime.tenantID, publication.KeyID)
	if err != nil {
		return fmt.Errorf("enterprise control: resolve active policy key: %w", err)
	}
	if err := publication.VerifyFor(policy, issuer, time.Now()); err != nil {
		return fmt.Errorf("enterprise control: verify active policy publication: %w", err)
	}
	if err := activation.VerifyFor(publication, policy, issuer, time.Now()); err != nil {
		return fmt.Errorf("enterprise control: verify active policy activation: %w", err)
	}
	if activation.ActivatesAt > observedAt.Unix() {
		return fmt.Errorf("enterprise control: active policy activation time has not arrived")
	}
	trust, err := runtime.trust.Current(ctx, runtime.tenantID)
	if err != nil {
		return fmt.Errorf("enterprise control: read active trust: %w", err)
	}
	state, err := loadControlState(runtime.statePath)
	if err != nil {
		return err
	}
	if err := state.accepts(runtime.tenantID, trust, policy); err != nil {
		return err
	}
	nextState := state
	nextState.TenantID = runtime.tenantID
	nextState.TrustRevision = trust.Revision
	nextState.TrustPolicyRevision = trust.PolicyRevision
	nextState.TrustRevocationEpoch = trust.RevocationEpoch
	nextState.PolicyRevision = policy.Revision
	nextState.PolicyRevocationEpoch = policy.RevocationEpoch
	if nextState.EnforcementPublication != publication.ID {
		nextState.EnforcementPublication = publication.ID
		nextState.EnforcementObservedAt = observedAt.Unix()
		nextState.EnforcementAckDelivered = false
	}
	if err := runtime.policies.InstallWithCommit(ctx, policy, func() error {
		if err := writeSecureJSON(runtime.policyPath, policy); err != nil {
			return fmt.Errorf("enterprise control: persist active policy: %w", err)
		}
		return saveControlState(runtime.statePath, nextState)
	}); err != nil {
		return fmt.Errorf("enterprise control: install active policy: %w", err)
	}
	if nextState.EnforcementAckDelivered {
		return nil
	}
	ack, err := authority.NewPolicyAcknowledgement(publication, runtime.rolloutAgentID, authority.PolicyAckEnforced, time.Unix(nextState.EnforcementObservedAt, 0), runtime.rolloutKeyID)
	if err != nil {
		return fmt.Errorf("enterprise control: create enforced acknowledgement: %w", err)
	}
	if err := ack.Sign(runtime.rolloutPrivate); err != nil {
		return fmt.Errorf("enterprise control: sign enforced acknowledgement: %w", err)
	}
	if _, err := runtime.rolloutClient.Acknowledge(ctx, ack); err != nil {
		return fmt.Errorf("enterprise control: submit enforced acknowledgement: %w", err)
	}
	nextState.EnforcementAckDelivered = true
	if err := saveControlState(runtime.statePath, nextState); err != nil {
		return fmt.Errorf("enterprise control: persist enforced acknowledgement: %w", err)
	}
	return nil
}

func (runtime *Runtime) installRemoteMandateBundleLocked(bundle decision.MandateBundle) error {
	if runtime.mandateBundlePath == "" || runtime.mandates == nil {
		return fmt.Errorf("enterprise control: mandate bundle refresh is not configured")
	}
	if bundle.TenantID != runtime.tenantID || bundle.SubjectAgentID != runtime.mandateAgentID {
		return fmt.Errorf("enterprise control: mandate bundle tenant or agent binding mismatch")
	}
	store, err := decision.NewStaticMandateStoreFromBundle(context.Background(), bundle, runtime.trust, runtime.trust, time.Now())
	if err != nil {
		return fmt.Errorf("enterprise control: verify remote mandate bundle: %w", err)
	}
	return runtime.installMandateBundleLocked(bundle, store)
}

// installMandateBundleLocked persists the complete signed replacement before
// exposing it to the enforcement ceiling. Its revision/hash floor prevents a
// still-valid lower snapshot from reintroducing a mandate that an empty or
// narrower higher snapshot removed.
func (runtime *Runtime) installMandateBundleLocked(bundle decision.MandateBundle, store decision.MandateStore) error {
	if runtime.mandateBundlePath == "" || runtime.mandates == nil {
		return fmt.Errorf("enterprise control: mandate bundle store is not initialized")
	}
	if bundle.TenantID != runtime.tenantID || bundle.SubjectAgentID != runtime.mandateAgentID {
		return fmt.Errorf("enterprise control: mandate bundle tenant or agent binding mismatch")
	}
	hash, err := bundle.Hash()
	if err != nil {
		return fmt.Errorf("enterprise control: hash mandate bundle: %w", err)
	}
	state, err := loadControlState(runtime.statePath)
	if err != nil {
		return err
	}
	if err := state.acceptsMandate(bundle, hash); err != nil {
		return err
	}
	nextState := state
	nextState.MandateRevision = bundle.Revision
	nextState.MandateRevocationEpoch = bundle.RevocationEpoch
	nextState.MandateHash = hash
	if err := writeSecureJSON(runtime.mandateBundlePath, bundle); err != nil {
		return fmt.Errorf("enterprise control: persist mandate bundle: %w", err)
	}
	if err := saveControlState(runtime.statePath, nextState); err != nil {
		return err
	}
	if err := runtime.mandates.Replace(store); err != nil {
		return err
	}
	return nil
}

func publicationTargetsAgent(publication authority.PolicyPublication, agentID string) bool {
	for _, expected := range publication.ExpectedAgents {
		if expected == agentID {
			return true
		}
	}
	return false
}

// ApplyDataExchange attaches the verified receiver gate to the supplied
// service config. A nil Runtime leaves the caller's existing config unchanged.
func (runtime *Runtime) ApplyDataExchange(config *dataexchange.ServiceConfig) error {
	if runtime == nil || !runtime.dataEnabled {
		return nil
	}
	if config == nil {
		return fmt.Errorf("enterprise control: data-exchange service config is required")
	}
	config.RequireGoverned = runtime.dataRequired
	if runtime.dataTransferQuota != nil {
		limiter, quotaErr := newTransferQuotaLimiter(*runtime.dataTransferQuota)
		if quotaErr != nil {
			return quotaErr
		}
		config.GovernedTransferQuota = limiter
	}
	if runtime.dataRetention != nil {
		policies, interval, retentionErr := dataRetentionPolicies(*runtime.dataRetention)
		if retentionErr != nil {
			return retentionErr
		}
		config.GovernedRetentionPolicies = policies
		config.RetentionSweepInterval = interval
	}
	config.GovernedVerifier = dataexchange.DecisionFrameVerifier{
		Enforcer:          runtime.enforcer,
		Resource:          func(_ coreapi.Addr, _ *dataexchange.Frame) string { return runtime.dataResource },
		RequireDisclosure: runtime.dataDisclosureRequired,
	}
	config.GovernedStreamVerifier = dataexchange.DecisionFrameVerifier{
		Enforcer:          runtime.enforcer,
		Resource:          func(_ coreapi.Addr, _ *dataexchange.Frame) string { return runtime.dataResource },
		RequireDisclosure: runtime.dataDisclosureRequired,
	}
	if runtime.receipts != nil {
		config.RequireGovernedReceipts = runtime.dataRequired
		config.GovernedReceiptRecorder = transportReceiptRecorder{signer: runtime.receipts, enforcementPoint: "dataexchange"}
	}
	return nil
}

// ApplyEventStream attaches the verified broker publication gate. A nil
// Runtime leaves the caller's service unchanged.
func (runtime *Runtime) ApplyEventStream(service *eventstream.Service) error {
	if runtime == nil || !runtime.eventEnabled {
		return nil
	}
	if service == nil {
		return fmt.Errorf("enterprise control: event-stream service is required")
	}
	if runtime.eventTransferQuota != nil {
		limiter, quotaErr := newTransferQuotaLimiter(*runtime.eventTransferQuota)
		if quotaErr != nil {
			return quotaErr
		}
		service.SetGovernedTransferQuota(limiter)
	}
	service.SetGovernedPublication(eventstream.DecisionEventVerifier{
		Enforcer:          runtime.enforcer,
		RequireDisclosure: runtime.eventDisclosureRequired,
		Resource: func(_ coreapi.Addr, event *eventstream.Event) string {
			return strings.Replace(runtime.eventTemplate, "{topic}", event.Topic, 1)
		},
	}, runtime.eventRequired)
	if runtime.receipts != nil {
		service.SetGovernedReceiptRecorder(transportReceiptRecorder{signer: runtime.receipts, enforcementPoint: "eventstream"}, runtime.eventRequired)
	}
	return nil
}

// RequireEnabledServiceGates proves that every enabled transport has a
// mandatory governed rule. The enterprise daemon profile calls this after the
// attachment has been verified, so an omitted or permissive rule cannot leave
// an alternate legacy ingress path open.
func (runtime *Runtime) RequireEnabledServiceGates(dataExchangeEnabled, eventStreamEnabled bool) error {
	if dataExchangeEnabled && (runtime == nil || !runtime.dataEnabled || !runtime.dataRequired || runtime.receipts == nil) {
		return fmt.Errorf("enterprise control: enabled data exchange requires data_exchange.require_governed=true")
	}
	if eventStreamEnabled && (runtime == nil || !runtime.eventEnabled || !runtime.eventRequired || runtime.receipts == nil) {
		return fmt.Errorf("enterprise control: enabled event stream requires event_stream.require_governed=true")
	}
	return nil
}

func validateConfig(config Config) error {
	if !identifier(config.TenantID) || !identifier(config.RootKeyID) {
		return fmt.Errorf("enterprise control: tenant_id and root_key_id are required identifiers")
	}
	if strings.TrimSpace(config.RootPublicKey) == "" || strings.TrimSpace(config.TrustBundlePath) == "" || strings.TrimSpace(config.PolicyBundlePath) == "" {
		return fmt.Errorf("enterprise control: root_public_key, trust_bundle_path, and policy_bundle_path are required")
	}
	if config.DataExchange == nil && config.EventStream == nil && config.ActionControl == nil && config.Rollout == nil && config.Receipts == nil && config.Mandates == nil {
		return fmt.Errorf("enterprise control: enable at least one governed boundary or control-plane attachment")
	}
	if config.ActionControl != nil {
		registry := actionregistry.Builtins()
		if err := config.ActionControl.Profile.Validate(registry); err != nil {
			return fmt.Errorf("enterprise control: action_control.profile: %w", err)
		}
		mode := config.ActionControl.Profile.Mode.Normalize()
		agentID := config.ActionControl.AgentID
		if agentID == "" && config.OutboundDecisions != nil {
			agentID = config.OutboundDecisions.AgentID
		}
		if mode != actionregistry.ModeOff && !identifier(agentID) {
			return fmt.Errorf("enterprise control: enabled action_control requires agent_id")
		}
		if mode == actionregistry.ModeManagedEnforce {
			if config.OutboundDecisions == nil {
				return fmt.Errorf("enterprise control: managed action_control requires outbound_decisions")
			}
			if config.OutboundDecisions.AgentID != agentID {
				return fmt.Errorf("enterprise control: action_control and outbound_decisions agent_id must match")
			}
			federated := false
			for _, definition := range registry.Definitions() {
				if definition.Privacy == actionregistry.PrivacyFederatedContent && config.ActionControl.Profile.AppliesTo(registry, definition.Name) {
					federated = true
					break
				}
			}
			if federated {
				outbound := config.OutboundDecisions
				if outbound.Audience == "" || outbound.Purpose == "" || outbound.EvaluatorResidency == "" {
					return fmt.Errorf("enterprise control: managed content actions require hosted federation audience, purpose, and evaluator_residency")
				}
				labels := append([]string(nil), outbound.ContentLabels...)
				if len(labels) == 0 {
					labels = []string{"unclassified"}
				}
				retention := outbound.RetentionClass
				if retention == "" {
					retention = "exchange-7d"
				}
				if _, err := decision.NewFederatedContent(decision.DisclosureBinding{
					Version: decision.DisclosureBindingRetentionVersion, ContentHash: decision.HashPayload(nil),
					ContentType: "application/octet-stream", Labels: labels, Recipient: outbound.Audience,
					Purpose: outbound.Purpose, Residency: outbound.EvaluatorResidency, RetentionClass: retention,
				}, nil); err != nil {
					return fmt.Errorf("enterprise control: managed hosted federation metadata: %w", err)
				}
			}
		}
		if config.ActionControl.ContinuationDirectory != "" {
			if mode != actionregistry.ModeManagedEnforce {
				return fmt.Errorf("enterprise control: continuation_directory requires managed action_control")
			}
			if _, err := resolveBundlePath(".", config.ActionControl.ContinuationDirectory); err != nil {
				return fmt.Errorf("enterprise control: action_control.continuation_directory: %w", err)
			}
		}
		switch config.ActionControl.Risk {
		case "", decision.RiskLow, decision.RiskMedium, decision.RiskHigh, decision.RiskCritical:
		default:
			return fmt.Errorf("enterprise control: action_control.risk is invalid")
		}
	}
	if config.DataExchange != nil && !validResource(config.DataExchange.Resource) {
		return fmt.Errorf("enterprise control: data_exchange.resource must be valid UTF-8 text of 1-1024 bytes")
	}
	if config.DataExchange != nil && config.DataExchange.RequireDisclosure && !config.DataExchange.RequireGoverned {
		return fmt.Errorf("enterprise control: data_exchange.require_disclosure requires require_governed")
	}
	if config.DataExchange != nil && config.DataExchange.RequireContentInspection {
		return fmt.Errorf("enterprise control: data_exchange.require_content_inspection was replaced by Pilot-hosted federation action control")
	}
	if config.DataExchange != nil && config.DataExchange.TransferQuota != nil {
		if !config.DataExchange.RequireGoverned {
			return fmt.Errorf("enterprise control: data_exchange.transfer_quota requires require_governed")
		}
		if _, err := newTransferQuotaLimiter(*config.DataExchange.TransferQuota); err != nil {
			return fmt.Errorf("enterprise control: data_exchange.transfer_quota: %w", err)
		}
	}
	if config.DataExchange != nil && config.DataExchange.Retention != nil {
		if !config.DataExchange.RequireGoverned || !config.DataExchange.RequireDisclosure {
			return fmt.Errorf("enterprise control: data_exchange.retention requires require_governed and require_disclosure")
		}
		if _, _, err := dataRetentionPolicies(*config.DataExchange.Retention); err != nil {
			return fmt.Errorf("enterprise control: data_exchange.retention: %w", err)
		}
	}
	if config.EventStream != nil {
		template := config.EventStream.ResourceTemplate
		if !validResourceTemplate(template) {
			return fmt.Errorf("enterprise control: event_stream.resource_template must be valid UTF-8 text containing exactly one {topic}")
		}
	}
	if config.EventStream != nil && config.EventStream.RequireDisclosure && !config.EventStream.RequireGoverned {
		return fmt.Errorf("enterprise control: event_stream.require_disclosure requires require_governed")
	}
	if config.EventStream != nil && config.EventStream.RequireContentInspection {
		return fmt.Errorf("enterprise control: event_stream.require_content_inspection was replaced by Pilot-hosted federation action control")
	}
	if config.EventStream != nil && config.EventStream.TransferQuota != nil {
		if !config.EventStream.RequireGoverned {
			return fmt.Errorf("enterprise control: event_stream.transfer_quota requires require_governed")
		}
		if _, err := newTransferQuotaLimiter(*config.EventStream.TransferQuota); err != nil {
			return fmt.Errorf("enterprise control: event_stream.transfer_quota: %w", err)
		}
	}
	if config.Mandates != nil {
		legacyPath := strings.TrimSpace(config.Mandates.Path) != ""
		bundlePath := strings.TrimSpace(config.Mandates.BundlePath) != ""
		if legacyPath == bundlePath {
			return fmt.Errorf("enterprise control: mandates requires exactly one of path or bundle_path")
		}
		if bundlePath {
			if !identifier(config.Mandates.AgentID) {
				return fmt.Errorf("enterprise control: mandate bundle requires agent_id")
			}
			if config.Rollout == nil || config.Rollout.AgentID != config.Mandates.AgentID {
				return fmt.Errorf("enterprise control: mandate bundle requires rollout for the same agent_id")
			}
		}
	}
	if config.Receipts != nil {
		if !identifier(config.Receipts.AgentID) || !identifier(config.Receipts.KeyID) || strings.TrimSpace(config.Receipts.SeedPath) == "" || strings.TrimSpace(config.Receipts.JournalPath) == "" {
			return fmt.Errorf("enterprise control: receipts requires agent_id, key_id, seed_path, and journal_path")
		}
		exportConfigured := config.Receipts.ExportEndpoint != "" || config.Receipts.ExportAcknowledgementPath != "" || config.Receipts.ExportBearerTokenEnv != "" || config.Receipts.ExportIntervalSeconds != 0 || config.Receipts.ExportBatchSize != 0
		if exportConfigured {
			if strings.TrimSpace(config.Receipts.ExportEndpoint) == "" || strings.TrimSpace(config.Receipts.ExportAcknowledgementPath) == "" {
				return fmt.Errorf("enterprise control: receipt export requires export_endpoint and export_acknowledgement_path")
			}
			if config.Receipts.ExportBearerTokenEnv != "" && !identifier(config.Receipts.ExportBearerTokenEnv) {
				return fmt.Errorf("enterprise control: receipt export bearer token environment name is invalid")
			}
			if config.Receipts.ExportIntervalSeconds < 0 || config.Receipts.ExportIntervalSeconds > 3600 || (config.Receipts.ExportIntervalSeconds > 0 && config.Receipts.ExportIntervalSeconds < 5) {
				return fmt.Errorf("enterprise control: receipts.export_interval_seconds must be 0 or 5-3600")
			}
			if config.Receipts.ExportBatchSize < 0 || config.Receipts.ExportBatchSize > 1000 {
				return fmt.Errorf("enterprise control: receipts.export_batch_size must be 0 or 1-1000")
			}
		}
	}
	if config.Rollout != nil {
		if strings.TrimSpace(config.Rollout.AuthorityEndpoint) == "" || !identifier(config.Rollout.AgentID) || !identifier(config.Rollout.AcknowledgementKeyID) || strings.TrimSpace(config.Rollout.AcknowledgementSeedPath) == "" {
			return fmt.Errorf("enterprise control: rollout requires authority_endpoint, agent_id, acknowledgement_key_id, and acknowledgement_seed_path")
		}
		if config.Rollout.PollIntervalSeconds < 0 || config.Rollout.PollIntervalSeconds > 3600 || (config.Rollout.PollIntervalSeconds > 0 && config.Rollout.PollIntervalSeconds < 5) {
			return fmt.Errorf("enterprise control: rollout.poll_interval_seconds must be 0 or 5-3600")
		}
	}
	if config.Fleet != nil {
		if config.Rollout == nil {
			return fmt.Errorf("enterprise control: fleet requires rollout enrollment")
		}
		if config.Fleet.ReportIntervalSeconds < 0 || config.Fleet.ReportIntervalSeconds > 3600 || (config.Fleet.ReportIntervalSeconds > 0 && config.Fleet.ReportIntervalSeconds < 5) {
			return fmt.Errorf("enterprise control: fleet.report_interval_seconds must be 0 or 5-3600")
		}
		if config.Fleet.StateSyncIntervalSeconds < 0 || config.Fleet.StateSyncIntervalSeconds > 3600 || (config.Fleet.StateSyncIntervalSeconds > 0 && config.Fleet.StateSyncIntervalSeconds < 2) {
			return fmt.Errorf("enterprise control: fleet.state_sync_interval_seconds must be 0 or 2-3600")
		}
		if !config.Fleet.StateSyncEnabled && (strings.TrimSpace(config.Fleet.StateDirectory) != "" || config.Fleet.StateSyncIntervalSeconds != 0) {
			return fmt.Errorf("enterprise control: fleet state directory and interval require state_sync_enabled")
		}
		if filepath.IsAbs(config.Fleet.StateDirectory) {
			return fmt.Errorf("enterprise control: fleet.state_directory must be relative")
		}
		if len(config.Fleet.AgentVersion) > 128 || strings.ContainsAny(config.Fleet.AgentVersion, "\r\n\x00") || config.Fleet.HarnessID != "" && !identifier(config.Fleet.HarnessID) || len(config.Fleet.HarnessVersion) > 128 || strings.ContainsAny(config.Fleet.HarnessVersion, "\r\n\x00") || config.Fleet.ConnectorVersion != "" && !identifier(config.Fleet.ConnectorVersion) {
			return fmt.Errorf("enterprise control: fleet runtime and harness markers are invalid")
		}
	}
	if config.OutboundDecisions != nil {
		outbound := config.OutboundDecisions
		if strings.TrimSpace(outbound.AuthorityEndpoint) == "" || !identifier(outbound.AgentID) || !identifier(outbound.IntentKeyID) || strings.TrimSpace(outbound.IntentSeedPath) == "" {
			return fmt.Errorf("enterprise control: outbound_decisions requires authority_endpoint, agent_id, intent_key_id, and intent_seed_path")
		}
		switch outbound.Risk {
		case "", decision.RiskLow, decision.RiskMedium, decision.RiskHigh, decision.RiskCritical:
		default:
			return fmt.Errorf("enterprise control: outbound_decisions.risk is invalid")
		}
		if outbound.RequestTimeoutSeconds < 0 || outbound.RequestTimeoutSeconds > 60 {
			return fmt.Errorf("enterprise control: outbound_decisions.request_timeout_seconds must be 0-60")
		}
		if outbound.EvaluatorResidency != "" && !validEnterpriseResidency(outbound.EvaluatorResidency) {
			return fmt.Errorf("enterprise control: outbound_decisions.evaluator_residency is invalid")
		}
		if outbound.EvaluatorAttestation != nil {
			attestor := outbound.EvaluatorAttestation
			if outbound.EvaluatorResidency == "" || !identifier(attestor.AttestorID) || !identifier(attestor.KeyID) {
				return fmt.Errorf("enterprise control: evaluator_attestation requires evaluator_residency, attestor_id, and key_id")
			}
			if _, err := decodeEvaluatorAttestorKey(attestor.PublicKey); err != nil {
				return err
			}
		}
		if (outbound.Audience == "") != (outbound.Purpose == "") || outbound.Purpose != "" && !validResource(outbound.Purpose) {
			return fmt.Errorf("enterprise control: outbound_decisions audience and purpose must be configured together")
		}
		if outbound.MandateID != "" {
			if !identifier(outbound.MandateID) || outbound.Audience == "" || config.Mandates == nil {
				return fmt.Errorf("enterprise control: outbound_decisions mandate_id requires audience, purpose, and mandates")
			}
		}
	}
	if config.ContentInspection != nil {
		return fmt.Errorf("enterprise control: content_inspection is no longer supported; use managed Pilot-hosted federation action control")
	}
	return nil
}

func newTransferQuotaLimiter(config TransferQuotaConfig) (*decision.TransferQuotaLimiter, error) {
	limiter, err := decision.NewTransferQuotaLimiter(decision.TransferQuotaConfig{
		Window:     time.Duration(config.WindowSeconds) * time.Second,
		MaxBytes:   config.MaxBytes,
		MaxActions: config.MaxActions,
		MaxSenders: config.MaxSenders,
	})
	if err != nil {
		return nil, err
	}
	return limiter, nil
}

func dataRetentionPolicies(config DataRetentionConfig) ([]dataexchange.GovernedRetentionPolicy, time.Duration, error) {
	if len(config.Classes) == 0 || len(config.Classes) > 32 {
		return nil, 0, fmt.Errorf("retention requires 1-32 classes")
	}
	policies := make([]dataexchange.GovernedRetentionPolicy, 0, len(config.Classes))
	seen := make(map[string]struct{}, len(config.Classes))
	for _, configured := range config.Classes {
		if !validRetentionClass(configured.Class) || configured.RetainForSeconds < 1 || configured.RetainForSeconds > int64((10*365*24*time.Hour)/time.Second) {
			return nil, 0, fmt.Errorf("invalid retention class")
		}
		if _, exists := seen[configured.Class]; exists {
			return nil, 0, fmt.Errorf("duplicate retention class %q", configured.Class)
		}
		seen[configured.Class] = struct{}{}
		policies = append(policies, dataexchange.GovernedRetentionPolicy{Class: configured.Class, RetainFor: time.Duration(configured.RetainForSeconds) * time.Second})
	}
	interval := time.Duration(config.SweepIntervalSeconds) * time.Second
	if config.SweepIntervalSeconds != 0 && (interval < time.Second || interval > 24*time.Hour) {
		return nil, 0, fmt.Errorf("sweep_interval_seconds must be 0 or 1-86400")
	}
	return policies, interval, nil
}

func validRetentionClass(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || (character == '-' && index > 0 && index+1 < len(value)) {
			continue
		}
		return false
	}
	return true
}

func validEnterpriseResidency(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] == '-' || value[len(value)-1] == '-' {
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

func decodeRoot(encoded string) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return nil, fmt.Errorf("enterprise control: root_public_key must be canonical base64 Ed25519")
	}
	return ed25519.PublicKey(decoded), nil
}

func decodeEvaluatorAttestorKey(encoded string) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return nil, fmt.Errorf("enterprise control: evaluator_attestation.public_key must be canonical base64 Ed25519")
	}
	return ed25519.PublicKey(decoded), nil
}

func resolveBundlePath(directory, configured string) (string, error) {
	if strings.TrimSpace(configured) == "" {
		return "", fmt.Errorf("path is required")
	}
	if filepath.IsAbs(configured) {
		return "", fmt.Errorf("absolute paths are not allowed")
	}
	cleaned := filepath.Clean(configured)
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes control configuration directory")
	}
	return filepath.Join(directory, cleaned), nil
}

func readSecureJSON[T any](path string) (T, error) {
	var value T
	contents, err := readSecureBytes(path)
	if err != nil {
		return value, err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return value, fmt.Errorf("trailing JSON value")
		}
		return value, fmt.Errorf("trailing data: %w", err)
	}
	return value, nil
}

func readSecureBytes(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("must be a regular file, not a symlink")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("must not be group- or world-writable")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return contents, nil
}

func secureDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("is not a directory")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("must not be group- or world-writable")
	}
	return nil
}

func loadControlState(path string) (controlState, error) {
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return controlState{}, nil
		}
		return controlState{}, fmt.Errorf("enterprise control: read persisted state: %w", err)
	}
	state, err := readSecureJSON[controlState](path)
	if err != nil {
		return controlState{}, fmt.Errorf("enterprise control: read persisted state: %w", err)
	}
	if !identifier(state.TenantID) || state.TrustRevision == 0 || state.TrustPolicyRevision == 0 || state.TrustRevocationEpoch == 0 || state.PolicyRevision == 0 || state.PolicyRevocationEpoch == 0 {
		return controlState{}, fmt.Errorf("enterprise control: persisted state is invalid")
	}
	if (state.MandateRevision == 0) != (state.MandateHash == "") || (state.MandateRevision == 0) != (state.MandateRevocationEpoch == 0) || (state.MandateHash != "" && !lowerHex(state.MandateHash, 64)) {
		return controlState{}, fmt.Errorf("enterprise control: persisted mandate state is invalid")
	}
	if (state.EnforcementPublication == "") != (state.EnforcementObservedAt == 0) || state.EnforcementAckDelivered && state.EnforcementPublication == "" || state.EnforcementPublication != "" && !identifier(state.EnforcementPublication) {
		return controlState{}, fmt.Errorf("enterprise control: persisted enforcement acknowledgement is invalid")
	}
	return state, nil
}

func (state controlState) accepts(tenantID string, trust authority.TrustBundle, policy authority.PolicyBundle) error {
	if err := state.acceptsTrust(tenantID, trust); err != nil {
		return err
	}
	if state.TenantID != "" && (policy.Revision < state.PolicyRevision || policy.RevocationEpoch < state.PolicyRevocationEpoch) {
		return fmt.Errorf("enterprise control: signed state is below the persisted rollback floor")
	}
	return nil
}

func (state controlState) acceptsTrust(tenantID string, trust authority.TrustBundle) error {
	if state.TenantID == "" {
		return nil
	}
	if state.TenantID != tenantID {
		return fmt.Errorf("enterprise control: persisted state belongs to a different tenant")
	}
	if trust.Revision < state.TrustRevision || trust.PolicyRevision < state.TrustPolicyRevision || trust.RevocationEpoch < state.TrustRevocationEpoch {
		return fmt.Errorf("enterprise control: signed state is below the persisted rollback floor")
	}
	return nil
}

func (state controlState) acceptsMandate(bundle decision.MandateBundle, hash string) error {
	if state.TenantID == "" {
		return fmt.Errorf("enterprise control: persisted control state is required before installing mandate bundle")
	}
	if bundle.Revision < state.MandateRevision || bundle.RevocationEpoch < state.MandateRevocationEpoch || (bundle.Revision == state.MandateRevision && state.MandateHash != "" && hash != state.MandateHash) {
		return fmt.Errorf("enterprise control: mandate bundle is below the persisted rollback floor")
	}
	return nil
}

func lowerHex(value string, expectedLength int) bool {
	if len(value) != expectedLength {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func readEd25519Seed(path string) (ed25519.PrivateKey, error) {
	contents, err := readSecureBytes(path)
	if err != nil {
		return nil, err
	}
	encoded := strings.TrimSpace(string(contents))
	seed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(seed) != ed25519.SeedSize || base64.StdEncoding.EncodeToString(seed) != encoded {
		return nil, fmt.Errorf("must be canonical base64 Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func saveControlState(path string, state controlState) error {
	contents, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("enterprise control: encode persisted state: %w", err)
	}
	if err := atomicWriteSecureBytes(path, contents); err != nil {
		return fmt.Errorf("enterprise control: persist state: %w", err)
	}
	return nil
}

func writeSecureJSON(path string, value any) error {
	contents, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return atomicWriteSecureBytes(path, contents)
}

// atomicWriteSecureBytes replaces a protected attachment file without ever
// following a symlink. The sibling temporary file and parent-directory sync
// make a successfully returned update recoverable across a daemon restart.
func atomicWriteSecureBytes(path string, contents []byte) error {
	directory := filepath.Dir(path)
	if err := secureDirectory(directory); err != nil {
		return fmt.Errorf("protect parent directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("target must be a regular file, not a symlink")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".enterprise-control-state-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect temporary file: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("commit temporary file: %w", err)
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open parent directory: %w", err)
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return fmt.Errorf("sync parent directory: %w", err)
	}
	return nil
}

func identifier(value string) bool {
	if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) {
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

func validResource(value string) bool {
	return len(value) > 0 && len(value) <= 1024 && utf8.ValidString(value)
}

func validResourceTemplate(value string) bool {
	return validResource(value) && strings.Count(value, "{topic}") == 1
}

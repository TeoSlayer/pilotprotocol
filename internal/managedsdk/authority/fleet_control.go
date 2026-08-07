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
	"unicode/utf8"

	"github.com/pilot-protocol/common/decision"
)

const (
	FleetNodeControlVersion uint16 = 1
	FleetActivityVersion    uint16 = 1
	FleetNodeControlDomain         = "pilot-fleet-node-control-v1"
	FleetActivityDomain            = "pilot-fleet-activity-v1"
	FleetControlAckVersion  uint16 = 1
	FleetControlAckDomain          = "pilot-fleet-control-ack-v1"
	MaxFleetControlTags            = 16
)

// FleetNodeControl is the signed desired state for one enrolled node. It is a
// deliberately small replacement for arbitrary remote shell access: operators
// can organize a node, declare the expected runtime and policy revision, or
// quarantine it. The node and the authority both verify this object before
// treating it as current control state.
type FleetNodeControl struct {
	Version               uint16   `json:"version"`
	TenantID              string   `json:"tenant_id"`
	AgentID               string   `json:"agent_id"`
	Revision              uint64   `json:"revision"`
	Group                 string   `json:"group,omitempty"`
	Tags                  []string `json:"tags,omitempty"`
	DesiredVersion        string   `json:"desired_version,omitempty"`
	DesiredPolicyRevision uint64   `json:"desired_policy_revision,omitempty"`
	Quarantined           bool     `json:"quarantined"`
	Reason                string   `json:"reason"`
	IssuedAt              int64    `json:"issued_at"`
	KeyID                 string   `json:"key_id"`
	Signature             string   `json:"signature"`
}

const (
	FleetControlApplied          = "applied"
	FleetControlPartiallyApplied = "partially_applied"
	FleetControlRejected         = "rejected"
)

// FleetControlAcknowledgement is signed by the enrolled node after it has
// reconciled one exact desired-state revision. It distinguishes a published
// control from a control the workload actually verified and applied.
type FleetControlAcknowledgement struct {
	Version               uint16 `json:"version"`
	TenantID              string `json:"tenant_id"`
	AgentID               string `json:"agent_id"`
	ControlRevision       uint64 `json:"control_revision"`
	Status                string `json:"status"`
	DetailCode            string `json:"detail_code,omitempty"`
	AppliedPolicyRevision uint64 `json:"applied_policy_revision,omitempty"`
	RunningVersion        string `json:"running_version,omitempty"`
	Quarantined           bool   `json:"quarantined"`
	ObservedAt            int64  `json:"observed_at"`
	KeyID                 string `json:"key_id"`
	Signature             string `json:"signature"`
}

func (ack FleetControlAcknowledgement) Validate() error {
	if ack.Version != FleetControlAckVersion || ack.ControlRevision == 0 || ack.ObservedAt <= 0 {
		return fmt.Errorf("authority: invalid fleet control acknowledgement version, revision, or time")
	}
	for name, value := range map[string]string{"tenant_id": ack.TenantID, "agent_id": ack.AgentID, "key_id": ack.KeyID} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	switch ack.Status {
	case FleetControlApplied:
		if ack.DetailCode != "" {
			return fmt.Errorf("authority: applied fleet control acknowledgement has a detail code")
		}
	case FleetControlPartiallyApplied, FleetControlRejected:
		if err := validateIdentifier("detail_code", ack.DetailCode); err != nil {
			return err
		}
	default:
		return fmt.Errorf("authority: invalid fleet control acknowledgement status")
	}
	if !boundedFleetText(ack.RunningVersion, 128, true) {
		return fmt.Errorf("authority: invalid acknowledged runtime version")
	}
	return nil
}

func (ack FleetControlAcknowledgement) Canonical() ([]byte, error) {
	if err := ack.Validate(); err != nil {
		return nil, err
	}
	writer := canonicalWriter{}
	writer.string(FleetControlAckDomain)
	writer.u16(ack.Version)
	writer.string(ack.TenantID)
	writer.string(ack.AgentID)
	writer.u64(ack.ControlRevision)
	writer.string(ack.Status)
	writer.string(ack.DetailCode)
	writer.u64(ack.AppliedPolicyRevision)
	writer.string(ack.RunningVersion)
	if ack.Quarantined {
		writer.u16(1)
	} else {
		writer.u16(0)
	}
	writer.i64(ack.ObservedAt)
	writer.string(ack.KeyID)
	if writer.err != nil {
		return nil, writer.err
	}
	return writer.Buffer.Bytes(), nil
}

func (ack *FleetControlAcknowledgement) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("authority: invalid fleet control acknowledgement signing key")
	}
	canonical, err := ack.Canonical()
	if err != nil {
		return err
	}
	ack.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return nil
}

func (ack FleetControlAcknowledgement) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	if err := ack.Validate(); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize || ack.ObservedAt > now.Unix()+int64(MaxBundleClockSkew/time.Second) || ack.ObservedAt < now.Add(-24*time.Hour).Unix() {
		return fmt.Errorf("authority: fleet control acknowledgement is outside its accepted observation window")
	}
	canonical, err := ack.Canonical()
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(ack.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("authority: invalid fleet control acknowledgement signature")
	}
	return nil
}

func (control FleetNodeControl) Validate() error {
	if control.Version != FleetNodeControlVersion || control.Revision == 0 || control.IssuedAt <= 0 {
		return fmt.Errorf("authority: invalid fleet node control version, revision, or issue time")
	}
	for name, value := range map[string]string{"tenant_id": control.TenantID, "agent_id": control.AgentID, "key_id": control.KeyID} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if control.Group != "" {
		if err := validateIdentifier("fleet group", control.Group); err != nil {
			return err
		}
	}
	if len(control.Tags) > MaxFleetControlTags {
		return fmt.Errorf("authority: fleet control has too many tags")
	}
	tags := append([]string(nil), control.Tags...)
	sort.Strings(tags)
	for index, tag := range tags {
		if err := validateIdentifier("fleet tag", tag); err != nil {
			return err
		}
		if index > 0 && tags[index-1] == tag {
			return fmt.Errorf("authority: duplicate fleet control tag")
		}
	}
	if !boundedFleetText(control.DesiredVersion, 128, true) || !boundedFleetText(control.Reason, 256, false) || len(strings.TrimSpace(control.Reason)) < 8 {
		return fmt.Errorf("authority: invalid fleet control version or reason")
	}
	return nil
}

func (control FleetNodeControl) Canonical() ([]byte, error) {
	if err := control.Validate(); err != nil {
		return nil, err
	}
	tags := append([]string(nil), control.Tags...)
	sort.Strings(tags)
	writer := canonicalWriter{}
	writer.string(FleetNodeControlDomain)
	writer.u16(control.Version)
	writer.string(control.TenantID)
	writer.string(control.AgentID)
	writer.u64(control.Revision)
	writer.string(control.Group)
	writer.u16(uint16(len(tags)))
	for _, tag := range tags {
		writer.string(tag)
	}
	writer.string(control.DesiredVersion)
	writer.u64(control.DesiredPolicyRevision)
	if control.Quarantined {
		writer.u16(1)
	} else {
		writer.u16(0)
	}
	writer.string(control.Reason)
	writer.i64(control.IssuedAt)
	writer.string(control.KeyID)
	if writer.err != nil {
		return nil, writer.err
	}
	return writer.Buffer.Bytes(), nil
}

func (control *FleetNodeControl) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("authority: invalid fleet control signing key")
	}
	canonical, err := control.Canonical()
	if err != nil {
		return err
	}
	control.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return nil
}

func (control FleetNodeControl) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	if err := control.Validate(); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize || control.IssuedAt > now.Unix()+int64(MaxBundleClockSkew/time.Second) {
		return fmt.Errorf("authority: invalid fleet control key or issue time")
	}
	canonical, err := control.Canonical()
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(control.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("authority: invalid fleet control signature")
	}
	return nil
}

// FleetActivity is privacy-bounded, signed operational telemetry for a
// governed action. It carries the action and coarse resource class but never a
// resource identifier, destination, prompt, payload, path, or environment
// value. Signed receipts remain the authoritative execution evidence.
type FleetActivity struct {
	Version        uint16                     `json:"version"`
	ID             string                     `json:"id"`
	TenantID       string                     `json:"tenant_id"`
	AgentID        string                     `json:"agent_id"`
	Action         string                     `json:"action"`
	ResourceClass  string                     `json:"resource_class"`
	Risk           decision.RiskClass         `json:"risk"`
	Outcome        decision.Outcome           `json:"outcome"`
	Result         decision.EnforcementResult `json:"result"`
	IntentHash     string                     `json:"intent_hash"`
	DecisionID     string                     `json:"decision_id"`
	DurationMillis int64                      `json:"duration_millis"`
	ObservedAt     int64                      `json:"observed_at"`
	KeyID          string                     `json:"key_id"`
	Signature      string                     `json:"signature"`
}

func NewFleetActivity(intent decision.Intent, result decision.Decision, enforcement decision.EnforcementResult, duration time.Duration, keyID string, observedAt int64) (FleetActivity, error) {
	intentHash, err := intent.Hash()
	if err != nil {
		return FleetActivity{}, err
	}
	resourceClass := "resource"
	if prefix, _, found := strings.Cut(intent.Resource, ":"); found && prefix != "" {
		resourceClass = prefix
	}
	digest := sha256.Sum256([]byte(FleetActivityDomain + "\x00" + intent.TenantID + "\x00" + intent.AgentID + "\x00" + intentHash + "\x00" + result.ID))
	activity := FleetActivity{
		Version: FleetActivityVersion, ID: hex.EncodeToString(digest[:]), TenantID: intent.TenantID, AgentID: intent.AgentID,
		Action: intent.Action, ResourceClass: resourceClass, Risk: intent.Risk, Outcome: result.Outcome, Result: enforcement,
		IntentHash: intentHash, DecisionID: result.ID, DurationMillis: duration.Milliseconds(), ObservedAt: observedAt, KeyID: keyID,
	}
	if err := activity.Validate(); err != nil {
		return FleetActivity{}, err
	}
	return activity, nil
}

func (activity FleetActivity) Validate() error {
	if activity.Version != FleetActivityVersion || !lowerHexIdentifier(activity.ID, 64) || !lowerHexIdentifier(activity.IntentHash, 64) {
		return fmt.Errorf("authority: invalid fleet activity identity")
	}
	for name, value := range map[string]string{
		"tenant_id": activity.TenantID, "agent_id": activity.AgentID, "action": activity.Action,
		"resource_class": activity.ResourceClass, "decision_id": activity.DecisionID, "key_id": activity.KeyID,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	switch activity.Risk {
	case decision.RiskLow, decision.RiskMedium, decision.RiskHigh, decision.RiskCritical:
	default:
		return fmt.Errorf("authority: invalid fleet activity risk")
	}
	switch activity.Outcome {
	case decision.Allow, decision.Deny, decision.Constrain, decision.ApprovalRequired:
	default:
		return fmt.Errorf("authority: invalid fleet activity outcome")
	}
	switch activity.Result {
	case decision.Enforced, decision.Denied, decision.ApprovalPending, decision.Failed:
	default:
		return fmt.Errorf("authority: invalid fleet activity result")
	}
	if activity.DurationMillis < 0 || activity.DurationMillis > int64((24*time.Hour)/time.Millisecond) || activity.ObservedAt <= 0 {
		return fmt.Errorf("authority: invalid fleet activity timing")
	}
	return nil
}

func (activity FleetActivity) Canonical() ([]byte, error) {
	if err := activity.Validate(); err != nil {
		return nil, err
	}
	writer := canonicalWriter{}
	writer.string(FleetActivityDomain)
	writer.u16(activity.Version)
	writer.string(activity.ID)
	writer.string(activity.TenantID)
	writer.string(activity.AgentID)
	writer.string(activity.Action)
	writer.string(activity.ResourceClass)
	writer.string(string(activity.Risk))
	writer.string(string(activity.Outcome))
	writer.string(string(activity.Result))
	writer.string(activity.IntentHash)
	writer.string(activity.DecisionID)
	writer.i64(activity.DurationMillis)
	writer.i64(activity.ObservedAt)
	writer.string(activity.KeyID)
	if writer.err != nil {
		return nil, writer.err
	}
	return writer.Buffer.Bytes(), nil
}

func (activity *FleetActivity) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("authority: invalid fleet activity signing key")
	}
	canonical, err := activity.Canonical()
	if err != nil {
		return err
	}
	activity.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return nil
}

func (activity FleetActivity) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	if err := activity.Validate(); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize || activity.ObservedAt > now.Unix()+int64(MaxBundleClockSkew/time.Second) || activity.ObservedAt < now.Add(-24*time.Hour).Unix() {
		return fmt.Errorf("authority: fleet activity is outside its accepted observation window")
	}
	canonical, err := activity.Canonical()
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(activity.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("authority: invalid fleet activity signature")
	}
	return nil
}

func boundedFleetText(value string, maximum int, allowEmpty bool) bool {
	if (!allowEmpty && strings.TrimSpace(value) == "") || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

// FleetControlAuthorizer applies the cached signed quarantine ceiling after
// deterministic/semantic policy evaluation. A quarantine can only narrow
// authority; a missing control record leaves ordinary open-agent behavior
// unchanged.
type FleetControlAuthorizer struct {
	Base        decision.Authorizer
	Quarantined func(string, string) bool
}

func (authorizer FleetControlAuthorizer) Authorize(ctx context.Context, intent decision.Intent) (decision.Decision, error) {
	result, err := authorizer.Base.Authorize(ctx, intent)
	return authorizer.apply(intent, result, err)
}

func (authorizer FleetControlAuthorizer) AuthorizeDisclosure(ctx context.Context, intent decision.Intent, disclosure decision.DisclosureBinding) (decision.Decision, error) {
	aware, ok := authorizer.Base.(decision.DisclosureAuthorizer)
	if !ok {
		return decision.Decision{}, fmt.Errorf("authority: base authorizer does not support disclosure binding")
	}
	result, err := aware.AuthorizeDisclosure(ctx, intent, disclosure)
	return authorizer.apply(intent, result, err)
}

// AuthorizeFederatedContent preserves the hosted full-content evaluation path
// through the fleet quarantine ceiling. Wrapping an evaluator must never erase
// a capability required by the account federation ingress.
func (authorizer FleetControlAuthorizer) AuthorizeFederatedContent(ctx context.Context, intent decision.Intent, content decision.FederatedContent) (decision.Decision, error) {
	aware, ok := authorizer.Base.(decision.FederatedContentAuthorizer)
	if !ok {
		return decision.Decision{}, fmt.Errorf("authority: base authorizer does not support federated content")
	}
	result, err := aware.AuthorizeFederatedContent(ctx, intent, content)
	return authorizer.apply(intent, result, err)
}

func (authorizer FleetControlAuthorizer) apply(intent decision.Intent, result decision.Decision, err error) (decision.Decision, error) {
	if err != nil {
		return decision.Decision{}, err
	}
	if authorizer.Quarantined == nil || !authorizer.Quarantined(intent.TenantID, intent.AgentID) {
		return result, nil
	}
	result.Outcome = decision.Deny
	result.Constraints = nil
	result.Reasons = append(result.Reasons, "fleet_quarantine")
	return result, nil
}

type fleetControlCache struct {
	mu       sync.RWMutex
	controls map[string]FleetNodeControl
}

func (cache *fleetControlCache) replace(controls []FleetNodeControl) {
	current := make(map[string]FleetNodeControl, len(controls))
	for _, control := range controls {
		current[control.TenantID+"\x00"+control.AgentID] = control
	}
	cache.mu.Lock()
	cache.controls = current
	cache.mu.Unlock()
}

func (cache *fleetControlCache) put(control FleetNodeControl) {
	cache.mu.Lock()
	if cache.controls == nil {
		cache.controls = make(map[string]FleetNodeControl)
	}
	cache.controls[control.TenantID+"\x00"+control.AgentID] = control
	cache.mu.Unlock()
}

func (cache *fleetControlCache) quarantined(tenantID, agentID string) bool {
	cache.mu.RLock()
	control, found := cache.controls[tenantID+"\x00"+agentID]
	cache.mu.RUnlock()
	return found && control.Quarantined
}

// SPDX-License-Identifier: AGPL-3.0-or-later

// Package decisionpolicy implements Pilot's small deterministic v1 action
// policy. It is both an authority.PolicyValidator and a decision.Authorizer /
// AuthorityCeiling, keeping managed answers below locally signed policy.
package decisionpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
)

const (
	Engine        = "pilot-action-policy"
	EngineVersion = "1"
	ContentType   = "application/vnd.pilot.action-policy+json"
	MaxRules      = 256
)

type Document struct {
	Version        uint16           `json:"version"`
	DefaultOutcome decision.Outcome `json:"default_outcome"`
	Rules          []Rule           `json:"rules"`
}

type Rule struct {
	ID               string                `json:"id"`
	Agents           []string              `json:"agents"`
	Actions          []string              `json:"actions"`
	ResourcePrefixes []string              `json:"resource_prefixes"`
	Risks            []decision.RiskClass  `json:"risks"`
	Outcome          decision.Outcome      `json:"outcome"`
	Reasons          []string              `json:"reasons,omitempty"`
	Constraints      []decision.Constraint `json:"constraints,omitempty"`
	Approval         *ApprovalPlan         `json:"approval,omitempty"`
	Disclosure       *DisclosureRule       `json:"disclosure,omitempty"`
}

// DisclosureRule adds typed data-governance conditions to an ordinary action
// rule. All labels must be present; each non-empty list of content types,
// recipients, purposes, and residencies is an exact OR match. A rule with a
// disclosure clause never matches a bare V1 authorization request.
type DisclosureRule struct {
	LabelsAll        []string `json:"labels_all,omitempty"`
	ContentTypes     []string `json:"content_types,omitempty"`
	Recipients       []string `json:"recipients,omitempty"`
	Purposes         []string `json:"purposes,omitempty"`
	Residencies      []string `json:"residencies,omitempty"`
	RetentionClasses []string `json:"retention_classes,omitempty"`
}

// ApprovalPlan is a signed-policy declaration of the authority unlocked after
// a rule's approval_required outcome has satisfied its named-key threshold.
// It deliberately carries no approver display names or mutable UI state.
type ApprovalPlan struct {
	ApproverKeyIDs    []string              `json:"approver_key_ids"`
	RequiredApprovals uint16                `json:"required_approvals"`
	ValiditySeconds   int64                 `json:"validity_seconds"`
	Outcome           decision.Outcome      `json:"outcome"`
	Constraints       []decision.Constraint `json:"constraints,omitempty"`
}

type compiled struct {
	document Document
}

func Compile(payload []byte) (*compiled, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var document Document
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decisionpolicy: decode: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decisionpolicy: trailing JSON value")
		}
		return nil, fmt.Errorf("decisionpolicy: trailing data: %w", err)
	}
	if document.Version != 1 {
		return nil, fmt.Errorf("decisionpolicy: unsupported version %d", document.Version)
	}
	if document.DefaultOutcome != decision.Deny {
		return nil, fmt.Errorf("decisionpolicy: v1 requires default_outcome %q", decision.Deny)
	}
	if len(document.Rules) > MaxRules {
		return nil, fmt.Errorf("decisionpolicy: at most %d rules are allowed", MaxRules)
	}
	seen := make(map[string]struct{}, len(document.Rules))
	for index, rule := range document.Rules {
		if err := validateRule(rule); err != nil {
			return nil, fmt.Errorf("decisionpolicy: rule[%d]: %w", index, err)
		}
		if _, exists := seen[rule.ID]; exists {
			return nil, fmt.Errorf("decisionpolicy: duplicate rule id %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
	}
	return &compiled{document: document}, nil
}

func validateRule(rule Rule) error {
	if !identifier(rule.ID) {
		return fmt.Errorf("invalid id")
	}
	if err := validatePatterns("agents", rule.Agents, 128, func(pattern string) bool {
		return pattern == "*" || identifier(pattern)
	}); err != nil {
		return err
	}
	if err := validatePatterns("actions", rule.Actions, 128, validActionPattern); err != nil {
		return err
	}
	if err := validatePatterns("resource_prefixes", rule.ResourcePrefixes, 1024, validResourcePrefix); err != nil {
		return err
	}
	if len(rule.Risks) == 0 || len(rule.Risks) > 4 {
		return fmt.Errorf("risks must contain 1-4 values")
	}
	riskSeen := make(map[decision.RiskClass]struct{}, len(rule.Risks))
	for _, risk := range rule.Risks {
		switch risk {
		case decision.RiskLow, decision.RiskMedium, decision.RiskHigh, decision.RiskCritical:
		default:
			return fmt.Errorf("invalid risk %q", risk)
		}
		if _, exists := riskSeen[risk]; exists {
			return fmt.Errorf("duplicate risk %q", risk)
		}
		riskSeen[risk] = struct{}{}
	}
	if err := validateOutcome(rule.Outcome, rule.Reasons, rule.Constraints); err != nil {
		return err
	}
	if rule.Disclosure != nil {
		if err := validateDisclosureRule(*rule.Disclosure); err != nil {
			return fmt.Errorf("invalid disclosure rule: %w", err)
		}
	}
	if rule.Outcome == decision.ApprovalRequired {
		if rule.Approval != nil {
			if err := validateApprovalPlan(*rule.Approval); err != nil {
				return fmt.Errorf("invalid approval plan: %w", err)
			}
		}
	} else if rule.Approval != nil {
		return fmt.Errorf("approval plan requires approval_required outcome")
	}
	return nil
}

func validateDisclosureRule(rule DisclosureRule) error {
	if len(rule.LabelsAll)+len(rule.ContentTypes)+len(rule.Recipients)+len(rule.Purposes)+len(rule.Residencies)+len(rule.RetentionClasses) == 0 {
		return fmt.Errorf("at least one disclosure condition is required")
	}
	if err := validateStringSet("labels_all", rule.LabelsAll, 16, validDisclosureLabel); err != nil {
		return err
	}
	if err := validateStringSet("content_types", rule.ContentTypes, 16, validDisclosureContentType); err != nil {
		return err
	}
	if err := validateStringSet("recipients", rule.Recipients, 16, validDisclosureText); err != nil {
		return err
	}
	if err := validateStringSet("purposes", rule.Purposes, 16, validDisclosureText); err != nil {
		return err
	}
	if err := validateStringSet("residencies", rule.Residencies, 16, validDisclosureResidency); err != nil {
		return err
	}
	return validateStringSet("retention_classes", rule.RetentionClasses, 16, validDisclosureLabel)
}

func validateStringSet(name string, values []string, max int, valid func(string) bool) error {
	if len(values) == 0 {
		return nil
	}
	if len(values) > max {
		return fmt.Errorf("%s must contain at most %d values", name, max)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !valid(value) {
			return fmt.Errorf("invalid %s value %q", name, value)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("duplicate %s value %q", name, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validDisclosureLabel(value string) bool {
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

func validDisclosureContentType(value string) bool {
	if value == "" || len(value) > 128 || value != strings.ToLower(value) {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(value)
	return err == nil && len(parameters) == 0 && mediaType == value && strings.Contains(mediaType, "/")
}

func validDisclosureText(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validDisclosureResidency(value string) bool {
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

func validateApprovalPlan(plan ApprovalPlan) error {
	if len(plan.ApproverKeyIDs) == 0 || len(plan.ApproverKeyIDs) > decision.MaxApprovalKeys || plan.RequiredApprovals == 0 || int(plan.RequiredApprovals) > len(plan.ApproverKeyIDs) {
		return fmt.Errorf("invalid approver threshold")
	}
	seen := make(map[string]struct{}, len(plan.ApproverKeyIDs))
	for _, keyID := range plan.ApproverKeyIDs {
		if !identifier(keyID) {
			return fmt.Errorf("invalid approver key ID %q", keyID)
		}
		if _, exists := seen[keyID]; exists {
			return fmt.Errorf("duplicate approver key ID %q", keyID)
		}
		seen[keyID] = struct{}{}
	}
	if plan.ValiditySeconds <= 0 || plan.ValiditySeconds > int64(decision.MaxApprovalTransactionTTL/time.Second) {
		return fmt.Errorf("validity_seconds must be in (0, %d]", int64(decision.MaxApprovalTransactionTTL/time.Second))
	}
	if plan.Outcome != decision.Allow && plan.Outcome != decision.Constrain {
		return fmt.Errorf("outcome must be allow or constrain")
	}
	if plan.Outcome == decision.Allow && len(plan.Constraints) != 0 {
		return fmt.Errorf("allow outcome cannot carry constraints")
	}
	if plan.Outcome == decision.Constrain && len(plan.Constraints) == 0 {
		return fmt.Errorf("constrain outcome requires constraints")
	}
	if err := validateOutcome(plan.Outcome, nil, plan.Constraints); err != nil {
		return err
	}
	return nil
}

func validateOutcome(outcome decision.Outcome, reasons []string, constraints []decision.Constraint) error {
	probe := decision.Decision{
		Version: decision.SchemaVersion, ID: "policy-validation", IntentHash: strings.Repeat("0", 64),
		TenantID: "policy-validation", AgentID: "policy-validation", Outcome: outcome,
		Reasons: reasons, Constraints: constraints, ProviderID: "policy-validation",
		IssuedAt: 1, ExpiresAt: 2, KeyID: "policy-validation",
	}
	if err := probe.Validate(); err != nil {
		return fmt.Errorf("invalid outcome: %w", err)
	}
	return nil
}

func validatePatterns(name string, patterns []string, maxLength int, valid func(string) bool) error {
	if len(patterns) == 0 || len(patterns) > 64 {
		return fmt.Errorf("%s must contain 1-64 values", name)
	}
	seen := make(map[string]struct{}, len(patterns))
	for _, pattern := range patterns {
		if len(pattern) > maxLength || !valid(pattern) {
			return fmt.Errorf("invalid %s pattern %q", name, pattern)
		}
		if _, exists := seen[pattern]; exists {
			return fmt.Errorf("duplicate %s pattern %q", name, pattern)
		}
		seen[pattern] = struct{}{}
	}
	return nil
}

func identifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._:/@-", character) {
			continue
		}
		return false
	}
	return true
}

func validActionPattern(pattern string) bool {
	if pattern == "*" {
		return true
	}
	base := strings.TrimSuffix(pattern, "*")
	if strings.Contains(base, "*") || base == "" || base[0] < 'a' || base[0] > 'z' {
		return false
	}
	for _, character := range base[1:] {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || strings.ContainsRune("._-", character) {
			continue
		}
		return false
	}
	return true
}

func validResourcePrefix(prefix string) bool {
	if prefix == "*" {
		return true
	}
	if prefix == "" || strings.Contains(prefix, "*") {
		return false
	}
	for _, character := range prefix {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func (policy *compiled) evaluate(intent decision.Intent) decision.Decision {
	for _, rule := range policy.document.Rules {
		if matches(rule, intent, nil) {
			return decision.Decision{
				Outcome: rule.Outcome, Reasons: append([]string(nil), rule.Reasons...),
				Constraints: append([]decision.Constraint(nil), rule.Constraints...),
			}
		}
	}
	return decision.Decision{Outcome: policy.document.DefaultOutcome, Reasons: []string{"policy:default"}}
}

func (policy *compiled) evaluateDisclosure(intent decision.Intent, disclosure decision.DisclosureBinding) decision.Decision {
	for _, rule := range policy.document.Rules {
		if matches(rule, intent, &disclosure) {
			return decision.Decision{
				Outcome: rule.Outcome, Reasons: append([]string(nil), rule.Reasons...),
				Constraints: append([]decision.Constraint(nil), rule.Constraints...),
			}
		}
	}
	return decision.Decision{Outcome: policy.document.DefaultOutcome, Reasons: []string{"policy:default"}}
}

func (policy *compiled) approvalPlan(intent decision.Intent) *ApprovalPlan {
	for _, rule := range policy.document.Rules {
		if matches(rule, intent, nil) {
			if rule.Outcome != decision.ApprovalRequired || rule.Approval == nil {
				return nil
			}
			plan := cloneApprovalPlan(*rule.Approval)
			return &plan
		}
	}
	return nil
}

func matches(rule Rule, intent decision.Intent, disclosure *decision.DisclosureBinding) bool {
	return matchesExact(rule.Agents, intent.AgentID) && matchesPrefix(rule.Actions, intent.Action) &&
		matchesResourcePrefix(rule.ResourcePrefixes, intent.Resource) && matchesRisk(rule.Risks, intent.Risk) &&
		matchesDisclosure(rule.Disclosure, disclosure)
}

func matchesDisclosure(rule *DisclosureRule, disclosure *decision.DisclosureBinding) bool {
	if rule == nil {
		return true
	}
	if disclosure == nil {
		return false
	}
	return containsAll(disclosure.Labels, rule.LabelsAll) && matchesExactOrEmpty(rule.ContentTypes, disclosure.ContentType) &&
		matchesExactOrEmpty(rule.Recipients, disclosure.Recipient) && matchesExactOrEmpty(rule.Purposes, disclosure.Purpose) &&
		matchesExactOrEmpty(rule.Residencies, disclosure.Residency) && matchesExactOrEmpty(rule.RetentionClasses, disclosure.RetentionClass)
}

func containsAll(values, expected []string) bool {
	for _, wanted := range expected {
		found := false
		for _, value := range values {
			if value == wanted {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func matchesExactOrEmpty(expected []string, value string) bool {
	return len(expected) == 0 || matchesExact(expected, value)
}

func matchesExact(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if pattern == "*" || pattern == value {
			return true
		}
	}
	return false
}

func matchesPrefix(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if pattern == "*" || (strings.HasSuffix(pattern, "*") && strings.HasPrefix(value, strings.TrimSuffix(pattern, "*"))) || pattern == value {
			return true
		}
	}
	return false
}

func matchesResourcePrefix(prefixes []string, value string) bool {
	for _, prefix := range prefixes {
		if prefix == "*" || strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func matchesRisk(risks []decision.RiskClass, value decision.RiskClass) bool {
	for _, risk := range risks {
		if risk == value {
			return true
		}
	}
	return false
}

type EngineInstance struct {
	manager *authority.PolicyManager
	mu      sync.Mutex
	cache   map[string]cachedPolicy
}

type cachedPolicy struct {
	revision uint64
	policy   *compiled
}

func New(manager *authority.PolicyManager) (*EngineInstance, error) {
	if manager == nil {
		return nil, fmt.Errorf("decisionpolicy: policy manager is required")
	}
	return &EngineInstance{manager: manager, cache: make(map[string]cachedPolicy)}, nil
}

func (engine *EngineInstance) ValidatePolicy(_ context.Context, name, version, contentType string, payload []byte) error {
	if name != Engine || version != EngineVersion || contentType != ContentType {
		return fmt.Errorf("decisionpolicy: unsupported engine tuple %q/%q/%q", name, version, contentType)
	}
	_, err := Compile(payload)
	return err
}

// Validator is usable while constructing the PolicyManager before an
// EngineInstance can reference that manager.
type Validator struct{}

func (Validator) ValidatePolicy(_ context.Context, name, version, contentType string, payload []byte) error {
	if name != Engine || version != EngineVersion || contentType != ContentType {
		return fmt.Errorf("decisionpolicy: unsupported engine tuple %q/%q/%q", name, version, contentType)
	}
	_, err := Compile(payload)
	return err
}

func (engine *EngineInstance) Authorize(ctx context.Context, intent decision.Intent) (decision.Decision, error) {
	bundle, policy, err := engine.active(ctx, intent.TenantID)
	if err != nil {
		return decision.Decision{}, err
	}
	result := policy.evaluate(intent)
	result.PolicyRevision = bundle.Revision
	result.RevocationEpoch = bundle.RevocationEpoch
	return result, nil
}

// AuthorizeDisclosure verifies the explicit metadata-to-Intent binding before
// evaluating the disclosure-aware deterministic policy. Rules with a
// disclosure clause never match an ordinary V1 request, so a tenant can make
// typed metadata a real authorization precondition rather than a UI hint.
func (engine *EngineInstance) AuthorizeDisclosure(ctx context.Context, intent decision.Intent, disclosure decision.DisclosureBinding) (decision.Decision, error) {
	if err := disclosure.VerifyIntent(intent); err != nil {
		return decision.Decision{}, err
	}
	bundle, policy, err := engine.active(ctx, intent.TenantID)
	if err != nil {
		return decision.Decision{}, err
	}
	result := policy.evaluateDisclosure(intent, disclosure)
	result.PolicyRevision = bundle.Revision
	result.RevocationEpoch = bundle.RevocationEpoch
	return result, nil
}

// ApprovalPlanFor returns the signed policy plan for an exact current
// approval_required result. It rejects stale state or a rule with no long-run
// plan, leaving the existing short-lived approval path available to policies
// that intentionally omit one.
func (engine *EngineInstance) ApprovalPlanFor(ctx context.Context, intent decision.Intent, initial decision.Decision) (ApprovalPlan, error) {
	bundle, policy, err := engine.active(ctx, intent.TenantID)
	if err != nil {
		return ApprovalPlan{}, err
	}
	if initial.Outcome != decision.ApprovalRequired || initial.PolicyRevision != bundle.Revision || initial.RevocationEpoch != bundle.RevocationEpoch {
		return ApprovalPlan{}, fmt.Errorf("decisionpolicy: initial approval decision is not current")
	}
	plan := policy.approvalPlan(intent)
	if plan == nil {
		return ApprovalPlan{}, fmt.Errorf("decisionpolicy: matching rule has no long-running approval plan")
	}
	return *plan, nil
}

// ApprovalPlanForDisclosure resolves an approval plan using the same typed
// rule that issued a disclosure-bound approval_required Decision. Legacy
// ApprovalPlanFor deliberately cannot match those rules, preventing a caller
// from opening a long-running approval path after omitting data metadata.
func (engine *EngineInstance) ApprovalPlanForDisclosure(ctx context.Context, intent decision.Intent, initial decision.Decision, disclosure decision.DisclosureBinding) (ApprovalPlan, error) {
	if err := disclosure.VerifyIntent(intent); err != nil {
		return ApprovalPlan{}, err
	}
	bundle, policy, err := engine.active(ctx, intent.TenantID)
	if err != nil {
		return ApprovalPlan{}, err
	}
	if initial.Outcome != decision.ApprovalRequired || initial.PolicyRevision != bundle.Revision || initial.RevocationEpoch != bundle.RevocationEpoch {
		return ApprovalPlan{}, fmt.Errorf("decisionpolicy: initial approval decision is not current")
	}
	plan := policy.approvalPlanDisclosure(intent, disclosure)
	if plan == nil {
		return ApprovalPlan{}, fmt.Errorf("decisionpolicy: matching disclosure rule has no long-running approval plan")
	}
	return *plan, nil
}

func cloneApprovalPlan(plan ApprovalPlan) ApprovalPlan {
	return ApprovalPlan{
		ApproverKeyIDs: append([]string(nil), plan.ApproverKeyIDs...), RequiredApprovals: plan.RequiredApprovals,
		ValiditySeconds: plan.ValiditySeconds, Outcome: plan.Outcome,
		Constraints: append([]decision.Constraint(nil), plan.Constraints...),
	}
}

func (engine *EngineInstance) Check(ctx context.Context, intent decision.Intent, remote decision.Decision) error {
	_, policy, err := engine.active(ctx, intent.TenantID)
	if err != nil {
		return err
	}
	return checkLocalOutcome(policy.evaluate(intent), remote)
}

// CheckDisclosure proves that a remote signed decision is no broader than the
// locally installed policy for the same typed disclosure. This is the method
// called by governed receivers and brokers before they release a message,
// file, stream, or event.
func (engine *EngineInstance) CheckDisclosure(ctx context.Context, intent decision.Intent, remote decision.Decision, disclosure decision.DisclosureBinding) error {
	if err := disclosure.VerifyIntent(intent); err != nil {
		return err
	}
	_, policy, err := engine.active(ctx, intent.TenantID)
	if err != nil {
		return err
	}
	return checkLocalOutcome(policy.evaluateDisclosure(intent, disclosure), remote)
}

func checkLocalOutcome(local, remote decision.Decision) error {
	if remote.Outcome == decision.Deny || remote.Outcome == decision.ApprovalRequired {
		return nil
	}
	switch local.Outcome {
	case decision.Deny, decision.ApprovalRequired:
		return fmt.Errorf("decisionpolicy: remote outcome expands local %s", local.Outcome)
	case decision.Constrain:
		if remote.Outcome != decision.Constrain || !containsConstraints(remote.Constraints, local.Constraints) {
			return fmt.Errorf("decisionpolicy: remote outcome drops local constraints")
		}
	case decision.Allow:
		if remote.Outcome != decision.Allow && remote.Outcome != decision.Constrain {
			return fmt.Errorf("decisionpolicy: unsupported remote outcome %s", remote.Outcome)
		}
	default:
		return fmt.Errorf("decisionpolicy: invalid local outcome")
	}
	return nil
}

func (engine *EngineInstance) active(ctx context.Context, tenantID string) (authority.PolicyBundle, *compiled, error) {
	bundle, err := engine.manager.Active(ctx, tenantID)
	if err != nil {
		return authority.PolicyBundle{}, nil, err
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if cached, exists := engine.cache[tenantID]; exists && cached.revision == bundle.Revision {
		return bundle, cached.policy, nil
	}
	policy, err := Compile(bundle.Payload)
	if err != nil {
		return authority.PolicyBundle{}, nil, fmt.Errorf("decisionpolicy: active policy no longer validates: %w", err)
	}
	engine.cache[tenantID] = cachedPolicy{revision: bundle.Revision, policy: policy}
	return bundle, policy, nil
}

func containsConstraints(actual, required []decision.Constraint) bool {
	for _, want := range required {
		found := false
		for _, candidate := range actual {
			if candidate == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

var _ authority.PolicyValidator = Validator{}
var _ decision.Authorizer = (*EngineInstance)(nil)
var _ decision.DisclosureAuthorizer = (*EngineInstance)(nil)
var _ decision.AuthorityCeiling = (*EngineInstance)(nil)
var _ decision.DisclosureCeiling = (*EngineInstance)(nil)

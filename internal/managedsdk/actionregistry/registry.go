// SPDX-License-Identifier: AGPL-3.0-or-later

// Package actionregistry defines the canonical action vocabulary shared by
// management policy, node capability reports, and real side-effect adapters.
//
// Importing this package does not enable governance. The zero-value Profile is
// explicitly unmanaged, so existing nodes and protocols retain their current
// behavior until an operator selects actions and a non-off mode.
package actionregistry

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const SchemaVersion uint16 = 1

type ControlMode string

const (
	ModeOff            ControlMode = "off"
	ModeObserve        ControlMode = "observe"
	ModeLocalEnforce   ControlMode = "local_enforce"
	ModeManagedEnforce ControlMode = "managed_enforce"
)

func (mode ControlMode) Normalize() ControlMode {
	if mode == "" {
		return ModeOff
	}
	return mode
}

func (mode ControlMode) Validate() error {
	switch mode.Normalize() {
	case ModeOff, ModeObserve, ModeLocalEnforce, ModeManagedEnforce:
		return nil
	default:
		return fmt.Errorf("actionregistry: unsupported control mode %q", mode)
	}
}

func (mode ControlMode) Enforces() bool {
	mode = mode.Normalize()
	return mode == ModeLocalEnforce || mode == ModeManagedEnforce
}

func (mode ControlMode) Managed() bool { return mode.Normalize() == ModeManagedEnforce }

type PayloadBinding string

const (
	PayloadHash          PayloadBinding = "sha256"
	PayloadCanonicalHash PayloadBinding = "canonical_sha256"
)

type PrivacyClass string

const (
	PrivacyMetadataOnly     PrivacyClass = "metadata_only"
	PrivacyTypedMetadata    PrivacyClass = "typed_metadata"
	PrivacyLocalOnly        PrivacyClass = "local_only"
	PrivacyPayloadOptIn     PrivacyClass = "payload_opt_in"
	PrivacyFederatedContent PrivacyClass = "federated_content"
)

// Definition is the product contract for one canonical action. An action is
// not considered enforced merely because it appears here: a node must also
// report a matching, enforceable adapter capability.
type Definition struct {
	Version        uint16         `json:"version"`
	Name           string         `json:"name"`
	Aliases        []string       `json:"aliases,omitempty"`
	ResourceKind   string         `json:"resource_kind"`
	PayloadBinding PayloadBinding `json:"payload_binding"`
	Privacy        PrivacyClass   `json:"privacy"`
	Suspendable    bool           `json:"suspendable"`
	Resumable      bool           `json:"resumable"`
	Constraints    []string       `json:"constraints,omitempty"`
	Description    string         `json:"description"`
}

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+$`)
var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)

func (definition Definition) Validate() error {
	if definition.Version != SchemaVersion || !namePattern.MatchString(definition.Name) {
		return fmt.Errorf("actionregistry: invalid action identity %q", definition.Name)
	}
	if !identifierPattern.MatchString(definition.ResourceKind) {
		return fmt.Errorf("actionregistry: invalid resource kind for %q", definition.Name)
	}
	switch definition.PayloadBinding {
	case PayloadHash, PayloadCanonicalHash:
	default:
		return fmt.Errorf("actionregistry: invalid payload binding for %q", definition.Name)
	}
	switch definition.Privacy {
	case PrivacyMetadataOnly, PrivacyTypedMetadata, PrivacyLocalOnly, PrivacyPayloadOptIn, PrivacyFederatedContent:
	default:
		return fmt.Errorf("actionregistry: invalid privacy class for %q", definition.Name)
	}
	if definition.Resumable && !definition.Suspendable {
		return fmt.Errorf("actionregistry: resumable action %q must be suspendable", definition.Name)
	}
	if strings.TrimSpace(definition.Description) == "" || len(definition.Description) > 256 {
		return fmt.Errorf("actionregistry: invalid description for %q", definition.Name)
	}
	seen := map[string]struct{}{definition.Name: {}}
	for _, alias := range definition.Aliases {
		if !namePattern.MatchString(alias) {
			return fmt.Errorf("actionregistry: invalid alias %q", alias)
		}
		if _, duplicate := seen[alias]; duplicate {
			return fmt.Errorf("actionregistry: duplicate alias %q", alias)
		}
		seen[alias] = struct{}{}
	}
	seen = make(map[string]struct{}, len(definition.Constraints))
	for _, constraint := range definition.Constraints {
		if !identifierPattern.MatchString(constraint) {
			return fmt.Errorf("actionregistry: invalid constraint %q", constraint)
		}
		if _, duplicate := seen[constraint]; duplicate {
			return fmt.Errorf("actionregistry: duplicate constraint %q", constraint)
		}
		seen[constraint] = struct{}{}
	}
	return nil
}

type Registry struct {
	byName    map[string]Definition
	canonical []Definition
}

func New(definitions []Definition) (*Registry, error) {
	registry := &Registry{byName: make(map[string]Definition)}
	for _, definition := range definitions {
		definition.Aliases = append([]string(nil), definition.Aliases...)
		definition.Constraints = append([]string(nil), definition.Constraints...)
		if err := definition.Validate(); err != nil {
			return nil, err
		}
		for _, name := range append([]string{definition.Name}, definition.Aliases...) {
			if existing, duplicate := registry.byName[name]; duplicate {
				return nil, fmt.Errorf("actionregistry: name %q belongs to both %q and %q", name, existing.Name, definition.Name)
			}
			registry.byName[name] = definition
		}
		registry.canonical = append(registry.canonical, definition)
	}
	sort.Slice(registry.canonical, func(i, j int) bool { return registry.canonical[i].Name < registry.canonical[j].Name })
	return registry, nil
}

func (registry *Registry) Resolve(name string) (Definition, bool) {
	if registry == nil {
		return Definition{}, false
	}
	definition, found := registry.byName[strings.TrimSpace(name)]
	return definition, found
}

func (registry *Registry) CanonicalName(name string) (string, bool) {
	definition, found := registry.Resolve(name)
	return definition.Name, found
}

func (registry *Registry) Definitions() []Definition {
	if registry == nil {
		return nil
	}
	out := make([]Definition, len(registry.canonical))
	copy(out, registry.canonical)
	for index := range out {
		out[index].Aliases = append([]string(nil), out[index].Aliases...)
		out[index].Constraints = append([]string(nil), out[index].Constraints...)
	}
	return out
}

// Profile is an explicitly selected node policy posture. Empty mode is a
// compatibility alias for off. Every non-off profile must name actions (or
// the explicit "*" selector), preventing an upgrade from silently governing
// newly added actions.
type Profile struct {
	Version       uint16      `json:"version,omitempty"`
	Mode          ControlMode `json:"mode,omitempty"`
	Actions       []string    `json:"actions,omitempty"`
	StrictReceive []string    `json:"strict_receive,omitempty"`
}

func (profile Profile) Validate(registry *Registry) error {
	if profile.Version != 0 && profile.Version != SchemaVersion {
		return fmt.Errorf("actionregistry: unsupported profile version %d", profile.Version)
	}
	if err := profile.Mode.Validate(); err != nil {
		return err
	}
	mode := profile.Mode.Normalize()
	if mode == ModeOff {
		if len(profile.Actions) > 0 || len(profile.StrictReceive) > 0 {
			return fmt.Errorf("actionregistry: off profile cannot select actions")
		}
		return nil
	}
	if registry == nil {
		return fmt.Errorf("actionregistry: registry is required for an enabled profile")
	}
	actions, all, err := normalizeSelection(registry, profile.Actions)
	if err != nil {
		return err
	}
	if len(actions) == 0 && !all {
		return fmt.Errorf("actionregistry: enabled profile requires explicit actions or *")
	}
	if len(profile.StrictReceive) > 0 && !mode.Enforces() {
		return fmt.Errorf("actionregistry: strict receive requires an enforcement mode")
	}
	strict, strictAll, err := normalizeSelection(registry, profile.StrictReceive)
	if err != nil {
		return fmt.Errorf("actionregistry: strict receive: %w", err)
	}
	if strictAll && !all {
		return fmt.Errorf("actionregistry: strict receive * requires governed actions *")
	}
	if !all {
		for action := range strict {
			if _, governed := actions[action]; !governed {
				return fmt.Errorf("actionregistry: strict receive action %q is not governed", action)
			}
		}
	}
	return nil
}

func (profile Profile) AppliesTo(registry *Registry, action string) bool {
	if profile.Mode.Normalize() == ModeOff || registry == nil {
		return false
	}
	canonical, found := registry.CanonicalName(action)
	if !found {
		return false
	}
	selection, all, err := normalizeSelection(registry, profile.Actions)
	if err != nil {
		return false
	}
	_, selected := selection[canonical]
	return all || selected
}

func (profile Profile) Enforces(registry *Registry, action string) bool {
	return profile.Mode.Enforces() && profile.AppliesTo(registry, action)
}

func (profile Profile) Observes(registry *Registry, action string) bool {
	return profile.Mode.Normalize() == ModeObserve && profile.AppliesTo(registry, action)
}

func (profile Profile) RequiresGovernedReceive(registry *Registry, action string) bool {
	if !profile.Mode.Enforces() || registry == nil {
		return false
	}
	canonical, found := registry.CanonicalName(action)
	if !found {
		return false
	}
	selection, all, err := normalizeSelection(registry, profile.StrictReceive)
	if err != nil {
		return false
	}
	_, selected := selection[canonical]
	return all || selected
}

func normalizeSelection(registry *Registry, values []string) (map[string]struct{}, bool, error) {
	selection := make(map[string]struct{}, len(values))
	all := false
	for _, raw := range values {
		name := strings.TrimSpace(raw)
		if name == "*" {
			if all || len(values) != 1 {
				return nil, false, fmt.Errorf("actionregistry: * must be the only selector")
			}
			all = true
			continue
		}
		canonical, found := registry.CanonicalName(name)
		if !found {
			return nil, false, fmt.Errorf("actionregistry: unknown action %q", name)
		}
		if _, duplicate := selection[canonical]; duplicate {
			return nil, false, fmt.Errorf("actionregistry: duplicate action %q", canonical)
		}
		selection[canonical] = struct{}{}
	}
	return selection, all, nil
}

// AdapterCapability is a node's signed/reportable assertion that a concrete
// adapter can observe or enforce an action. Management must not infer this
// from the registry alone.
type AdapterCapability struct {
	Action         string `json:"action"`
	AdapterID      string `json:"adapter_id"`
	AdapterVersion string `json:"adapter_version"`
	Observe        bool   `json:"observe"`
	Enforce        bool   `json:"enforce"`
	Suspend        bool   `json:"suspend"`
	Resume         bool   `json:"resume"`
	Receipt        bool   `json:"receipt"`
}

// Validate checks a concrete adapter claim against the canonical registry.
// It is exported because signed fleet capability reports are validated in the
// authority package rather than trusting browser or adapter-supplied labels.
func (capability AdapterCapability) Validate(registry *Registry) error {
	definition, found := registry.Resolve(capability.Action)
	if !found {
		return fmt.Errorf("actionregistry: capability references unknown action %q", capability.Action)
	}
	if !identifierPattern.MatchString(capability.AdapterID) || strings.TrimSpace(capability.AdapterVersion) == "" || len(capability.AdapterVersion) > 64 {
		return fmt.Errorf("actionregistry: invalid adapter identity for %q", definition.Name)
	}
	if capability.Enforce && !capability.Observe {
		return fmt.Errorf("actionregistry: enforcing adapter %q must also observe", capability.AdapterID)
	}
	if capability.Suspend && (!capability.Enforce || !definition.Suspendable) {
		return fmt.Errorf("actionregistry: adapter %q cannot suspend %q", capability.AdapterID, definition.Name)
	}
	if capability.Resume && (!capability.Suspend || !definition.Resumable) {
		return fmt.Errorf("actionregistry: adapter %q cannot resume %q", capability.AdapterID, definition.Name)
	}
	return nil
}

func Builtins() *Registry {
	registry, err := New(builtinDefinitions())
	if err != nil {
		panic(err)
	}
	return registry
}

func builtinDefinitions() []Definition {
	definition := func(name, resource string, privacy PrivacyClass, suspendable, resumable bool, description string, aliases ...string) Definition {
		return Definition{Version: SchemaVersion, Name: name, Aliases: aliases, ResourceKind: resource, PayloadBinding: PayloadCanonicalHash, Privacy: privacy, Suspendable: suspendable, Resumable: resumable, Description: description}
	}
	return []Definition{
		definition("browser.navigate", "url", PrivacyMetadataOnly, true, true, "Navigate a controlled browser to a URL."),
		definition("data.export", "destination", PrivacyFederatedContent, true, true, "Export bounded data to an external destination."),
		definition("data.read", "message", PrivacyMetadataOnly, false, false, "Read a received message or bounded data object.", "message.read"),
		definition("data.send.binary", "agent", PrivacyFederatedContent, true, true, "Send binary data to a Pilot peer."),
		definition("data.send.json", "agent", PrivacyFederatedContent, true, true, "Send JSON data to a Pilot peer."),
		definition("data.send.text", "agent", PrivacyFederatedContent, true, true, "Send a text message to a Pilot peer.", "message.send"),
		definition("event.publish", "topic", PrivacyFederatedContent, true, true, "Publish an event to a Pilot topic."),
		definition("file.delete", "file", PrivacyLocalOnly, false, false, "Delete a local or managed file."),
		definition("file.read", "file", PrivacyLocalOnly, false, false, "Read a local or managed file."),
		definition("file.share", "agent", PrivacyFederatedContent, true, true, "Share a file with a Pilot peer."),
		definition("file.write", "file", PrivacyLocalOnly, true, true, "Write a local or managed file."),
		definition("http.request", "url", PrivacyFederatedContent, true, true, "Issue an outbound HTTP request."),
		definition("process.execute", "executable", PrivacyLocalOnly, true, false, "Start a local process."),
		definition("tool.invoke", "tool", PrivacyFederatedContent, true, true, "Invoke a registered agent tool."),
		definition("trust.accept", "agent", PrivacyMetadataOnly, true, true, "Accept an inbound trust relationship."),
		definition("trust.auto_accept", "agent", PrivacyMetadataOnly, false, false, "Automatically accept an inbound trust relationship."),
		definition("trust.reject", "agent", PrivacyMetadataOnly, false, false, "Reject an inbound trust request."),
		definition("trust.request", "agent", PrivacyMetadataOnly, true, true, "Request a trust relationship with another agent."),
		definition("trust.revoke", "agent", PrivacyMetadataOnly, false, false, "Revoke an existing trust relationship."),
		definition("wallet.pay", "counterparty", PrivacyFederatedContent, true, true, "Transfer value to a counterparty."),
		definition("webhook.send", "url", PrivacyFederatedContent, true, true, "Deliver an outbound webhook."),
	}
}

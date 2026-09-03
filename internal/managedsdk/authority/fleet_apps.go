// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	FleetAppsVersion uint16 = 1

	// FleetAppsDocumentPath is the desired-app-set document's path relative to
	// the node's fleet state root. It is delivered by an ordinary signed
	// FleetStateMutation: apps deliberately introduce no new wire protocol and
	// no new command vocabulary, so a node that already accepts state
	// mutations needs no protocol upgrade to accept apps.
	FleetAppsDocumentPath = "apps.json"

	MaxFleetAppsEntries   = 64
	MaxFleetAppGrants     = 64
	MaxFleetAppReasonSize = 256
)

// fleetAppIDPattern mirrors app-store/pkg/manifest idPattern. The authority
// refuses to distribute an identifier the node's manifest validator would
// later reject, so an operator learns at approval time rather than at the
// node's next reconcile.
var fleetAppIDPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9_-]*[a-z0-9])?)+$`)

// fleetAppVersionPattern mirrors the manifest's simplified semver.
var fleetAppVersionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$`)

// FleetAppGrant is one manifest-declared capability that a tenant
// administrator accepted on the fleet's behalf. It carries no authority of its
// own: the node re-reads the installed manifest and refuses to start an app
// whose declared grants are not covered by this accepted set, so a catalogue
// that later widens an app's grants fails closed instead of silently gaining
// capability across the fleet.
type FleetAppGrant struct {
	Cap    string `json:"cap"`
	Target string `json:"target"`
}

func (grant FleetAppGrant) Validate() error {
	if !boundedFleetText(grant.Cap, 64, false) || !boundedFleetText(grant.Target, 512, true) {
		return fmt.Errorf("authority: invalid fleet app grant")
	}
	return nil
}

// FleetAppSpec is one desired app. Version pins what the node resolves out of
// the publisher-signed catalogue; the bundle's per-platform sha256 stays in
// that catalogue rather than here, because one desired-state document is
// distributed unchanged to a mixed-platform fleet.
type FleetAppSpec struct {
	ID             string          `json:"id"`
	Version        string          `json:"version"`
	AcceptedGrants []FleetAppGrant `json:"accepted_grants"`
	ApprovedBy     string          `json:"approved_by"`
	ApprovedAt     int64           `json:"approved_at"`
}

func (spec FleetAppSpec) Validate() error {
	if !fleetAppIDPattern.MatchString(spec.ID) || len(spec.ID) > 128 {
		return fmt.Errorf("authority: invalid fleet app id")
	}
	if !fleetAppVersionPattern.MatchString(spec.Version) {
		return fmt.Errorf("authority: invalid fleet app version for %s", spec.ID)
	}
	if err := validateIdentifier("fleet app approver", spec.ApprovedBy); err != nil {
		return err
	}
	if spec.ApprovedAt <= 0 {
		return fmt.Errorf("authority: fleet app %s carries no approval time", spec.ID)
	}
	if len(spec.AcceptedGrants) > MaxFleetAppGrants {
		return fmt.Errorf("authority: fleet app %s declares too many accepted grants", spec.ID)
	}
	seen := make(map[string]struct{}, len(spec.AcceptedGrants))
	for _, grant := range spec.AcceptedGrants {
		if err := grant.Validate(); err != nil {
			return err
		}
		key := grant.Cap + "\x00" + grant.Target
		if _, exists := seen[key]; exists {
			return fmt.Errorf("authority: fleet app %s repeats an accepted grant", spec.ID)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// FleetAppsDocument is the complete desired app set for one node. It is
// declarative on purpose: the node reconciles toward it and is free to be
// offline, restarted, or rebuilt from an empty disk in between. A container
// fleet member whose filesystem is discarded on restart converges to the same
// set without the authority replaying anything.
type FleetAppsDocument struct {
	Version  uint16         `json:"version"`
	TenantID string         `json:"tenant_id"`
	AgentID  string         `json:"agent_id"`
	Desired  []FleetAppSpec `json:"desired"`
	Reason   string         `json:"reason"`
	IssuedAt int64          `json:"issued_at"`
}

func (document FleetAppsDocument) Validate() error {
	if document.Version != FleetAppsVersion || document.IssuedAt <= 0 {
		return fmt.Errorf("authority: invalid fleet apps document")
	}
	for name, value := range map[string]string{"tenant_id": document.TenantID, "agent_id": document.AgentID} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if !boundedFleetText(document.Reason, MaxFleetAppReasonSize, false) || len(strings.TrimSpace(document.Reason)) < 8 {
		return fmt.Errorf("authority: invalid fleet apps document reason")
	}
	if len(document.Desired) > MaxFleetAppsEntries {
		return fmt.Errorf("authority: fleet apps document exceeds %d entries", MaxFleetAppsEntries)
	}
	seen := make(map[string]struct{}, len(document.Desired))
	for _, spec := range document.Desired {
		if err := spec.Validate(); err != nil {
			return err
		}
		if _, exists := seen[spec.ID]; exists {
			return fmt.Errorf("authority: fleet apps document repeats %s", spec.ID)
		}
		seen[spec.ID] = struct{}{}
	}
	return nil
}

// Normalize orders the desired set so that re-approving an unchanged fleet
// produces a byte-identical document. Without this the console would queue a
// mutation, and the node would report a new revision, every time an operator
// opened the page and pressed save with nothing changed.
func (document *FleetAppsDocument) Normalize() {
	sort.Slice(document.Desired, func(i, j int) bool { return document.Desired[i].ID < document.Desired[j].ID })
	for index := range document.Desired {
		grants := document.Desired[index].AcceptedGrants
		sort.Slice(grants, func(i, j int) bool {
			if grants[i].Cap != grants[j].Cap {
				return grants[i].Cap < grants[j].Cap
			}
			return grants[i].Target < grants[j].Target
		})
	}
}

// FleetAppState is one app as the node actually found it, reported back
// through the ordinary fleet state mirror rather than a new channel.
//
// DeclaredGrants is what the installed bundle's manifest actually asks for.
// The catalogue does not publish grants — they exist only inside the signed
// bundle — so the fleet is the only truthful source for them. A node that
// installs an app the tenant has not yet reviewed reports the grants here and
// holds the app unstarted, which lets the console show an operator the real
// capability list before anyone accepts it.
type FleetAppState struct {
	ID             string          `json:"id"`
	Version        string          `json:"version"`
	Status         string          `json:"status"`
	Detail         string          `json:"detail,omitempty"`
	BinarySHA256   string          `json:"binary_sha256,omitempty"`
	DeclaredGrants []FleetAppGrant `json:"declared_grants,omitempty"`
	ObservedAt     int64           `json:"observed_at"`
}

const (
	FleetAppInstalled    = "installed"
	FleetAppPending      = "pending"
	FleetAppFailed       = "failed"
	FleetAppGrantBlocked = "grant_blocked"
)

func (state FleetAppState) Validate() error {
	if !fleetAppIDPattern.MatchString(state.ID) || state.ObservedAt <= 0 {
		return fmt.Errorf("authority: invalid fleet app state")
	}
	switch state.Status {
	case FleetAppInstalled, FleetAppPending, FleetAppFailed, FleetAppGrantBlocked:
	default:
		return fmt.Errorf("authority: invalid fleet app status for %s", state.ID)
	}
	if state.Version != "" && !fleetAppVersionPattern.MatchString(state.Version) {
		return fmt.Errorf("authority: invalid fleet app state version for %s", state.ID)
	}
	if state.BinarySHA256 != "" && !lowerHexIdentifier(state.BinarySHA256, 64) {
		return fmt.Errorf("authority: invalid fleet app binary digest for %s", state.ID)
	}
	if !boundedFleetText(state.Detail, 512, true) || !utf8.ValidString(state.Detail) {
		return fmt.Errorf("authority: invalid fleet app state detail for %s", state.ID)
	}
	if len(state.DeclaredGrants) > MaxFleetAppGrants {
		return fmt.Errorf("authority: fleet app %s reports too many declared grants", state.ID)
	}
	for _, grant := range state.DeclaredGrants {
		if err := grant.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// FleetAppsReport is the node-authored inventory document. The node writes it
// into its own state tree, so it arrives through the existing signed snapshot
// and needs no separate endpoint, storage, or retention policy.
type FleetAppsReport struct {
	Version    uint16          `json:"version"`
	TenantID   string          `json:"tenant_id"`
	AgentID    string          `json:"agent_id"`
	Apps       []FleetAppState `json:"apps"`
	ObservedAt int64           `json:"observed_at"`
}

// FleetAppsReportPath is where the node publishes its inventory. It is
// deliberately distinct from FleetAppsDocumentPath: the authority owns the
// desired set and the node owns the observed set, so neither overwrites the
// other and drift between them is visible rather than resolved silently.
const FleetAppsReportPath = "apps-observed.json"

func (report FleetAppsReport) Validate() error {
	if report.Version != FleetAppsVersion || report.ObservedAt <= 0 {
		return fmt.Errorf("authority: invalid fleet apps report")
	}
	for name, value := range map[string]string{"tenant_id": report.TenantID, "agent_id": report.AgentID} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if len(report.Apps) > MaxFleetAppsEntries {
		return fmt.Errorf("authority: fleet apps report exceeds %d entries", MaxFleetAppsEntries)
	}
	for _, state := range report.Apps {
		if err := state.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// GrantsCovered reports whether every grant an installed manifest declares is
// covered by what the administrator accepted. The node calls this before it
// lets the supervisor start an app; the authority calls it to show drift in
// the console. Both must agree, so the comparison lives here rather than in
// either caller.
func GrantsCovered(declared, accepted []FleetAppGrant) bool {
	allowed := make(map[string]struct{}, len(accepted))
	for _, grant := range accepted {
		allowed[grant.Cap+"\x00"+grant.Target] = struct{}{}
	}
	for _, grant := range declared {
		if _, ok := allowed[grant.Cap+"\x00"+grant.Target]; !ok {
			return false
		}
	}
	return true
}

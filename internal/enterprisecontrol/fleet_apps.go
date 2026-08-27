// SPDX-License-Identifier: AGPL-3.0-or-later

package enterprisecontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	appmanifest "github.com/pilot-protocol/app-store/pkg/manifest"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
)

// AppsConfig enables managed app reconciliation. It is opt-in for the same
// reason fleet state sync is: an unmanaged node must never acquire software
// because some authority asked it to.
type AppsConfig struct {
	Enabled                  bool   `json:"enabled,omitempty"`
	InstallRoot              string `json:"install_root,omitempty"`
	StagingRoot              string `json:"staging_root,omitempty"`
	InstallerPath            string `json:"installer_path,omitempty"`
	ReconcileIntervalSeconds int64  `json:"reconcile_interval_seconds,omitempty"`
}

// AppReconcileResult is bounded operational information for daemon logs. App
// identifiers are catalogue-public, so they may cross this boundary; local
// paths and manifest contents may not.
type AppReconcileResult struct {
	Desired   int
	Installed int
	Staged    int
	Removed   int
	Failed    int
}

// AppInstaller performs the actual bundle fetch, verification, and extraction.
//
// It is an interface because the verified install path currently lives in
// pilotctl's `package main` and cannot be linked into the daemon. Reconciliation
// logic is therefore testable without a real network or a real pilotctl binary,
// and the concrete implementation can later be swapped for an extracted
// library without touching anything here.
type AppInstaller interface {
	// Install places appID at the requested version beneath root, performing
	// the same catalogue signature and sha256 checks an operator would get at
	// the keyboard.
	Install(ctx context.Context, appID, version, root string) error
	// Remove deletes appID from root. Removing an app that is not present is
	// not an error.
	Remove(ctx context.Context, appID, root string) error
}

// PilotctlInstaller drives the pilotctl binary that ships beside the daemon.
//
// Shelling out is deliberate rather than convenient: pilotctl owns the only
// implementation of the catalogue trust chain (publisher signature, per-platform
// bundle pin, sha256 verification, sideload clamping). Reimplementing that here
// would create a second, subtly different verifier — the one outcome that must
// not happen for a security boundary.
type PilotctlInstaller struct {
	BinaryPath string
	Timeout    time.Duration
}

func (installer PilotctlInstaller) timeout() time.Duration {
	if installer.Timeout > 0 {
		return installer.Timeout
	}
	return 10 * time.Minute
}

func (installer PilotctlInstaller) Install(ctx context.Context, appID, version, root string) error {
	ctx, cancel := context.WithTimeout(ctx, installer.timeout())
	defer cancel()
	// --force lets an install replace a wrong-version copy in place; the
	// catalogue signature and sha256 gates still run either way.
	// The pinned version is passed through so the node installs what the
	// operator approved. pilotctl fails closed when the catalogue has moved
	// on, which surfaces as version_unavailable rather than silently
	// installing whatever release happens to be current.
	arguments := []string{"appstore", "install", appID, "--force"}
	if strings.TrimSpace(version) != "" {
		arguments = append(arguments, "--version", version)
	}
	command := exec.CommandContext(ctx, installer.BinaryPath, arguments...)
	command.Env = append(os.Environ(), "PILOT_APPSTORE_ROOT="+root)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install %s: %w: %s", appID, err, boundedInstallerOutput(output))
	}
	return nil
}

func (installer PilotctlInstaller) Remove(ctx context.Context, appID, root string) error {
	target := filepath.Join(root, appID)
	if _, err := os.Stat(target); os.IsNotExist(err) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, installer.timeout())
	defer cancel()
	command := exec.CommandContext(ctx, installer.BinaryPath, "appstore", "uninstall", appID, "--yes")
	command.Env = append(os.Environ(), "PILOT_APPSTORE_ROOT="+root)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("uninstall %s: %w: %s", appID, err, boundedInstallerOutput(output))
	}
	return nil
}

// boundedInstallerOutput keeps a failing subprocess's tail for the daemon log
// without letting an unbounded child write flood it.
func boundedInstallerOutput(output []byte) string {
	const limit = 512
	text := strings.TrimSpace(string(output))
	if len(text) > limit {
		text = text[len(text)-limit:]
	}
	return strings.ReplaceAll(text, "\n", " ")
}

// HasAppReconcile reports whether this node reconciles managed apps.
//
// It requires the state mirror rather than the full fleet control channel:
// the desired document is delivered as a state mutation and then read from
// disk, so reconciliation is correct even during a spell when the authority is
// unreachable. Config load already refuses to enable apps without state sync.
func (runtime *Runtime) HasAppReconcile() bool {
	return runtime != nil && runtime.appsEnabled && runtime.fleetStateEnabled && runtime.fleetStateRoot != ""
}

func (runtime *Runtime) AppReconcileInterval() time.Duration {
	if !runtime.HasAppReconcile() {
		return 0
	}
	return runtime.appsInterval
}

// ReconcileApps converges the node's installed apps toward the authority's
// desired set and republishes what it observes.
//
// The two-root design is the grant boundary. An app whose declared grants the
// tenant has not accepted is installed into the staging root, which the
// supervisor does not scan — so its binary exists, its manifest can be read and
// reported, and it cannot run. Promotion into the live install root happens
// only once the desired document carries an acceptance covering every grant the
// manifest declares. A catalogue that later widens an app's grants demotes it
// back to staging on the next pass rather than silently gaining capability.
func (runtime *Runtime) ReconcileApps(ctx context.Context, installer AppInstaller) (AppReconcileResult, error) {
	if !runtime.HasAppReconcile() {
		return AppReconcileResult{}, fmt.Errorf("enterprise control: app reconciliation is not configured")
	}
	if installer == nil {
		return AppReconcileResult{}, fmt.Errorf("enterprise control: app installer is required")
	}
	runtime.appsMu.Lock()
	defer runtime.appsMu.Unlock()

	runtime.mu.Lock()
	tenantID, agentID := runtime.tenantID, runtime.rolloutAgentID
	stateRoot, installRoot, stagingRoot := runtime.fleetStateRoot, runtime.appsInstallRoot, runtime.appsStagingRoot
	runtime.mu.Unlock()

	desired, err := readDesiredApps(filepath.Join(stateRoot, authority.FleetAppsDocumentPath), tenantID, agentID)
	if err != nil {
		return AppReconcileResult{}, err
	}
	if err := secureDirectory(installRoot); err != nil {
		return AppReconcileResult{}, fmt.Errorf("enterprise control: app install root: %w", err)
	}
	if err := secureDirectory(stagingRoot); err != nil {
		return AppReconcileResult{}, fmt.Errorf("enterprise control: app staging root: %w", err)
	}

	result := AppReconcileResult{Desired: len(desired.Desired)}
	observed := make([]authority.FleetAppState, 0, len(desired.Desired))
	wanted := make(map[string]struct{}, len(desired.Desired))
	now := time.Now().UTC()

	for _, spec := range desired.Desired {
		wanted[spec.ID] = struct{}{}
		state := runtime.reconcileOneApp(ctx, installer, spec, installRoot, stagingRoot, now)
		switch state.Status {
		case authority.FleetAppInstalled:
			result.Installed++
		case authority.FleetAppGrantBlocked:
			result.Staged++
		case authority.FleetAppFailed:
			result.Failed++
		}
		observed = append(observed, state)
	}

	// Anything this node installed under management but no longer wants is
	// withdrawn from both roots. Apps a local operator installed by hand are
	// deliberately untouched: management adds and removes what it was asked
	// to, and does not assert ownership of the whole install root.
	for _, appID := range managedAppIDs(stagingRoot) {
		if _, keep := wanted[appID]; keep {
			continue
		}
		if err := installer.Remove(ctx, appID, stagingRoot); err == nil {
			result.Removed++
		}
	}
	for _, appID := range previouslyManaged(runtime.appsManaged, wanted) {
		if err := installer.Remove(ctx, appID, installRoot); err == nil {
			result.Removed++
		}
	}
	runtime.appsManaged = wanted

	sort.Slice(observed, func(i, j int) bool { return observed[i].ID < observed[j].ID })
	report := authority.FleetAppsReport{
		Version: authority.FleetAppsVersion, TenantID: tenantID, AgentID: agentID,
		Apps: observed, ObservedAt: now.Unix(),
	}
	if err := writeObservedApps(filepath.Join(stateRoot, authority.FleetAppsReportPath), report); err != nil {
		return result, err
	}
	return result, nil
}

func (runtime *Runtime) reconcileOneApp(ctx context.Context, installer AppInstaller, spec authority.FleetAppSpec, installRoot, stagingRoot string, now time.Time) authority.FleetAppState {
	state := authority.FleetAppState{ID: spec.ID, Version: spec.Version, ObservedAt: now.Unix()}

	live, liveErr := readAppManifest(filepath.Join(installRoot, spec.ID))
	staged, stagedErr := readAppManifest(filepath.Join(stagingRoot, spec.ID))

	// Already live at the right version with an acceptance that still covers
	// what it declares: nothing to do.
	if liveErr == nil && live.AppVersion == spec.Version {
		declared := manifestGrants(live)
		state.DeclaredGrants, state.BinarySHA256 = declared, live.Binary.SHA256
		if authority.GrantsCovered(declared, spec.AcceptedGrants) {
			state.Status = authority.FleetAppInstalled
			return state
		}
		// Acceptance no longer covers the manifest. Demote rather than let a
		// widened grant set keep running.
		if err := installer.Remove(ctx, spec.ID, installRoot); err != nil {
			state.Status, state.Detail = authority.FleetAppFailed, "demote_failed"
			return state
		}
		liveErr, live = fmt.Errorf("demoted"), appmanifest.Manifest{}
	}

	// Ensure a staged copy at the requested version exists so the manifest —
	// the only truthful source of grants — can be read.
	if stagedErr != nil || staged.AppVersion != spec.Version {
		if err := installer.Install(ctx, spec.ID, spec.Version, stagingRoot); err != nil {
			state.Status, state.Detail = authority.FleetAppFailed, "install_failed"
			return state
		}
		staged, stagedErr = readAppManifest(filepath.Join(stagingRoot, spec.ID))
		if stagedErr != nil {
			state.Status, state.Detail = authority.FleetAppFailed, "manifest_unreadable"
			return state
		}
	}

	declared := manifestGrants(staged)
	state.DeclaredGrants, state.BinarySHA256 = declared, staged.Binary.SHA256
	if staged.AppVersion != "" {
		state.Version = staged.AppVersion
	}

	if !authority.GrantsCovered(declared, spec.AcceptedGrants) {
		// Held deliberately: installed, readable, reported, not running.
		state.Status, state.Detail = authority.FleetAppGrantBlocked, "awaiting_grant_acceptance"
		return state
	}

	// Accepted — promote into the supervisor's scan root.
	if err := installer.Install(ctx, spec.ID, spec.Version, installRoot); err != nil {
		state.Status, state.Detail = authority.FleetAppFailed, "promote_failed"
		return state
	}
	if err := installer.Remove(ctx, spec.ID, stagingRoot); err != nil {
		// A leftover staged copy is inert; it must not fail the reconcile.
		state.Detail = "staging_cleanup_deferred"
	}
	state.Status = authority.FleetAppInstalled
	return state
}

func readDesiredApps(path, tenantID, agentID string) (authority.FleetAppsDocument, error) {
	var document authority.FleetAppsDocument
	raw, err := os.ReadFile(path) // #nosec G304 -- path is built from the runtime's own confined state root.
	if os.IsNotExist(err) {
		// No desired set is a valid state meaning "manage no apps here".
		return authority.FleetAppsDocument{Version: authority.FleetAppsVersion, TenantID: tenantID, AgentID: agentID}, nil
	}
	if err != nil {
		return document, fmt.Errorf("enterprise control: read desired apps: %w", err)
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return document, fmt.Errorf("enterprise control: parse desired apps: %w", err)
	}
	if err := document.Validate(); err != nil {
		return authority.FleetAppsDocument{}, err
	}
	// The document arrives inside a signed, revision-fenced mutation, but it
	// then sits on local disk. Re-checking that it still addresses this node
	// costs nothing and refuses a file copied from another machine.
	if document.TenantID != tenantID || document.AgentID != agentID {
		return authority.FleetAppsDocument{}, fmt.Errorf("enterprise control: desired apps document addresses another node")
	}
	return document, nil
}

// writeObservedApps republishes the inventory only when something an operator
// would care about actually changed.
//
// This is not an optimization. The report lives inside the fleet state mirror,
// so every rewrite bumps the node's state revision — and the console fences its
// mutations on that revision. Refreshing a timestamp every reconcile tick would
// invalidate an operator's in-flight install before they could confirm it.
func writeObservedApps(path string, report authority.FleetAppsReport) error {
	if err := report.Validate(); err != nil {
		return err
	}
	if existing, err := os.ReadFile(path); err == nil { // #nosec G304 -- confined state root.
		var previous authority.FleetAppsReport
		if json.Unmarshal(existing, &previous) == nil && sameObservedApps(previous, report) {
			return nil
		}
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteSecureBytes(path, append(encoded, '\n'))
}

// sameObservedApps compares two inventories ignoring observation timestamps,
// which advance on every tick regardless of whether anything happened.
func sameObservedApps(previous, current authority.FleetAppsReport) bool {
	if previous.Version != current.Version || previous.TenantID != current.TenantID ||
		previous.AgentID != current.AgentID || len(previous.Apps) != len(current.Apps) {
		return false
	}
	for index := range current.Apps {
		before, after := previous.Apps[index], current.Apps[index]
		if before.ID != after.ID || before.Version != after.Version || before.Status != after.Status ||
			before.Detail != after.Detail || before.BinarySHA256 != after.BinarySHA256 ||
			len(before.DeclaredGrants) != len(after.DeclaredGrants) {
			return false
		}
		for grantIndex := range after.DeclaredGrants {
			if before.DeclaredGrants[grantIndex] != after.DeclaredGrants[grantIndex] {
				return false
			}
		}
	}
	return true
}

func readAppManifest(directory string) (appmanifest.Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(directory, "manifest.json")) // #nosec G304 -- directory is confined to a managed app root.
	if err != nil {
		return appmanifest.Manifest{}, err
	}
	parsed, err := appmanifest.Parse(raw)
	if err != nil {
		return appmanifest.Manifest{}, err
	}
	if errs := parsed.Validate(); len(errs) > 0 {
		return appmanifest.Manifest{}, fmt.Errorf("manifest validation: %v", errs[0])
	}
	return *parsed, nil
}

func manifestGrants(parsed appmanifest.Manifest) []authority.FleetAppGrant {
	grants := make([]authority.FleetAppGrant, 0, len(parsed.Grants))
	for _, grant := range parsed.Grants {
		grants = append(grants, authority.FleetAppGrant{Cap: grant.Cap, Target: grant.Target})
	}
	sort.Slice(grants, func(i, j int) bool {
		if grants[i].Cap != grants[j].Cap {
			return grants[i].Cap < grants[j].Cap
		}
		return grants[i].Target < grants[j].Target
	})
	return grants
}

// managedAppIDs lists app directories under a root the runtime fully owns.
func managedAppIDs(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			ids = append(ids, entry.Name())
		}
	}
	sort.Strings(ids)
	return ids
}

// previouslyManaged returns the apps this runtime installed on an earlier pass
// that the authority no longer wants. Tracking what management placed is what
// keeps an operator's hand-installed apps out of scope for removal.
func previouslyManaged(managed map[string]struct{}, wanted map[string]struct{}) []string {
	stale := make([]string, 0, len(managed))
	for appID := range managed {
		if _, keep := wanted[appID]; !keep {
			stale = append(stale, appID)
		}
	}
	sort.Strings(stale)
	return stale
}

// withinDirectory reports whether candidate sits inside parent. It is used to
// keep the staging root outside the supervisor's scan root, so the guard has
// to resist a relative path that climbs back in.
func withinDirectory(parent, candidate string) bool {
	absParent, parentErr := filepath.Abs(parent)
	absCandidate, candidateErr := filepath.Abs(candidate)
	if parentErr != nil || candidateErr != nil {
		return false
	}
	relative, err := filepath.Rel(absParent, absCandidate)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

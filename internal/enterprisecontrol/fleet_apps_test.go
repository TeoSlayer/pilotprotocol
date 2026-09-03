// SPDX-License-Identifier: AGPL-3.0-or-later

package enterprisecontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
)

// fakeInstaller stands in for the pilotctl subprocess. It plants a manifest
// declaring whatever grants the test wants, which is the only thing the
// reconciler reads out of an installed bundle.
type fakeInstaller struct {
	grants     map[string][]authority.FleetAppGrant
	version    map[string]string
	failFor    map[string]bool
	installLog []string
	removeLog  []string
}

func newFakeInstaller() *fakeInstaller {
	return &fakeInstaller{
		grants:  map[string][]authority.FleetAppGrant{},
		version: map[string]string{},
		failFor: map[string]bool{},
	}
}

func (installer *fakeInstaller) Install(_ context.Context, appID, version, root string) error {
	installer.installLog = append(installer.installLog, appID+"@"+version+"->"+filepath.Base(root))
	if installer.failFor[appID] {
		return fmt.Errorf("simulated install failure")
	}
	if planted, ok := installer.version[appID]; ok {
		version = planted
	}
	directory := filepath.Join(root, appID)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	grants := make([]map[string]string, 0, len(installer.grants[appID]))
	for _, grant := range installer.grants[appID] {
		grants = append(grants, map[string]string{"cap": grant.Cap, "target": grant.Target})
	}
	manifest := map[string]any{
		"manifest_version": 1,
		"id":               appID,
		"app_version":      version,
		"name":             "Test App",
		"description":      "A test app used by the reconciler unit tests.",
		"binary":           map[string]string{"runtime": "go", "path": "app", "sha256": "aa" + repeat("0", 62)},
		"grants":           grants,
		"store":            map[string]string{"publisher": "ed25519:" + repeat("A", 44), "signature": repeat("B", 64)},
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), encoded, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, "app"), []byte("#!/bin/sh\n"), 0o700)
}

func (installer *fakeInstaller) Remove(_ context.Context, appID, root string) error {
	installer.removeLog = append(installer.removeLog, appID+"<-"+filepath.Base(root))
	return os.RemoveAll(filepath.Join(root, appID))
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func newAppsTestRuntime(t *testing.T) (*Runtime, string, string, string) {
	t.Helper()
	base := t.TempDir()
	stateRoot := filepath.Join(base, "state")
	installRoot := filepath.Join(base, "apps")
	stagingRoot := filepath.Join(base, "apps-pending")
	for _, directory := range []string{stateRoot, installRoot, stagingRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	runtime := &Runtime{
		tenantID: "tenant-a", rolloutAgentID: "agent-a",
		fleetStateEnabled: true, fleetStateRoot: stateRoot,
		appsEnabled: true, appsInstallRoot: installRoot, appsStagingRoot: stagingRoot,
		appsInterval: 30 * time.Second, appsManaged: map[string]struct{}{},
	}
	return runtime, stateRoot, installRoot, stagingRoot
}

func writeDesired(t *testing.T, stateRoot string, specs ...authority.FleetAppSpec) {
	t.Helper()
	document := authority.FleetAppsDocument{
		Version: authority.FleetAppsVersion, TenantID: "tenant-a", AgentID: "agent-a",
		Desired: specs, Reason: "unit test desired set", IssuedAt: time.Now().Unix(),
	}
	document.Normalize()
	if err := document.Validate(); err != nil {
		t.Fatalf("desired document invalid: %v", err)
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateRoot, authority.FleetAppsDocumentPath), append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readObserved(t *testing.T, stateRoot string) map[string]authority.FleetAppState {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(stateRoot, authority.FleetAppsReportPath))
	if err != nil {
		t.Fatalf("read observed report: %v", err)
	}
	var report authority.FleetAppsReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("observed report invalid: %v", err)
	}
	states := make(map[string]authority.FleetAppState, len(report.Apps))
	for _, state := range report.Apps {
		states[state.ID] = state
	}
	return states
}

// An app the tenant has not reviewed must land in staging, never in the
// supervisor's scan root. This is the whole grant boundary.
func TestReconcileHoldsUnreviewedAppOutOfInstallRoot(t *testing.T) {
	runtime, stateRoot, installRoot, stagingRoot := newAppsTestRuntime(t)
	installer := newFakeInstaller()
	installer.grants["io.pilot.duckdb"] = []authority.FleetAppGrant{{Cap: "fs.read", Target: "$APP/*"}}

	writeDesired(t, stateRoot, authority.FleetAppSpec{
		ID: "io.pilot.duckdb", Version: "1.5.4", ApprovedBy: "operator", ApprovedAt: time.Now().Unix(),
	})

	result, err := runtime.ReconcileApps(context.Background(), installer)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if result.Staged != 1 || result.Installed != 0 {
		t.Fatalf("expected one staged and none installed, got %+v", result)
	}
	if _, err := os.Stat(filepath.Join(installRoot, "io.pilot.duckdb")); !os.IsNotExist(err) {
		t.Fatal("unreviewed app reached the supervisor's install root")
	}
	if _, err := os.Stat(filepath.Join(stagingRoot, "io.pilot.duckdb")); err != nil {
		t.Fatalf("expected staged copy: %v", err)
	}
	state := readObserved(t, stateRoot)["io.pilot.duckdb"]
	if state.Status != authority.FleetAppGrantBlocked {
		t.Fatalf("status = %q, want %q", state.Status, authority.FleetAppGrantBlocked)
	}
	// The report must carry the grants so the console can show them.
	if len(state.DeclaredGrants) != 1 || state.DeclaredGrants[0].Cap != "fs.read" {
		t.Fatalf("declared grants not reported: %+v", state.DeclaredGrants)
	}
}

// Once the desired document accepts exactly what the manifest declares, the
// app is promoted into the install root and the staged copy is cleaned up.
func TestReconcilePromotesAppOnceGrantsAccepted(t *testing.T) {
	runtime, stateRoot, installRoot, stagingRoot := newAppsTestRuntime(t)
	installer := newFakeInstaller()
	grants := []authority.FleetAppGrant{{Cap: "fs.read", Target: "$APP/*"}, {Cap: "audit.log", Target: "*"}}
	installer.grants["io.pilot.duckdb"] = grants

	writeDesired(t, stateRoot, authority.FleetAppSpec{
		ID: "io.pilot.duckdb", Version: "1.5.4", AcceptedGrants: grants,
		ApprovedBy: "operator", ApprovedAt: time.Now().Unix(),
	})

	result, err := runtime.ReconcileApps(context.Background(), installer)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if result.Installed != 1 || result.Staged != 0 {
		t.Fatalf("expected one installed, got %+v", result)
	}
	if _, err := os.Stat(filepath.Join(installRoot, "io.pilot.duckdb")); err != nil {
		t.Fatalf("accepted app missing from install root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stagingRoot, "io.pilot.duckdb")); !os.IsNotExist(err) {
		t.Fatal("staged copy was not cleaned up after promotion")
	}
	if state := readObserved(t, stateRoot)["io.pilot.duckdb"]; state.Status != authority.FleetAppInstalled {
		t.Fatalf("status = %q, want installed", state.Status)
	}
}

// A partial acceptance must not promote. Covering one of two declared grants
// is not covering the manifest.
func TestReconcileRefusesPartialGrantAcceptance(t *testing.T) {
	runtime, stateRoot, installRoot, _ := newAppsTestRuntime(t)
	installer := newFakeInstaller()
	installer.grants["io.pilot.duckdb"] = []authority.FleetAppGrant{
		{Cap: "fs.read", Target: "$APP/*"},
		{Cap: "net.dial", Target: "api.example.com"},
	}

	writeDesired(t, stateRoot, authority.FleetAppSpec{
		ID: "io.pilot.duckdb", Version: "1.5.4",
		AcceptedGrants: []authority.FleetAppGrant{{Cap: "fs.read", Target: "$APP/*"}},
		ApprovedBy:     "operator", ApprovedAt: time.Now().Unix(),
	})

	if _, err := runtime.ReconcileApps(context.Background(), installer); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(installRoot, "io.pilot.duckdb")); !os.IsNotExist(err) {
		t.Fatal("app with an uncovered grant was promoted")
	}
	if state := readObserved(t, stateRoot)["io.pilot.duckdb"]; state.Status != authority.FleetAppGrantBlocked {
		t.Fatalf("status = %q, want grant_blocked", state.Status)
	}
}

// If a catalogue republish widens an app's grants, a node that already runs it
// must demote it rather than keep running the wider capability set.
func TestReconcileDemotesAppWhenGrantsWiden(t *testing.T) {
	runtime, stateRoot, installRoot, stagingRoot := newAppsTestRuntime(t)
	installer := newFakeInstaller()
	original := []authority.FleetAppGrant{{Cap: "fs.read", Target: "$APP/*"}}
	installer.grants["io.pilot.duckdb"] = original

	spec := authority.FleetAppSpec{
		ID: "io.pilot.duckdb", Version: "1.5.4", AcceptedGrants: original,
		ApprovedBy: "operator", ApprovedAt: time.Now().Unix(),
	}
	writeDesired(t, stateRoot, spec)
	if _, err := runtime.ReconcileApps(context.Background(), installer); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(installRoot, "io.pilot.duckdb")); err != nil {
		t.Fatalf("expected app installed after first pass: %v", err)
	}

	// The app is republished asking for more than was accepted.
	installer.grants["io.pilot.duckdb"] = append(original, authority.FleetAppGrant{Cap: "proc.exec", Target: "/bin/sh"})
	if err := installer.Install(context.Background(), "io.pilot.duckdb", "1.5.4", installRoot); err != nil {
		t.Fatal(err)
	}

	if _, err := runtime.ReconcileApps(context.Background(), installer); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(installRoot, "io.pilot.duckdb")); !os.IsNotExist(err) {
		t.Fatal("app with widened grants stayed in the install root")
	}
	if _, err := os.Stat(filepath.Join(stagingRoot, "io.pilot.duckdb")); err != nil {
		t.Fatalf("demoted app should be staged for review: %v", err)
	}
	if state := readObserved(t, stateRoot)["io.pilot.duckdb"]; state.Status != authority.FleetAppGrantBlocked {
		t.Fatalf("status = %q, want grant_blocked", state.Status)
	}
}

// Dropping an app from the desired set withdraws it from the node.
func TestReconcileRemovesAppDroppedFromDesiredSet(t *testing.T) {
	runtime, stateRoot, installRoot, stagingRoot := newAppsTestRuntime(t)
	installer := newFakeInstaller()
	grants := []authority.FleetAppGrant{{Cap: "audit.log", Target: "*"}}
	installer.grants["io.pilot.duckdb"] = grants

	writeDesired(t, stateRoot, authority.FleetAppSpec{
		ID: "io.pilot.duckdb", Version: "1.5.4", AcceptedGrants: grants,
		ApprovedBy: "operator", ApprovedAt: time.Now().Unix(),
	})
	if _, err := runtime.ReconcileApps(context.Background(), installer); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	writeDesired(t, stateRoot)
	result, err := runtime.ReconcileApps(context.Background(), installer)
	if err != nil {
		t.Fatalf("removal pass: %v", err)
	}
	if result.Removed != 1 {
		t.Fatalf("expected one removal, got %+v", result)
	}
	for _, root := range []string{installRoot, stagingRoot} {
		if _, err := os.Stat(filepath.Join(root, "io.pilot.duckdb")); !os.IsNotExist(err) {
			t.Fatalf("app still present under %s", root)
		}
	}
}

// An app a local operator installed by hand is not management's to remove.
func TestReconcileLeavesUnmanagedAppsAlone(t *testing.T) {
	runtime, stateRoot, installRoot, _ := newAppsTestRuntime(t)
	installer := newFakeInstaller()
	if err := installer.Install(context.Background(), "io.pilot.handrolled", "0.1.0", installRoot); err != nil {
		t.Fatal(err)
	}
	writeDesired(t, stateRoot)

	if _, err := runtime.ReconcileApps(context.Background(), installer); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(installRoot, "io.pilot.handrolled")); err != nil {
		t.Fatalf("hand-installed app was removed by management: %v", err)
	}
}

// A desired document addressed to another node must be refused even though it
// arrived through a signed channel — the file also sits on local disk.
func TestReconcileRefusesDocumentForAnotherNode(t *testing.T) {
	runtime, stateRoot, _, _ := newAppsTestRuntime(t)
	document := authority.FleetAppsDocument{
		Version: authority.FleetAppsVersion, TenantID: "tenant-a", AgentID: "agent-elsewhere",
		Reason: "document copied from another machine", IssuedAt: time.Now().Unix(),
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateRoot, authority.FleetAppsDocumentPath), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.ReconcileApps(context.Background(), newFakeInstaller()); err == nil {
		t.Fatal("expected a document addressed to another node to be refused")
	}
}

// A missing desired document means "manage no apps here", not an error.
func TestReconcileTreatsMissingDocumentAsEmptyDesiredSet(t *testing.T) {
	runtime, stateRoot, _, _ := newAppsTestRuntime(t)
	result, err := runtime.ReconcileApps(context.Background(), newFakeInstaller())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if result.Desired != 0 {
		t.Fatalf("expected empty desired set, got %+v", result)
	}
	if _, err := os.Stat(filepath.Join(stateRoot, authority.FleetAppsReportPath)); err != nil {
		t.Fatalf("an empty reconcile must still publish an inventory: %v", err)
	}
}

// A failing install is reported, not fatal, and must not leave the app in the
// install root.
func TestReconcileReportsInstallFailure(t *testing.T) {
	runtime, stateRoot, installRoot, _ := newAppsTestRuntime(t)
	installer := newFakeInstaller()
	installer.failFor["io.pilot.duckdb"] = true

	writeDesired(t, stateRoot, authority.FleetAppSpec{
		ID: "io.pilot.duckdb", Version: "1.5.4", ApprovedBy: "operator", ApprovedAt: time.Now().Unix(),
	})
	result, err := runtime.ReconcileApps(context.Background(), installer)
	if err != nil {
		t.Fatalf("a failing app must not fail the whole reconcile: %v", err)
	}
	if result.Failed != 1 {
		t.Fatalf("expected one failure, got %+v", result)
	}
	if _, err := os.Stat(filepath.Join(installRoot, "io.pilot.duckdb")); !os.IsNotExist(err) {
		t.Fatal("failed install left an app in the install root")
	}
	if state := readObserved(t, stateRoot)["io.pilot.duckdb"]; state.Status != authority.FleetAppFailed {
		t.Fatalf("status = %q, want failed", state.Status)
	}
}

func TestWithinDirectoryRejectsNestedStagingRoot(t *testing.T) {
	if !withinDirectory("/var/pilot/apps", "/var/pilot/apps/pending") {
		t.Fatal("nested staging root should be detected")
	}
	if withinDirectory("/var/pilot/apps", "/var/pilot/apps-pending") {
		t.Fatal("sibling staging root must not be treated as nested")
	}
	if withinDirectory("/var/pilot/apps", "/var/pilot") {
		t.Fatal("parent directory must not be treated as nested")
	}
}

// The inventory must not be rewritten when nothing changed. Every rewrite
// bumps the state revision the console fences its mutations on, so a ticking
// timestamp would invalidate an operator's in-flight install.
func TestReconcileDoesNotRewriteUnchangedInventory(t *testing.T) {
	runtime, stateRoot, _, _ := newAppsTestRuntime(t)
	installer := newFakeInstaller()
	grants := []authority.FleetAppGrant{{Cap: "audit.log", Target: "*"}}
	installer.grants["io.pilot.duckdb"] = grants
	writeDesired(t, stateRoot, authority.FleetAppSpec{
		ID: "io.pilot.duckdb", Version: "1.5.4", AcceptedGrants: grants,
		ApprovedBy: "operator", ApprovedAt: time.Now().Unix(),
	})

	if _, err := runtime.ReconcileApps(context.Background(), installer); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	reportPath := filepath.Join(stateRoot, authority.FleetAppsReportPath)
	first, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}

	// A later pass with identical results must leave the bytes untouched even
	// though wall-clock time has advanced.
	time.Sleep(1100 * time.Millisecond)
	if _, err := runtime.ReconcileApps(context.Background(), installer); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	second, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("unchanged inventory was rewritten, which would churn the state revision")
	}
}

// A real change must still be published.
func TestReconcileRepublishesInventoryOnChange(t *testing.T) {
	runtime, stateRoot, _, _ := newAppsTestRuntime(t)
	installer := newFakeInstaller()
	installer.grants["io.pilot.duckdb"] = []authority.FleetAppGrant{{Cap: "audit.log", Target: "*"}}
	writeDesired(t, stateRoot, authority.FleetAppSpec{
		ID: "io.pilot.duckdb", Version: "1.5.4", ApprovedBy: "operator", ApprovedAt: time.Now().Unix(),
	})
	if _, err := runtime.ReconcileApps(context.Background(), installer); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if status := readObserved(t, stateRoot)["io.pilot.duckdb"].Status; status != authority.FleetAppGrantBlocked {
		t.Fatalf("expected grant_blocked, got %q", status)
	}

	// Accept the grants; the inventory must now report installed.
	writeDesired(t, stateRoot, authority.FleetAppSpec{
		ID: "io.pilot.duckdb", Version: "1.5.4",
		AcceptedGrants: []authority.FleetAppGrant{{Cap: "audit.log", Target: "*"}},
		ApprovedBy:     "operator", ApprovedAt: time.Now().Unix(),
	})
	if _, err := runtime.ReconcileApps(context.Background(), installer); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if status := readObserved(t, stateRoot)["io.pilot.duckdb"].Status; status != authority.FleetAppInstalled {
		t.Fatalf("expected installed after acceptance, got %q", status)
	}
}

// Cross-repo invariant: the console writes these paths through the state
// mutation channel, so the node's own protected-path guard must not refuse
// them. If someone renames a document to include "policy" or "trust", installs
// silently stop working.
func TestAppDocumentPathsAreNotProtected(t *testing.T) {
	for _, path := range []string{authority.FleetAppsDocumentPath, authority.FleetAppsReportPath} {
		if fleetMutationPathProtected(path) {
			t.Fatalf("%q is refused by the node's protected-path guard", path)
		}
	}
}

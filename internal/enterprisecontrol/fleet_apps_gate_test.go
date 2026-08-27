// SPDX-License-Identifier: AGPL-3.0-or-later

package enterprisecontrol

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
)

// HasAppReconcile is the gate that decides whether a managed node ever acts on
// the App Store's desired document. It shipped defaulting to false with nothing
// in the adoption path able to turn it on, so the console queued installs that
// no node would ever perform. These cases pin the contract adoption must
// satisfy, including the fleet-state dependency: both the desired document and
// the observed report travel as fleet state, so apps without it would accept
// the option and then silently never reconcile.
func TestHasAppReconcileRequiresAppsAndFleetState(t *testing.T) {
	for _, testCase := range []struct {
		name             string
		apps, fleetState bool
		stateRoot        string
		want             bool
	}{
		{name: "apps and fleet state", apps: true, fleetState: true, stateRoot: "/tmp/state", want: true},
		{name: "apps without fleet state", apps: true, fleetState: false, stateRoot: "/tmp/state", want: false},
		{name: "apps with no state root", apps: true, fleetState: true, stateRoot: "", want: false},
		{name: "fleet state without apps", apps: false, fleetState: true, stateRoot: "/tmp/state", want: false},
		{name: "neither", apps: false, fleetState: false, stateRoot: "", want: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			runtime := &Runtime{appsEnabled: testCase.apps, fleetStateEnabled: testCase.fleetState, fleetStateRoot: testCase.stateRoot}
			if got := runtime.HasAppReconcile(); got != testCase.want {
				t.Fatalf("HasAppReconcile()=%v want %v", got, testCase.want)
			}
		})
	}
	// A nil runtime must not panic the daemon's startup check.
	var absent *Runtime
	if absent.HasAppReconcile() {
		t.Fatal("nil runtime reported app reconcile")
	}
}

// An enabled reconciler with a zero interval would spin as fast as the loop
// allows, so the interval must always be positive once the gate is open.
func TestAppReconcileIntervalIsPositiveWhenEnabled(t *testing.T) {
	runtime := &Runtime{appsEnabled: true, fleetStateEnabled: true, fleetStateRoot: "/tmp/state", appsInterval: 30_000_000_000}
	if runtime.AppReconcileInterval() <= 0 {
		t.Fatal("enabled reconciler reported a non-positive interval")
	}
	disabled := &Runtime{}
	if disabled.AppReconcileInterval() != 0 {
		t.Fatal("disabled reconciler reported an interval")
	}
}

// recordingInstaller captures the arguments the reconciler would run.
type recordingInstaller struct {
	installs []string
	fail     error
}

func (installer *recordingInstaller) Install(_ context.Context, appID, version, root string) error {
	installer.installs = append(installer.installs, appID+"@"+version)
	return installer.fail
}

func (installer *recordingInstaller) Remove(context.Context, string, string) error { return nil }

// The desired document pins the version the operator approved. It must reach
// the installer, or the node silently installs whatever the catalogue happens
// to carry at reconcile time -- software nobody approved.
func TestReconcilePassesTheApprovedVersionToTheInstaller(t *testing.T) {
	installer := &recordingInstaller{fail: errors.New("install refused")}
	runtime := &Runtime{appsEnabled: true, fleetStateEnabled: true, fleetStateRoot: t.TempDir()}
	state := runtime.reconcileOneApp(
		context.Background(), installer,
		authority.FleetAppSpec{ID: "io.pilot.example", Version: "1.2.3"},
		filepath.Join(t.TempDir(), "apps"), filepath.Join(t.TempDir(), "pending"),
		time.Now(),
	)
	if len(installer.installs) == 0 {
		t.Fatal("reconcile never attempted an install")
	}
	if installer.installs[0] != "io.pilot.example@1.2.3" {
		t.Fatalf("installer received %q, losing the approved version pin", installer.installs[0])
	}
	if state.Status != authority.FleetAppFailed {
		t.Fatalf("a refused install must report failed, got %q", state.Status)
	}
}

// A freshly adopted node has neither app root on disk: the supervisor creates
// the install root only when it starts with apps already present, and nothing
// creates the staging root at all. Reconcile therefore has to create both, or
// it fails on every tick forever and no app can ever be installed. Found by
// running the real end-to-end install against a newly adopted node.
func TestReconcileCreatesBothAppRootsOnAFreshNode(t *testing.T) {
	home := t.TempDir()
	installRoot := filepath.Join(home, ".pilot", "apps")
	stagingRoot := filepath.Join(home, ".pilot", "apps-pending")

	for _, root := range []string{installRoot, stagingRoot} {
		if _, err := os.Stat(root); !os.IsNotExist(err) {
			t.Fatalf("precondition: %s already exists", root)
		}
		if err := ensureSecureDirectory(root); err != nil {
			t.Fatalf("ensureSecureDirectory(%s): %v", root, err)
		}
		info, err := os.Stat(root)
		if err != nil {
			t.Fatalf("%s was not created: %v", root, err)
		}
		if !info.IsDir() {
			t.Fatalf("%s is not a directory", root)
		}
		// secureDirectory rejects group- or world-writable roots, so creation
		// must not hand back something it will then refuse.
		if info.Mode().Perm()&0o022 != 0 {
			t.Fatalf("%s created group/world writable: %v", root, info.Mode().Perm())
		}
		// Idempotent: a second reconcile tick must not fail.
		if err := ensureSecureDirectory(root); err != nil {
			t.Fatalf("second call on %s failed: %v", root, err)
		}
	}
}

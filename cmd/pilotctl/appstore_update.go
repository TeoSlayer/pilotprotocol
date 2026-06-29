package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pilot-protocol/app-store/pkg/manifest"
)

// installedApp is one app present in the install root, identified by the
// authoritative on-disk record: its manifest's id + app_version.
type installedApp struct {
	ID         string
	AppVersion string
}

// scanInstalledApps reads the install root and returns each installed app's id
// and version straight from its manifest.json (the version of record). Apps with
// an unreadable/invalid manifest are skipped — they surface as broken in `list`.
func scanInstalledApps() ([]installedApp, error) {
	root := appStoreRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var apps []installedApp
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, e.Name(), "manifest.json"))
		if err != nil {
			continue
		}
		m, err := manifest.Parse(raw)
		if err != nil {
			continue
		}
		apps = append(apps, installedApp{ID: m.ID, AppVersion: m.AppVersion})
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].ID < apps[j].ID })
	return apps, nil
}

// outdatedApp pairs an installed app with the newer version the catalogue offers.
type outdatedApp struct {
	ID        string `json:"id"`
	Installed string `json:"installed"`
	Available string `json:"available"`
}

// findOutdated cross-references installed apps against the signed catalogue and
// returns those whose catalogue version is strictly newer than what's installed.
// This is the missing client link: install records a version, the catalogue
// advertises one, but nothing compared them until now.
func findOutdated() ([]outdatedApp, error) {
	installed, err := scanInstalledApps()
	if err != nil {
		return nil, err
	}
	cat, err := loadCatalogue()
	if err != nil {
		return nil, err
	}
	latest := make(map[string]string, len(cat.Apps))
	for _, e := range cat.Apps {
		latest[e.ID] = e.Version
	}
	var out []outdatedApp
	for _, a := range installed {
		if v, ok := latest[a.ID]; ok && semverCompare(v, a.AppVersion) > 0 {
			out = append(out, outdatedApp{ID: a.ID, Installed: a.AppVersion, Available: v})
		}
	}
	return out, nil
}

// cmdAppStoreOutdated lists installed apps that have a newer version in the
// catalogue. Exit status is 0 even when some are outdated (it's a report); the
// JSON form is stable for scripting an auto-upgrade.
func cmdAppStoreOutdated(_ []string) {
	out, err := findOutdated()
	if err != nil {
		fatalHint("io_error", "is the install root present and the catalogue reachable?", "outdated: %v", err)
	}
	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(out)
		return
	}
	if len(out) == 0 {
		fmt.Println("all installed apps are up to date")
		return
	}
	fmt.Printf("%-32s %-12s %-12s\n", "APP", "INSTALLED", "AVAILABLE")
	for _, o := range out {
		fmt.Printf("%-32s %-12s %-12s\n", o.ID, o.Installed, o.Available)
	}
	fmt.Printf("\nupgrade with: pilotctl appstore upgrade <id>   (or --all)\n")
}

// cmdAppStoreUpgrade upgrades one app (or --all outdated apps) to the catalogue's
// current version by re-running the same verified install with --force. The
// supervisor detects the on-disk version bump on its next rescan, refuses any
// downgrade, and restarts the app at the new version. Reusing install means the
// upgrade goes through the exact catalogue-sha + manifest-sha + trust-anchor
// checks a fresh install does — no second, weaker code path.
func cmdAppStoreUpgrade(args []string) {
	all := false
	var id string
	for _, a := range args {
		switch a {
		case "--all":
			all = true
		case "-h", "--help":
			fmt.Fprintln(os.Stderr, "usage: pilotctl appstore upgrade <id> | --all")
			return
		default:
			id = a
		}
	}
	if !all && id == "" {
		fatalHint("invalid_argument", "usage: pilotctl appstore upgrade <id> | --all", "missing app id (or --all)")
	}

	outdated, err := findOutdated()
	if err != nil {
		fatalHint("io_error", "is the install root present and the catalogue reachable?", "upgrade: %v", err)
	}
	byID := make(map[string]outdatedApp, len(outdated))
	for _, o := range outdated {
		byID[o.ID] = o
	}

	var targets []outdatedApp
	if all {
		targets = outdated
		if len(targets) == 0 {
			fmt.Println("all installed apps are up to date")
			return
		}
	} else {
		o, ok := byID[id]
		if !ok {
			// Either not installed, not in the catalogue, or already current.
			fmt.Printf("%s is already up to date (or not a catalogue app)\n", id)
			return
		}
		targets = []outdatedApp{o}
	}

	for _, o := range targets {
		fmt.Printf("==> upgrading %s %s → %s\n", o.ID, o.Installed, o.Available)
		// --force: install over the existing app dir; the supervisor applies the
		// version bump (and refuses a downgrade) on its next rescan.
		cmdAppStoreInstall([]string{o.ID, "--force"})
	}
	fmt.Printf("\nupgraded %s\n", strings.TrimSpace(pluralApps(len(targets))))
}

func pluralApps(n int) string {
	if n == 1 {
		return "1 app"
	}
	return fmt.Sprintf("%d apps", n)
}

// semverCompare compares two MAJOR.MINOR.PATCH versions, ignoring any
// prerelease/build suffix beyond the numeric core. Returns -1, 0, or 1. A
// missing component counts as 0 (so "1.2" == "1.2.0").
func semverCompare(a, b string) int {
	ap := semverParts(a)
	bp := semverParts(b)
	for i := 0; i < 3; i++ {
		if ap[i] != bp[i] {
			if ap[i] < bp[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func semverParts(v string) [3]int {
	core := v
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	var out [3]int
	for i, s := range strings.SplitN(core, ".", 3) {
		if i > 2 {
			break
		}
		n := 0
		for _, c := range s {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		out[i] = n
	}
	return out
}

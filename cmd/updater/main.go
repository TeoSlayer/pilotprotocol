// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pilot-protocol/updater"
)

var version = "dev"

// defaultStatePath returns the auto-update control file, matching pilotctl's
// ~/.pilot/auto-update.json so `pilotctl update enable/disable` and this loop
// share one source of truth. Empty if the home dir can't be resolved (the
// updater then treats auto-update as disabled — opt-in).
func defaultStatePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return home + "/.pilot/auto-update.json"
}

// envBool reports whether the named environment variable is set to a truthy
// value ("1", "true", "yes", case-insensitive). Used as the default for
// --skip-attestation so the opt-out can be set without a CLI flag.
func envBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func main() {
	installDir := flag.String("install-dir", "", "directory containing pilot binaries (required)")
	repo := flag.String("repo", "pilot-protocol/pilotprotocol", "GitHub owner/repo for releases")
	pin := flag.String("pin", "", "pin to a specific release tag (e.g. v1.10.5); empty = follow latest")
	interval := flag.Duration("interval", 1*time.Hour, "check interval")
	logLevel := flag.String("log-level", "info", "log level (debug, info, warn, error)")
	logFormat := flag.String("log-format", "text", "log format (text, json)")
	showVersion := flag.Bool("version", false, "print version and exit")
	statePath := flag.String("state-path", defaultStatePath(), "JSON control file {\"enabled\":bool} for automatic updates; auto-update is OFF until enabled (e.g. via `pilotctl update enable`)")
	// --skip-attestation opts out of SLSA provenance verification of
	// checksums.txt. Verification is performed in-process via sigstore-go (no
	// `gh` CLI or external tooling required) and fails CLOSED if provenance
	// cannot be established. This flag exists only for test/air-gapped
	// environments; leave it off in production. Default false: verification
	// stays on. Mirrors the --state-path pattern with an env fallback.
	skipAttestation := flag.Bool("skip-attestation", envBool("PILOT_UPDATER_SKIP_ATTESTATION"),
		"skip SLSA attestation verification (default off); for test/air-gapped use only — production verifies in-process, no `gh` needed")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	if *installDir == "" {
		fmt.Fprintln(os.Stderr, "error: --install-dir is required")
		os.Exit(2)
	}

	setupLogging(*logLevel, *logFormat)

	u := updater.New(updater.Config{
		CheckInterval:   *interval,
		Repo:            *repo,
		InstallDir:      *installDir,
		Version:         version,
		PinnedVersion:   *pin,
		StatePath:       *statePath,
		SkipAttestation: *skipAttestation,
	})

	u.Start()
	slog.Info("updater started",
		"install_dir", *installDir,
		"repo", *repo,
		"interval", interval.String(),
	)

	// Keep the installed app ADAPTERS current too, not just the pilot binaries.
	// On the same cadence and behind the same enable switch as binary updates,
	// run `pilotctl appstore upgrade --all` so a new app version OR a same-version
	// republish (see recordInstalledBundleSHA / outdated "rebuilt") reaches the
	// fleet without anyone running upgrade by hand. Each upgrade re-runs the full
	// catalogue-signature + manifest-signature + trust-anchor gate that install
	// does, so this adds automation, not trust. Opt out with
	// PILOT_UPDATER_NO_APP_UPGRADE for hosts that want binary-only updates.
	if !envBool("PILOT_UPDATER_NO_APP_UPGRADE") {
		go appUpgradeLoop(*installDir, *statePath, *interval)
		slog.Info("app auto-upgrade loop started", "interval", interval.String())
	}
	if *pin != "" {
		slog.Info("version pinned", "tag", *pin)
	}
	if *skipAttestation {
		slog.Warn("SLSA attestation verification disabled (--skip-attestation); update provenance will NOT be checked")
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	slog.Info("shutting down")
	u.Stop()
}

func setupLogging(level, format string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if format == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(h))
}

// autoUpdateEnabled reports whether automatic updates are switched on, reading
// the same {"enabled":bool} control file pilotctl writes (`pilotctl update
// enable`). Absent/unreadable/malformed → off, matching the "OFF by default"
// contract the updater library applies to binary updates.
func autoUpdateEnabled(statePath string) bool {
	if statePath == "" {
		return false
	}
	b, err := os.ReadFile(statePath) // #nosec G304 -- operator-provided control path, same file pilotctl manages
	if err != nil {
		return false
	}
	var s struct {
		Enabled bool `json:"enabled"`
	}
	if json.Unmarshal(b, &s) != nil {
		return false
	}
	return s.Enabled
}

// appUpgradeLoop periodically runs `pilotctl appstore upgrade --all` while
// auto-update is enabled. First run is after one interval (not at boot), so a
// freshly-started updater doesn't immediately churn apps.
func appUpgradeLoop(installDir, statePath string, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		if !autoUpdateEnabled(statePath) {
			continue
		}
		runAppUpgrade(installDir)
	}
}

// runAppUpgrade execs the co-located pilotctl to upgrade any outdated app. It is
// idempotent — when nothing is outdated `upgrade --all` is a no-op — and bounded
// so a hung download can't wedge the loop.
func runAppUpgrade(installDir string) {
	bin := filepath.Join(installDir, "pilotctl")
	if _, err := os.Stat(bin); err != nil {
		return // no pilotctl beside us; nothing to drive the upgrade
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "appstore", "upgrade", "--all").CombinedOutput() // #nosec G204 -- fixed argv, bin is the co-located pilotctl
	trimmed := strings.TrimSpace(string(out))
	if err != nil {
		slog.Warn("app auto-upgrade run failed", "err", err, "output", trimmed)
		return
	}
	slog.Info("app auto-upgrade complete", "output", trimmed)
}

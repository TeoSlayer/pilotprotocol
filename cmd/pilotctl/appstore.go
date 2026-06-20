// SPDX-License-Identifier: AGPL-3.0-or-later
//
// pilotctl appstore — list installed apps and call their IPC methods.
//
// The daemon's app-store plugin spawns each installed app under
// ~/.pilot/apps/<id>/ with its own unix-domain socket at
// <install_root>/<id>/app.sock. This subcommand reaches them directly
// (no daemon round-trip): it reads each app's manifest and dials the
// socket using the same length-prefixed JSON framing the apps speak.

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pilot-protocol/app-store/pkg/ipc"
	"github.com/pilot-protocol/app-store/pkg/manifest"
	"github.com/pilot-protocol/common/consent"
	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/pilotprotocol/pkg/telemetry"
)

// cryptoSHA256 is named so the sha256 import isn't ambiguous-looking.
func cryptoSHA256() hash.Hash { return sha256.New() }

const defaultAppStoreRoot = ".pilot/apps"

// cmdAppStore is the entry point dispatched from main.go's switch.
func cmdAppStore(args []string) {
	if len(args) == 0 {
		appStoreHelp()
		return
	}
	switch args[0] {
	case "list":
		cmdAppStoreList(args[1:])
	case "call":
		cmdAppStoreCall(args[1:])
	case "status":
		cmdAppStoreStatus(args[1:])
	case "view":
		cmdAppStoreView(args[1:])
	case "audit":
		cmdAppStoreAudit(args[1:])
	case "uninstall":
		cmdAppStoreUninstall(args[1:])
	case "verify":
		cmdAppStoreVerify(args[1:])
	case "install":
		cmdAppStoreInstall(args[1:])
	case "gen-key":
		cmdAppStoreGenKey(args[1:])
	case "sign":
		cmdAppStoreSign(args[1:])
	case "sign-catalogue", "sign-catalog":
		cmdAppStoreSignCatalogue(args[1:])
	case "catalogue", "catalog":
		cmdAppStoreCatalogue(args[1:])
	case "restart":
		cmdAppStoreRestart(args[1:])
	case "caps":
		cmdAppStoreCaps(args[1:])
	case "actions":
		cmdAppStoreActions(args[1:])
	case "help", "-h", "--help":
		appStoreHelp()
	default:
		fatalHint("invalid_argument",
			"available: list, status, view, audit, uninstall, verify, install, gen-key, sign, sign-catalogue, catalogue, restart, caps, actions, call",
			"unknown appstore subcommand: %s", args[0])
	}
}

// AppStoreHelpText is the appstore subcommand's help block. Exported as
// a const so the upstream `commandHelp` table in main.go can register
// it under the "appstore" key — that way `pilotctl appstore <sub>
// --help` resolves through pilotctl's per-command help intercept and
// prints this text, instead of falling through to "No specific help".
const AppStoreHelpText = `pilotctl appstore — list installed apps and call their methods

Usage:
  pilotctl appstore list                     list installed apps + their methods
  pilotctl appstore status <id>              deep-dive on one app's pinned state
  pilotctl appstore view <id> [--all-changelog]
                                             detail page: description, vendor, changelog,
                                             size, source, methods, permissions (works
                                             whether or not the app is installed)
  pilotctl appstore audit <id> [--tail N] [--event NAME] [--since DURATION]
                                             show the supervisor lifecycle log
                                             event names: supervise-start, supervise-stop,
                                                          spawn, exit, suspend, verify-fail, spawn-fail
                                             duration: Go syntax (e.g. 10m, 1h, 24h)
  pilotctl appstore uninstall <id> --yes     remove an installed app from the install root
  pilotctl appstore verify <bundle-dir>      sha256-check a pre-install bundle against its manifest
  pilotctl appstore catalogue                list apps available for one-command install
  pilotctl appstore install <app-id> [--force]
                                             install by catalogue ID (fetches + verifies + extracts)
  pilotctl appstore install <bundle-dir> --local [--force]
                                             sideload a local bundle (sandbox: fs.read/fs.write
                                             under $APP, audit.log; no net, no key.sign, no hooks)
  pilotctl appstore gen-key <key-file>       generate a fresh ed25519 publisher keypair; prints the public side
  pilotctl appstore sign --key <key-file> <manifest>
                                             sign (or re-sign) a manifest's store.signature so the supervisor accepts it
  pilotctl appstore sign-catalogue --key <key-file> <catalogue.json>
                                             sign the catalogue, writing a detached <catalogue>.sig pilotctl verifies on load
  pilotctl appstore restart <id>             ask the daemon to clear crash-loop suspension and respawn this app
  pilotctl appstore caps <id>                show the manifest's spend caps and current rolling-window usage
  pilotctl appstore actions [--tail N] [--event NAME]
                                             show the pilotctl-side action log (install/uninstall — survives app removal)
  pilotctl appstore call <id> <method> [json-args] [--timeout 2m]
                                             dispatch an IPC call into an app
                                             (--timeout / $PILOT_APPSTORE_CALL_TIMEOUT;
                                              default 120s — raise for slow methods)

Install root is taken from $PILOT_APPSTORE_ROOT or ~/.pilot/apps.
`

func appStoreHelp() {
	fmt.Fprint(os.Stderr, AppStoreHelpText)
}

func appStoreRoot() string {
	if r := os.Getenv("PILOT_APPSTORE_ROOT"); r != "" {
		return r
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return defaultAppStoreRoot
	}
	return filepath.Join(home, defaultAppStoreRoot)
}

// ── list ───────────────────────────────────────────────────────────────

type appListEntry struct {
	ID              string   `json:"id"`
	AppVersion      string   `json:"app_version"`
	ManifestVersion int      `json:"manifest_version"`
	Protection      string   `json:"protection"`
	Methods         []string `json:"methods"`
	SocketReady     bool     `json:"socket_ready"`
	BinaryPresent   bool     `json:"binary_present"`
	Suspended       bool     `json:"suspended,omitempty"`
	ManifestValid   bool     `json:"manifest_valid"`
	Sideloaded      bool     `json:"sideloaded,omitempty"`
}

func cmdAppStoreList(_ []string) {
	root := appStoreRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if jsonOutput {
				_ = json.NewEncoder(os.Stdout).Encode([]appListEntry{})
				return
			}
			fmt.Fprintf(os.Stderr, "no install root at %s — install an app first\n", root)
			return
		}
		fatalHint("io_error", "check the install root permissions", "read %s: %v", root, err)
	}

	var apps []appListEntry
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		mfPath := filepath.Join(dir, "manifest.json")
		raw, err := os.ReadFile(mfPath)
		if err != nil {
			continue
		}
		m, err := manifest.Parse(raw)
		if err != nil {
			continue
		}
		binPath := filepath.Join(dir, m.Binary.Path)
		sockPath := filepath.Join(dir, "app.sock")
		_, sockErr := os.Stat(sockPath)
		_, binErr := os.Stat(binPath)
		// The supervisor drops a .suspended sentinel when the crash-loop
		// budget is spent. Detecting it from disk lets list report
		// "suspended" without daemon IPC.
		_, suspErr := os.Stat(filepath.Join(dir, ".suspended"))
		_, sideErr := os.Stat(filepath.Join(dir, manifest.SideloadMarkerName))
		// Run the manifest's semantic Validate too — an app the
		// supervisor will silently skip should be VISIBLY broken in
		// list output, not look like a normal "stopped" app.
		validationOK := len(m.Validate()) == 0
		apps = append(apps, appListEntry{
			ID:              m.ID,
			AppVersion:      m.AppVersion,
			ManifestVersion: m.ManifestVersion,
			Protection:      m.Protection,
			Methods:         append([]string(nil), m.Exposes...),
			SocketReady:     sockErr == nil,
			BinaryPresent:   binErr == nil,
			Suspended:       suspErr == nil,
			ManifestValid:   validationOK,
			Sideloaded:      sideErr == nil,
		})
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].ID < apps[j].ID })

	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(apps)
		return
	}

	if len(apps) == 0 {
		fmt.Printf("no apps installed under %s\n", root)
		return
	}
	fmt.Printf("install root: %s\n\n", root)
	for _, a := range apps {
		state := "stopped"
		switch {
		case !a.ManifestValid:
			state = "INVALID — manifest fails validation; supervisor will skip it (see `pilotctl appstore status " + a.ID + "`)"
		case a.Suspended:
			state = "SUSPENDED — run `pilotctl appstore restart " + a.ID + "` to clear"
		case !a.BinaryPresent:
			state = "missing-binary"
		case a.SocketReady:
			state = "ready"
		}
		fmt.Printf("  %s\n", a.ID)
		versionLine := fmt.Sprintf("%s (manifest v%d, %s)", a.AppVersion, a.ManifestVersion, a.Protection)
		if a.Sideloaded {
			versionLine += " [sideloaded]"
		}
		fmt.Printf("    version:  %s\n", versionLine)
		fmt.Printf("    state:    %s\n", state)
		if len(a.Methods) > 0 {
			fmt.Printf("    methods:  %v\n", a.Methods)
		}
		fmt.Println()
	}
}

// ── status ─────────────────────────────────────────────────────────────

type appStatusReport struct {
	ID                 string   `json:"id"`
	AppVersion         string   `json:"app_version"`
	ManifestVersion    int      `json:"manifest_version"`
	Protection         string   `json:"protection"`
	Methods            []string `json:"methods"`
	BinaryPath         string   `json:"binary_path"`
	BinarySize         int64    `json:"binary_size,omitempty"`
	BinarySHA256       string   `json:"binary_sha256_pinned"`
	BinarySHA256OK     bool     `json:"binary_sha256_ok"`
	BinarySHA256Actual string   `json:"binary_sha256_actual,omitempty"` // populated on mismatch so operators can diagnose without recomputing
	BinaryPresent      bool     `json:"binary_present"`
	SocketPath         string   `json:"socket_path"`
	SocketReady        bool     `json:"socket_ready"`
	DBPresent          bool     `json:"db_present"`
	IdentityPresent    bool     `json:"identity_present"`
	AuditLogPath       string   `json:"audit_log_path"`
	AuditLogPresent    bool     `json:"audit_log_present"`
	AuditLogSize       int64    `json:"audit_log_size,omitempty"`
	ManifestValid      bool     `json:"manifest_valid"`
	ManifestErrors     []string `json:"manifest_errors,omitempty"`
	Grants             []string `json:"grants"`
	SpendCaps          []string `json:"spend_caps,omitempty"`
	Extends            []string `json:"extends,omitempty"`
}

func cmdAppStoreStatus(args []string) {
	if len(args) < 1 {
		fatalHint("invalid_argument",
			"usage: pilotctl appstore status <app-id>",
			"missing app id")
	}
	appID := args[0]
	root := appStoreRoot()
	dir := filepath.Join(root, appID)
	mfPath := filepath.Join(dir, "manifest.json")
	raw, err := os.ReadFile(mfPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fatalHint("invalid_argument",
				fmt.Sprintf("try `pilotctl appstore list` to see what's installed under %s", root),
				"app %q not installed: %v", appID, err)
		}
		fatalHint("io_error", "check install root permissions",
			"read %s: %v", mfPath, err)
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		fatalHint("internal_error",
			"the pinned manifest is corrupt; reinstall the app",
			"parse manifest: %v", err)
	}

	binPath := filepath.Join(dir, m.Binary.Path)
	sockPath := filepath.Join(dir, "app.sock")
	dbPath := filepath.Join(dir, "data.db")
	idPath := filepath.Join(dir, "identity.json")
	auditPath := filepath.Join(dir, "supervisor.log")

	// Validate the manifest semantically. The supervisor silently
	// skips manifests that fail Validate (see scanInstalled), so an
	// operator debugging "why isn't this spawning?" needs to see
	// validation status here — not buried in the daemon's log.
	validationErrs := m.Validate()
	validationStrs := make([]string, 0, len(validationErrs))
	for _, e := range validationErrs {
		validationStrs = append(validationStrs, e.Error())
	}

	report := appStatusReport{
		ID:              m.ID,
		AppVersion:      m.AppVersion,
		ManifestVersion: m.ManifestVersion,
		Protection:      m.Protection,
		Methods:         append([]string(nil), m.Exposes...),
		BinaryPath:      binPath,
		ManifestValid:   len(validationErrs) == 0,
		ManifestErrors:  validationStrs,
		BinarySHA256:    m.Binary.SHA256,
		SocketPath:      sockPath,
		AuditLogPath:    auditPath,
	}
	if info, err := os.Stat(binPath); err == nil {
		report.BinaryPresent = true
		report.BinarySize = info.Size()
		actual := sha256File(binPath)
		report.BinarySHA256OK = actual == m.Binary.SHA256
		if !report.BinarySHA256OK {
			// Only surface the actual hash on mismatch — for the
			// matching case it duplicates the pinned value. Lets
			// operators diff against the manifest without re-running
			// shasum themselves.
			report.BinarySHA256Actual = actual
		}
	}
	if _, err := os.Stat(sockPath); err == nil {
		report.SocketReady = true
	}
	if _, err := os.Stat(dbPath); err == nil {
		report.DBPresent = true
	}
	if _, err := os.Stat(idPath); err == nil {
		report.IdentityPresent = true
	}
	if info, err := os.Stat(auditPath); err == nil {
		report.AuditLogPresent = true
		report.AuditLogSize = info.Size()
	}
	for _, g := range m.Grants {
		report.Grants = append(report.Grants, fmt.Sprintf("%s:%s", g.Cap, g.Target))
	}
	// Lift the structured spend caps out of the grants block too —
	// the raw `Grants` strings only show cap+target, not the rolling
	// window or amount. Operators looking at "what is this wallet
	// allowed to spend?" need the structured view. Including the
	// sign-purpose target distinguishes manifests that declare
	// multiple caps with identical asset/limit/window for different
	// signing surfaces (e.g. x402-auth vs evm-eip3009).
	for _, c := range parseCapsFromGrants(m.Grants) {
		report.SpendCaps = append(report.SpendCaps,
			fmt.Sprintf("%d %s per %s (target=%s)", c.limit, c.asset, humanDuration(c.window), c.target))
	}
	for _, e := range m.Extends {
		report.Extends = append(report.Extends, e.Primitive)
	}

	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(report)
		return
	}

	state := "stopped"
	switch {
	case !report.BinaryPresent:
		state = "missing-binary"
	case !report.BinarySHA256OK:
		state = "BINARY-SHA256-MISMATCH"
	case report.SocketReady:
		state = "ready"
	}

	fmt.Printf("app:            %s\n", report.ID)
	fmt.Printf("version:        %s (manifest v%d)\n", report.AppVersion, report.ManifestVersion)
	fmt.Printf("protection:     %s\n", report.Protection)
	fmt.Printf("state:          %s\n", state)
	if report.ManifestValid {
		fmt.Printf("manifest:       valid\n")
	} else {
		fmt.Printf("manifest:       INVALID — %d validation error(s); the supervisor will skip this app:\n", len(report.ManifestErrors))
		for _, e := range report.ManifestErrors {
			fmt.Printf("                  - %s\n", e)
		}
	}
	fmt.Printf("\n")
	fmt.Printf("binary:         %s\n", report.BinaryPath)
	if report.BinaryPresent {
		fmt.Printf("  size:         %d bytes\n", report.BinarySize)
		fmt.Printf("  sha256 pin:   %s\n", report.BinarySHA256)
		if report.BinarySHA256OK {
			fmt.Printf("  sha256 ok:    yes\n")
		} else {
			fmt.Printf("  sha256 ok:    NO — on-disk binary does not match the pinned hash\n")
			if report.BinarySHA256Actual != "" {
				fmt.Printf("  sha256 actual: %s\n", report.BinarySHA256Actual)
			}
		}
	} else {
		fmt.Printf("  status:       NOT PRESENT — the daemon will refuse to spawn this app\n")
	}
	fmt.Printf("socket:         %s (%s)\n", report.SocketPath, boolToReady(report.SocketReady))
	fmt.Printf("data.db:        %s\n", boolToPresent(report.DBPresent))
	fmt.Printf("identity:       %s\n", boolToPresent(report.IdentityPresent))
	if report.AuditLogPresent {
		fmt.Printf("audit log:      %s (%d bytes) — read with `pilotctl appstore audit %s`\n",
			report.AuditLogPath, report.AuditLogSize, report.ID)
	} else {
		fmt.Printf("audit log:      %s (none yet)\n", report.AuditLogPath)
	}
	if len(report.Methods) > 0 {
		fmt.Printf("\nexposes:\n")
		for _, m := range report.Methods {
			fmt.Printf("  - %s\n", m)
		}
	}
	if len(report.Grants) > 0 {
		fmt.Printf("\ngrants (user accepted at install):\n")
		for _, g := range report.Grants {
			fmt.Printf("  - %s\n", g)
		}
	}
	if len(report.SpendCaps) > 0 {
		fmt.Printf("\nspend caps (rolling-window limits):\n")
		for _, c := range report.SpendCaps {
			fmt.Printf("  - %s\n", c)
		}
		fmt.Printf("  (use `pilotctl appstore caps %s` for live usage)\n", report.ID)
	}
	if len(report.Extends) > 0 {
		fmt.Printf("\nextends (hooks registered):\n")
		for _, e := range report.Extends {
			fmt.Printf("  - %s\n", e)
		}
	}
}

func boolToReady(b bool) string {
	if b {
		return "ready"
	}
	return "not ready"
}

func boolToPresent(b bool) string {
	if b {
		return "present"
	}
	return "missing"
}

// exposedMethods reads the pinned manifest for appID and returns its
// `exposes` list. Best-effort: returns nil on any read/parse failure so
// the caller can fall through to the bare IPC error rather than mask it.
func exposedMethods(appID string) []string {
	raw, err := os.ReadFile(filepath.Join(appStoreRoot(), appID, "manifest.json"))
	if err != nil {
		return nil
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		return nil
	}
	out := append([]string(nil), m.Exposes...)
	sort.Strings(out)
	return out
}

func sha256File(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := cryptoSHA256()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// ── audit ──────────────────────────────────────────────────────────────

type auditLine struct {
	At       string `json:"at"`
	AppID    string `json:"app"`
	Event    string `json:"event"`
	PID      int    `json:"pid,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`
	Reason   string `json:"reason,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	BinaryAt string `json:"binary_path,omitempty"`
}

func cmdAppStoreAudit(args []string) {
	if len(args) < 1 {
		fatalHint("invalid_argument",
			"usage: pilotctl appstore audit <app-id> [--tail N] [--event NAME] [--since DURATION]",
			"missing app id")
	}
	appID := args[0]
	tail := 0
	eventFilter := ""
	var sinceCutoff time.Time
	var sinceDuration time.Duration
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--tail", "-n":
			if i+1 >= len(args) {
				fatalHint("invalid_argument",
					"--tail expects an integer count",
					"missing tail count")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 0 {
				fatalHint("invalid_argument",
					"--tail expects a non-negative integer",
					"parse tail %q: %v", args[i+1], err)
			}
			tail = n
			i++
		case "--event", "-e":
			if i+1 >= len(args) {
				fatalHint("invalid_argument",
					"--event expects an event name (spawn, exit, suspend, verify-fail, spawn-fail)",
					"missing event name")
			}
			eventFilter = args[i+1]
			i++
		case "--since", "-s":
			// Accept Go duration syntax (10m, 1h30m, 24h). Anything
			// time.ParseDuration accepts works — same shape ops people
			// already know from `journalctl --since`-ish tools.
			if i+1 >= len(args) {
				fatalHint("invalid_argument",
					"--since expects a Go duration (e.g. 10m, 1h, 24h)",
					"missing duration")
			}
			d, err := time.ParseDuration(args[i+1])
			if err != nil || d <= 0 {
				fatalHint("invalid_argument",
					"--since expects a positive duration like 10m, 1h, 24h",
					"parse since %q: %v", args[i+1], err)
			}
			sinceCutoff = time.Now().Add(-d)
			sinceDuration = d
			i++
		default:
			fatalHint("invalid_argument",
				"available flags: --tail N, --event NAME, --since DURATION",
				"unknown audit flag: %s", args[i])
		}
	}

	appDir := filepath.Join(appStoreRoot(), appID)
	logPath := filepath.Join(appDir, "supervisor.log")
	rotatedPath := filepath.Join(appDir, "supervisor.log.1")

	// Read rotated file first (older entries) then active (newer)
	// so display order stays chronological after rotation. The
	// rotated file is optional — missing means rotation never fired.
	var lines []auditLine
	appendLogFile := func(path string, required bool) bool {
		f, err := os.Open(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return !required // ok when optional, fail when required
			}
			fatalHint("io_error",
				"check the install root permissions and that the app id is correct",
				"open %s: %v", path, err)
			return false
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			raw := scanner.Bytes()
			if len(raw) == 0 {
				continue
			}
			var ev auditLine
			if err := json.Unmarshal(raw, &ev); err != nil {
				// Skip malformed lines but don't fail the command — a single
				// corrupt line shouldn't block forensics on the rest.
				continue
			}
			lines = append(lines, ev)
		}
		if err := scanner.Err(); err != nil {
			fatalHint("io_error",
				"the log file may be corrupt; try `cat` to inspect raw bytes",
				"scan %s: %v", path, err)
		}
		return true
	}
	_ = appendLogFile(rotatedPath, false) // optional
	activeExists := appendLogFile(logPath, false)
	if !activeExists && len(lines) == 0 {
		// Neither file exists — no audit log at all yet.
		if jsonOutput {
			_ = json.NewEncoder(os.Stdout).Encode([]auditLine{})
			return
		}
		fmt.Printf("no audit log yet at %s — the app has not run since the supervisor started writing logs\n", logPath)
		return
	}

	if eventFilter != "" {
		filtered := lines[:0]
		for _, ev := range lines {
			if ev.Event == eventFilter {
				filtered = append(filtered, ev)
			}
		}
		lines = filtered
	}
	if !sinceCutoff.IsZero() {
		filtered := lines[:0]
		for _, ev := range lines {
			// Audit timestamps land as RFC3339Nano (supervisor uses
			// time.Now().UTC()); parse defensively and drop lines we
			// can't interpret rather than blowing up the whole query.
			t, err := time.Parse(time.RFC3339Nano, ev.At)
			if err != nil {
				continue
			}
			if !t.Before(sinceCutoff) {
				filtered = append(filtered, ev)
			}
		}
		lines = filtered
	}
	if tail > 0 && len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}

	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(lines)
		return
	}

	if len(lines) == 0 {
		switch {
		case eventFilter != "" && sinceDuration > 0:
			fmt.Printf("no %q events in last %s for %s\n", eventFilter, humanDuration(sinceDuration), logPath)
		case eventFilter != "":
			fmt.Printf("no %q events in %s\n", eventFilter, logPath)
		case sinceDuration > 0:
			fmt.Printf("no events in last %s for %s\n", humanDuration(sinceDuration), logPath)
		default:
			fmt.Printf("audit log %s is empty\n", logPath)
		}
		return
	}
	header := fmt.Sprintf("audit log: %s (%d events shown", logPath, len(lines))
	if eventFilter != "" {
		header += fmt.Sprintf(", filtered to event=%q", eventFilter)
	}
	if sinceDuration > 0 {
		header += fmt.Sprintf(", since last %s", humanDuration(sinceDuration))
	}
	header += ")"
	fmt.Println(header)
	fmt.Println()
	for _, ev := range lines {
		fmt.Printf("  %s  %-12s", ev.At, ev.Event)
		if ev.PID > 0 {
			fmt.Printf(" pid=%d", ev.PID)
		}
		if ev.Event == "exit" {
			fmt.Printf(" exit_code=%d", ev.ExitCode)
		}
		if ev.SHA256 != "" {
			fmt.Printf(" sha256=%s", shortHex(ev.SHA256))
		}
		if ev.Reason != "" {
			fmt.Printf(" reason=%q", ev.Reason)
		}
		fmt.Println()
	}
}

// shortHex collapses a hex digest to "abcd1234…ef01" — first 8 + last 4
// characters joined by an ellipsis — keeping audit-log lines readable
// while still pinning down the binary version when grepping for
// incidents. Returns the input unchanged if it's already short.
func shortHex(h string) string {
	if len(h) <= 16 {
		return h
	}
	return h[:8] + "…" + h[len(h)-4:]
}

// ── uninstall ──────────────────────────────────────────────────────────

// cmdAppStoreUninstall removes an installed app's directory tree from the
// install root. Destructive — requires --yes to confirm. Does NOT
// coordinate with the daemon's supervisor, so until the daemon is
// restarted the supervisor will keep failing the binary sha256 check on
// every respawn (visible in the audit log as "verify-fail" lines, capped
// at one per 30s by the supervisor backoff).
func cmdAppStoreUninstall(args []string) {
	if len(args) < 1 {
		fatalHint("invalid_argument",
			"usage: pilotctl appstore uninstall <app-id> --yes",
			"missing app id")
	}
	appID := args[0]
	confirmed := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--yes", "-y":
			confirmed = true
		default:
			fatalHint("invalid_argument",
				"available flags: --yes",
				"unknown uninstall flag: %s", args[i])
		}
	}
	if !confirmed {
		fatalHint("invalid_argument",
			"uninstall is destructive — pass --yes to confirm",
			"refusing to uninstall %q without --yes", appID)
	}

	root := appStoreRoot()
	dir := filepath.Join(root, appID)
	info, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fatalHint("invalid_argument",
				fmt.Sprintf("try `pilotctl appstore list` to see what's installed under %s", root),
				"app %q not installed", appID)
		}
		fatalHint("io_error", "check install root permissions",
			"stat %s: %v", dir, err)
	}
	if !info.IsDir() {
		fatalHint("internal_error",
			"the install root layout is corrupt; inspect manually",
			"%s is not a directory", dir)
	}

	// Read the manifest BEFORE deleting it so we can snapshot the
	// binary sha256 + app_version into the uninstall audit record.
	// The per-app supervisor.log is going away with the dir; the
	// pilotctl-audit log at the install-root level is what survives.
	var snapSHA, snapVer string
	mfPath := filepath.Join(dir, "manifest.json")
	if raw, err := os.ReadFile(mfPath); err == nil {
		if m, perr := manifest.Parse(raw); perr == nil {
			snapSHA = m.Binary.SHA256
			snapVer = m.AppVersion
		}
	}

	// Race-aware removal. The daemon's supervise goroutine is still
	// running and writes to <dir>/supervisor.log on every verify-fail
	// (every 30s), which can racily recreate the log file mid-delete
	// and turn RemoveAll into a "directory not empty" failure. Manifest
	// removal first triggers the supervisor's rescanForGone to cancel
	// the per-app goroutine; then the dir delete has no live writer.
	if err := os.Remove(mfPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		fatalHint("io_error",
			"check install root permissions",
			"remove manifest %s: %v", mfPath, err)
	}
	// Retry RemoveAll a few times to ride out the supervisor's
	// in-flight audit writes; the rescan loop cancels the goroutine
	// within ~RescanInterval (default 30s in prod, but the audit
	// writes themselves happen at the 30s verify-fail cadence, so a
	// handful of short retries is usually enough).
	const (
		removeRetries = 8
		retryDelay    = 250 * time.Millisecond
	)
	var rmErr error
	for i := 0; i < removeRetries; i++ {
		if err := os.RemoveAll(dir); err == nil {
			rmErr = nil
			break
		} else {
			rmErr = err
			time.Sleep(retryDelay)
		}
	}
	if rmErr != nil {
		fatalHint("io_error",
			"manifest removed but the dir is racing the supervisor; rerun `pilotctl appstore uninstall --yes` after the daemon's next rescan settles (~30s)",
			"remove %s: %v", dir, rmErr)
	}

	// Forensic trail at the install-root level (survives the deletion
	// of the app dir). Pairs with the install-time event we wrote
	// into supervisor.log earlier — gives "this app existed between
	// install T0 and uninstall T1" reconstructable post-hoc.
	writePilotctlAudit(root, pilotctlAuditEvent{
		Event:  "uninstalled",
		AppID:  appID,
		SHA256: snapSHA,
		AppVer: snapVer,
		Reason: fmt.Sprintf("actor=%s removed=%s", currentActor(), dir),
	})

	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"id":            appID,
			"removed":       dir,
			"daemon_notice": "supervisor's next rescan (≤30s) will cancel the per-app goroutine; manifest already removed",
		})
		return
	}
	fmt.Printf("removed %s\n", dir)
	fmt.Println("note: the daemon's supervisor will cancel its per-app goroutine on its next rescan")
	fmt.Println("      (≤30s); no daemon restart needed")
}

// ── verify ─────────────────────────────────────────────────────────────

// verifyReport is the --json shape returned by `appstore verify`.
type verifyReport struct {
	BundleDir       string `json:"bundle_dir"`
	AppID           string `json:"id"`
	AppVersion      string `json:"app_version"`
	ManifestVersion int    `json:"manifest_version"`
	Protection      string `json:"protection"`
	BinaryPath      string `json:"binary_path"` // path inside the bundle (manifest.Binary.Path)
	BinarySize      int64  `json:"binary_size"`
	ExpectedSHA256  string `json:"expected_sha256"` // from manifest.Binary.SHA256
	ActualSHA256    string `json:"actual_sha256"`   // computed from on-disk bytes
	OK              bool   `json:"ok"`
}

// cmdAppStoreVerify sha256-checks a pre-install bundle against its
// own manifest. This is the same trust check the supervisor runs at
// every launch, exposed pre-install so app authors can validate their
// build output AND users can sanity-check a downloaded bundle before
// dropping it into <install_root>/<id>/.
//
// Bundle layout (same as the on-disk install layout):
//
//	<bundle-dir>/
//	  manifest.json
//	  <manifest.Binary.Path>  (typically bin/<name>)
func cmdAppStoreVerify(args []string) {
	if len(args) < 1 {
		fatalHint("invalid_argument",
			"usage: pilotctl appstore verify <bundle-dir>",
			"missing bundle dir")
	}
	bundleDir := args[0]
	info, err := os.Stat(bundleDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fatalHint("invalid_argument",
				"pass a directory containing manifest.json and the binary",
				"bundle dir %q does not exist", bundleDir)
		}
		fatalHint("io_error", "check the bundle path", "stat %s: %v", bundleDir, err)
	}
	if !info.IsDir() {
		fatalHint("invalid_argument",
			"verify expects a directory, not a file (extract the tarball first)",
			"%s is not a directory", bundleDir)
	}

	mfPath := filepath.Join(bundleDir, "manifest.json")
	raw, err := os.ReadFile(mfPath)
	if err != nil {
		fatalHint("invalid_argument",
			"every bundle must contain a manifest.json at the top level",
			"read %s: %v", mfPath, err)
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		fatalHint("invalid_argument",
			"the bundle's manifest.json failed JSON parsing",
			"parse manifest: %v", err)
	}
	if errs := m.Validate(); len(errs) > 0 {
		// Catch semantic errors (unknown cap, missing required fields,
		// malformed store.publisher) BEFORE telling the user "verified" —
		// otherwise install/scan silently skip the app later.
		fatalHint("invalid_argument",
			"the bundle's manifest passed JSON parsing but failed semantic validation; fix the listed issues before installing",
			"manifest validation: %s", validationErrSummary(errs))
	}

	binPath := filepath.Join(bundleDir, m.Binary.Path)
	binInfo, err := os.Stat(binPath)
	if err != nil {
		fatalHint("invalid_argument",
			fmt.Sprintf("manifest expects binary at %q (relative to bundle root)", m.Binary.Path),
			"binary not found: %v", err)
	}
	actual := sha256File(binPath)

	report := verifyReport{
		BundleDir:       bundleDir,
		AppID:           m.ID,
		AppVersion:      m.AppVersion,
		ManifestVersion: m.ManifestVersion,
		Protection:      m.Protection,
		BinaryPath:      m.Binary.Path,
		BinarySize:      binInfo.Size(),
		ExpectedSHA256:  m.Binary.SHA256,
		ActualSHA256:    actual,
		OK:              actual == m.Binary.SHA256 && m.Binary.SHA256 != "",
	}

	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(report)
		if !report.OK {
			os.Exit(2)
		}
		return
	}

	fmt.Printf("bundle:         %s\n", report.BundleDir)
	fmt.Printf("app:            %s\n", report.AppID)
	fmt.Printf("version:        %s (manifest v%d, %s)\n", report.AppVersion, report.ManifestVersion, report.Protection)
	fmt.Printf("binary:         %s (%d bytes)\n", report.BinaryPath, report.BinarySize)
	fmt.Printf("  expected:     %s\n", report.ExpectedSHA256)
	fmt.Printf("  actual:       %s\n", report.ActualSHA256)
	if report.OK {
		fmt.Printf("\nVERIFY OK — bundle's binary matches the manifest's pinned sha256.\n")
		return
	}
	if report.ExpectedSHA256 == "" {
		fmt.Fprintf(os.Stderr, "\nVERIFY FAILED — manifest is missing binary.sha256; refuse to install.\n")
	} else {
		fmt.Fprintf(os.Stderr, "\nVERIFY FAILED — bundle binary does NOT match the manifest's pinned sha256.\n")
	}
	os.Exit(2)
}

// ── install ────────────────────────────────────────────────────────────

// installReport is the --json shape returned by `appstore install`.
type installReport struct {
	AppID           string `json:"id"`
	AppVersion      string `json:"app_version"`
	ManifestVersion int    `json:"manifest_version"`
	InstalledTo     string `json:"installed_to"`
	BinarySHA256    string `json:"binary_sha256"`
	DaemonNotice    string `json:"daemon_notice"`
}

// cmdAppStoreInstall places a verified bundle into the install root.
// Layout matches what the supervisor expects (see plugin/appstore/supervisor.go:
// scanInstalled). Atomic move-rename means a daemon scanning the install
// root never sees a partially-written app dir.
//
// Steps:
//  1. sha256-check the bundle (same logic as `verify`)
//  2. reject if app already installed unless --force
//  3. stage into <install_root>/<id>.staging/
//  4. atomic rename .staging → <id>
//
// The daemon's supervisor only scans on Start, so an install while the
// daemon is running is invisible until the next daemon restart — the
// success message and JSON note callers about this.
func cmdAppStoreInstall(args []string) {
	if len(args) < 1 {
		fatalHint("invalid_argument",
			"usage: pilotctl appstore install <app-id-or-dir> [--force] [--local]",
			"missing app id or bundle dir")
	}
	target := args[0]
	force := false
	allowLocal := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--force", "-f":
			force = true
		case "--local":
			// Required acknowledgement when installing from a local
			// directory. Catalogue installs ignore this; path installs
			// without --local fail closed so a typo'd app id (which
			// happens to also exist as a directory in the cwd) can't
			// silently sideload an unsigned bundle.
			allowLocal = true
		default:
			fatalHint("invalid_argument",
				"available flags: --force, --local",
				"unknown install flag: %s", args[i])
		}
	}

	// Resolve `target` to a local bundle dir and a source tag.
	// Catalogue path = signed, runs the standard signature gate.
	// Local path = sideload, requires --local AND must satisfy the
	// sideload allow-list before the supervisor will load it.
	bundleDir, source, err := resolveInstallTarget(target)
	if err != nil {
		fatalHint("invalid_argument",
			"the argument must be either a catalogue ID (`pilotctl appstore catalogue` to list) or a path to a bundle dir containing manifest.json",
			"%v", err)
	}
	if source == installSourceLocal && !allowLocal {
		fatalHint("invalid_argument",
			"local sideloads carry no catalogue signature; pass --local to confirm you trust this bundle's source. The supervisor will clamp the manifest to a small allow-list (fs.read/fs.write under $APP, audit.log). No net.dial, key.sign, ipc.call to other apps, or daemon hooks.",
			"refusing to install local path %q without --local", target)
	}

	// 1. Validate the bundle — same shape as verify. Reusing the
	//    surface manifest.Parse + sha256File makes the trust check
	//    identical to what the supervisor runs at every spawn.
	info, err := os.Stat(bundleDir)
	if err != nil || !info.IsDir() {
		fatalHint("invalid_argument",
			"pass a directory containing manifest.json and the binary",
			"bundle dir %q is not a directory: %v", bundleDir, err)
	}
	raw, err := os.ReadFile(filepath.Join(bundleDir, "manifest.json"))
	if err != nil {
		fatalHint("invalid_argument",
			"every bundle must contain a manifest.json at the top level",
			"read manifest: %v", err)
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		fatalHint("invalid_argument",
			"the bundle's manifest.json failed JSON parsing",
			"parse manifest: %v", err)
	}
	if errs := m.Validate(); len(errs) > 0 {
		// Same gate as verify — never plant a manifest that the
		// supervisor will silently skip on scanInstalled.
		fatalHint("invalid_argument",
			"refusing to install a manifest the supervisor will reject; fix the listed issues and re-run",
			"manifest validation: %s", validationErrSummary(errs))
	}
	if source == installSourceLocal {
		// Same allow-list the supervisor enforces at scan time. We
		// check it here too so users find out at install time, not at
		// the next supervisor poll, what they need to strip from the
		// manifest. Failing closed: no marker is planted unless the
		// manifest passes.
		if err := manifest.EnforceSideloadPolicy(m); err != nil {
			fatalHint("invalid_argument",
				"sideloaded apps may only declare audit.log, fs.read $APP/*, fs.write $APP/*. Remove the offending grant or use the catalogue install path for a reviewed app.",
				"%v", err)
		}
	}
	srcBin := filepath.Join(bundleDir, m.Binary.Path)
	if _, err := os.Stat(srcBin); err != nil {
		fatalHint("invalid_argument",
			fmt.Sprintf("manifest pins binary at %q", m.Binary.Path),
			"binary missing in bundle: %v", err)
	}
	if m.Binary.SHA256 == "" {
		fatalHint("invalid_argument",
			"every binary must declare a sha256 in the manifest; refuse to install unsigned bytes",
			"manifest missing binary.sha256")
	}
	if got := sha256File(srcBin); got != m.Binary.SHA256 {
		fatalHint("integrity_error",
			"run `pilotctl appstore verify` for a side-by-side; this bundle is tampered or built from a different source than the manifest claims",
			"binary sha256 mismatch: manifest=%s actual=%s", m.Binary.SHA256, got)
	}

	root := appStoreRoot()
	finalDir := filepath.Join(root, m.ID)
	stagingDir := finalDir + ".staging"

	// 2. Reject existing install unless --force.
	if _, err := os.Stat(finalDir); err == nil {
		if !force {
			fatalHint("conflict",
				"app already installed; uninstall first or pass --force to overwrite",
				"refusing to overwrite %s without --force", finalDir)
		}
	}

	// 3. Stage atomically. We may have a leftover staging dir from a
	//    previous crashed install — blow it away unconditionally.
	if err := os.RemoveAll(stagingDir); err != nil {
		fatalHint("io_error", "check install root permissions",
			"clean stale staging dir %s: %v", stagingDir, err)
	}
	if err := os.MkdirAll(stagingDir, 0o700); err != nil {
		fatalHint("io_error", "check install root permissions",
			"mkdir staging %s: %v", stagingDir, err)
	}
	// Write manifest.json (0644 — readable by everyone in the user's group; not secret).
	if err := os.WriteFile(filepath.Join(stagingDir, "manifest.json"), raw, 0o644); err != nil {
		_ = os.RemoveAll(stagingDir)
		fatalHint("io_error", "check install root permissions", "write manifest: %v", err)
	}
	// Place the binary at the manifest-declared path inside staging.
	dstBin := filepath.Join(stagingDir, m.Binary.Path)
	if err := os.MkdirAll(filepath.Dir(dstBin), 0o700); err != nil {
		_ = os.RemoveAll(stagingDir)
		fatalHint("io_error", "check install root permissions", "mkdir binary parent: %v", err)
	}
	if err := copyFile(srcBin, dstBin, 0o755); err != nil {
		_ = os.RemoveAll(stagingDir)
		fatalHint("io_error", "check install root permissions", "copy binary: %v", err)
	}
	// Re-verify the staged binary against the manifest pin. Cheap
	// defense against a copy that silently went wrong (FS bug, disk
	// error). If this ever fails it's a hard refusal — staging gets
	// cleaned up, no partial install ever reaches the supervisor.
	if got := sha256File(dstBin); got != m.Binary.SHA256 {
		_ = os.RemoveAll(stagingDir)
		fatalHint("integrity_error",
			"the staged copy does not match the bundle — possible disk-level corruption",
			"staged binary sha256 mismatch: manifest=%s staged=%s", m.Binary.SHA256, got)
	}

	if source == installSourceLocal {
		// Plant the sentinel before the atomic rename so the moment
		// the dir appears under InstallRoot it's already tagged
		// sideloaded — there's no window where the supervisor could
		// scan a sideloaded dir and treat it as catalogue-trusted.
		// 0o400: read-only to the owning user; the file's mere
		// existence is the signal, no content needed.
		markerPath := filepath.Join(stagingDir, manifest.SideloadMarkerName)
		if err := os.WriteFile(markerPath, nil, 0o400); err != nil {
			_ = os.RemoveAll(stagingDir)
			fatalHint("io_error", "check install root permissions",
				"write sideload marker: %v", err)
		}
	}

	// 4. Atomic swap. Rename of directories is atomic on Linux/macOS
	//    as long as the destination does not already exist; with
	//    --force we have to step aside the previous install first.
	if force {
		previousDir := finalDir + ".previous"
		_ = os.RemoveAll(previousDir)
		if _, err := os.Stat(finalDir); err == nil {
			if err := os.Rename(finalDir, previousDir); err != nil {
				_ = os.RemoveAll(stagingDir)
				fatalHint("io_error", "the previous install could not be moved aside",
					"rename %s → %s: %v", finalDir, previousDir, err)
			}
		}
		if err := os.Rename(stagingDir, finalDir); err != nil {
			// Best-effort restore so we don't leave the user with no app at all.
			if err2 := os.Rename(previousDir, finalDir); err2 != nil {
				fatalHint("io_error", "rollback also failed — inspect the install root manually",
					"rename staged → final: %v; rollback also failed: %v", err, err2)
			}
			_ = os.RemoveAll(stagingDir)
			fatalHint("io_error", "the swap failed but the previous install was restored",
				"rename staged → final: %v", err)
		}
		_ = os.RemoveAll(previousDir)
	} else {
		if err := os.Rename(stagingDir, finalDir); err != nil {
			_ = os.RemoveAll(stagingDir)
			fatalHint("io_error", "check install root permissions",
				"rename staged → final: %v", err)
		}
	}

	// Drop a forensic line into the supervisor's audit log so the
	// install moment is recoverable post-hoc. Without this, the
	// only timestamp for "when did this app land?" is the
	// supervisor's first supervise-start, which happens later (up
	// to RescanInterval) and doesn't record who ran the command.
	// Best-effort: a log-write failure is reported as a warning,
	// not fatal — the install itself already succeeded on disk.
	writeInstallAudit(finalDir, m.ID, m.AppVersion, m.Binary.SHA256, bundleDir, force)

	// Mirror to the install-root-level pilotctl-audit log too, so
	// the install+uninstall lifecycle pair stays reconstructable
	// after the app dir (and its per-app supervisor.log) is gone.
	reason := fmt.Sprintf("actor=%s source=%s", currentActor(), bundleDir)
	if force {
		reason += " --force"
	}
	writePilotctlAudit(root, pilotctlAuditEvent{
		Event:  "installed",
		AppID:  m.ID,
		AppVer: m.AppVersion,
		SHA256: m.Binary.SHA256,
		Reason: reason,
	})

	// Emit a telemetry event for the successful install.
	// Consent-gated (telemetry flag, default on). Best-effort: a send
	// failure is logged but not fatal — the install already succeeded on disk.
	{
		home, _ := os.UserHomeDir()
		if consent.GetConsent(home, "telemetry") {
			url := os.Getenv("PILOT_TELEMETRY_URL")
			if url == "" {
				url = telemetry.DefaultEndpoint
			}
			sourceStr := "catalogue"
			if source == installSourceLocal {
				sourceStr = "local"
			}
			payload, _ := json.Marshal(map[string]string{
				"app_id":  m.ID,
				"version": m.AppVersion,
				"source":  sourceStr,
			})
			identityPath := configDir() + "/identity.json"
			client := telemetry.NewClientFromIdentity(url, identityPath, nodeIDFromDaemon())
			err := client.Send(telemetry.Event{
				Kind:    "app_installed",
				TS:      time.Now().UTC().Format(time.RFC3339),
				Payload: payload,
			})
			if err != nil {
				slog.Warn("telemetry send failed, install still successful", "app", m.ID, "err", err)
			}
		}
	}

	report := installReport{
		AppID:           m.ID,
		AppVersion:      m.AppVersion,
		ManifestVersion: m.ManifestVersion,
		InstalledTo:     finalDir,
		BinarySHA256:    m.Binary.SHA256,
		DaemonNotice:    "supervisor periodically rescans the install root; this app will be picked up within ~30s (no daemon restart needed)",
	}
	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(report)
		return
	}
	fmt.Printf("installed %s v%s (manifest v%d) → %s\n",
		report.AppID, report.AppVersion, report.ManifestVersion, report.InstalledTo)
	if source == installSourceLocal {
		fmt.Println("mode: SIDELOADED — manifest-level allow-list applied (audit.log, fs.read/$APP, fs.write/$APP).")
		fmt.Println("      this is NOT an OS sandbox: a malicious binary that ignores its manifest can still")
		fmt.Println("      misbehave at the syscall level. Only install paths from sources you trust.")
	}
	fmt.Println("note: the daemon rescans the install root periodically —")
	fmt.Println("      this app will be picked up within ~30s (no daemon restart needed)")
}

// pilotctlAuditFileName is the JSONL log of operator-initiated
// pilotctl actions, sitting at the INSTALL ROOT level (not inside
// any app dir) so it survives uninstall. 0600 — same threat model
// as the per-app supervisor.log.
const pilotctlAuditFileName = ".pilotctl-audit.log"

// pilotctlAuditMaxSize is the size cap for the root-level audit log.
// When reached, the log is rotated to .pilotctl-audit.log.1 (single
// rotation — only one historical file kept). At ~150 B/event this gives
// roughly 700,000 entries before rotation, or decades of heavy use.
const pilotctlAuditMaxSize = 100 * 1024 * 1024 // 100 MiB

// pilotctlAuditEvent is one row of the root-level audit log.
// Operator-side counterpart to the supervisor's auditEvent; lives in
// a different file because the use cases differ — supervisor.log
// tracks the supervised process's lifecycle and dies with the app;
// .pilotctl-audit.log tracks operator commands and persists for
// post-uninstall forensics.
type pilotctlAuditEvent struct {
	At     string `json:"at"`
	Event  string `json:"event"`
	AppID  string `json:"app"`
	AppVer string `json:"app_version,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// currentActor returns the OS user invoking pilotctl, for the audit
// trail. Falls back to "unknown" so the log is still parseable when
// $USER isn't set (test runs, exotic init environments).
func currentActor() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "unknown"
}

// writePilotctlAudit appends a single JSONL line to the install-
// root-level pilotctl audit log. Best-effort: failures land as
// warnings on stderr — the operator's command already succeeded
// on disk; an audit-write failure shouldn't make pilotctl exit
// non-zero and confuse scripting consumers.
func writePilotctlAudit(installRoot string, ev pilotctlAuditEvent) {
	if ev.At == "" {
		ev.At = time.Now().UTC().Format(time.RFC3339Nano)
	}
	body, err := json.Marshal(ev)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: pilotctl audit marshal: %v\n", err)
		return
	}
	body = append(body, '\n')
	path := filepath.Join(installRoot, pilotctlAuditFileName)

	// Rotate if the log exceeds the size cap. Single-rotation model:
	// .pilotctl-audit.log → .pilotctl-audit.log.1, then start fresh.
	// Best-effort — rotation failure doesn't block the audit write.
	// Matches the supervisor.log.1 pattern so readers that already
	// handle supervisor.log rotation can consume this with no changes.
	if fi, err := os.Stat(path); err == nil && fi.Size() >= pilotctlAuditMaxSize {
		rotatedPath := path + ".1"
		if err := os.Rename(path, rotatedPath); err != nil {
			fmt.Fprintf(os.Stderr, "warn: pilotctl audit rotate %s → %s: %v\n",
				path, rotatedPath, err)
		}
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: pilotctl audit open %s: %v\n", path, err)
		return
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		fmt.Fprintf(os.Stderr, "warn: pilotctl audit write %s: %v\n", path, err)
	}
}

// writeInstallAudit appends a single JSONL line to the supervisor's
// audit log marking the install moment. Mirrors the supervisor's own
// auditEvent shape so `pilotctl appstore audit` reads the line back
// without special handling. 0600 matches the supervisor's audit-log
// perms (see plugin/appstore/supervisor.go:writeAuditLine).
//
// Fields populated:
//   - at:    RFC3339Nano of the install moment
//   - app:   manifest id
//   - event: "installed"
//   - sha256: pinned binary hash (same field the supervisor stamps on spawn)
//   - reason: bundle source path + actor + --force flag — operator + provenance
//     trail in case forensics need to chase "where did this come from?"
func writeInstallAudit(appDir, appID, appVer, binSHA, bundleSrc string, forced bool) {
	actor := os.Getenv("USER")
	if actor == "" {
		actor = "unknown"
	}
	reason := fmt.Sprintf("actor=%s source=%s app_version=%s", actor, bundleSrc, appVer)
	if forced {
		reason += " --force"
	}
	line := map[string]any{
		"at":     time.Now().UTC().Format(time.RFC3339Nano),
		"app":    appID,
		"event":  "installed",
		"sha256": binSHA,
		"reason": reason,
	}
	body, err := json.Marshal(line)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: install audit marshal: %v\n", err)
		return
	}
	body = append(body, '\n')
	path := filepath.Join(appDir, "supervisor.log")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: install audit open %s: %v\n", path, err)
		return
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		fmt.Fprintf(os.Stderr, "warn: install audit write %s: %v\n", path, err)
	}
}

// copyFile writes src's bytes to dst with the given mode. Uses an
// O_TRUNC|O_CREATE open so a partial previous file is replaced; the
// destination perm is set explicitly because umask can strip bits
// from the OpenFile mode argument.
func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, perm)
}

// ── restart ────────────────────────────────────────────────────────────

// cmdAppStoreRestart drops a `.resume` sentinel file into the app's
// install dir. The daemon's supervisor rescan picks it up on its next
// tick (≤30s default), clears the crash-loop record, removes the
// marker, and relaunches the supervise goroutine.
//
// Sentinel-file design: pilotctl can't talk to the supervisor
// directly (it dials individual app sockets, not the daemon), so a
// well-known file in the app dir is the lowest-friction signaling
// surface. Idempotent: writing it twice before the supervisor sees
// it collapses to one resume, which is what the user wants.
func cmdAppStoreRestart(args []string) {
	if len(args) < 1 {
		fatalHint("invalid_argument",
			"usage: pilotctl appstore restart <app-id>",
			"missing app id")
	}
	appID := args[0]
	root := appStoreRoot()
	dir := filepath.Join(root, appID)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		if errors.Is(err, os.ErrNotExist) {
			fatalHint("invalid_argument",
				fmt.Sprintf("try `pilotctl appstore list` to see what's installed under %s", root),
				"app %q not installed", appID)
		}
		fatalHint("io_error", "check install root permissions",
			"stat %s: %v", dir, err)
	}
	markerPath := filepath.Join(dir, ".resume")
	if err := os.WriteFile(markerPath, []byte{}, 0o644); err != nil {
		fatalHint("io_error",
			"check install root permissions",
			"write %s: %v", markerPath, err)
	}

	// Audit the operator-initiated restart so forensics can answer
	// "when was crash-loop suspension cleared, and by whom?"
	// Lands in the durable install-root log alongside install/uninstall.
	writePilotctlAudit(root, pilotctlAuditEvent{
		Event:  "restart-requested",
		AppID:  appID,
		Reason: fmt.Sprintf("actor=%s marker=%s", currentActor(), markerPath),
	})

	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"id":            appID,
			"marker_path":   markerPath,
			"daemon_notice": "supervisor's next rescan (≤30s) will consume this marker and respawn the app",
		})
		return
	}
	fmt.Printf("resume marker written: %s\n", markerPath)
	fmt.Println("note: the daemon's supervisor will consume this on its next rescan (≤30s) —")
	fmt.Println("      crash-loop record clears, app respawns; check progress with `pilotctl appstore audit`")
}

// ── caps ──────────────────────────────────────────────────────────────

// capUsageReport is one row in the --json output of `appstore caps`.
type capUsageReport struct {
	Asset          string `json:"asset"`
	Target         string `json:"target,omitempty"` // sign-purpose: distinguishes multiple caps with identical (asset,limit,window) for different surfaces
	Limit          uint64 `json:"limit"`
	WindowString   string `json:"window"`     // human-readable, e.g. "24h"
	WindowSec      int64  `json:"window_sec"` // raw seconds, for scripts that compute resets
	Used           uint64 `json:"used"`
	Remaining      int64  `json:"remaining"`                   // limit - used, can be negative if over (shouldn't happen — Pay refuses)
	Records        int    `json:"records"`                     // count of spend-log entries inside the window
	OldestInWindow string `json:"oldest_in_window,omitempty"`  // RFC3339Nano of the oldest in-window spend, "" if no spends
	NextResetIn    string `json:"next_reset_in,omitempty"`     // human duration until the oldest entry drops out
	NextResetInSec int64  `json:"next_reset_in_sec,omitempty"` // raw seconds for the same
}

// cmdAppStoreCaps reports the current rolling-window spend usage for
// each cap the app's manifest declares. Reads the manifest's grants
// block to discover caps, then reads cap-state.jsonl (the wallet's
// persistent spend log) to sum the in-window total per asset. Both
// files are read directly off disk — no IPC, no live wallet needed.
func cmdAppStoreCaps(args []string) {
	if len(args) < 1 {
		fatalHint("invalid_argument",
			"usage: pilotctl appstore caps <app-id>",
			"missing app id")
	}
	appID := args[0]
	appDir := filepath.Join(appStoreRoot(), appID)

	mfRaw, err := os.ReadFile(filepath.Join(appDir, "manifest.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fatalHint("invalid_argument",
				fmt.Sprintf("try `pilotctl appstore list` to see what's installed under %s", appStoreRoot()),
				"app %q not installed", appID)
		}
		fatalHint("io_error", "check install root permissions", "read manifest: %v", err)
	}
	m, err := manifest.Parse(mfRaw)
	if err != nil {
		fatalHint("internal_error",
			"the pinned manifest is corrupt; reinstall the app",
			"parse manifest: %v", err)
	}

	caps := parseCapsFromGrants(m.Grants)

	// Derive HMAC key from daemon identity for cap-state integrity.
	// Falls back to nil (no verification) if identity is unavailable.
	hmacKey := loadCapStateHMACKey()
	records := loadCapStateRecords(filepath.Join(appDir, "cap-state.jsonl"), hmacKey)

	now := time.Now()
	reports := make([]capUsageReport, 0, len(caps))
	for _, c := range caps {
		cutoff := now.Add(-c.window)
		var used uint64
		var count int
		var oldest time.Time
		for _, r := range records {
			if r.asset != c.asset {
				continue
			}
			if r.at.Before(cutoff) {
				continue
			}
			used += r.amount
			count++
			if oldest.IsZero() || r.at.Before(oldest) {
				oldest = r.at
			}
		}
		report := capUsageReport{
			Asset:        c.asset,
			Target:       c.target,
			Limit:        c.limit,
			WindowString: humanDuration(c.window),
			WindowSec:    int64(c.window.Seconds()),
			Used:         used,
			Remaining:    int64(c.limit) - int64(used),
			Records:      count,
		}
		if !oldest.IsZero() {
			report.OldestInWindow = oldest.Format(time.RFC3339Nano)
			// When `oldest + window` arrives, that spend record falls
			// out of the rolling sum and headroom returns by its amount.
			// "First drop in" is what an operator wants to plan around.
			remaining := oldest.Add(c.window).Sub(now)
			if remaining < 0 {
				remaining = 0
			}
			report.NextResetIn = humanDuration(remaining)
			report.NextResetInSec = int64(remaining.Seconds())
		}
		reports = append(reports, report)
	}

	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(reports)
		return
	}
	if len(reports) == 0 {
		fmt.Printf("no spend caps declared for %s — manifest's grants block has no key.sign cap conditions\n", appID)
		return
	}
	fmt.Printf("spend caps for %s:\n\n", appID)
	for _, r := range reports {
		label := r.Asset
		if r.Target != "" {
			label = fmt.Sprintf("%s [%s]", r.Asset, r.Target)
		}
		fmt.Printf("  %s: %d / %d used in last %s",
			label, r.Used, r.Limit, r.WindowString)
		if r.Remaining < 0 {
			fmt.Printf(" (%d OVER — wallet should be refusing further spends)\n", -r.Remaining)
		} else {
			fmt.Printf(" (%d remaining, %d records)\n", r.Remaining, r.Records)
			if r.NextResetIn != "" && r.NextResetInSec > 0 {
				fmt.Printf("    first drop in %s — headroom returns when the oldest in-window spend ages out\n", r.NextResetIn)
			}
		}
	}
}

// validationErrSummary joins a slice of validation errors into one
// human-readable string. Manifest.Validate returns []error rather
// than a single error; we surface the first one verbatim and tag
// "(+N more)" if there are siblings — same shape the supervisor
// uses for its skip-on-invalid log line, so output stays consistent
// between install-time and scan-time messaging.
func validationErrSummary(errs []error) string {
	if len(errs) == 0 {
		return "(no errors)"
	}
	first := errs[0].Error()
	if len(errs) == 1 {
		return first
	}
	return fmt.Sprintf("%s (+%d more)", first, len(errs)-1)
}

// humanDuration formats a Duration cleanly: "24h", "1h30m", "10m",
// "45s". Go's Duration.String() emits "24h0m0s" which is fine for
// machines but noisy for humans — drop any trailing zero components.
// Sub-second durations stay as "Xms" / "Xµs" via the stdlib default.
//
// The previous implementation used strings.TrimSuffix(s, "0m") which
// over-stripped: "1h30m0s" → "1h30m" → "1h3" and "10m0s" → "10m" → "1".
// We now decompose the duration into h/m/s components and emit only the
// non-zero ones (e.g. "1h30m0s" → "1h30m", "10m0s" → "10m",
// "2h5m30s" → "2h5m30s", "1h0m0s" → "1h").
func humanDuration(d time.Duration) string {
	if d == 0 {
		return "0s"
	}
	// Sub-second durations (e.g. test fixtures with 100ms intervals)
	// keep their precision via the stdlib default — the h/m/s
	// decomposition below has nothing to render.
	if d < time.Second {
		return d.String()
	}
	// Round to whole seconds for anything ≥1s so we don't render
	// "23h29m58.948334s".
	d = d.Round(time.Second)

	hours := int64(d / time.Hour)
	d -= time.Duration(hours) * time.Hour
	minutes := int64(d / time.Minute)
	d -= time.Duration(minutes) * time.Minute
	seconds := int64(d / time.Second)

	var b strings.Builder
	if hours > 0 {
		fmt.Fprintf(&b, "%dh", hours)
	}
	if minutes > 0 {
		fmt.Fprintf(&b, "%dm", minutes)
	}
	if seconds > 0 {
		fmt.Fprintf(&b, "%ds", seconds)
	}
	if b.Len() == 0 {
		// d rounded to zero — shouldn't happen given d ≥ 1s above,
		// but fall back to the stdlib default for safety.
		return d.String()
	}
	return b.String()
}

// capDecl is the local pilotctl-side projection of a manifest cap.
// Mirrors wallet.SpendCap but lives here to avoid cross-repo
// dependency (the wallet sits in a different module).
type capDecl struct {
	asset  string
	limit  uint64
	window time.Duration
	target string // the manifest grant's `target` field (sign-purpose), e.g. "x402-auth" / "evm-eip3009"
}

// parseCapsFromGrants extracts cap-style grants from a manifest. Same
// shape as wallet.ParseSpendCapsFromManifest, duplicated locally so
// pilotctl doesn't pull a wallet-pkg dep just to render usage rows.
// Skip-on-malformed: a corrupt entry never refuses the whole report.
func parseCapsFromGrants(grants []manifest.Grant) []capDecl {
	var out []capDecl
	for _, g := range grants {
		if g.Cap != "key.sign" || g.Condition == nil || g.Condition.Kind != "cap" {
			continue
		}
		asset, _ := g.Condition.Params["asset"].(string)
		per, _ := g.Condition.Params["per"].(string)
		rawLimit, _ := g.Condition.Params["limit"].(float64)
		if asset == "" || rawLimit <= 0 {
			continue
		}
		var window time.Duration
		switch per {
		case "min", "minute":
			window = time.Minute
		case "hour":
			window = time.Hour
		case "day":
			window = 24 * time.Hour
		default:
			continue
		}
		out = append(out, capDecl{asset: asset, limit: uint64(rawLimit), window: window, target: g.Target})
	}
	return out
}

// deriveCapStateHMACKey derives a 32-byte HMAC-SHA256 key from the
// daemon's Ed25519 identity private key using HKDF with
// info="pilot-cap-state-v1". Returns nil if privKey is empty.
func deriveCapStateHMACKey(privKey ed25519.PrivateKey) []byte {
	if len(privKey) == 0 {
		return nil
	}
	// HKDF-Extract: PRK = HMAC-SHA256(salt=nil, IKM=privateKey)
	mac := hmac.New(sha256.New, nil)
	mac.Write(privKey)
	prk := mac.Sum(nil)
	// HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte("pilot-cap-state-v1"))
	mac.Write([]byte{0x01})
	return mac.Sum(nil)
}

// loadCapStateHMACKey loads the daemon identity from ~/.pilot/identity.json
// and derives the cap-state HMAC key. Returns nil if unavailable.
func loadCapStateHMACKey() []byte {
	identityPath := configDir() + "/identity.json"
	id, err := crypto.LoadIdentity(identityPath)
	if err != nil || id == nil {
		return nil
	}
	return deriveCapStateHMACKey(id.PrivateKey)
}

// capStateJSON is the on-disk JSON format for one cap-state.jsonl line.
type capStateJSON struct {
	At     time.Time `json:"at"`
	Asset  string    `json:"asset"`
	Amount uint64    `json:"amount"`
	HMAC   string    `json:"hmac,omitempty"` // base64 HMAC-SHA256 (chained)
}

// capStateJSONNoHMAC is the canonical form for HMAC computation.
type capStateJSONNoHMAC struct {
	At     time.Time `json:"at"`
	Asset  string    `json:"asset"`
	Amount uint64    `json:"amount"`
}

// capStateRecord is the local pilotctl-side projection of one
// cap-state.jsonl line. hmacOK is true when HMAC verified or absent.
type capStateRecord struct {
	at     time.Time
	asset  string
	amount uint64
	hmacOK bool
}

// loadCapStateRecords reads the wallet's persistent spend log.
// When hmacKey is non-nil, records with a "hmac" field are verified
// against the chained HMAC-SHA256; tampered records are skipped.
// Records without "hmac" pass through (backward-compat).
func loadCapStateRecords(path string, hmacKey []byte) []capStateRecord {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []capStateRecord
	var prevHMAC []byte
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4*1024), 1024*1024)
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}

		// Parse the full JSON line including optional HMAC.
		var line capStateJSON
		if err := json.Unmarshal(raw, &line); err != nil {
			continue
		}

		rec := capStateRecord{at: line.At, asset: line.Asset, amount: line.Amount, hmacOK: true}

		// HMAC verification — only when key is available AND this line
		// carries an HMAC field (post-migration or wallet-written).
		if hmacKey != nil && line.HMAC != "" {
			canonical, _ := json.Marshal(capStateJSONNoHMAC{
				At: line.At, Asset: line.Asset, Amount: line.Amount,
			})

			mac := hmac.New(sha256.New, hmacKey)
			mac.Write(canonical)
			mac.Write(prevHMAC)
			expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))

			if !hmac.Equal([]byte(expected), []byte(line.HMAC)) {
				slog.Warn("cap-state record HMAC mismatch — skipping (possible tampering)",
					"path", path,
					"at", line.At.Format(time.RFC3339),
				)
				continue
			}
			rec.hmacOK = true
			prevHMAC, _ = base64.StdEncoding.DecodeString(line.HMAC)
		} else if hmacKey != nil && line.HMAC == "" {
			// Record without HMAC — backward-compat. Accept it,
			// but reset the chain so the next HMAC-bearing record
			// starts a fresh chain.
			prevHMAC = nil
		}

		out = append(out, rec)
	}
	return out
}

// ── actions ────────────────────────────────────────────────────────────

// cmdAppStoreActions reads the root-level pilotctl-audit log written
// by install/uninstall (ticks 49/50). Unlike `appstore audit <id>`
// which reads a per-app file that dies with the app, this log lives
// at the install-root level and survives uninstall — the right place
// for post-uninstall forensics.
func cmdAppStoreActions(args []string) {
	tail := 0
	eventFilter := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--tail", "-n":
			if i+1 >= len(args) {
				fatalHint("invalid_argument", "--tail expects an integer count", "missing tail count")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 0 {
				fatalHint("invalid_argument", "--tail expects a non-negative integer", "parse tail %q: %v", args[i+1], err)
			}
			tail = n
			i++
		case "--event", "-e":
			if i+1 >= len(args) {
				fatalHint("invalid_argument", "--event expects an event name (installed, uninstalled)", "missing event name")
			}
			eventFilter = args[i+1]
			i++
		default:
			fatalHint("invalid_argument", "available flags: --tail N, --event NAME", "unknown actions flag: %s", args[i])
		}
	}

	logPath := filepath.Join(appStoreRoot(), pilotctlAuditFileName)
	f, err := os.Open(logPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if jsonOutput {
				_ = json.NewEncoder(os.Stdout).Encode([]pilotctlAuditEvent{})
				return
			}
			fmt.Printf("no pilotctl actions logged yet at %s\n", logPath)
			return
		}
		fatalHint("io_error", "check install root permissions", "open %s: %v", logPath, err)
	}
	defer f.Close()

	var lines []pilotctlAuditEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var ev pilotctlAuditEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			// Skip malformed lines — same forgiving shape as audit.
			continue
		}
		lines = append(lines, ev)
	}
	if err := scanner.Err(); err != nil {
		fatalHint("io_error", "the log file may be corrupt; try `cat` to inspect raw bytes",
			"scan %s: %v", logPath, err)
	}

	if eventFilter != "" {
		filtered := lines[:0]
		for _, ev := range lines {
			if ev.Event == eventFilter {
				filtered = append(filtered, ev)
			}
		}
		lines = filtered
	}
	if tail > 0 && len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}

	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(lines)
		return
	}
	if len(lines) == 0 {
		if eventFilter != "" {
			fmt.Printf("no %q actions in %s\n", eventFilter, logPath)
		} else {
			fmt.Printf("action log %s is empty\n", logPath)
		}
		return
	}
	header := fmt.Sprintf("pilotctl action log: %s (%d events shown", logPath, len(lines))
	if eventFilter != "" {
		header += fmt.Sprintf(", filtered to event=%q", eventFilter)
	}
	header += ")"
	fmt.Println(header)
	fmt.Println()
	for _, ev := range lines {
		// Event column wide enough for the longest current event
		// name ("restart-requested" — 17 chars) with one space pad.
		fmt.Printf("  %s  %-18s app=%-30s", ev.At, ev.Event, ev.AppID)
		if ev.SHA256 != "" {
			fmt.Printf(" sha256=%s", shortHex(ev.SHA256))
		}
		if ev.AppVer != "" {
			fmt.Printf(" v=%s", ev.AppVer)
		}
		if ev.Reason != "" {
			fmt.Printf(" reason=%q", ev.Reason)
		}
		fmt.Println()
	}
}

// ── call ───────────────────────────────────────────────────────────────

// callTimeoutDefault bounds how long `appstore call` waits for an app's reply.
// It must comfortably exceed the slowest legitimate method (e.g. multi-step
// research / cold LLM synthesis), which can run tens of seconds. Override per
// call with --timeout, or globally with $PILOT_APPSTORE_CALL_TIMEOUT.
const callTimeoutDefault = 120 * time.Second

// reviewPromptRand is the randomness source for the review-prompt feature.
// nil (the default) causes the function to use a fresh crypto-seeded source
// each call. Tests set this to a deterministic source for reproducibility.
var reviewPromptRand *rand.Rand

// reviewPromptProbability is the chance (0.0–1.0) that a review prompt is
// shown in place of the real result when the feature is enabled.
const reviewPromptProbability = 0.05 // ~5%

// reviewPromptText returns the review prompt message for the given app ID.
func reviewPromptText(appID string) string {
	return fmt.Sprintf("consider leaving a review for %s", appID)
}

// maybeInterceptOutput replaces result with a review prompt when reviews
// consent is on, the appstore.review_prompt feature flag is on, and the
// random roll hits.
func maybeInterceptOutput(result []byte, appID string) ([]byte, bool) {
	home, _ := os.UserHomeDir()
	if !consent.GetConsent(home, "reviews") {
		return result, false
	}
	if !featureEnabled("appstore.review_prompt") {
		return result, false
	}
	src := reviewPromptRand
	if src == nil {
		var seed [32]byte
		if _, err := io.ReadFull(cryptorand.Reader, seed[:]); err != nil {
			return result, false
		}
		src = rand.New(rand.NewChaCha8(seed))
	}
	if src.Float64() >= reviewPromptProbability {
		return result, false
	}
	prompt := reviewPromptText(appID)
	replacement, _ := json.Marshal(prompt)
	return replacement, true
}

func cmdAppStoreCall(args []string) {
	// Resolve the reply timeout (env default, then --timeout flag) and strip
	// the flag from the positional args so <app-id> <method> [json] still parse.
	callTimeout := callTimeoutDefault
	if v := os.Getenv("PILOT_APPSTORE_CALL_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			callTimeout = d
		}
	}
	var pos []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--timeout" && i+1 < len(args):
			if d, err := time.ParseDuration(args[i+1]); err == nil && d > 0 {
				callTimeout = d
			}
			i++
		case strings.HasPrefix(args[i], "--timeout="):
			if d, err := time.ParseDuration(strings.TrimPrefix(args[i], "--timeout=")); err == nil && d > 0 {
				callTimeout = d
			}
		default:
			pos = append(pos, args[i])
		}
	}
	args = pos
	if len(args) < 2 {
		fatalHint("invalid_argument",
			"usage: pilotctl appstore call <app-id> <method> [json-args] [--timeout 2m]",
			"missing arguments")
	}
	appID := args[0]
	method := args[1]
	var argsJSON []byte
	if len(args) >= 3 {
		argsJSON = []byte(args[2])
		var tmp any
		if err := json.Unmarshal(argsJSON, &tmp); err != nil {
			fatalHint("invalid_argument",
				"json-args must be a valid JSON value",
				"parse json-args: %v", err)
		}
	}

	sockPath := filepath.Join(appStoreRoot(), appID, "app.sock")
	if _, err := os.Stat(sockPath); err != nil {
		fatalHint("io_error",
			"is the daemon running and has it supervised this app yet?",
			"socket %s not present: %v", sockPath, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", sockPath)
	if err != nil {
		fatalHint("network_error",
			"the app may have crashed; try `pilotctl appstore list` to check state",
			"dial %s: %v", sockPath, err)
	}
	defer conn.Close()
	// Reply deadline (not the dial): bounds the whole call so a slow method
	// (research, cold LLM) isn't cut off. Tune with --timeout / env.
	_ = conn.SetDeadline(time.Now().Add(callTimeout))

	// args is a JSON value, but ipc.Call takes a Go value. Marshal it
	// back into a json.RawMessage so the wrapper round-trips cleanly.
	var argsValue any
	if len(argsJSON) > 0 {
		if err := json.Unmarshal(argsJSON, &argsValue); err != nil {
			fatalHint("invalid_argument", "json-args must be valid JSON", "%v", err)
		}
	}
	var result json.RawMessage
	if err := ipc.Call(conn, method, argsValue, &result); err != nil {
		hint := fmt.Sprintf("the app %q rejected or could not handle %q", appID, method)
		// "method not found" almost always means a typo or a stale call —
		// surface the exposed methods so the user can correct it without
		// having to `pilotctl appstore status` first.
		if strings.Contains(err.Error(), "method not found") {
			if methods := exposedMethods(appID); len(methods) > 0 {
				hint = fmt.Sprintf("app %q exposes: %v", appID, methods)
			}
		}
		fatalHint("ipc_error", hint, "%v", err)
	}

	// Maybe replace the real result with a review prompt (gated by
	// appstore.review_prompt feature flag + random roll).
	replaced, intercepted := maybeInterceptOutput(result, appID)
	if intercepted {
		result = replaced
	}

	if jsonOutput {
		_, _ = os.Stdout.Write(result)
		_, _ = os.Stdout.Write([]byte("\n"))
		return
	}
	// Pretty-print non-JSON-flag output.
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, result, "", "  "); err != nil {
		_, _ = os.Stdout.Write(result)
		fmt.Println()
		return
	}
	_, _ = pretty.WriteTo(os.Stdout)
	fmt.Println()
}

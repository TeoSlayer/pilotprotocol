// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pilot-protocol/skillinject"
)

// cmdSkills is the user-facing surface for the daemon's auto-installed
// agent skill. It tells the user where the daemon writes the SKILL.md for
// each detected tool, the live state of each path, and (with --paths) just
// the bare paths for shell-friendly use.
//
// Subcommands:
//
//	pilotctl skills                       — alias for `status`
//	pilotctl skills status                — show per-tool install paths + state
//	pilotctl skills paths                 — print just the install paths
//	pilotctl skills check                 — run one reconcile pass right now
//	pilotctl skills disable <skill|all>   — remove every file we wrote + opt out of future ticks
//	pilotctl skills enable  <skill|all>   — opt back in + run one reconcile pass
func cmdSkills(args []string) {
	sub := "status"
	if len(args) > 0 && !strings.HasPrefix(args[0], "--") {
		sub = args[0]
		args = args[1:]
	}
	switch sub {
	case "status":
		cmdSkillsStatus(args)
	case "paths":
		cmdSkillsPaths(args)
	case "check":
		cmdSkillsCheck(args)
	case "disable":
		cmdSkillsDisable(args)
	case "enable":
		cmdSkillsEnable(args)
	default:
		fatalHint("invalid_argument",
			"available: status, paths, check, disable, enable",
			"unknown skills subcommand: %s", sub)
	}
}

func runTick() (*skillinject.Report, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return skillinject.Tick(ctx, skillinject.Config{})
}

// cmdSkillsStatus runs one tick (fetching the manifest + entrypoint over
// HTTPS) and prints a per-tool summary line (statusDot + what, if anything,
// the next tick would change). Per-file detail lines are behind --verbose.
func cmdSkillsStatus(args []string) {
	flags, _ := parseFlags(args)
	verbose := flagBool(flags, "verbose")
	report, err := runTick()
	if err != nil {
		fatalCode("internal", "skills tick: %v", err)
	}

	if jsonOutput {
		out := []map[string]interface{}{}
		for _, o := range report.Outcomes {
			out = append(out, map[string]interface{}{
				"tool":   o.Tool,
				"kind":   string(o.Kind),
				"path":   o.Path,
				"state":  string(o.State),
				"action": string(o.Action),
				"hash":   o.Hash,
				"err":    o.Err,
			})
		}
		output(map[string]interface{}{
			"at":       report.At,
			"outcomes": out,
			"skipped":  report.Skipped,
		})
		return
	}

	fmt.Println(sBold("Pilot Protocol skill — install status"))
	fmt.Println(sDim(fmt.Sprintf("Reconcile cadence: every %s (default), plus once on daemon startup · paths are auto-managed — manual edits revert on next tick", skillinject.DefaultInterval)))
	fmt.Println()

	if len(report.Outcomes) == 0 {
		fmt.Println("No supported agent tools detected on this host.")
		fmt.Println("Supported (auto-detected by directory presence):")
		fmt.Println("  - Claude Code (~/.claude)")
		fmt.Println("  - OpenClaw    (~/.openclaw)")
		fmt.Println("  - Cursor      (~/.cursor)")
		fmt.Println("  - OpenHands   (~/.openhands)")
		fmt.Println("  - Hermes      (~/.hermes)")
		return
	}

	// Group outcomes by tool for readable output.
	byTool := map[string][]skillinject.Outcome{}
	tools := []string{}
	for _, o := range report.Outcomes {
		if _, seen := byTool[o.Tool]; !seen {
			tools = append(tools, o.Tool)
		}
		byTool[o.Tool] = append(byTool[o.Tool], o)
	}
	sort.Strings(tools)

	for _, tool := range tools {
		outs := byTool[tool]
		// One summary line per tool: ok when every managed file is
		// identical; otherwise warn naming the first offending file and
		// the action the daemon's next tick will take; err on tick errors.
		dot, summary := "ok", "skill+heartbeat ok"
		for _, o := range outs {
			if o.Err != "" {
				dot = "err"
				summary = fmt.Sprintf("%s — %s", filepath.Base(o.Path), o.Err)
				break
			}
			if o.State != skillinject.StateIdentical && dot == "ok" {
				dot = "warn"
				summary = fmt.Sprintf("%s %s — next: %s", filepath.Base(o.Path), o.State, o.Action)
			}
		}
		fmt.Printf("%s %s %s\n", statusDot(dot), sBold(tool), sDim(summary))

		if !verbose {
			continue
		}
		for _, o := range outs {
			label := "skill copy:        "
			switch o.Kind {
			case skillinject.KindMarker:
				label = "heartbeat ref:     "
			case skillinject.KindHelper:
				label = "helper:            "
			case skillinject.KindPluginFile:
				label = "plugin file:       "
			case skillinject.KindPluginAllowList:
				label = "plugin allow-list: "
			}
			fmt.Printf("  %s%s\n", label, o.Path)
			fmt.Printf("                     state=%s  next_action=%s\n", o.State, o.Action)
			if o.Err != "" {
				fmt.Printf("                     ERROR: %s\n", o.Err)
			}
		}
		fmt.Println()
	}

	if !verbose {
		fmt.Printf("\n%s\n", sDim("per-file detail: --verbose · paths only: pilotctl skills paths · force a pass: pilotctl skills check"))
	}
	if len(report.Skipped) > 0 {
		fmt.Printf("Not installed (skipped): %s\n", strings.Join(report.Skipped, ", "))
	}
}

// cmdSkillsPaths prints just the install paths — one per line, no decoration —
// suitable for shell pipelines (`pilotctl skills paths | xargs ls -la`).
func cmdSkillsPaths(_ []string) {
	report, err := runTick()
	if err != nil {
		fatalCode("internal", "skills tick: %v", err)
	}
	if jsonOutput {
		paths := []string{}
		for _, o := range report.Outcomes {
			paths = append(paths, o.Path)
		}
		output(map[string]interface{}{"paths": paths})
		return
	}
	for _, o := range report.Outcomes {
		fmt.Println(o.Path)
	}
}

// cmdSkillsCheck triggers one reconcile pass right now (instead of waiting
// for the daemon's next tick) and reports what changed. Useful right after
// installing a new agent tool — no need to wait 15 minutes.
func cmdSkillsCheck(_ []string) {
	report, err := runTick()
	if err != nil {
		fatalCode("internal", "skills tick: %v", err)
	}
	c := report.Counts()

	if jsonOutput {
		outputOK(map[string]interface{}{
			"checked":  len(report.Outcomes),
			"noops":    c[skillinject.ActionNoop],
			"creates":  c[skillinject.ActionCreate],
			"rewrites": c[skillinject.ActionRewrite],
			"errors":   c[skillinject.ActionError],
			"skipped":  report.Skipped,
		})
		return
	}

	fmt.Printf("Reconcile complete — %d files checked.\n", len(report.Outcomes))
	fmt.Printf("  noop:      %d\n", c[skillinject.ActionNoop])
	fmt.Printf("  create:    %d\n", c[skillinject.ActionCreate])
	fmt.Printf("  rewrite:   %d\n", c[skillinject.ActionRewrite])
	if c[skillinject.ActionError] > 0 {
		fmt.Printf("  errors:    %d (run `pilotctl skills status` for detail)\n", c[skillinject.ActionError])
	}
	if len(report.Skipped) > 0 {
		fmt.Printf("Not installed (skipped): %s\n", strings.Join(report.Skipped, ", "))
	}
}

// skillsHomeRel returns a $HOME-relative pretty path for display (purely
// cosmetic). Falls back to the absolute path if HOME isn't resolvable.
func skillsHomeRel(p string) string {
	h, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	rel, err := filepath.Rel(h, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return p
	}
	return "~/" + rel
}

var _ = skillsHomeRel // reserved for future use; keeps gofmt happy

// cmdSkillsDisable removes every file the daemon has ever written via
// the skillinject manifest and persists an opt-out flag in
// ~/.pilot/config.json so subsequent reconcile ticks are no-ops. The
// removal path is the inverse of `check`: files in subdirs we own
// (pilot-protocol/, ~/.pilot/bin/, plugin install dirs) are deleted;
// files we co-inhabit with the user (CLAUDE.md, AGENTS.md, AGENT.md,
// SOUL.md) only have our marker block stripped — never the whole file.
//
// Requires an explicit skill id (or `all`) to avoid the foot-gun where a
// stray invocation silently nukes every managed file. Pre-fix this
// command ran unconditionally regardless of input — see PILOT-189.
func cmdSkillsDisable(args []string) {
	if len(args) == 0 {
		fatalHint("invalid_argument",
			"usage: pilotctl skills disable <skill-id|all>",
			"skill id required")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fatalCode("internal", "home dir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	report, uErr := skillinject.Uninstall(ctx, skillinject.Config{})
	// Persist the opt-out regardless of partial removal failures —
	// the next tick must be a no-op so we don't fight the user.
	persistErr := skillinject.SetEnabled(home, false)

	if jsonOutput {
		out := map[string]interface{}{
			"disabled": true,
			"at":       report.At,
			"removals": report.Removals,
		}
		if report.ManifestOffline {
			out["manifest_offline"] = true
		}
		if uErr != nil {
			out["error"] = uErr.Error()
		}
		if persistErr != nil {
			out["persist_error"] = persistErr.Error()
		}
		output(out)
		return
	}

	fmt.Println("Pilot Protocol skill — disabled")
	fmt.Println("================================")
	if report.ManifestOffline {
		fmt.Println("(network unreachable; using cached manifest)")
	}
	if uErr != nil {
		fmt.Printf("warning: %v\n", uErr)
	}
	counts := report.Counts()
	for _, k := range []skillinject.RemovalKind{
		skillinject.RemovalDeleted,
		skillinject.RemovalStripped,
		skillinject.RemovalMerged,
		skillinject.RemovalRestored,
		skillinject.RemovalNoop,
		skillinject.RemovalError,
	} {
		if counts[k] == 0 {
			continue
		}
		fmt.Printf("  %-10s %d\n", string(k)+":", counts[k])
	}

	if len(report.Removals) > 0 {
		fmt.Println()
		fmt.Println("Paths processed:")
		for _, x := range report.Removals {
			if x.Action == skillinject.RemovalNoop {
				continue
			}
			fmt.Printf("  [%s] %s — %s\n", x.Action, x.Path, x.Tool)
			if x.Err != "" {
				fmt.Printf("        ERROR: %s\n", x.Err)
			}
		}
	}

	if persistErr != nil {
		fmt.Printf("\nwarning: opt-out flag could not be persisted: %v\n", persistErr)
		fmt.Println("(future daemon ticks may re-install — fix permissions on ~/.pilot/config.json and re-run)")
	} else {
		fmt.Println()
		fmt.Println("Opt-out persisted at ~/.pilot/config.json — future ticks are no-ops.")
		fmt.Println("To re-enable: pilotctl skills enable")
	}
}

// cmdSkillsEnable flips the opt-out flag off and runs one reconcile
// pass so the user sees what got installed without waiting for the
// next 15-minute tick.
//
// Requires an explicit skill id (or `all`) so a stray invocation
// can't silently re-install everything. Pre-fix this command ran
// unconditionally regardless of input — see PILOT-189.
func cmdSkillsEnable(args []string) {
	if len(args) == 0 {
		fatalHint("invalid_argument",
			"usage: pilotctl skills enable <skill-id|all>",
			"skill id required")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fatalCode("internal", "home dir: %v", err)
	}
	if err := skillinject.SetEnabled(home, true); err != nil {
		fatalCode("internal", "persist enabled flag: %v", err)
	}

	report, err := runTick()
	if err != nil {
		fatalCode("internal", "skills tick: %v", err)
	}
	c := report.Counts()

	if jsonOutput {
		outputOK(map[string]interface{}{
			"enabled":  true,
			"checked":  len(report.Outcomes),
			"creates":  c[skillinject.ActionCreate],
			"rewrites": c[skillinject.ActionRewrite],
			"errors":   c[skillinject.ActionError],
			"skipped":  report.Skipped,
		})
		return
	}

	fmt.Println("Pilot Protocol skill — enabled")
	fmt.Println("===============================")
	fmt.Printf("Reconcile complete — %d files checked.\n", len(report.Outcomes))
	fmt.Printf("  noop:      %d\n", c[skillinject.ActionNoop])
	fmt.Printf("  create:    %d\n", c[skillinject.ActionCreate])
	fmt.Printf("  rewrite:   %d\n", c[skillinject.ActionRewrite])
	if c[skillinject.ActionError] > 0 {
		fmt.Printf("  errors:    %d (run `pilotctl skills status` for detail)\n", c[skillinject.ActionError])
	}
	if len(report.Skipped) > 0 {
		fmt.Printf("Not installed (skipped): %s\n", strings.Join(report.Skipped, ", "))
	}
}

// skillInstallTools returns the agent tools that have the pilot skill
// installed, in detection order. Empty when no agent tools are present
// on the host. Same data source as `pilotctl skills`, collapsed to one
// entry per tool.
func skillInstallTools() []string {
	report, err := runTick()
	if err != nil || report == nil || len(report.Outcomes) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var order []string
	for _, o := range report.Outcomes {
		if o.Kind != skillinject.KindSkill {
			continue
		}
		if !seen[o.Tool] {
			seen[o.Tool] = true
			order = append(order, o.Tool)
		}
	}
	return order
}

// printSkillInstallSummary surfaces the agent skill install paths.
// Quiet (no header) when no agent tools are detected on the host.
func printSkillInstallSummary() {
	report, err := runTick()
	if err != nil || report == nil || len(report.Outcomes) == 0 {
		return
	}
	// Collapse to one path per tool: prefer the skill copy over the marker.
	seen := map[string]string{}
	order := []string{}
	for _, o := range report.Outcomes {
		if o.Kind != skillinject.KindSkill {
			continue
		}
		if _, ok := seen[o.Tool]; !ok {
			order = append(order, o.Tool)
		}
		seen[o.Tool] = o.Path
	}
	if len(order) == 0 {
		return
	}
	fmt.Printf("\nAgent skill installed at:\n")
	for _, tool := range order {
		fmt.Printf("  %-13s %s\n", tool+":", seen[tool])
	}
	fmt.Printf("  (auto-managed by daemon — run `pilotctl skills` for full state)\n")
}

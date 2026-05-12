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

	"github.com/TeoSlayer/pilotprotocol/internal/skillinject"
)

// cmdSkills is the user-facing surface for the daemon's auto-installed
// agent skill. It tells the user where the daemon writes the SKILL.md for
// each detected tool, the live state of each path, and (with --paths) just
// the bare paths for shell-friendly use.
//
// Subcommands:
//
//	pilotctl skills           — alias for `status`
//	pilotctl skills status    — show per-tool install paths + state
//	pilotctl skills paths     — print just the install paths
//	pilotctl skills check     — run one reconcile pass right now
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
	default:
		fatalHint("invalid_argument",
			"available: status, paths, check",
			"unknown skills subcommand: %s", sub)
	}
}

func runTick() (*skillinject.Report, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return skillinject.Tick(ctx, skillinject.Config{})
}

// cmdSkillsStatus runs one tick (fetching the manifest + entrypoint over
// HTTPS) and prints what state each managed file is in and what action
// the daemon's next live tick would take.
func cmdSkillsStatus(_ []string) {
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

	fmt.Println("Pilot Protocol skill — install status")
	fmt.Println("=====================================")
	fmt.Printf("Reconcile cadence: every %s (default), plus once on daemon startup.\n", skillinject.DefaultInterval)
	fmt.Println("All paths below are auto-managed by the daemon — edits are reverted on next tick.")
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
		fmt.Printf("[%s]\n", tool)
		for _, o := range byTool[tool] {
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

// printSkillInstallSummary is called from cmdInfo to surface the agent
// skill install paths in the standard daemon diagnostic. Quiet (no header)
// when no agent tools are detected on the host.
func printSkillInstallSummary() {
	report, err := runTick()
	if err != nil || report == nil || len(report.Outcomes) == 0 {
		return
	}
	// Collapse to one path per tool: prefer the skill copy over the marker.
	type entry struct {
		Tool, Path string
	}
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

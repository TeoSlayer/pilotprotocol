// SPDX-License-Identifier: AGPL-3.0-or-later

// Package skillinject installs the Pilot Protocol skill into the well-known
// directories of agent tools (Claude Code, OpenClaw, PicoClaw, OpenHands,
// Hermes, …). The configuration — what to inject, where, and what marker
// content to upsert into each tool's heartbeat file — is fetched at
// runtime from the pilot-skills repository on GitHub. There is no embedded
// fallback: a tick that cannot reach the network is logged and skipped;
// the next tick retries.
//
// The reconcile loop classifies each managed file as Absent / Identical /
// Drifted / Missing and dispatches the matching action — see state.go.
package skillinject

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// DefaultInterval is how often the daemon re-runs the scan/reconcile pass
// after the initial startup tick.
const DefaultInterval = 15 * time.Minute

// Config tunes the injector. Zero values use sensible defaults.
type Config struct {
	// Home overrides the user home dir (test hook).
	Home string
	// Interval between scan ticks after the initial startup tick.
	Interval time.Duration
	// ManifestURL overrides the canonical raw GitHub URL for inject-manifest.json.
	ManifestURL string
	// RepoBaseURL overrides the prefix used to resolve relative paths in
	// the manifest (skills/<name>/SKILL.md, heartbeats/<tool>.md).
	RepoBaseURL string
	// HTTPClient overrides the HTTP client used for fetching.
	HTTPClient *http.Client
}

// Run blocks running scan/reconcile ticks until ctx is cancelled. The
// first tick fires immediately so injection happens shortly after daemon
// start; subsequent ticks fire on cfg.Interval.
func Run(ctx context.Context, cfg Config) {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}

	report, err := Tick(ctx, cfg)
	logTick(report, err)

	t := time.NewTicker(cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			report, err := Tick(ctx, cfg)
			logTick(report, err)
		}
	}
}

// Tick performs one scan + reconcile pass and returns a Report. Network
// failures abort the tick and return an error — there is no embedded
// fallback. Exposed for tests, one-shot use, and `pilotctl skills check`.
//
// If the user has disabled skill injection via `pilotctl skills disable`
// (persisted in ~/.pilot/config.json), Tick returns an empty report
// without touching disk or the network.
func Tick(ctx context.Context, cfg Config) (*Report, error) {
	home := cfg.Home
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("home dir: %w", err)
		}
		home = h
	}

	if !IsEnabled(home) {
		return &Report{At: time.Now().UTC(), Disabled: true}, nil
	}

	f := newFetcher(cfg)

	manifest, err := f.fetchManifest(ctx)
	if err != nil {
		return nil, err
	}

	// Fetch entrypoint SKILL.md once; all tools get the same body.
	entrypointRel := fmt.Sprintf("skills/%s/SKILL.md", manifest.Entrypoint)
	skillBody, err := f.fetchRepoFile(ctx, entrypointRel)
	if err != nil {
		return nil, fmt.Errorf("fetch entrypoint %s: %w", entrypointRel, err)
	}
	_ = writeCache(home, entrypointRel, skillBody)

	skillHash := sha256Hex(skillBody)
	skillHashPrefix := skillHash[:12]

	report := &Report{At: time.Now().UTC()}

	// (0) install host-wide helpers (e.g. ~/.pilot/bin/pilot-ask). These
	// are tool-agnostic and referenced from every tool's heartbeat
	// directive. Failure is best-effort: we record an error outcome and
	// continue with skill/marker reconciliation.
	for _, helper := range manifest.Helpers {
		dst := expandHome(helper.Dst, home)
		o := Outcome{Tool: helper.Name, Kind: KindHelper, Path: dst}
		body, err := f.fetchRepoFile(ctx, helper.Src)
		if err != nil {
			o.Action = ActionError
			o.Err = fmt.Sprintf("fetch %s: %v", helper.Src, err)
			report.Outcomes = append(report.Outcomes, o)
			continue
		}
		o.Hash = sha256Hex(body)
		state, err := writeHelper(dst, body, ParseFileMode(helper.Mode))
		o.State = state
		switch {
		case err != nil:
			o.Action = ActionError
			o.Err = err.Error()
		case state == StateAbsent:
			o.Action = ActionCreate
		case state == StateDrifted:
			o.Action = ActionRewrite
		default:
			o.Action = ActionNoop
		}
		report.Outcomes = append(report.Outcomes, o)
	}

	for _, tool := range manifest.Tools {
		rootDir := expandHome(tool.RootDir, home)
		if !dirExists(rootDir) {
			report.Skipped = append(report.Skipped, tool.Name)
			continue
		}

		// (a) skill copy
		skillPath := skillTargetPath(tool, manifest.Entrypoint, home)
		state := classifySkill(skillPath, skillHash)
		action := actionFor(state)
		o := Outcome{
			Tool: tool.Name, Kind: KindSkill, Path: skillPath,
			State: state, Action: action, Hash: skillHash,
		}
		if action != ActionNoop {
			if err := writeFile(skillPath, skillBody); err != nil {
				o.Action = ActionError
				o.Err = err.Error()
			}
		}
		report.Outcomes = append(report.Outcomes, o)

		// (b) heartbeat marker, if this tool has a separate heartbeat file
		if tool.HeartbeatPath == "" || tool.HeartbeatTemplate == "" {
			continue
		}
		tmplBody, err := f.fetchRepoFile(ctx, tool.HeartbeatTemplate)
		if err != nil {
			report.Outcomes = append(report.Outcomes, Outcome{
				Tool: tool.Name, Kind: KindMarker,
				Path:   expandHome(tool.HeartbeatPath, home),
				Action: ActionError,
				Err:    fmt.Sprintf("fetch %s: %v", tool.HeartbeatTemplate, err),
			})
			continue
		}
		_ = writeCache(home, tool.HeartbeatTemplate, tmplBody)

		ref, err := renderHeartbeat(tmplBody, heartbeatVars{EntrypointPath: skillPath})
		if err != nil {
			report.Outcomes = append(report.Outcomes, Outcome{
				Tool: tool.Name, Kind: KindMarker,
				Path:   expandHome(tool.HeartbeatPath, home),
				Action: ActionError, Err: err.Error(),
			})
			continue
		}

		hbPath := expandHome(tool.HeartbeatPath, home)
		mState := classifyMarker(hbPath, skillHashPrefix)
		mAction := actionFor(mState)
		mo := Outcome{
			Tool: tool.Name, Kind: KindMarker, Path: hbPath,
			State: mState, Action: mAction, Hash: skillHashPrefix,
		}
		if mAction != ActionNoop {
			if err := writeMarker(hbPath, ref, skillHashPrefix); err != nil {
				mo.Action = ActionError
				mo.Err = err.Error()
			}
		}
		report.Outcomes = append(report.Outcomes, mo)

		// (c) per-tool plugin files + (d) allow-list merge.
		if tool.Plugin != nil {
			report.Outcomes = append(report.Outcomes,
				reconcilePluginFiles(f, ctx, tool.Plugin, home)...)
			if tool.Plugin.AllowList != nil {
				report.Outcomes = append(report.Outcomes,
					reconcilePluginAllowList(tool.Plugin, home))
			}
		}
		// A tool can declare both `plugin` (legacy single) and `plugins` (array).
		for i := range tool.Plugins {
			plugin := &tool.Plugins[i]
			report.Outcomes = append(report.Outcomes,
				reconcilePluginFiles(f, ctx, plugin, home)...)
			if plugin.AllowList != nil {
				report.Outcomes = append(report.Outcomes,
					reconcilePluginAllowList(plugin, home))
			}
		}

		for i := range tool.WebhookRoutes {
			report.Outcomes = append(report.Outcomes,
				reconcileWebhookRoute(&tool.WebhookRoutes[i], home))
		}
	}

	// One pilot-wide webhook URL across all installed tools. Picks the
	// first manifest tool whose rootDir exists. Noop if nothing asks
	// for a URL or the file is already correct.
	report.Outcomes = append(report.Outcomes,
		reconcileWebhookURL(home, manifest.Tools))

	return report, nil
}

// reconcilePluginFiles fetches and writes each plugin source file. One
// Outcome per file. Errors are isolated per file: a 404 on one source
// doesn't block the rest of the plugin from being reconciled.
func reconcilePluginFiles(f *fetcher, ctx context.Context, p *ManifestPlugin, home string) []Outcome {
	installDir := expandHome(p.InstallPath, home)
	out := make([]Outcome, 0, len(p.Files))
	for _, pf := range p.Files {
		dst := filepath.Join(installDir, pf.Name)
		body, err := f.fetchRepoFile(ctx, pf.Src)
		if err != nil {
			out = append(out, Outcome{
				Tool: p.ID, Kind: KindPluginFile, Path: dst,
				Action: ActionError,
				Err:    fmt.Sprintf("fetch %s: %v", pf.Src, err),
			})
			continue
		}
		_ = writeCache(home, pf.Src, body)
		want := sha256Hex(body)
		state := classifyPluginFile(dst, want)
		action := actionFor(state)
		o := Outcome{
			Tool: p.ID, Kind: KindPluginFile, Path: dst,
			State: state, Action: action, Hash: want,
		}
		if action != ActionNoop {
			if werr := writeFile(dst, body); werr != nil {
				o.Action = ActionError
				o.Err = werr.Error()
			}
		}
		out = append(out, o)
	}
	return out
}

// reconcileWebhookRoute merges a named route into a YAML config so the
// tool's webhook receiver accepts pilot events. Single Outcome per
// route; the path field points at the YAML file mutated. Same
// classify→action→merge shape as plugin reconciliation; the YAML merge
// itself follows the 6-step safety contract in mergeWebhookRoute.
func reconcileWebhookRoute(r *ManifestWebhookRoute, home string) Outcome {
	cfgPath := expandHome(r.ConfigPath, home)
	o := Outcome{Tool: r.RouteName, Kind: KindWebhookRoute, Path: cfgPath}
	state := classifyWebhookRoute(cfgPath, r.RoutesYamlPath, r.RouteName, r.Route)
	o.State = state
	o.Action = actionFor(state)
	if o.Action == ActionNoop {
		return o
	}
	if err := mergeWebhookRoute(cfgPath, r.RoutesYamlPath, r.RouteName, r.Route); err != nil {
		o.Action = ActionError
		o.Err = err.Error()
	}
	return o
}

// reconcilePluginAllowList does a JSON-merge into the tool's plugin
// config so the plugin id appears in the trust array AND its entries
// row has enabled=true. Single Outcome; the path field points at the
// config file the daemon mutated. Read-modify-write is atomic via
// .tmp + rename.
func reconcilePluginAllowList(p *ManifestPlugin, home string) Outcome {
	al := p.AllowList
	cfgPath := expandHome(al.ConfigPath, home)
	o := Outcome{
		Tool: p.ID, Kind: KindPluginAllowList, Path: cfgPath,
	}
	state := classifyPluginAllowList(cfgPath, al.AllowListJsonPath, al.EntriesJsonPath, p.ID)
	o.State = state
	o.Action = actionFor(state)
	if o.Action == ActionNoop {
		return o
	}
	if err := mergePluginAllowList(cfgPath, al.AllowListJsonPath, al.EntriesJsonPath, p.ID); err != nil {
		o.Action = ActionError
		o.Err = err.Error()
	}
	return o
}

// skillTargetPath returns where the entrypoint SKILL.md should be written
// for one tool. Most tools follow the AgentSkills directory convention
// (<skillsDir>/<name>/SKILL.md). Tools with skillNaming="flat" use a
// single-file layout (<skillsDir>/<name>.md, e.g. OpenHands microagents).
func skillTargetPath(mt ManifestTool, entrypoint, home string) string {
	skillsDir := expandHome(mt.SkillsDir, home)
	if mt.SkillNaming == "flat" {
		return skillsDir + "/" + entrypoint + ".md"
	}
	return skillsDir + "/" + entrypoint + "/SKILL.md"
}

func logTick(r *Report, err error) {
	if err != nil {
		slog.Warn("skillinject tick failed", "err", err)
		return
	}
	if r == nil {
		return
	}
	c := r.Counts()
	slog.Info("skillinject tick",
		"tools_skipped", len(r.Skipped),
		"noops", c[ActionNoop],
		"creates", c[ActionCreate],
		"rewrites", c[ActionRewrite],
		"errors", c[ActionError],
	)
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

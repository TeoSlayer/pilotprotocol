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
func Tick(ctx context.Context, cfg Config) (*Report, error) {
	home := cfg.Home
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("home dir: %w", err)
		}
		home = h
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
	skillShort := skillHash[:12]

	report := &Report{At: time.Now().UTC()}

	for _, mt := range manifest.Tools {
		rootDir := expandHome(mt.RootDir, home)
		if !dirExists(rootDir) {
			report.Skipped = append(report.Skipped, mt.Name)
			continue
		}

		// (a) skill copy
		skillPath := skillTargetPath(mt, manifest.Entrypoint, home)
		state := classifySkill(skillPath, skillHash)
		action := actionFor(state)
		o := Outcome{
			Tool: mt.Name, Kind: KindSkill, Path: skillPath,
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
		if mt.HeartbeatPath == "" || mt.HeartbeatTemplate == "" {
			continue
		}
		tmplBody, err := f.fetchRepoFile(ctx, mt.HeartbeatTemplate)
		if err != nil {
			report.Outcomes = append(report.Outcomes, Outcome{
				Tool: mt.Name, Kind: KindMarker,
				Path: expandHome(mt.HeartbeatPath, home),
				Action: ActionError,
				Err:    fmt.Sprintf("fetch %s: %v", mt.HeartbeatTemplate, err),
			})
			continue
		}
		_ = writeCache(home, mt.HeartbeatTemplate, tmplBody)

		ref, err := renderHeartbeat(tmplBody, heartbeatVars{EntrypointPath: skillPath})
		if err != nil {
			report.Outcomes = append(report.Outcomes, Outcome{
				Tool: mt.Name, Kind: KindMarker,
				Path: expandHome(mt.HeartbeatPath, home),
				Action: ActionError, Err: err.Error(),
			})
			continue
		}

		hbPath := expandHome(mt.HeartbeatPath, home)
		mState := classifyMarker(hbPath, skillShort)
		mAction := actionFor(mState)
		mo := Outcome{
			Tool: mt.Name, Kind: KindMarker, Path: hbPath,
			State: mState, Action: mAction, Hash: skillShort,
		}
		if mAction != ActionNoop {
			if err := writeMarker(hbPath, ref, skillShort); err != nil {
				mo.Action = ActionError
				mo.Err = err.Error()
			}
		}
		report.Outcomes = append(report.Outcomes, mo)
	}

	return report, nil
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

// SPDX-License-Identifier: AGPL-3.0-or-later

package skillinject

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// manifestCacheRel is the path under cacheDir(home) where Tick stashes
// the most recent manifest. Uninstall reads from this cache when the
// network is unreachable so disable still works offline.
const manifestCacheRel = "inject-manifest.json"

// RemovalKind names the action Uninstall took on one path. Mirrors
// Action / Kind in state.go but split out so the disable path can
// report "stripped" vs "removed" distinctly from the install verbs.
type RemovalKind string

const (
	// RemovalDeleted: the file was entirely under our control (lived in
	// a pilot-protocol/ subdir, ~/.pilot/bin, etc.) and is now gone.
	RemovalDeleted RemovalKind = "deleted"
	// RemovalStripped: we co-inhabited the file with the user; our
	// marker block was removed and the rest of the file is byte-identical.
	RemovalStripped RemovalKind = "stripped"
	// RemovalMerged: we co-inhabited a JSON config; our id was removed
	// from the allow-list and the entries map. Other keys preserved.
	RemovalMerged RemovalKind = "merged"
	// RemovalRestored: a .pilot-bak snapshot from install time was found
	// and we restored from it byte-for-byte (preferred over a manual
	// inverse-merge when available).
	RemovalRestored RemovalKind = "restored"
	// RemovalNoop: nothing on disk to remove for this path.
	RemovalNoop RemovalKind = "noop"
	// RemovalError: a removal attempt failed; see Err.
	RemovalError RemovalKind = "error"
)

// Removal is one entry in the disable report. Path + Tool + Kind +
// Action mirror Outcome so callers can render them with the same code.
type Removal struct {
	Tool   string      `json:"tool"`
	Kind   FileKind    `json:"kind"`
	Path   string      `json:"path"`
	Action RemovalKind `json:"action"`
	Err    string      `json:"err,omitempty"`
}

// RemovalReport is what Uninstall returns to its caller.
type RemovalReport struct {
	At              time.Time `json:"at"`
	Removals        []Removal `json:"removals"`
	ManifestOffline bool      `json:"manifest_offline,omitempty"`
}

// Counts returns how many removals hit each RemovalKind.
func (r *RemovalReport) Counts() map[RemovalKind]int {
	c := map[RemovalKind]int{}
	for _, x := range r.Removals {
		c[x.Action]++
	}
	return c
}

// Uninstall is the inverse of Tick: it removes every file/marker the
// daemon has ever written via the skillinject manifest. Safety rules:
//
//   - Files in subdirs we own (~/.<tool>/skills/pilot-protocol/, ~/.pilot/bin/,
//     plugin install paths) are DELETED outright.
//   - Files we co-inhabit with the user (CLAUDE.md, AGENTS.md, AGENT.md,
//     SOUL.md) have ONLY our marker block stripped — the file is left on
//     disk even if it becomes empty. Never delete a user-owned file.
//   - Plugin allow-list JSON (openclaw.json) is restored from .pilot-bak
//     when present, otherwise we inverse-merge: remove our id from the
//     allow array and delete entries.<id>.
//
// Network failures are tolerated: if the manifest can't be fetched we
// fall back to the cached copy under ~/.pilot/skills-cache/. If that's
// also missing we return an error — fresh boxes that have never run a
// tick have nothing to remove anyway.
func Uninstall(ctx context.Context, cfg Config) (*RemovalReport, error) {
	home := cfg.Home
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("home dir: %w", err)
		}
		home = h
	}

	report := &RemovalReport{At: time.Now().UTC()}

	manifest, offline, err := loadManifestForUninstall(ctx, cfg, home)
	if err != nil {
		// Nothing to walk — but we still flip the enabled flag below
		// at the caller. Surface a single noop so output isn't empty.
		return report, fmt.Errorf("load manifest for uninstall: %w", err)
	}
	report.ManifestOffline = offline

	// Helpers (~/.pilot/bin/pilot-ask, etc.) — delete-safe, our dir.
	for _, h := range manifest.Helpers {
		dst := expandHome(h.Dst, home)
		report.Removals = append(report.Removals, removeOwnedFile(h.Name, KindHelper, dst))
	}

	// Per-tool surfaces.
	for _, mt := range manifest.Tools {
		// (a) Skill copy — under ~/.<tool>/skills/pilot-protocol/ (or
		// flat at ~/.openhands/microagents/pilot-protocol.md for tools
		// using SkillNaming="flat"). Either way the file is ours.
		skillPath := skillTargetPath(mt, manifest.Entrypoint, home)
		report.Removals = append(report.Removals, removeOwnedFile(mt.Name, KindSkill, skillPath))

		// After deleting the skill copy, try to remove its parent
		// directory if it's now empty. Only one level up — never
		// touch ~/.<tool>/skills/ itself.
		pruneEmptyParent(skillPath)

		// (b) Heartbeat marker — file we co-inhabit. Strip only.
		if mt.HeartbeatPath != "" {
			hbPath := expandHome(mt.HeartbeatPath, home)
			report.Removals = append(report.Removals, stripMarkerFile(mt.Name, hbPath))
		}

		// (c) Plugin files — ours, in a pilot-named subdir.
		if mt.Plugin != nil {
			installDir := expandHome(mt.Plugin.InstallPath, home)
			for _, pf := range mt.Plugin.Files {
				dst := filepath.Join(installDir, pf.Name)
				report.Removals = append(report.Removals, removeOwnedFile(mt.Plugin.ID, KindPluginFile, dst))
			}
			// Try to remove the plugin install dir if empty after.
			if dirIsEmpty(installDir) {
				_ = os.Remove(installDir)
			}

			// (d) Plugin allow-list — co-inhabited JSON. Restore from
			// backup if possible, otherwise inverse-merge.
			if mt.Plugin.AllowList != nil {
				cfgPath := expandHome(mt.Plugin.AllowList.ConfigPath, home)
				report.Removals = append(report.Removals,
					removePluginAllowListEntry(mt.Plugin, cfgPath))
			}
		}
	}

	return report, nil
}

// loadManifestForUninstall tries the network first, then falls back to
// the on-disk cache written by the last successful Tick. Returns the
// manifest, whether we used the offline fallback, and any error.
func loadManifestForUninstall(ctx context.Context, cfg Config, home string) (*Manifest, bool, error) {
	f := newFetcher(cfg)
	if m, err := f.fetchManifest(ctx); err == nil {
		return m, false, nil
	}
	cached := filepath.Join(cacheDir(home), manifestCacheRel)
	raw, err := os.ReadFile(cached)
	if err != nil {
		return nil, false, fmt.Errorf("network unreachable and no cached manifest at %s", cached)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, false, fmt.Errorf("parse cached manifest: %w", err)
	}
	return &m, true, nil
}

// removeOwnedFile deletes a file we entirely own (skill copies, helpers,
// plugin source files). Missing file → noop. Used by paths where the
// directory layout guarantees we created the file.
func removeOwnedFile(tool string, kind FileKind, path string) Removal {
	r := Removal{Tool: tool, Kind: kind, Path: path}
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		r.Action = RemovalNoop
		return r
	}
	if err := os.Remove(path); err != nil {
		r.Action = RemovalError
		r.Err = err.Error()
		return r
	}
	r.Action = RemovalDeleted
	return r
}

// stripMarkerFile removes our marker block from a user-owned heartbeat
// file (CLAUDE.md, AGENTS.md, AGENT.md, SOUL.md). SAFETY: never deletes
// the file, even if our marker was the only content. The user can `rm`
// it themselves if they want it gone.
func stripMarkerFile(tool, path string) Removal {
	r := Removal{Tool: tool, Kind: KindMarker, Path: path}
	cur, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			r.Action = RemovalNoop
			return r
		}
		r.Action = RemovalError
		r.Err = err.Error()
		return r
	}
	if !markerRE.Match(cur) {
		// File exists but no marker — user already removed it, or this
		// file pre-existed and we never inserted (e.g. tool wasn't
		// detected on this host at install time). Leave untouched.
		r.Action = RemovalNoop
		return r
	}
	stripped := markerRE.ReplaceAllString(string(cur), "")
	if err := writeFile(path, []byte(stripped)); err != nil {
		r.Action = RemovalError
		r.Err = err.Error()
		return r
	}
	r.Action = RemovalStripped
	return r
}

// removePluginAllowListEntry undoes our merge into a tool's plugin
// allow-list JSON (today openclaw.json). Preferred path: if a
// .pilot-bak snapshot exists from install time and the current file
// would still parse, restore the snapshot byte-for-byte. Fallback:
// inverse-merge — remove our id from the allow array and delete the
// entries.<id> row, preserving all other user keys.
//
// SAFETY: never deletes the file. If the user has 5 plugins of their
// own and we added pilot, after disable the file still contains those
// 5 plugins.
func removePluginAllowListEntry(p *ManifestPlugin, cfgPath string) Removal {
	al := p.AllowList
	r := Removal{Tool: p.ID, Kind: KindPluginAllowList, Path: cfgPath}

	// Path A: file gone entirely. Nothing to do.
	cur, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Best-effort: still try to clean up the .pilot-bak if
			// somehow present without the live file.
			_ = os.Remove(cfgPath + BackupSuffix)
			r.Action = RemovalNoop
			return r
		}
		r.Action = RemovalError
		r.Err = err.Error()
		return r
	}

	// Path B: prefer restoring from .pilot-bak. We trust the backup
	// only if (1) it exists, (2) it parses as valid JSON, and (3) it
	// does NOT itself contain our id (i.e. it really is the pre-install
	// snapshot, not a snapshot of a later state).
	bakPath := cfgPath + BackupSuffix
	if bak, bErr := os.ReadFile(bakPath); bErr == nil {
		var bakObj map[string]any
		if json.Unmarshal(bak, &bakObj) == nil &&
			!allowListContains(bakObj, al.AllowListJsonPath, p.ID) &&
			!entryEnabled(bakObj, al.EntriesJsonPath, p.ID) {
			if err := writeFileAtomic(cfgPath, bak, 0o644); err != nil {
				r.Action = RemovalError
				r.Err = err.Error()
				return r
			}
			_ = os.Remove(bakPath)
			r.Action = RemovalRestored
			return r
		}
	}

	// Path C: inverse-merge. Parse the current config, remove our id
	// from the allow array, delete entries.<id>, and write back.
	var obj map[string]any
	if err := json.Unmarshal(cur, &obj); err != nil {
		// Refuse to overwrite an unparseable config — same paranoia as
		// the install path's mergePluginAllowList.
		r.Action = RemovalError
		r.Err = fmt.Sprintf("parse plugin config (refusing to overwrite): %v", err)
		return r
	}
	changed := removeAllowListEntry(obj, al.AllowListJsonPath, p.ID)
	if removeEntriesEntry(obj, al.EntriesJsonPath, p.ID) {
		changed = true
	}
	if !changed {
		// Config exists, parses, but doesn't contain our id — we never
		// merged here (or someone already cleaned up).
		_ = os.Remove(bakPath) // cleanup any orphan backup
		r.Action = RemovalNoop
		return r
	}

	next, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		r.Action = RemovalError
		r.Err = err.Error()
		return r
	}
	next = append(next, '\n')
	if err := writeFileAtomic(cfgPath, next, 0o644); err != nil {
		r.Action = RemovalError
		r.Err = err.Error()
		return r
	}
	_ = os.Remove(bakPath)
	r.Action = RemovalMerged
	return r
}

// removeAllowListEntry drops id from the string array at jsonPath in
// obj. Returns true if anything was removed.
func removeAllowListEntry(obj map[string]any, jsonPath, id string) bool {
	parent, leaf := walkObject(obj, jsonPath, false)
	if parent == nil {
		return false
	}
	arr, ok := parent[leaf].([]any)
	if !ok {
		return false
	}
	filtered := make([]any, 0, len(arr))
	removed := false
	for _, v := range arr {
		if s, isStr := v.(string); isStr && s == id {
			removed = true
			continue
		}
		filtered = append(filtered, v)
	}
	if !removed {
		return false
	}
	parent[leaf] = filtered
	return true
}

// removeEntriesEntry deletes entries.<id> from obj. Returns true if the
// key existed and was removed.
func removeEntriesEntry(obj map[string]any, jsonPath, id string) bool {
	parent, leaf := walkObject(obj, jsonPath, false)
	if parent == nil {
		return false
	}
	entries, ok := parent[leaf].(map[string]any)
	if !ok {
		return false
	}
	if _, present := entries[id]; !present {
		return false
	}
	delete(entries, id)
	return true
}

// pruneEmptyParent removes the parent directory of path iff it is now
// empty AND its basename is "pilot-protocol" (our well-known subdir
// name). The basename check is a belt-and-suspenders guard: we never
// rm an empty parent that wasn't ours.
func pruneEmptyParent(path string) {
	dir := filepath.Dir(path)
	if filepath.Base(dir) != "pilot-protocol" {
		return
	}
	if !dirIsEmpty(dir) {
		return
	}
	if err := os.Remove(dir); err != nil {
		slog.Debug("skillinject: prune empty dir failed", "dir", dir, "err", err)
	}
}

// dirIsEmpty returns true if path is a directory and contains zero
// entries. Returns false on any error (including "not a directory").
func dirIsEmpty(path string) bool {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}
	return len(entries) == 0
}

// manifestJSON re-marshals the parsed manifest so Tick can cache it.
// Pulled out so tests can serialize a fixture manifest the same way.
func manifestJSON(m *Manifest) ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

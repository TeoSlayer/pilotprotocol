// SPDX-License-Identifier: AGPL-3.0-or-later

package skillinject

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// pluginAllowListState describes what the daemon would do to the tool's
// plugin config JSON to ensure our plugin is trusted + enabled.
//
// Three states:
//   - StateIdentical: allow-list contains our id AND entries.<id>.enabled
//     is true. No write needed.
//   - StateAbsent: config file doesn't exist on disk. Tool isn't
//     installed → skip (caller handles this).
//   - StateDrifted: config exists but the id is missing from allow-list
//     OR entries.<id>.enabled isn't true. Daemon merges + rewrites.
//
// Same idiom as classifySkill / classifyMarker — read-only inspection
// here, the actual mutation lives in mergePluginAllowList.
func classifyPluginAllowList(configPath, allowJsonPath, entriesJsonPath, pluginID string) State {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		// Don't conflate "config file missing" with "needs writing" —
		// if the tool isn't installed at all, the caller's dirExists
		// check on rootDir already skipped this whole tool. A missing
		// config file at this point means the tool installed but
		// hasn't run yet; treat as drifted so the daemon creates it.
		if os.IsNotExist(err) {
			return StateDrifted
		}
		return StateDrifted
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		// Unparseable config = something the user is editing or that
		// belongs to a future version we don't recognise. Refuse to
		// rewrite; treat as drifted so the next tick re-checks and
		// the caller surfaces an error in the outcome.
		return StateDrifted
	}
	inAllow := allowListContains(obj, allowJsonPath, pluginID)
	enabled := entryEnabled(obj, entriesJsonPath, pluginID)
	if inAllow && enabled {
		return StateIdentical
	}
	return StateDrifted
}

// BackupSuffix is appended to the original config file path before
// mergePluginAllowList overwrites it. Kept distinct from openclaw's
// own .bak / .bak.N rotation so we can identify our own snapshots
// and not interfere with the tool's rolling backup chain.
const BackupSuffix = ".pilot-bak"

// mergePluginAllowList rewrites the tool's plugin config JSON so the
// allow-list at allowJsonPath contains pluginID and the entries map
// at entriesJsonPath has {pluginID: {"enabled": true}}. Preserves all
// other keys (modulo Go's JSON re-marshal: 2-space indent + map keys
// alphabetically sorted, which is stable across runs so subsequent
// idempotent ticks produce byte-identical files).
//
// Safety contract — defense in depth, because openclaw.json is the
// user's live config and corrupting it would brick their tool:
//
//	(1) The original bytes are read into memory and held throughout
//	    the operation as `originalBytes`. Every failure path below
//	    has a way back to those bytes.
//	(2) If parsing the user's config fails, we refuse to write —
//	    we never overwrite a malformed file the user might be
//	    mid-editing. Caller surfaces the error in the next tick.
//	(3) If the post-merge marshal produces a different shape than
//	    we expected (lost a key, scrambled a value), we refuse to
//	    write and return an error. This is the "verification before
//	    swap" rung — a paranoid round-trip self-check.
//	(4) Before atomically swapping the file, we write a sidecar
//	    backup at <path>.pilot-bak with the original bytes. If
//	    anything explodes between this point and the rename, the
//	    backup is on disk and a human can restore manually.
//	(5) The swap itself uses .tmp + rename, which is atomic on
//	    every POSIX filesystem we care about — no torn writes.
//	(6) After the swap, we read the file back and re-parse it.
//	    If it doesn't parse, or the round-trip lost a top-level key
//	    that was in the original, we ROLL BACK from the .pilot-bak
//	    snapshot. This catches kernel/FS-level corruption that
//	    slipped past the in-memory checks.
//
// If the config file is missing, the merge creates it with only the
// managed keys. No backup is written in that case (nothing to
// preserve).
func mergePluginAllowList(configPath, allowJsonPath, entriesJsonPath, pluginID string) error {
	// (1) Snapshot the original bytes IN MEMORY. From here on,
	// `originalBytes` is our point-of-no-return — every failure
	// path below restores or aborts cleanly.
	var (
		originalBytes   []byte
		originalExisted bool
		obj             map[string]any
	)
	raw, err := os.ReadFile(configPath)
	switch {
	case err != nil && os.IsNotExist(err):
		obj = map[string]any{}
	case err != nil:
		return fmt.Errorf("read plugin config: %w", err)
	default:
		originalBytes = append([]byte(nil), raw...) // defensive copy
		originalExisted = true
		// (2) Refuse to operate on a malformed config. The user
		// might be mid-edit; respecting their state is more
		// important than landing our merge this tick.
		if uerr := json.Unmarshal(raw, &obj); uerr != nil {
			return fmt.Errorf("parse plugin config (refusing to overwrite a malformed user config): %w", uerr)
		}
		if obj == nil {
			obj = map[string]any{}
		}
	}

	// Snapshot which top-level keys the user had BEFORE we mutated
	// the in-memory map. Used by the post-swap verification step
	// (6) to catch silent key loss across the round-trip.
	originalTopKeys := make(map[string]struct{}, len(obj))
	for k := range obj {
		originalTopKeys[k] = struct{}{}
	}

	if err := ensureAllowListEntry(obj, allowJsonPath, pluginID); err != nil {
		return err
	}
	if err := ensureEntryEnabled(obj, entriesJsonPath, pluginID); err != nil {
		return err
	}

	next, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal merged plugin config: %w", err)
	}
	next = append(next, '\n')

	// (3) Self-check: round-trip the bytes we're about to write
	// through Unmarshal and make sure they still parse and still
	// contain every top-level key the user originally had. This
	// catches any in-memory corruption between mutate and write.
	if err := verifyMarshalRoundTrip(next, originalTopKeys, pluginID, allowJsonPath, entriesJsonPath); err != nil {
		return fmt.Errorf("pre-write verification failed (refusing to write): %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return fmt.Errorf("ensure parent dir for plugin config: %w", err)
	}

	// (4) Drop a sidecar backup of the original bytes BEFORE we
	// swap. Skipped when no original existed (nothing to back up)
	// or when the proposed write is byte-identical to the original
	// (no risk of data loss anyway).
	if originalExisted && !bytes.Equal(originalBytes, next) {
		bakPath := configPath + BackupSuffix
		if err := writeFileAtomic(bakPath, originalBytes, 0o644); err != nil {
			return fmt.Errorf("write pre-merge backup: %w", err)
		}
	}

	// (5) Atomic swap: write tmp, rename.
	if err := writeFileAtomic(configPath, next, 0o644); err != nil {
		return fmt.Errorf("write plugin config: %w", err)
	}

	// (6) Post-swap verification. Read the file back, re-parse, and
	// confirm every original top-level key survived AND our managed
	// keys are present. If anything is off, restore from the
	// .pilot-bak snapshot and return an error so the next tick
	// retries cleanly.
	if err := verifyOnDiskResult(configPath, originalTopKeys, pluginID, allowJsonPath, entriesJsonPath); err != nil {
		if originalExisted {
			if rbErr := writeFileAtomic(configPath, originalBytes, 0o644); rbErr != nil {
				return fmt.Errorf("post-write verification failed (%v); ROLLBACK ALSO FAILED (%v); manual restore: cp %s%s %s",
					err, rbErr, configPath, BackupSuffix, configPath)
			}
			return fmt.Errorf("post-write verification failed; rolled back from in-memory snapshot: %w", err)
		}
		return fmt.Errorf("post-write verification failed (no rollback — no original existed): %w", err)
	}

	return nil
}

// writeFileAtomic writes content to path via .tmp + rename. Used by
// both the live-config swap and the .pilot-bak snapshot so both share
// the same atomicity guarantee.
func writeFileAtomic(path string, content []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// verifyMarshalRoundTrip parses bytes that are about to be written and
// confirms (a) they parse cleanly, (b) every key that was in the
// original top-level object is still present, (c) our id is in the
// allow-list, (d) our entry has enabled=true. Pre-write rung in the
// safety contract: catches in-memory corruption before it hits disk.
func verifyMarshalRoundTrip(bytes []byte, originalTopKeys map[string]struct{}, pluginID, allowJsonPath, entriesJsonPath string) error {
	var rt map[string]any
	if err := json.Unmarshal(bytes, &rt); err != nil {
		return fmt.Errorf("re-parse: %w", err)
	}
	for k := range originalTopKeys {
		if _, ok := rt[k]; !ok {
			return fmt.Errorf("top-level key %q lost during marshal", k)
		}
	}
	if !allowListContains(rt, allowJsonPath, pluginID) {
		return fmt.Errorf("allow-list missing plugin id %q after marshal", pluginID)
	}
	if !entryEnabled(rt, entriesJsonPath, pluginID) {
		return fmt.Errorf("entries.%s.enabled missing or not true after marshal", pluginID)
	}
	return nil
}

// verifyOnDiskResult reads the file we just wrote and re-runs the
// same checks as verifyMarshalRoundTrip. Post-swap rung in the safety
// contract: catches filesystem-level corruption that slipped past the
// in-memory check (truncated write, page-cache mismatch, etc.). Note:
// this is paranoid; in practice it should never fire after a
// successful writeFileAtomic. The cost is one fs.ReadFile per tick
// per managed config.
func verifyOnDiskResult(configPath string, originalTopKeys map[string]struct{}, pluginID, allowJsonPath, entriesJsonPath string) error {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read-back: %w", err)
	}
	return verifyMarshalRoundTrip(raw, originalTopKeys, pluginID, allowJsonPath, entriesJsonPath)
}

// walkObject traverses obj along a dotted path, materializing missing
// nested objects when create is true. Returns the final container and
// the leaf key. Returns nil + empty string if any intermediate node is
// not a JSON object and create is false.
func walkObject(obj map[string]any, jsonPath string, create bool) (map[string]any, string) {
	parts := strings.Split(jsonPath, ".")
	if len(parts) == 0 {
		return nil, ""
	}
	cur := obj
	for i := 0; i < len(parts)-1; i++ {
		p := parts[i]
		next, ok := cur[p].(map[string]any)
		if !ok {
			if !create {
				return nil, ""
			}
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
	return cur, parts[len(parts)-1]
}

func allowListContains(obj map[string]any, jsonPath, id string) bool {
	parent, leaf := walkObject(obj, jsonPath, false)
	if parent == nil {
		return false
	}
	raw, ok := parent[leaf]
	if !ok {
		return false
	}
	// JSON arrays unmarshal as []any
	arr, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, v := range arr {
		if s, ok := v.(string); ok && s == id {
			return true
		}
	}
	return false
}

func ensureAllowListEntry(obj map[string]any, jsonPath, id string) error {
	parent, leaf := walkObject(obj, jsonPath, true)
	if parent == nil {
		return fmt.Errorf("walk allow-list path %q: parent missing", jsonPath)
	}
	cur, _ := parent[leaf].([]any)
	for _, v := range cur {
		if s, ok := v.(string); ok && s == id {
			return nil
		}
	}
	parent[leaf] = append(cur, id)
	return nil
}

func entryEnabled(obj map[string]any, jsonPath, id string) bool {
	parent, leaf := walkObject(obj, jsonPath, false)
	if parent == nil {
		return false
	}
	entries, ok := parent[leaf].(map[string]any)
	if !ok {
		return false
	}
	entry, ok := entries[id].(map[string]any)
	if !ok {
		return false
	}
	enabled, _ := entry["enabled"].(bool)
	return enabled
}

func ensureEntryEnabled(obj map[string]any, jsonPath, id string) error {
	parent, leaf := walkObject(obj, jsonPath, true)
	if parent == nil {
		return fmt.Errorf("walk entries path %q: parent missing", jsonPath)
	}
	entries, ok := parent[leaf].(map[string]any)
	if !ok {
		entries = map[string]any{}
		parent[leaf] = entries
	}
	entry, ok := entries[id].(map[string]any)
	if !ok {
		entry = map[string]any{}
		entries[id] = entry
	}
	entry["enabled"] = true
	return nil
}

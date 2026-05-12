// SPDX-License-Identifier: AGPL-3.0-or-later

package skillinject

import (
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

// mergePluginAllowList atomically rewrites the tool's plugin config
// JSON so that the allow-list at allowJsonPath contains pluginID and
// the entries map at entriesJsonPath has {pluginID: {"enabled": true}}.
// Preserves all other keys byte-for-byte modulo Go's JSON
// re-serialization (consistent 2-space indent, no key reordering
// beyond what encoding/json guarantees — alphabetical for map keys).
//
// If the config file is missing, it is created with only the managed
// keys. The daemon does NOT create the parent directory tree beyond
// the file itself; the tool's own install is expected to provide it.
//
// Failure semantics: any read/parse/write error returns the error
// without partial writes (uses .tmp + rename).
func mergePluginAllowList(configPath, allowJsonPath, entriesJsonPath, pluginID string) error {
	var obj map[string]any
	raw, err := os.ReadFile(configPath)
	switch {
	case err != nil && os.IsNotExist(err):
		obj = map[string]any{}
	case err != nil:
		return fmt.Errorf("read plugin config: %w", err)
	default:
		if uerr := json.Unmarshal(raw, &obj); uerr != nil {
			return fmt.Errorf("parse plugin config (refusing to overwrite a malformed user config): %w", uerr)
		}
		if obj == nil {
			obj = map[string]any{}
		}
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

	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return fmt.Errorf("ensure parent dir for plugin config: %w", err)
	}
	tmp := configPath + ".tmp"
	if err := os.WriteFile(tmp, next, 0o644); err != nil {
		return fmt.Errorf("write tmp plugin config: %w", err)
	}
	if err := os.Rename(tmp, configPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename plugin config into place: %w", err)
	}
	return nil
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

// SPDX-License-Identifier: AGPL-3.0-or-later

package skillinject

import (
	"encoding/json"
	"testing"
)

// TestManifest_MultiPluginUnmarshal pins the schema extension: a tool
// entry can declare an array of plugins under `plugins`, parallel to
// the legacy single-plugin `plugin` slot. Older manifests using
// only `plugin` must continue to parse unchanged.
func TestManifest_MultiPluginUnmarshal(t *testing.T) {
	t.Parallel()

	const body = `{
      "version": 1,
      "entrypoint": "pilotctl",
      "tools": [
        {
          "name": "openclaw",
          "rootDir": "~/.openclaw",
          "skillsDir": "~/.openclaw/skills",
          "plugins": [
            {
              "id": "pilotprotocol-webhook-receiver",
              "installPath": "~/.openclaw/extensions/pilotprotocol-webhook-receiver",
              "files": [
                {"name": "openclaw.plugin.json", "src": "wf/openclaw/webhook/openclaw.plugin.json"},
                {"name": "index.mjs",            "src": "wf/openclaw/webhook/index.mjs"}
              ],
              "allowList": {
                "configPath":        "~/.openclaw/openclaw.json",
                "allowListJsonPath": "plugins.allow",
                "entriesJsonPath":   "plugins.entries"
              }
            }
          ]
        }
      ]
    }`

	var m Manifest
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(m.Tools) != 1 {
		t.Fatalf("Tools len=%d want=1", len(m.Tools))
	}
	tool := m.Tools[0]
	if tool.Plugin != nil {
		t.Fatalf("Plugin (legacy slot) should be nil when only `plugins` is set, got %+v", tool.Plugin)
	}
	if len(tool.Plugins) != 1 {
		t.Fatalf("Plugins len=%d want=1", len(tool.Plugins))
	}
	p := tool.Plugins[0]
	if p.ID != "pilotprotocol-webhook-receiver" {
		t.Fatalf("plugin id=%q want=%q", p.ID, "pilotprotocol-webhook-receiver")
	}
	if len(p.Files) != 2 {
		t.Fatalf("plugin Files len=%d want=2", len(p.Files))
	}
	if p.AllowList == nil || p.AllowList.AllowListJsonPath != "plugins.allow" {
		t.Fatalf("AllowList not parsed: %+v", p.AllowList)
	}
}

// TestManifest_LegacySinglePluginStillParses guards backwards-compat
// for the existing `plugin` (singular) slot, which currently appears
// nowhere in the canonical manifest but is documented as the v1
// pre-multi schema. Removing it would silently break any external
// fork that depended on the older shape.
func TestManifest_LegacySinglePluginStillParses(t *testing.T) {
	t.Parallel()
	const body = `{
      "version": 1,
      "entrypoint": "pilotctl",
      "tools": [
        {
          "name": "openclaw",
          "rootDir": "~/.openclaw",
          "skillsDir": "~/.openclaw/skills",
          "plugin": {
            "id": "legacy-singleton",
            "installPath": "~/.openclaw/extensions/legacy-singleton",
            "files": [{"name": "index.mjs", "src": "wf/legacy.mjs"}]
          }
        }
      ]
    }`
	var m Manifest
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	tool := m.Tools[0]
	if tool.Plugin == nil {
		t.Fatal("legacy `plugin` slot must still parse")
	}
	if tool.Plugin.ID != "legacy-singleton" {
		t.Fatalf("legacy plugin id=%q", tool.Plugin.ID)
	}
	if len(tool.Plugins) != 0 {
		t.Fatalf("new Plugins[] should be empty when only legacy slot is used, got %d", len(tool.Plugins))
	}
}

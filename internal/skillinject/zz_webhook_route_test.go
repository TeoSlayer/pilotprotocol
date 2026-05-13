// SPDX-License-Identifier: AGPL-3.0-or-later

package skillinject

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestMergeWebhookRoute_CreatesFileWhenMissing covers the cold-start
// path: the user has hermes installed but hasn't run it yet, so there
// is no ~/.hermes/config.yaml. The merge should create it with only
// our route at the named path.
func TestMergeWebhookRoute_CreatesFileWhenMissing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "hermes", "config.yaml")
	route := map[string]interface{}{
		"secret":       "abc123",
		"events":       []interface{}{"message.received"},
		"deliver_only": true,
	}
	if err := mergeWebhookRoute(cfgPath, "platforms.webhook.extra.routes", "pilot-events", route); err != nil {
		t.Fatalf("merge: %v", err)
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var got map[string]any
	if err := yaml.Unmarshal(raw, &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	leaf := lookupYamlPath(got, "platforms.webhook.extra.routes", "pilot-events")
	if leaf == nil {
		t.Fatalf("route missing after create:\n%s", raw)
	}
}

// TestMergeWebhookRoute_PreservesOtherKeys is the regression guard for
// the "we own the route but not the file" contract. A user has hand-
// configured channels (telegram, discord), and our merge should leave
// every other top-level key intact.
func TestMergeWebhookRoute_PreservesOtherKeys(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	original := `platforms:
  telegram:
    enabled: true
    token: t-12345
  webhook:
    extra:
      port: 8644
      routes:
        legacy:
          secret: old-secret
          deliver_only: false
agents:
  defaults:
    workspace: /opt/hermes
`
	if err := os.WriteFile(cfgPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	route := map[string]interface{}{
		"secret":       "pilot-secret",
		"events":       []interface{}{"message.received", "file.received"},
		"deliver_only": true,
	}
	if err := mergeWebhookRoute(cfgPath, "platforms.webhook.extra.routes", "pilot-events", route); err != nil {
		t.Fatalf("merge: %v", err)
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := yaml.Unmarshal(raw, &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Our route is present and equal.
	leaf := lookupYamlPath(got, "platforms.webhook.extra.routes", "pilot-events")
	if leaf == nil {
		t.Fatal("pilot-events route missing")
	}
	if !yamlEqual(leaf, route) {
		t.Fatalf("pilot-events drifted from want:\ngot=%v\nwant=%v", leaf, route)
	}
	// Pre-existing keys must survive.
	if v := lookupYamlPath(got, "platforms", "telegram"); v == nil {
		t.Fatal("platforms.telegram lost")
	}
	if v := lookupYamlPath(got, "platforms.webhook.extra.routes", "legacy"); v == nil {
		t.Fatal("platforms.webhook.extra.routes.legacy lost")
	}
	// The unmodified port + agents block must be intact.
	if v := lookupYamlPath(got, "platforms.webhook", "extra"); v == nil {
		t.Fatal("platforms.webhook.extra lost")
	}
	if _, ok := got["agents"]; !ok {
		t.Fatal("top-level agents key lost")
	}
}

// TestMergeWebhookRoute_Idempotent confirms that running merge a
// second time when state is identical produces NO write (the
// classify+actionFor path short-circuits) and the on-disk bytes are
// byte-identical to what the first merge produced.
func TestMergeWebhookRoute_Idempotent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	route := map[string]interface{}{
		"secret":       "abc",
		"deliver_only": true,
	}
	if err := mergeWebhookRoute(cfgPath, "platforms.webhook.extra.routes", "pilot-events", route); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// Now use the public reconcile entrypoint (classify → action →
	// merge) to validate the noop short-circuit. Running mergeWebhookRoute
	// directly would always write; reconcileWebhookRoute is the path
	// the daemon takes.
	r := &ManifestWebhookRoute{
		ConfigPath:     cfgPath,
		RoutesYamlPath: "platforms.webhook.extra.routes",
		RouteName:      "pilot-events",
		Route:          route,
	}
	o := reconcileWebhookRoute(r, "")
	if o.Action != ActionNoop {
		t.Fatalf("second tick should be Noop, got %v (err=%q)", o.Action, o.Err)
	}
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("file should be byte-identical on noop tick\nbefore=%q\nafter=%q", before, after)
	}
}

// TestMergeWebhookRoute_RefusesMalformedConfig is the safety check
// that a corrupted user-edited config.yaml is never overwritten by
// the merge. The function reports an error; the reconcile path
// surfaces it as ActionError; the file stays untouched.
func TestMergeWebhookRoute_RefusesMalformedConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	garbage := "this is { not valid yaml at all : [::\n"
	if err := os.WriteFile(cfgPath, []byte(garbage), 0o600); err != nil {
		t.Fatal(err)
	}
	route := map[string]interface{}{"secret": "abc"}
	err := mergeWebhookRoute(cfgPath, "platforms.webhook.extra.routes", "pilot-events", route)
	if err == nil {
		t.Fatal("expected error on malformed user config; merge should refuse")
	}
	if !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("error message should explain refusal, got: %v", err)
	}
	// The file on disk must still be the original garbage — not overwritten.
	now, _ := os.ReadFile(cfgPath)
	if string(now) != garbage {
		t.Fatalf("merge mutated a malformed file\nwant=%q\ngot=%q", garbage, now)
	}
}

// TestManifest_WebhookRoutesUnmarshal pins the schema extension: a
// tool entry can declare an array of webhookRoutes alongside (or
// instead of) plugins.
func TestManifest_WebhookRoutesUnmarshal(t *testing.T) {
	t.Parallel()
	const body = `{
      "version": 1,
      "entrypoint": "pilotctl",
      "tools": [
        {
          "name": "hermes",
          "rootDir": "~/.hermes",
          "skillsDir": "~/.hermes/skills",
          "webhookRoutes": [
            {
              "configPath": "~/.hermes/config.yaml",
              "routesYamlPath": "platforms.webhook.extra.routes",
              "routeName": "pilot-events",
              "route": {
                "secret": "...",
                "events": ["message.received", "file.received"],
                "deliver_only": true
              }
            }
          ]
        }
      ]
    }`
	var m Manifest
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Tools) != 1 {
		t.Fatal("expected 1 tool")
	}
	wr := m.Tools[0].WebhookRoutes
	if len(wr) != 1 {
		t.Fatalf("WebhookRoutes len=%d want=1", len(wr))
	}
	if wr[0].RouteName != "pilot-events" {
		t.Fatalf("RouteName=%q", wr[0].RouteName)
	}
	if wr[0].Route["secret"] != "..." {
		t.Fatalf("Route.secret=%v", wr[0].Route["secret"])
	}
}

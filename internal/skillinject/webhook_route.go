// SPDX-License-Identifier: AGPL-3.0-or-later

package skillinject

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// classifyWebhookRoute inspects the target YAML config and reports
// whether the named route at the dotted path already matches the
// desired Route body.
//
//   - StateIdentical: route exists at the path and DeepEqual to the
//     manifest's body. No write needed.
//   - StateDrifted: route exists but differs, OR the file exists but
//     the path / entry is absent. Daemon merges + rewrites.
//   - StateDrifted (with create-on-write semantics): file missing.
//     Same response — the merge function creates it.
//
// Same idiom as classifyPluginAllowList: read-only inspection here,
// the mutation lives in mergeWebhookRoute.
func classifyWebhookRoute(configPath, routesYamlPath, routeName string, want map[string]interface{}) State {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		// File absent or unreadable → drifted (merge will handle both
		// cases). Caller already gated on dirExists for the tool root.
		return StateDrifted
	}
	var obj map[string]any
	if err := yaml.Unmarshal(raw, &obj); err != nil {
		// Unparseable config — never overwrite a malformed user file.
		// Return Drifted so the caller surfaces the error in the next
		// tick's outcome (the merge step will refuse with a clear msg).
		return StateDrifted
	}
	if obj == nil {
		return StateDrifted
	}
	got := lookupYamlPath(obj, routesYamlPath, routeName)
	if got == nil {
		return StateDrifted
	}
	// Normalize both sides through yaml round-trip to avoid spurious
	// drift from e.g. int vs uint type variance between user-edited
	// and manifest-provided YAML.
	if !yamlEqual(got, want) {
		return StateDrifted
	}
	return StateIdentical
}

// mergeWebhookRoute writes the named route into the tool's YAML
// config, preserving every other top-level key. Follows the same
// 6-step safety contract as mergePluginAllowList — see that comment
// for the full rationale.
func mergeWebhookRoute(configPath, routesYamlPath, routeName string, want map[string]interface{}) error {
	// (1) Snapshot the original bytes in memory.
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
		return fmt.Errorf("read webhook-route config: %w", err)
	default:
		originalBytes = append([]byte(nil), raw...)
		originalExisted = true
		// (2) Refuse to operate on a malformed config.
		if uerr := yaml.Unmarshal(raw, &obj); uerr != nil {
			return fmt.Errorf("parse webhook-route config (refusing to overwrite a malformed user config): %w", uerr)
		}
		if obj == nil {
			obj = map[string]any{}
		}
	}

	originalTopKeys := make(map[string]struct{}, len(obj))
	for k := range obj {
		originalTopKeys[k] = struct{}{}
	}

	if err := ensureWebhookRouteEntry(obj, routesYamlPath, routeName, want); err != nil {
		return err
	}

	next, err := marshalYAMLStable(obj)
	if err != nil {
		return fmt.Errorf("marshal merged webhook-route config: %w", err)
	}

	// (3) Pre-write verification: round-trip the bytes we're about to
	// commit and confirm (a) they parse, (b) every original top-level
	// key is still present, (c) our route is present and equal to the
	// manifest's want.
	if err := verifyWebhookRouteRoundTrip(next, originalTopKeys, routesYamlPath, routeName, want); err != nil {
		return fmt.Errorf("pre-write verification failed (refusing to write): %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return fmt.Errorf("ensure parent dir for webhook-route config: %w", err)
	}

	// (4) Sidecar backup of the original bytes if they differ. Re-uses
	// the BackupSuffix constant + writeFileAtomic helper from
	// plugin_allowlist.go so all skillinject-managed configs use the
	// same .pilot-bak rotation pattern.
	if originalExisted && !bytes.Equal(originalBytes, next) {
		bakPath := configPath + BackupSuffix
		if err := writeFileAtomic(bakPath, originalBytes, 0o644); err != nil {
			return fmt.Errorf("write pre-merge backup: %w", err)
		}
	}

	// (5) Atomic swap.
	if err := writeFileAtomic(configPath, next, 0o644); err != nil {
		return fmt.Errorf("write webhook-route config: %w", err)
	}

	// (6) Post-swap verification with rollback on failure.
	if err := verifyWebhookRouteOnDisk(configPath, originalTopKeys, routesYamlPath, routeName, want); err != nil {
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

// marshalYAMLStable marshals via yaml.v3 with 2-space indent (yaml's
// default). yaml.v3 doesn't guarantee map-key ordering across runs,
// but for our use case the daemon's reconcile loop is idempotent —
// subsequent ticks compare deep-equal and skip if want == got, so a
// shuffled order between identical writes is benign.
func marshalYAMLStable(obj map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(obj); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func verifyWebhookRouteRoundTrip(b []byte, originalTopKeys map[string]struct{}, routesYamlPath, routeName string, want map[string]interface{}) error {
	var rt map[string]any
	if err := yaml.Unmarshal(b, &rt); err != nil {
		return fmt.Errorf("re-parse: %w", err)
	}
	for k := range originalTopKeys {
		if _, ok := rt[k]; !ok {
			return fmt.Errorf("top-level key %q lost during marshal", k)
		}
	}
	got := lookupYamlPath(rt, routesYamlPath, routeName)
	if got == nil {
		return fmt.Errorf("route %q missing under %q after marshal", routeName, routesYamlPath)
	}
	if !yamlEqual(got, want) {
		return fmt.Errorf("route %q at %q drifted during marshal", routeName, routesYamlPath)
	}
	return nil
}

func verifyWebhookRouteOnDisk(configPath string, originalTopKeys map[string]struct{}, routesYamlPath, routeName string, want map[string]interface{}) error {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read-back: %w", err)
	}
	return verifyWebhookRouteRoundTrip(raw, originalTopKeys, routesYamlPath, routeName, want)
}

// lookupYamlPath walks routesYamlPath dotted-style and returns the
// entry at the named key, or nil if any intermediate node is missing
// or wrong-shaped. yaml.v3 unmarshals nested maps as
// map[string]interface{} when the top-level target is the same shape,
// so dotted navigation mirrors the JSON walkObject logic.
func lookupYamlPath(obj map[string]any, yamlPath, name string) interface{} {
	parts := strings.Split(yamlPath, ".")
	cur := obj
	for _, p := range parts {
		next, ok := cur[p].(map[string]any)
		if !ok {
			return nil
		}
		cur = next
	}
	return cur[name]
}

// ensureWebhookRouteEntry walks (or creates) the dotted path and
// assigns map[routeName] = want. yaml.v3 represents nested maps as
// map[string]any for our object-shaped targets.
func ensureWebhookRouteEntry(obj map[string]any, yamlPath, name string, want map[string]interface{}) error {
	parts := strings.Split(yamlPath, ".")
	if len(parts) == 0 {
		return fmt.Errorf("empty routesYamlPath")
	}
	cur := obj
	for _, p := range parts {
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
	cur[name] = want
	return nil
}

// yamlEqual compares two YAML values for deep equality after a
// marshal/unmarshal round-trip on each. Necessary because user-edited
// YAML may have ints stored as int64 / float64 / strings depending on
// the source, while manifest-derived values come from JSON unmarshaling
// where numerics are float64. Round-tripping both through YAML
// normalizes the types.
func yamlEqual(a, b interface{}) bool {
	aBytes, err := yaml.Marshal(a)
	if err != nil {
		return false
	}
	bBytes, err := yaml.Marshal(b)
	if err != nil {
		return false
	}
	var aN, bN interface{}
	if err := yaml.Unmarshal(aBytes, &aN); err != nil {
		return false
	}
	if err := yaml.Unmarshal(bBytes, &bN); err != nil {
		return false
	}
	return reflect.DeepEqual(aN, bN)
}

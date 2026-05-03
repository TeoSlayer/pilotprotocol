// SPDX-License-Identifier: AGPL-3.0-or-later

package skillinject

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// configFileName is the per-user pilot config file. The same file the
// rest of pilotctl reads from. We only touch our own subkey.
const configFileName = "config.json"

// configKey is the subkey under which we store the opt-out flag.
const configKey = "skill_inject"

// EnabledFlag describes the persisted opt-out state. Stored at
// ~/.pilot/config.json under "skill_inject" → {"enabled": bool}.
type EnabledFlag struct {
	Enabled bool `json:"enabled"`
}

func configFilePath(home string) string {
	return filepath.Join(home, ".pilot", configFileName)
}

// IsEnabled returns whether skill injection is on. Defaults to TRUE
// (opt-out, not opt-in) when the flag isn't present, so fresh installs
// get the feature without any extra step.
func IsEnabled(home string) bool {
	f, err := os.Open(configFilePath(home))
	if err != nil {
		return true
	}
	defer f.Close()
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(f).Decode(&raw); err != nil {
		return true
	}
	sub, ok := raw[configKey]
	if !ok {
		return true
	}
	var flag EnabledFlag
	if err := json.Unmarshal(sub, &flag); err != nil {
		return true
	}
	return flag.Enabled
}

// SetEnabled persists the opt-out flag. Reads the existing config (if
// any), updates only the skill_inject key, writes back atomically.
func SetEnabled(home string, enabled bool) error {
	p := configFilePath(home)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	raw := map[string]json.RawMessage{}
	if b, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(b, &raw)
	}
	flagJSON, err := json.Marshal(EnabledFlag{Enabled: enabled})
	if err != nil {
		return err
	}
	raw[configKey] = flagJSON
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

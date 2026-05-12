// SPDX-License-Identifier: AGPL-3.0-or-later

package skillinject

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

// DefaultManifestURL is the canonical raw GitHub URL for the inject
// manifest. Overridable via Config.ManifestURL (test hook).
const DefaultManifestURL = "https://raw.githubusercontent.com/TeoSlayer/pilot-skills/main/inject-manifest.json"

// DefaultRepoBaseURL is the prefix used to fetch any path the manifest
// references (skills/<name>/SKILL.md, heartbeats/<tool>.md). Overridable
// via Config.RepoBaseURL.
const DefaultRepoBaseURL = "https://raw.githubusercontent.com/TeoSlayer/pilot-skills/main/"

// Manifest mirrors inject-manifest.json. Field tags match the upstream
// schema. Unknown fields are ignored (forward-compat with new tool fields).
type Manifest struct {
	Version     int              `json:"version"`
	Entrypoint  string           `json:"entrypoint"`
	Description string           `json:"description,omitempty"`
	Tools       []ManifestTool   `json:"tools"`
	Helpers     []ManifestHelper `json:"helpers,omitempty"`
}

// ManifestHelper is one helper script the daemon installs at a
// well-known path so any AI tool on the host can invoke it. Used to
// ship pilot-ask (the directory + specialist round-trip wrapper).
//
// Helpers are tool-agnostic — they live under ~/.pilot/bin/ and are
// referenced by every tool's heartbeat directive.
type ManifestHelper struct {
	Name string `json:"name"`
	// Src is a repo-relative path fetched via fetchRepoFile, e.g.
	// "workflow-injection/pilot-ask".
	Src string `json:"src"`
	// Dst is the absolute install target. Supports ~/ expansion, e.g.
	// "~/.pilot/bin/pilot-ask".
	Dst string `json:"dst"`
	// Mode is the file mode in octal string form, e.g. "0755". Empty
	// defaults to 0755 (helpers are executables).
	Mode string `json:"mode,omitempty"`
}

// ManifestTool is one tool target row.
type ManifestTool struct {
	Name              string          `json:"name"`
	RootDir           string          `json:"rootDir"`
	SkillsDir         string          `json:"skillsDir"`
	HeartbeatPath     string          `json:"heartbeatPath,omitempty"`
	HeartbeatTemplate string          `json:"heartbeatTemplate,omitempty"`
	SkillNaming       string          `json:"skillNaming,omitempty"` // "" = "directory" (default), "flat" = single-file
	SelfHeartbeat     bool            `json:"selfHeartbeat,omitempty"`
	Plugin            *ManifestPlugin `json:"plugin,omitempty"`
}

// ManifestPlugin describes a per-tool plugin that the daemon writes
// onto disk (alongside the heartbeat + skill copy) and tracks in the
// tool's own plugin allow-list. Today this is openclaw-only — the
// plugin registers a `before_prompt_build` hook that prepends the
// pilot directive into the system prompt on every turn. SKILL.md and
// the heartbeat file are loaded by their tools' own lifecycles
// (workspace bootstrap / periodic), neither fires per-turn, so the
// plugin is the only reliable per-prompt injection surface.
type ManifestPlugin struct {
	// ID matches openclaw.plugin.json's "id" field. Used as the
	// allow-list key + directory name.
	ID string `json:"id"`
	// InstallPath is where the plugin directory is written
	// (e.g. "~/.openclaw/extensions/pilotprotocol-prompt-injector").
	InstallPath string `json:"installPath"`
	// Files lists the plugin source files the daemon copies in.
	// Order doesn't matter — each file is reconciled independently.
	Files []ManifestPluginFile `json:"files"`
	// AllowList, if set, tells the daemon to ensure the plugin id
	// appears in the tool's plugin allow-list + entries map. Nil
	// disables the JSON-merge step (e.g. for tools without an
	// explicit allow-list concept).
	AllowList *ManifestPluginAllowList `json:"allowList,omitempty"`
}

// ManifestPluginFile is one file the daemon writes into the plugin
// install directory. Mirrors ManifestHelper but scoped to a plugin.
type ManifestPluginFile struct {
	// Name is the filename relative to InstallPath (e.g.
	// "openclaw.plugin.json", "index.mjs").
	Name string `json:"name"`
	// Src is a repo-relative path fetched via fetchRepoFile
	// (e.g. "workflow-injection/openclaw-plugin/index.mjs").
	Src string `json:"src"`
}

// ManifestPluginAllowList describes how the daemon merges its plugin id
// into a tool's configuration to mark the plugin as trusted/enabled.
// Today targets openclaw.json with paths `plugins.allow` (string array)
// and `plugins.entries.<id>.enabled` (bool).
type ManifestPluginAllowList struct {
	// ConfigPath is the JSON file the daemon merges into
	// (e.g. "~/.openclaw/openclaw.json").
	ConfigPath string `json:"configPath"`
	// AllowListJsonPath is a dotted path to the trust array. Created
	// if absent. Daemon appends the plugin id iff not already present.
	AllowListJsonPath string `json:"allowListJsonPath"`
	// EntriesJsonPath is a dotted path to the per-plugin entries
	// object (e.g. "plugins.entries"). The daemon ensures
	// `entries.<id>.enabled` is `true`.
	EntriesJsonPath string `json:"entriesJsonPath"`
}

// fetcher is a small wrapper around http.Client that returns response
// bodies. Pulled out so tests can inject a fake.
type fetcher struct {
	httpClient  *http.Client
	manifestURL string
	repoBase    string
}

func newFetcher(cfg Config) *fetcher {
	c := cfg.HTTPClient
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	mu := cfg.ManifestURL
	if mu == "" {
		mu = DefaultManifestURL
	}
	rb := cfg.RepoBaseURL
	if rb == "" {
		rb = DefaultRepoBaseURL
	}
	if !strings.HasSuffix(rb, "/") {
		rb += "/"
	}
	return &fetcher{httpClient: c, manifestURL: mu, repoBase: rb}
}

func (f *fetcher) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "pilot-daemon/skillinject")
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d for %s", resp.StatusCode, url)
	}
	const maxBody = 1 << 20 // 1 MiB cap
	return io.ReadAll(io.LimitReader(resp.Body, maxBody))
}

// fetchManifest grabs and parses the manifest from the configured URL.
func (f *fetcher) fetchManifest(ctx context.Context) (*Manifest, error) {
	body, err := f.get(ctx, f.manifestURL)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if m.Version != 1 {
		return nil, fmt.Errorf("unsupported manifest version: %d", m.Version)
	}
	if m.Entrypoint == "" {
		return nil, fmt.Errorf("manifest missing entrypoint")
	}
	if len(m.Tools) == 0 {
		return nil, fmt.Errorf("manifest has no tools")
	}
	return &m, nil
}

// fetchRepoFile retrieves a path relative to the repo root (e.g.
// "skills/pilotctl/SKILL.md", "heartbeats/openclaw.md").
func (f *fetcher) fetchRepoFile(ctx context.Context, relPath string) ([]byte, error) {
	relPath = strings.TrimPrefix(relPath, "/")
	url := f.repoBase + relPath
	return f.get(ctx, url)
}

// expandHome resolves "~/" in a manifest path against the user's home dir.
func expandHome(p, home string) string {
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	if p == "~" {
		return home
	}
	return p
}

// renderHeartbeat fills in {{.EntrypointPath}} (and any future fields) in
// the per-tool heartbeat template.
type heartbeatVars struct {
	EntrypointPath string
}

func renderHeartbeat(tmplBody []byte, v heartbeatVars) (string, error) {
	t, err := template.New("hb").Parse(string(tmplBody))
	if err != nil {
		return "", fmt.Errorf("parse heartbeat template: %w", err)
	}
	var sb strings.Builder
	if err := t.Execute(&sb, v); err != nil {
		return "", fmt.Errorf("render heartbeat template: %w", err)
	}
	return sb.String(), nil
}

// cacheDir is where fetched skill content is mirrored on disk. Used for
// telemetry and future offline fallback (currently no fallback).
func cacheDir(home string) string {
	return filepath.Join(home, ".pilot", "skills-cache")
}

func writeCache(home, relPath string, body []byte) error {
	p := filepath.Join(cacheDir(home), filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, body, 0o644)
}

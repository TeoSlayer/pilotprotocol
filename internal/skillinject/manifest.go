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
	Name              string `json:"name"`
	RootDir           string `json:"rootDir"`
	SkillsDir         string `json:"skillsDir"`
	HeartbeatPath     string `json:"heartbeatPath,omitempty"`
	HeartbeatTemplate string `json:"heartbeatTemplate,omitempty"`
	SkillNaming       string `json:"skillNaming,omitempty"` // "" = "directory" (default), "flat" = single-file
	SelfHeartbeat     bool   `json:"selfHeartbeat,omitempty"`
}

// fetcher is a small wrapper around http.Client that returns response
// bodies. Pulled out so tests can inject a fake.
type fetcher struct {
	httpClient *http.Client
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

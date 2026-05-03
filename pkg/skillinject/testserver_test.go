// SPDX-License-Identifier: AGPL-3.0-or-later

package skillinject

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeRepo is a tiny HTTP server that mimics raw.githubusercontent.com
// for the pilot-skills repo. Tests swap in different files to simulate
// drift, missing entrypoint, etc.
type fakeRepo struct {
	srv      *httptest.Server
	manifest Manifest
	files    map[string][]byte // relPath → body
}

func newFakeRepo(t *testing.T) *fakeRepo {
	t.Helper()
	r := &fakeRepo{files: map[string][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		path := strings.TrimPrefix(req.URL.Path, "/")
		if path == "inject-manifest.json" {
			b, _ := json.Marshal(r.manifest)
			w.Write(b)
			return
		}
		if body, ok := r.files[path]; ok {
			w.Write(body)
			return
		}
		http.NotFound(w, req)
	})
	r.srv = httptest.NewServer(mux)
	t.Cleanup(r.srv.Close)
	return r
}

// withDefault sets up a sane default manifest with one entrypoint and
// a configurable set of tools. testContent is served as the entrypoint
// SKILL.md and a benign heartbeat template is served per tool.
const testContent = "---\nname: pilotctl\n---\n\n# Test entrypoint skill\n\nbody.\n"
const testHeartbeat = "Pilot Protocol skill installed. See {{.EntrypointPath}} — overlay/NAT/peer/pilotctl."

// withTools builds a manifest with the given tool rows + serves the
// canonical entrypoint + heartbeat templates.
func (r *fakeRepo) withTools(tools []ManifestTool) {
	r.manifest = Manifest{
		Version:    1,
		Entrypoint: "pilotctl",
		Tools:      tools,
	}
	r.files["skills/pilotctl/SKILL.md"] = []byte(testContent)
	for _, t := range tools {
		if t.HeartbeatTemplate != "" {
			r.files[t.HeartbeatTemplate] = []byte(testHeartbeat)
		}
	}
}

// cfg returns a Config wired to point at the fake server.
func (r *fakeRepo) cfg(home string) Config {
	return Config{
		Home:        home,
		ManifestURL: r.srv.URL + "/inject-manifest.json",
		RepoBaseURL: r.srv.URL + "/",
	}
}

// setSkillBody overrides the entrypoint SKILL.md body (for drift tests).
func (r *fakeRepo) setSkillBody(body []byte) {
	r.files["skills/pilotctl/SKILL.md"] = body
}

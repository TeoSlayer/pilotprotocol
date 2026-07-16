// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The error strings below are VERBATIM, captured from a live daemon on this
// host or taken from the generating template. They are the whole reason the
// matching works, so they are pinned here rather than paraphrased — if an
// adapter changes its wording, these tests fail and tell us the graphs need
// re-matching before agents get a wrong hint.
const (
	// Captured live: pilotctl appstore call io.pilot.sqlite sqlite.query '{"sql":"SELECT 42"}'
	liveMissingParamErr = `ipc: server error: backend: missing required param(s): database`
	// Captured live: an unknown method on a real app.
	liveMethodNotFoundErr = `ipc: server error: method not found: sqlite.nosuch`
	// Shape from internal/scaffold/templates/client_http.go.tmpl ("backend: %s %s -> %d: %s")
	// with the body from internal/broker/broker.go's exhausted-budget branch.
	liveX402Err  = `ipc: server error: backend: POST /v1/run -> 402: {"error":"insufficient credit — per-user budget exhausted","credits_remaining":0}`
	liveQuotaErr = `ipc: server error: backend: POST /v1/run -> 429: {"error":"per-caller quota exceeded"}`
)

func writeGraph(t *testing.T, root, appID string, body string) {
	t.Helper()
	dir := filepath.Join(root, appID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, nextStepsFileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

const testGraphJSON = `{
  "schema": 1,
  "app": "io.pilot.testapp",
  "edges": [
    {"from": "*", "on": "err", "code": 402, "why": "budget exhausted",
     "then": [{"cmd": "pilotctl appstore call io.pilot.testapp testapp.balance '{}'", "why": "check balance", "kind": "recovery"}]},
    {"from": "*", "on": "err", "match": "no api key|401", "why": "not signed up",
     "then": [{"cmd": "pilotctl appstore call io.pilot.testapp testapp.signup '{}'", "why": "mint your key", "kind": "gateway"}]},
    {"from": "testapp.signup", "on": "ok", "why": "signed up",
     "then": [{"cmd": "pilotctl appstore call io.pilot.testapp testapp.send '{}'", "why": "send your first", "kind": "flow"}]},
    {"from": "*", "on": "ok", "why": "catch-all",
     "then": [{"cmd": "pilotctl appstore call io.pilot.testapp testapp.help '{}'", "why": "see everything"}]}
  ]
}`

func withAppRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	t.Setenv("PILOT_NEXT_STEPS", "")
	return root
}

func TestLoadNextStepsGraph(t *testing.T) {
	root := withAppRoot(t)
	writeGraph(t, root, "io.pilot.testapp", testGraphJSON)
	g := loadNextStepsGraph("io.pilot.testapp")
	if g == nil || len(g.Edges) != 4 {
		t.Fatalf("want a 4-edge graph, got %+v", g)
	}
}

// Every one of these is a NORMAL condition, not an error: the overwhelming
// majority of installed apps have no graph at all. Each must be silent.
func TestLoadNextStepsGraphDegradesSilently(t *testing.T) {
	root := withAppRoot(t)
	if g := loadNextStepsGraph("io.pilot.absent"); g != nil {
		t.Error("a missing graph must load as nil")
	}
	writeGraph(t, root, "io.pilot.bad", `{not json`)
	if g := loadNextStepsGraph("io.pilot.bad"); g != nil {
		t.Error("malformed JSON must load as nil, never panic")
	}
	// A FUTURE schema must be ignored rather than half-read: a guessed hint is
	// worse than no hint.
	writeGraph(t, root, "io.pilot.future", `{"schema":2,"app":"io.pilot.future","edges":[]}`)
	if g := loadNextStepsGraph("io.pilot.future"); g != nil {
		t.Error("an unknown schema must load as nil")
	}
	// A graph claiming to be another app must not apply to this one.
	writeGraph(t, root, "io.pilot.mine", `{"schema":1,"app":"io.pilot.theirs","edges":[]}`)
	if g := loadNextStepsGraph("io.pilot.mine"); g != nil {
		t.Error("a graph whose app id does not match its dir must load as nil")
	}
}

func TestRenderNextStepsMatchesLiveX402(t *testing.T) {
	root := withAppRoot(t)
	writeGraph(t, root, "io.pilot.testapp", testGraphJSON)
	e := renderNextSteps("io.pilot.testapp", "testapp.run", false, liveX402Err)
	if e == nil || e.Why != "budget exhausted" {
		t.Fatalf("a live 402 must select the 402 edge, got %+v", e)
	}
	out := renderNextStepsText(e)
	if !strings.Contains(out, "testapp.balance") || !strings.Contains(out, "(fixes the error above)") {
		t.Fatalf("render must name the fix and mark it as such:\n%s", out)
	}
}

// The regression that would make EVERY failure claim the budget was exhausted.
func TestRenderNextStepsQuotaIsNotBudget(t *testing.T) {
	root := withAppRoot(t)
	writeGraph(t, root, "io.pilot.testapp", testGraphJSON)
	e := renderNextSteps("io.pilot.testapp", "testapp.run", false, liveQuotaErr)
	if e != nil && e.Code == 402 {
		t.Fatalf("a 429 must not select the 402 edge, got %+v", e)
	}
}

func TestRenderNextStepsGatewayOnLive401(t *testing.T) {
	root := withAppRoot(t)
	writeGraph(t, root, "io.pilot.testapp", testGraphJSON)
	e := renderNextSteps("io.pilot.testapp", "testapp.send", false, "ipc: server error: backend: GET /v1/me -> 401: no api key")
	if e == nil || e.Why != "not signed up" {
		t.Fatalf("a 401 must route to the signup gateway, got %+v", e)
	}
	if !strings.Contains(renderNextStepsText(e), "(required first)") {
		t.Fatal("a gateway step must be marked required first")
	}
}

func TestRenderNextStepsPrefersExactMethod(t *testing.T) {
	root := withAppRoot(t)
	writeGraph(t, root, "io.pilot.testapp", testGraphJSON)
	e := renderNextSteps("io.pilot.testapp", "testapp.signup", true, "")
	if e == nil || e.Why != "signed up" {
		t.Fatalf("want the exact-method ok edge, got %+v", e)
	}
	e = renderNextSteps("io.pilot.testapp", "testapp.other", true, "")
	if e == nil || e.Why != "catch-all" {
		t.Fatalf("want the wildcard ok edge, got %+v", e)
	}
}

// An app with no graph — the state of every app today — must produce nothing.
func TestRenderNextStepsSilentWithoutGraph(t *testing.T) {
	withAppRoot(t)
	if e := renderNextSteps("io.pilot.nograph", "x.y", true, ""); e != nil {
		t.Fatal("an app with no graph must render nothing")
	}
}

func TestRenderNextStepsOffSwitch(t *testing.T) {
	root := withAppRoot(t)
	writeGraph(t, root, "io.pilot.testapp", testGraphJSON)
	for _, v := range []string{"off", "0", "false", "no", "OFF"} {
		t.Setenv("PILOT_NEXT_STEPS", v)
		if e := renderNextSteps("io.pilot.testapp", "testapp.signup", true, ""); e != nil {
			t.Errorf("PILOT_NEXT_STEPS=%q must disable hints", v)
		}
	}
}

// A live method-not-found already gets pilotctl's own `exposes` hint. The graph
// must not also fire a misleading edge on it.
func TestRenderNextStepsIgnoresMethodNotFound(t *testing.T) {
	root := withAppRoot(t)
	writeGraph(t, root, "io.pilot.testapp", testGraphJSON)
	e := renderNextSteps("io.pilot.testapp", "testapp.nosuch", false, liveMethodNotFoundErr)
	if e != nil {
		t.Fatalf("no edge matches a method-not-found; want silence, got %+v", e)
	}
}

func TestRenderNextStepsTextCapsAtThree(t *testing.T) {
	e := &nextStepsEdge{Why: "x", Then: []nextStepsStep{
		{Cmd: "pilotctl a", Why: "1"}, {Cmd: "pilotctl b", Why: "2"},
		{Cmd: "pilotctl c", Why: "3"}, {Cmd: "pilotctl d", Why: "4"},
	}}
	// Validation is authoring-side and lives in a different binary; the renderer
	// must never trust the file to have been gated.
	if strings.Contains(renderNextStepsText(e), "pilotctl d") {
		t.Fatal("render must hard-cap at three steps regardless of the file")
	}
}

func TestRenderNextStepsTextNilIsEmpty(t *testing.T) {
	if renderNextStepsText(nil) != "" {
		t.Fatal("a nil edge must render empty")
	}
	if nextStepsEnvelope(nil) != nil {
		t.Fatal("a nil edge must have no envelope")
	}
}

func TestCacheNextStepsRoundTrips(t *testing.T) {
	root := withAppRoot(t)
	dir := filepath.Join(root, "io.pilot.testapp")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var g nextStepsGraph
	if err := json.Unmarshal([]byte(testGraphJSON), &g); err != nil {
		t.Fatal(err)
	}
	cacheNextSteps(dir, &g)
	got := loadNextStepsGraph("io.pilot.testapp")
	if got == nil || len(got.Edges) != len(g.Edges) {
		t.Fatalf("cached graph did not round-trip: %+v", got)
	}
}

// An install with no graph must not litter the app dir with an empty file that
// later reads as "this app has a graph".
func TestCacheNextStepsNilIsNoOp(t *testing.T) {
	root := withAppRoot(t)
	dir := filepath.Join(root, "io.pilot.testapp")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cacheNextSteps(dir, nil)
	cacheNextSteps(dir, &nextStepsGraph{Schema: 1, App: "io.pilot.testapp"})
	if _, err := os.Stat(filepath.Join(dir, nextStepsFileName)); !os.IsNotExist(err) {
		t.Fatal("caching an absent or empty graph must write no file")
	}
}

func TestNextStepsEnvelopeIsStructured(t *testing.T) {
	root := withAppRoot(t)
	writeGraph(t, root, "io.pilot.testapp", testGraphJSON)
	e := renderNextSteps("io.pilot.testapp", "testapp.run", false, liveX402Err)
	b, err := json.Marshal(nextStepsEnvelope(e))
	if err != nil {
		t.Fatal(err)
	}
	var back nextStepsJSON
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Steps) != 1 || back.Steps[0].Kind != "recovery" {
		t.Fatalf("envelope must carry structured steps, got %s", b)
	}
}

// TestResolveMatchesAppTemplateSemantics pins the resolution rules this file
// shares with app-template's internal/nextsteps.Graph.Resolve.
//
// The two are deliberate duplicates: pilotctl must not depend on the app-template
// module, so a frozen wire contract is restated here (the same call
// appstore_demo.go's ProductDemo mirror makes). The cost of duplication is DRIFT
// — and drift here is silent and nasty, because a graph would validate at submit
// time against one set of rules and resolve at call time against another, so an
// author would ship an edge that never fires.
//
// These cases are the contract. They are mirrored one-for-one by
// TestResolve* in app-template's internal/nextsteps package; if you change
// matching semantics on either side, BOTH suites must be updated together.
func TestResolveMatchesAppTemplateSemantics(t *testing.T) {
	g := &nextStepsGraph{Schema: 1, App: "io.pilot.demoapp", Edges: []nextStepsEdge{
		{From: "*", On: "err", Match: `401|no api key`, Why: "wildcard-match"},
		{From: "*", On: "err", Code: 402, Why: "wildcard-code"},
		{From: "*", On: "ok", Why: "wildcard-ok"},
		{From: "*", On: "ok", Match: `"needs_signup"\s*:\s*true`, Why: "wildcard-ok-match"},
		{From: "demoapp.signup", On: "ok", Why: "exact-ok"},
		{From: "demoapp.send", On: "err", Match: `missing required param`, Why: "exact-err-match"},
	}}
	for i := range g.Edges {
		g.Edges[i].Then = []nextStepsStep{{Cmd: "pilotctl x", Why: "y"}}
	}

	cases := []struct {
		name    string
		method  string
		ok      bool
		payload string
		want    string // edge Why, or "" for no match
	}{
		{"exact method beats wildcard on success", "demoapp.signup", true, `{"ok":true}`, "exact-ok"},
		{"unrelated method falls back to wildcard", "demoapp.other", true, `{"ok":true}`, "wildcard-ok"},
		// The signup soft-fail: exit 0, and the discriminator is in the BODY.
		{"needs_signup body beats bare wildcard ok", "demoapp.get", true, `{"needs_signup":true}`, "wildcard-ok-match"},
		// THE case this suite originally missed, which let the two resolvers drift:
		// a bare exact-from edge must NOT shadow a wildcard gateway edge that
		// actually matched. `demoapp.signup` has an exact ok edge; a cold agent
		// calling it with a needs_signup body must still be routed to the gateway.
		{"discriminated wildcard beats bare exact-from", "demoapp.signup", true, `{"needs_signup":true}`, "wildcard-ok-match"},
		{"real 402 selects the code edge", "demoapp.run", false, liveX402Err, "wildcard-code"},
		{"429 does not select the 402 edge", "demoapp.run", false, liveQuotaErr, ""},
		{"exact method + match wins", "demoapp.send", false, liveMissingParamErr, "exact-err-match"},
		// A declared-but-unmatched discriminator is not a fallback.
		{"unmatched discriminator yields silence", "demoapp.send", false, "connection refused", ""},
		{"case-insensitive match", "demoapp.x", false, "GET /v1/me -> 401: No API Key", "wildcard-match"},
		{"no match at all is silent", "demoapp.x", false, "novel error", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := resolveNextStepsEdge(g, c.method, c.ok, c.payload)
			got := ""
			if e != nil {
				got = e.Why
			}
			if got != c.want {
				t.Errorf("resolve(%q, ok=%v) = %q, want %q", c.method, c.ok, got, c.want)
			}
		})
	}
}

// The live missing-param error is the single most common way an agent's first
// real call fails, so a graph must be able to key off it exactly.
func TestResolveOnLiveMissingParamError(t *testing.T) {
	g := &nextStepsGraph{Schema: 1, App: "io.pilot.sqlite", Edges: []nextStepsEdge{
		{From: "*", On: "err", Match: `missing required param\(s\): database`, Why: "needs a database",
			Then: []nextStepsStep{{Cmd: "pilotctl appstore call io.pilot.sqlite sqlite.query '{\"database\":\":memory:\",\"sql\":\"SELECT 1\"}'", Why: "pass database", Kind: "recovery"}}},
	}}
	if e := resolveNextStepsEdge(g, "sqlite.query", false, liveMissingParamErr); e == nil {
		t.Fatal("the live missing-param error must match its edge")
	}
	if e := resolveNextStepsEdge(g, "sqlite.query", false, "some other failure"); e != nil {
		t.Fatal("an unrelated error must not match")
	}
}

// TestLoadNextStepsGraphRefusesTraversal is a security regression test. appID
// comes straight from argv (`pilotctl appstore call <app-id> ...`), so a
// filepath.Join on it is a path traversal: gosec flagged exactly this as G703.
// Without resolveUnder, a crafted id would make pilotctl read a file outside the
// install root and print pieces of it back as "next steps".
func TestLoadNextStepsGraphRefusesTraversal(t *testing.T) {
	root := withAppRoot(t)

	// Plant a valid graph OUTSIDE the install root, and a traversal that would
	// reach it if the id were joined naively.
	outside := t.TempDir()
	rel, err := filepath.Rel(root, outside)
	if err != nil {
		t.Skipf("no relative path between temp dirs: %v", err)
	}
	// The planted graph's `app` MUST equal the traversing id, or the
	// app-id-mismatch check rejects the file first and this test passes for the
	// wrong reason — masking the very traversal it exists to catch. (It did:
	// re-introducing the naive filepath.Join left the first draft of this test
	// green.) With `app` matching, the ONLY thing that can stop the load is the
	// containment guard.
	escaped := strings.Replace(testGraphJSON, "io.pilot.testapp", rel, 1)
	if err := os.WriteFile(filepath.Join(outside, nextStepsFileName), []byte(escaped), 0o600); err != nil {
		t.Fatal(err)
	}
	if g := loadNextStepsGraph(rel); g != nil {
		t.Fatalf("a traversing app id (%q) must not load a graph from outside the install root", rel)
	}

	for _, bad := range []string{"../evil", "../../etc", "/etc/passwd", ""} {
		if g := loadNextStepsGraph(bad); g != nil {
			t.Errorf("app id %q must not resolve to a graph", bad)
		}
	}
}

// The write side is confined for the same reason: a graph is never worth writing
// a byte outside the tree the app store owns.
func TestCacheNextStepsRefusesTraversal(t *testing.T) {
	root := withAppRoot(t)
	outside := t.TempDir()
	var g nextStepsGraph
	if err := json.Unmarshal([]byte(testGraphJSON), &g); err != nil {
		t.Fatal(err)
	}
	cacheNextSteps(filepath.Join(root, "..", filepath.Base(outside)), &g)
	if _, err := os.Stat(filepath.Join(outside, nextStepsFileName)); err == nil {
		t.Fatal("cacheNextSteps wrote outside the install root")
	}
}

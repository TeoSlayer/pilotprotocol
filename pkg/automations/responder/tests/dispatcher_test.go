package responder_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/automations/responder"
)

// mustCompile compiles ep.ArgRegex via the exported Compile method.
func mustCompile(t *testing.T, ep *responder.EndpointConfig) {
	t.Helper()
	if err := ep.Compile(); err != nil {
		t.Fatalf("compile regex for %q: %v", ep.Name, err)
	}
}

func TestDispatch_UnknownCommand(t *testing.T) {
	cfg, err := responder.LoadConfigFrom(writeTempFile(t, `
commands:
  - name: known
    link: http://localhost/known
`))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	_, dispErr := responder.Dispatch(cfg, &responder.CommandRequest{Command: "unknown"})
	if dispErr == nil {
		t.Fatal("expected error for unknown command")
	}
	ucErr, ok := dispErr.(*responder.UnknownCommandError)
	if !ok {
		t.Fatalf("expected *UnknownCommandError, got %T: %v", dispErr, dispErr)
	}
	if ucErr.Command != "unknown" {
		t.Errorf("UnknownCommandError.Command = %q", ucErr.Command)
	}
	if !strings.Contains(ucErr.Error(), "known") {
		t.Errorf("error message should list available command 'known': %s", ucErr.Error())
	}
}

func TestDispatch_ServiceCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		from := r.URL.Query().Get("from")
		to := r.URL.Query().Get("to")
		fmt.Fprintf(w, "from=%s to=%s", from, to)
	}))
	defer srv.Close()

	yaml := fmt.Sprintf(`
commands:
  - name: testcmd
    link: %s/api
    arg_regex: '^from:\s*(?P<from>[^,\s]+)(?:\s*,\s*to:\s*(?P<to>[^,\s]+))?$'
`, srv.URL)

	cfg, err := responder.LoadConfigFrom(writeTempFile(t, yaml))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	result, err := responder.Dispatch(cfg, &responder.CommandRequest{
		Command: "testcmd",
		Body:    "from: 2026-04-01, to: 2026-04-02",
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if !strings.Contains(result, "from=2026-04-01") {
		t.Errorf("expected from in result, got: %q", result)
	}
	if !strings.Contains(result, "to=2026-04-02") {
		t.Errorf("expected to in result, got: %q", result)
	}
}

func TestDispatch_ServiceCallNoRegex(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "pong")
	}))
	defer srv.Close()

	cfg, err := responder.LoadConfigFrom(writeTempFile(t, fmt.Sprintf(`
commands:
  - name: ping
    link: %s/ping
`, srv.URL)))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	result, err := responder.Dispatch(cfg, &responder.CommandRequest{Command: "ping"})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result != "pong" {
		t.Errorf("expected pong, got %q", result)
	}
}

func TestDispatch_ServiceHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	cfg, err := responder.LoadConfigFrom(writeTempFile(t, fmt.Sprintf(`
commands:
  - name: failing
    link: %s/missing
`, srv.URL)))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	_, err = responder.Dispatch(cfg, &responder.CommandRequest{Command: "failing"})
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention 404: %v", err)
	}
}

func TestExtractParams_StockmarketMatch(t *testing.T) {
	ep := &responder.EndpointConfig{
		Name:     "stockmarket",
		ArgRegex: `^from:\s*(?P<from>\d{4}-\d{2}-\d{2})(?:\s*,\s*to:\s*(?P<to>\d{4}-\d{2}-\d{2}))?$`,
	}
	mustCompile(t, ep)

	cases := []struct {
		body     string
		wantFrom string
		wantTo   string
	}{
		{"from: 2026-04-01, to: 2026-04-02", "2026-04-01", "2026-04-02"},
		{"from: 2026-04-01", "2026-04-01", ""},
	}
	for _, tc := range cases {
		params, err := responder.ExtractParams(ep, tc.body)
		if err != nil {
			t.Errorf("body=%q: unexpected error: %v", tc.body, err)
			continue
		}
		if params["from"] != tc.wantFrom {
			t.Errorf("body=%q: from=%q, want %q", tc.body, params["from"], tc.wantFrom)
		}
		if params["to"] != tc.wantTo {
			t.Errorf("body=%q: to=%q, want %q", tc.body, params["to"], tc.wantTo)
		}
	}
}

func TestExtractParams_NoMatch(t *testing.T) {
	ep := &responder.EndpointConfig{
		Name:     "stockmarket",
		ArgRegex: `^from:\s*(?P<from>\d{4}-\d{2}-\d{2})$`,
	}
	mustCompile(t, ep)

	_, err := responder.ExtractParams(ep, "bad input")
	if err == nil {
		t.Fatal("expected error for non-matching body")
	}
}

func TestExtractParams_PolymarketRFC3339(t *testing.T) {
	ep := &responder.EndpointConfig{
		Name: "polymarket",
		ArgRegex: `^from:\s*(?P<from>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)` +
			`(?:\s*,\s*to:\s*(?P<to>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?))?$`,
	}
	mustCompile(t, ep)

	cases := []struct {
		body     string
		wantFrom string
		wantTo   string
	}{
		{"from: 2026-04-02T00:00:00Z", "2026-04-02T00:00:00Z", ""},
		{"from: 2026-04-01T00:00:00Z, to: 2026-04-02T00:00:00Z", "2026-04-01T00:00:00Z", "2026-04-02T00:00:00Z"},
	}
	for _, tc := range cases {
		params, err := responder.ExtractParams(ep, tc.body)
		if err != nil {
			t.Errorf("body=%q: %v", tc.body, err)
			continue
		}
		if params["from"] != tc.wantFrom {
			t.Errorf("from=%q want %q", params["from"], tc.wantFrom)
		}
		if params["to"] != tc.wantTo {
			t.Errorf("to=%q want %q", params["to"], tc.wantTo)
		}
	}
}

func TestBuildURL(t *testing.T) {
	cases := []struct {
		base   string
		params map[string]string
		want   string
	}{
		{
			"http://localhost:8100/summaries/polymarket",
			map[string]string{"from": "2026-04-02T00:00:00Z"},
			"http://localhost:8100/summaries/polymarket?from=2026-04-02T00%3A00%3A00Z",
		},
		{
			"http://localhost:8100/summaries/stockmarket",
			map[string]string{"from": "2026-04-02"},
			"http://localhost:8100/summaries/stockmarket?from=2026-04-02",
		},
		{
			"http://localhost:9000/ping",
			nil,
			"http://localhost:9000/ping",
		},
	}
	for _, tc := range cases {
		got, err := responder.BuildURL(tc.base, tc.params)
		if err != nil {
			t.Errorf("BuildURL(%q, %v): %v", tc.base, tc.params, err)
			continue
		}
		if got != tc.want {
			t.Errorf("BuildURL(%q, %v)\n got  %q\n want %q", tc.base, tc.params, got, tc.want)
		}
	}
}

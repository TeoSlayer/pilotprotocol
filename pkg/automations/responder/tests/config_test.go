package responder_test

import (
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/automations/responder"
)

func TestParseEndpointsYAML_ValidFull(t *testing.T) {
	yaml := `
commands:
  - name: polymarket
    link: http://localhost:8100/summaries/polymarket
    arg_regex: '^from:\s*(?P<from>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)(?:\s*,\s*to:\s*(?P<to>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?))?$'
  - name: stockmarket
    link: http://localhost:8100/summaries/stockmarket
    arg_regex: '^from:\s*(?P<from>\d{4}-\d{2}-\d{2})(?:\s*,\s*to:\s*(?P<to>\d{4}-\d{2}-\d{2}))?$'
`
	cfg, err := responder.ParseEndpointsYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Commands) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(cfg.Commands))
	}

	poly := cfg.Commands[0]
	if poly.Name != "polymarket" {
		t.Errorf("command[0].Name = %q, want %q", poly.Name, "polymarket")
	}
	if poly.Link != "http://localhost:8100/summaries/polymarket" {
		t.Errorf("command[0].Link = %q", poly.Link)
	}
	if poly.ArgRegex == "" {
		t.Error("command[0].ArgRegex should not be empty")
	}

	stock := cfg.Commands[1]
	if stock.Name != "stockmarket" {
		t.Errorf("command[1].Name = %q, want %q", stock.Name, "stockmarket")
	}
}

func TestParseEndpointsYAML_NoArgRegex(t *testing.T) {
	yaml := `
commands:
  - name: ping
    link: http://localhost:9000/ping
`
	cfg, err := responder.ParseEndpointsYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cfg.Commands))
	}
	if cfg.Commands[0].ArgRegex != "" {
		t.Errorf("expected empty ArgRegex, got %q", cfg.Commands[0].ArgRegex)
	}
}

func TestParseEndpointsYAML_SkipsComments(t *testing.T) {
	yaml := `
# this is a comment
commands:
  # another comment
  - name: svc
    link: http://localhost:1234/svc
    # arg_regex: ignored
`
	cfg, err := responder.ParseEndpointsYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cfg.Commands))
	}
	if cfg.Commands[0].ArgRegex != "" {
		t.Errorf("arg_regex should be empty (commented out), got %q", cfg.Commands[0].ArgRegex)
	}
}

func TestParseEndpointsYAML_Empty(t *testing.T) {
	cfg, err := responder.ParseEndpointsYAML(strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Commands) != 0 {
		t.Errorf("expected 0 commands, got %d", len(cfg.Commands))
	}
}

func TestParseEndpointsYAML_QuotedValues(t *testing.T) {
	yaml := `
commands:
  - name: 'svc'
    link: 'http://localhost:1234/svc'
    arg_regex: '^from:\s*(?P<from>\S+)$'
`
	cfg, err := responder.ParseEndpointsYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Commands[0].Name != "svc" {
		t.Errorf("expected name=svc, got %q", cfg.Commands[0].Name)
	}
	if cfg.Commands[0].Link != "http://localhost:1234/svc" {
		t.Errorf("unexpected link %q", cfg.Commands[0].Link)
	}
}

func TestLoadConfigFrom_MissingFile(t *testing.T) {
	_, err := responder.LoadConfigFrom("/nonexistent/path/endpoints.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadConfigFrom_InvalidRegex(t *testing.T) {
	path := writeTempFile(t, `
commands:
  - name: bad
    link: http://localhost/svc
    arg_regex: '^from:\s*(?P<from>[unclosed'
`)
	_, err := responder.LoadConfigFrom(path)
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestLoadConfigFrom_EmptyCommands(t *testing.T) {
	path := writeTempFile(t, "commands:\n")
	_, err := responder.LoadConfigFrom(path)
	if err == nil {
		t.Fatal("expected error for empty commands")
	}
}

func TestConfig_EndpointByName(t *testing.T) {
	cfg, err := responder.ParseEndpointsYAML(strings.NewReader(`
commands:
  - name: alpha
    link: http://localhost/alpha
  - name: beta
    link: http://localhost/beta
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	ep, ok := cfg.EndpointByName("alpha")
	if !ok || ep.Name != "alpha" {
		t.Errorf("EndpointByName(alpha) = %v, %v", ep, ok)
	}
	_, ok = cfg.EndpointByName("unknown")
	if ok {
		t.Error("EndpointByName(unknown) should return false")
	}
}

func TestSplitKV(t *testing.T) {
	cases := []struct {
		input   string
		wantKey string
		wantVal string
	}{
		// Unquoted values.
		{"name: polymarket", "name", "polymarket"},
		{"link: http://localhost:8080/path", "link", "http://localhost:8080/path"},
		{"key: value # inline comment", "key", "value"},
		{"nocoordinate", "nocoordinate", ""},
		// Double-quoted: \\ in YAML → \ in runtime string (escape processing).
		{`arg_regex: "^from:\\s*(?P<from>\\S+)$"`, "arg_regex", `^from:\s*(?P<from>\S+)$`},
		// Double-quoted with escaped double-quote inside.
		{`key: "value \"quoted\""`, "key", `value "quoted"`},
		// Single-quoted: verbatim, no escape processing.
		{`arg_regex: '^from:\s*(?P<from>\S+)$'`, "arg_regex", `^from:\s*(?P<from>\S+)$`},
	}
	for _, tc := range cases {
		k, v := responder.SplitKV(tc.input)
		if k != tc.wantKey || v != tc.wantVal {
			t.Errorf("SplitKV(%q) = (%q, %q), want (%q, %q)", tc.input, k, v, tc.wantKey, tc.wantVal)
		}
	}
}

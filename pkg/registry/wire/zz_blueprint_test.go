// SPDX-License-Identifier: AGPL-3.0-or-later

package wire_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

func TestLoadBlueprint_HappyPath(t *testing.T) {
	t.Parallel()
	bp := &wire.NetworkBlueprint{
		Name:     "test-net",
		JoinRule: "open",
	}
	data, err := json.Marshal(bp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bp.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := wire.LoadBlueprint(path)
	if err != nil {
		t.Fatalf("LoadBlueprint: %v", err)
	}
	if got.Name != bp.Name {
		t.Errorf("Name: got %q, want %q", got.Name, bp.Name)
	}
	if got.JoinRule != bp.JoinRule {
		t.Errorf("JoinRule: got %q, want %q", got.JoinRule, bp.JoinRule)
	}
}

func TestLoadBlueprint_FileNotFound(t *testing.T) {
	t.Parallel()
	_, err := wire.LoadBlueprint(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil || !strings.Contains(err.Error(), "read blueprint") {
		t.Fatalf("want 'read blueprint' err, got %v", err)
	}
}

func TestLoadBlueprint_BadJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{not json`), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := wire.LoadBlueprint(path)
	if err == nil || !strings.Contains(err.Error(), "parse blueprint") {
		t.Fatalf("want 'parse blueprint' err, got %v", err)
	}
}

func TestLoadBlueprint_MissingName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "noname.json")
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := wire.LoadBlueprint(path)
	if err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("want 'name is required' err, got %v", err)
	}
}

func TestValidateBlueprint_HappyPath(t *testing.T) {
	t.Parallel()
	bp := &wire.NetworkBlueprint{Name: "net", JoinRule: "open"}
	if err := wire.ValidateBlueprint(bp); err != nil {
		t.Fatalf("ValidateBlueprint: %v", err)
	}
}

func TestValidateBlueprint_NameRequired(t *testing.T) {
	t.Parallel()
	err := wire.ValidateBlueprint(&wire.NetworkBlueprint{})
	if err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("want 'name is required', got %v", err)
	}
}

func TestValidateBlueprint_AllJoinRules(t *testing.T) {
	t.Parallel()
	for _, jr := range []string{"", "open", "token", "invite"} {
		bp := &wire.NetworkBlueprint{Name: "n", JoinRule: jr}
		if jr == "token" {
			bp.JoinToken = "tok"
		}
		if err := wire.ValidateBlueprint(bp); err != nil {
			t.Errorf("JoinRule=%q: %v", jr, err)
		}
	}
}

func TestValidateBlueprint_InvalidJoinRule(t *testing.T) {
	t.Parallel()
	bp := &wire.NetworkBlueprint{Name: "n", JoinRule: "weird"}
	err := wire.ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "invalid join_rule") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateBlueprint_TokenRuleNeedsToken(t *testing.T) {
	t.Parallel()
	bp := &wire.NetworkBlueprint{Name: "n", JoinRule: "token"}
	err := wire.ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "join_token is required") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateBlueprint_RoleRequiresExternalID(t *testing.T) {
	t.Parallel()
	bp := &wire.NetworkBlueprint{
		Name:  "n",
		Roles: []wire.BlueprintRole{{Role: "admin"}},
	}
	err := wire.ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "external_id is required") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateBlueprint_RoleValidAndInvalid(t *testing.T) {
	t.Parallel()
	for _, r := range []string{"owner", "admin", "member"} {
		bp := &wire.NetworkBlueprint{
			Name:  "n",
			Roles: []wire.BlueprintRole{{ExternalID: "u", Role: r}},
		}
		if err := wire.ValidateBlueprint(bp); err != nil {
			t.Errorf("role=%q: %v", r, err)
		}
	}
	bp := &wire.NetworkBlueprint{
		Name:  "n",
		Roles: []wire.BlueprintRole{{ExternalID: "u", Role: "superadmin"}},
	}
	if err := wire.ValidateBlueprint(bp); err == nil ||
		!strings.Contains(err.Error(), "invalid role") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateBlueprint_IdentityProvider(t *testing.T) {
	t.Parallel()
	// missing URL
	err := wire.ValidateBlueprint(&wire.NetworkBlueprint{
		Name:             "n",
		IdentityProvider: &wire.BlueprintIdentityProvider{Type: "oidc"},
	})
	if err == nil || !strings.Contains(err.Error(), "identity_provider.url is required") {
		t.Fatalf("got %v", err)
	}
	// invalid type
	err = wire.ValidateBlueprint(&wire.NetworkBlueprint{
		Name:             "n",
		IdentityProvider: &wire.BlueprintIdentityProvider{Type: "weird", URL: "https://a.b"},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid identity_provider type") {
		t.Fatalf("got %v", err)
	}
	// happy path for each valid type
	for _, typ := range []string{"oidc", "saml", "webhook", "entra_id", "ldap"} {
		err := wire.ValidateBlueprint(&wire.NetworkBlueprint{
			Name: "n",
			IdentityProvider: &wire.BlueprintIdentityProvider{
				Type: typ,
				URL:  "https://example.com/auth",
			},
		})
		if err != nil {
			t.Errorf("type=%q: %v", typ, err)
		}
	}
}

func TestValidateBlueprint_AuditExport(t *testing.T) {
	t.Parallel()
	// invalid format
	err := wire.ValidateBlueprint(&wire.NetworkBlueprint{
		Name: "n",
		AuditExport: &wire.BlueprintAuditExport{
			Format:   "weird",
			Endpoint: "https://a.b",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid audit_export format") {
		t.Fatalf("got %v", err)
	}
	// missing endpoint
	err = wire.ValidateBlueprint(&wire.NetworkBlueprint{
		Name:        "n",
		AuditExport: &wire.BlueprintAuditExport{Format: "json"},
	})
	if err == nil || !strings.Contains(err.Error(), "audit_export.endpoint is required") {
		t.Fatalf("got %v", err)
	}
	// happy path syslog_cef (no URL validation)
	err = wire.ValidateBlueprint(&wire.NetworkBlueprint{
		Name:        "n",
		AuditExport: &wire.BlueprintAuditExport{Format: "syslog_cef", Endpoint: "1.2.3.4:514"},
	})
	if err != nil {
		t.Errorf("syslog_cef: %v", err)
	}
}

func TestValidateBlueprint_ExprPolicy(t *testing.T) {
	t.Parallel()
	// invalid JSON
	err := wire.ValidateBlueprint(&wire.NetworkBlueprint{
		Name:       "n",
		ExprPolicy: json.RawMessage(`{not json`),
	})
	if err == nil || !strings.Contains(err.Error(), "expr_policy: invalid JSON") {
		t.Fatalf("got %v", err)
	}
	// wrong version
	err = wire.ValidateBlueprint(&wire.NetworkBlueprint{
		Name:       "n",
		ExprPolicy: json.RawMessage(`{"version":2,"rules":[1]}`),
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported version") {
		t.Fatalf("got %v", err)
	}
	// no rules
	err = wire.ValidateBlueprint(&wire.NetworkBlueprint{
		Name:       "n",
		ExprPolicy: json.RawMessage(`{"version":1,"rules":null}`),
	})
	if err == nil || !strings.Contains(err.Error(), "at least one rule") {
		t.Fatalf("got %v", err)
	}
	// happy path
	err = wire.ValidateBlueprint(&wire.NetworkBlueprint{
		Name:       "n",
		ExprPolicy: json.RawMessage(`{"version":1,"rules":[{"on":"connect","match":"true"}]}`),
	})
	if err != nil {
		t.Errorf("happy: %v", err)
	}
}

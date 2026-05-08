// SPDX-License-Identifier: AGPL-3.0-or-later

package server_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/server"
)

// --- LoadBlueprint -------------------------------------------------------

func TestLoadBlueprintFileNotFound(t *testing.T) {
	t.Parallel()
	_, err := server.LoadBlueprint("/definitely/nonexistent/path/blueprint.json")
	if err == nil || !strings.Contains(err.Error(), "read blueprint") {
		t.Fatalf("%v", err)
	}
}

func TestLoadBlueprintBadJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "bp.json")
	if err := os.WriteFile(p, []byte(`{not json`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := server.LoadBlueprint(p)
	if err == nil || !strings.Contains(err.Error(), "parse blueprint") {
		t.Fatalf("%v", err)
	}
}

func TestLoadBlueprintMissingNameRejected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "bp.json")
	// Valid JSON but no "name".
	if err := os.WriteFile(p, []byte(`{"join_rule":"open"}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := server.LoadBlueprint(p)
	if err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("%v", err)
	}
}

func TestLoadBlueprintHappyPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "bp.json")
	payload := `{
		"name": "acme",
		"join_rule": "token",
		"join_token": "s3cret",
		"enterprise": true,
		"policy": {"max_members": 100, "allowed_ports": [80, 443], "description": "hq"},
		"roles": [{"external_id":"u1","role":"admin"}]
	}`
	if err := os.WriteFile(p, []byte(payload), 0600); err != nil {
		t.Fatal(err)
	}
	bp, err := server.LoadBlueprint(p)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if bp.Name != "acme" || bp.JoinRule != "token" || bp.JoinToken != "s3cret" || !bp.Enterprise {
		t.Fatalf("top-level fields: %+v", bp)
	}
	if bp.Policy == nil || bp.Policy.MaxMembers != 100 || len(bp.Policy.AllowedPorts) != 2 {
		t.Fatalf("policy: %+v", bp.Policy)
	}
	if len(bp.Roles) != 1 || bp.Roles[0].ExternalID != "u1" || bp.Roles[0].Role != "admin" {
		t.Fatalf("roles: %+v", bp.Roles)
	}
}

// --- ValidateBlueprint: name required -----------------------------------

func TestValidateBlueprintNameRequired(t *testing.T) {
	t.Parallel()
	bp := &server.NetworkBlueprint{Name: ""}
	err := server.ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("%v", err)
	}
}

// --- ValidateBlueprint: join_rule ---------------------------------------

func TestValidateBlueprintJoinRuleAllValidValues(t *testing.T) {
	t.Parallel()
	for _, jr := range []string{"", "open", "token", "invite"} {
		bp := &server.NetworkBlueprint{Name: "net", JoinRule: jr}
		if jr == "token" {
			bp.JoinToken = "t"
		}
		if err := server.ValidateBlueprint(bp); err != nil {
			t.Fatalf("join_rule=%q: %v", jr, err)
		}
	}
}

func TestValidateBlueprintJoinRuleInvalid(t *testing.T) {
	t.Parallel()
	bp := &server.NetworkBlueprint{Name: "net", JoinRule: "private"}
	err := server.ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "invalid join_rule") {
		t.Fatalf("%v", err)
	}
}

func TestValidateBlueprintTokenRuleRequiresToken(t *testing.T) {
	t.Parallel()
	bp := &server.NetworkBlueprint{Name: "net", JoinRule: "token", JoinToken: ""}
	err := server.ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "join_token is required") {
		t.Fatalf("%v", err)
	}
}

// --- ValidateBlueprint: roles -------------------------------------------

func TestValidateBlueprintRoleExternalIDRequired(t *testing.T) {
	t.Parallel()
	bp := &server.NetworkBlueprint{
		Name:  "net",
		Roles: []server.BlueprintRole{{ExternalID: "", Role: "admin"}},
	}
	err := server.ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "external_id is required") {
		t.Fatalf("%v", err)
	}
}

func TestValidateBlueprintRoleValidValues(t *testing.T) {
	t.Parallel()
	for _, r := range []string{"owner", "admin", "member"} {
		bp := &server.NetworkBlueprint{Name: "net", Roles: []server.BlueprintRole{{ExternalID: "u1", Role: r}}}
		if err := server.ValidateBlueprint(bp); err != nil {
			t.Fatalf("role=%q: %v", r, err)
		}
	}
}

func TestValidateBlueprintRoleInvalid(t *testing.T) {
	t.Parallel()
	bp := &server.NetworkBlueprint{
		Name:  "net",
		Roles: []server.BlueprintRole{{ExternalID: "u1", Role: "superuser"}},
	}
	err := server.ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "invalid role") || !strings.Contains(err.Error(), "superuser") {
		t.Fatalf("%v", err)
	}
}

// --- ValidateBlueprint: identity_provider -------------------------------

func TestValidateBlueprintIdentityProviderTypes(t *testing.T) {
	t.Parallel()
	for _, typ := range []string{"oidc", "saml", "webhook", "entra_id", "ldap"} {
		bp := &server.NetworkBlueprint{
			Name:             "net",
			IdentityProvider: &server.BlueprintIdentityProvider{Type: typ, URL: "https://idp"},
		}
		if err := server.ValidateBlueprint(bp); err != nil {
			t.Fatalf("type=%q: %v", typ, err)
		}
	}
}

func TestValidateBlueprintIdentityProviderInvalidType(t *testing.T) {
	t.Parallel()
	bp := &server.NetworkBlueprint{
		Name:             "net",
		IdentityProvider: &server.BlueprintIdentityProvider{Type: "magic", URL: "https://idp"},
	}
	err := server.ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "invalid identity_provider type") {
		t.Fatalf("%v", err)
	}
}

func TestValidateBlueprintIdentityProviderURLRequired(t *testing.T) {
	t.Parallel()
	bp := &server.NetworkBlueprint{
		Name:             "net",
		IdentityProvider: &server.BlueprintIdentityProvider{Type: "oidc", URL: ""},
	}
	err := server.ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "identity_provider.url is required") {
		t.Fatalf("%v", err)
	}
}

// --- ValidateBlueprint: audit_export ------------------------------------

func TestValidateBlueprintAuditExportFormats(t *testing.T) {
	t.Parallel()
	for _, f := range []string{"json", "splunk_hec", "syslog_cef"} {
		bp := &server.NetworkBlueprint{
			Name:        "net",
			AuditExport: &server.BlueprintAuditExport{Format: f, Endpoint: "https://e"},
		}
		if err := server.ValidateBlueprint(bp); err != nil {
			t.Fatalf("format=%q: %v", f, err)
		}
	}
}

func TestValidateBlueprintAuditExportInvalidFormat(t *testing.T) {
	t.Parallel()
	bp := &server.NetworkBlueprint{
		Name:        "net",
		AuditExport: &server.BlueprintAuditExport{Format: "protobuf", Endpoint: "https://e"},
	}
	err := server.ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "invalid audit_export format") {
		t.Fatalf("%v", err)
	}
}

func TestValidateBlueprintAuditExportEndpointRequired(t *testing.T) {
	t.Parallel()
	bp := &server.NetworkBlueprint{
		Name:        "net",
		AuditExport: &server.BlueprintAuditExport{Format: "json", Endpoint: ""},
	}
	err := server.ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "audit_export.endpoint is required") {
		t.Fatalf("%v", err)
	}
}

// --- ValidateBlueprint: expr_policy -------------------------------------

func TestValidateBlueprintExprPolicyBadJSON(t *testing.T) {
	t.Parallel()
	bp := &server.NetworkBlueprint{Name: "net", ExprPolicy: json.RawMessage(`{not json`)}
	err := server.ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "expr_policy: invalid JSON") {
		t.Fatalf("%v", err)
	}
}

func TestValidateBlueprintExprPolicyUnsupportedVersion(t *testing.T) {
	t.Parallel()
	bp := &server.NetworkBlueprint{Name: "net", ExprPolicy: json.RawMessage(`{"version":2,"rules":[1]}`)}
	err := server.ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "unsupported version 2") {
		t.Fatalf("%v", err)
	}
}

func TestValidateBlueprintExprPolicyMissingRules(t *testing.T) {
	t.Parallel()
	// rules field absent → len(check.Rules)==0 → error
	bp := &server.NetworkBlueprint{Name: "net", ExprPolicy: json.RawMessage(`{"version":1}`)}
	err := server.ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "at least one rule is required") {
		t.Fatalf("absent-rules: %v", err)
	}
	// rules=null explicitly → string(check.Rules)=="null" → error
	bp = &server.NetworkBlueprint{Name: "net", ExprPolicy: json.RawMessage(`{"version":1,"rules":null}`)}
	err = server.ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "at least one rule is required") {
		t.Fatalf("null-rules: %v", err)
	}
}

func TestValidateBlueprintExprPolicyHappy(t *testing.T) {
	t.Parallel()
	bp := &server.NetworkBlueprint{
		Name:       "net",
		ExprPolicy: json.RawMessage(`{"version":1,"rules":[{"name":"allow-all","match":"true"}]}`),
	}
	if err := server.ValidateBlueprint(bp); err != nil {
		t.Fatalf("%v", err)
	}
}

// --- ValidateBlueprint: full happy path --------------------------------

func TestValidateBlueprintFullHappyPath(t *testing.T) {
	t.Parallel()
	bp := &server.NetworkBlueprint{
		Name:       "acme-prod",
		JoinRule:   "token",
		JoinToken:  "t",
		Enterprise: true,
		Policy:     &server.BlueprintPolicy{MaxMembers: 10, AllowedPorts: []uint16{80}, Description: "p"},
		ExprPolicy: json.RawMessage(`{"version":1,"rules":[{"name":"a"}]}`),
		Roles: []server.BlueprintRole{
			{ExternalID: "u1", Role: "owner"},
			{ExternalID: "u2", Role: "admin"},
			{ExternalID: "u3", Role: "member"},
		},
		IdentityProvider: &server.BlueprintIdentityProvider{Type: "oidc", URL: "https://idp/discovery", Issuer: "issu", ClientID: "cid"},
		Webhooks:         &server.BlueprintWebhooks{AuditURL: "https://a", IdentityURL: "https://i"},
		AuditExport:      &server.BlueprintAuditExport{Format: "splunk_hec", Endpoint: "https://sp", Token: "tok", Index: "idx", Source: "src"},
	}
	if err := server.ValidateBlueprint(bp); err != nil {
		t.Fatalf("full happy: %v", err)
	}
}

// --- ValidateBlueprint: empty expr_policy is OK (skip branch) -----------

func TestValidateBlueprintEmptyExprPolicyIsOK(t *testing.T) {
	t.Parallel()
	// len(bp.ExprPolicy)==0 → skip the expr_policy validation entirely.
	bp := &server.NetworkBlueprint{Name: "net", ExprPolicy: nil}
	if err := server.ValidateBlueprint(bp); err != nil {
		t.Fatalf("nil ExprPolicy: %v", err)
	}
	bp = &server.NetworkBlueprint{Name: "net", ExprPolicy: json.RawMessage("")}
	if err := server.ValidateBlueprint(bp); err != nil {
		t.Fatalf("empty ExprPolicy: %v", err)
	}
}

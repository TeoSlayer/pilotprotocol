package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- LoadBlueprint -------------------------------------------------------

func TestLoadBlueprintFileNotFound(t *testing.T) {
	_, err := LoadBlueprint("/definitely/nonexistent/path/blueprint.json")
	if err == nil || !strings.Contains(err.Error(), "read blueprint") {
		t.Fatalf("%v", err)
	}
}

func TestLoadBlueprintBadJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bp.json")
	if err := os.WriteFile(p, []byte(`{not json`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadBlueprint(p)
	if err == nil || !strings.Contains(err.Error(), "parse blueprint") {
		t.Fatalf("%v", err)
	}
}

func TestLoadBlueprintMissingNameRejected(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bp.json")
	// Valid JSON but no "name".
	if err := os.WriteFile(p, []byte(`{"join_rule":"open"}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadBlueprint(p)
	if err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("%v", err)
	}
}

func TestLoadBlueprintHappyPath(t *testing.T) {
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
	bp, err := LoadBlueprint(p)
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
	bp := &NetworkBlueprint{Name: ""}
	err := ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("%v", err)
	}
}

// --- ValidateBlueprint: join_rule ---------------------------------------

func TestValidateBlueprintJoinRuleAllValidValues(t *testing.T) {
	for _, jr := range []string{"", "open", "token", "invite"} {
		bp := &NetworkBlueprint{Name: "net", JoinRule: jr}
		if jr == "token" {
			bp.JoinToken = "t"
		}
		if err := ValidateBlueprint(bp); err != nil {
			t.Fatalf("join_rule=%q: %v", jr, err)
		}
	}
}

func TestValidateBlueprintJoinRuleInvalid(t *testing.T) {
	bp := &NetworkBlueprint{Name: "net", JoinRule: "private"}
	err := ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "invalid join_rule") {
		t.Fatalf("%v", err)
	}
}

func TestValidateBlueprintTokenRuleRequiresToken(t *testing.T) {
	bp := &NetworkBlueprint{Name: "net", JoinRule: "token", JoinToken: ""}
	err := ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "join_token is required") {
		t.Fatalf("%v", err)
	}
}

// --- ValidateBlueprint: roles -------------------------------------------

func TestValidateBlueprintRoleExternalIDRequired(t *testing.T) {
	bp := &NetworkBlueprint{
		Name:  "net",
		Roles: []BlueprintRole{{ExternalID: "", Role: "admin"}},
	}
	err := ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "external_id is required") {
		t.Fatalf("%v", err)
	}
}

func TestValidateBlueprintRoleValidValues(t *testing.T) {
	for _, r := range []string{"owner", "admin", "member"} {
		bp := &NetworkBlueprint{Name: "net", Roles: []BlueprintRole{{ExternalID: "u1", Role: r}}}
		if err := ValidateBlueprint(bp); err != nil {
			t.Fatalf("role=%q: %v", r, err)
		}
	}
}

func TestValidateBlueprintRoleInvalid(t *testing.T) {
	bp := &NetworkBlueprint{
		Name:  "net",
		Roles: []BlueprintRole{{ExternalID: "u1", Role: "superuser"}},
	}
	err := ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "invalid role") || !strings.Contains(err.Error(), "superuser") {
		t.Fatalf("%v", err)
	}
}

// --- ValidateBlueprint: identity_provider -------------------------------

func TestValidateBlueprintIdentityProviderTypes(t *testing.T) {
	for _, typ := range []string{"oidc", "saml", "webhook", "entra_id", "ldap"} {
		bp := &NetworkBlueprint{
			Name:             "net",
			IdentityProvider: &BlueprintIdentityProvider{Type: typ, URL: "https://idp"},
		}
		if err := ValidateBlueprint(bp); err != nil {
			t.Fatalf("type=%q: %v", typ, err)
		}
	}
}

func TestValidateBlueprintIdentityProviderInvalidType(t *testing.T) {
	bp := &NetworkBlueprint{
		Name:             "net",
		IdentityProvider: &BlueprintIdentityProvider{Type: "magic", URL: "https://idp"},
	}
	err := ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "invalid identity_provider type") {
		t.Fatalf("%v", err)
	}
}

func TestValidateBlueprintIdentityProviderURLRequired(t *testing.T) {
	bp := &NetworkBlueprint{
		Name:             "net",
		IdentityProvider: &BlueprintIdentityProvider{Type: "oidc", URL: ""},
	}
	err := ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "identity_provider.url is required") {
		t.Fatalf("%v", err)
	}
}

// --- ValidateBlueprint: audit_export ------------------------------------

func TestValidateBlueprintAuditExportFormats(t *testing.T) {
	for _, f := range []string{"json", "splunk_hec", "syslog_cef"} {
		bp := &NetworkBlueprint{
			Name:        "net",
			AuditExport: &BlueprintAuditExport{Format: f, Endpoint: "https://e"},
		}
		if err := ValidateBlueprint(bp); err != nil {
			t.Fatalf("format=%q: %v", f, err)
		}
	}
}

func TestValidateBlueprintAuditExportInvalidFormat(t *testing.T) {
	bp := &NetworkBlueprint{
		Name:        "net",
		AuditExport: &BlueprintAuditExport{Format: "protobuf", Endpoint: "https://e"},
	}
	err := ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "invalid audit_export format") {
		t.Fatalf("%v", err)
	}
}

func TestValidateBlueprintAuditExportEndpointRequired(t *testing.T) {
	bp := &NetworkBlueprint{
		Name:        "net",
		AuditExport: &BlueprintAuditExport{Format: "json", Endpoint: ""},
	}
	err := ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "audit_export.endpoint is required") {
		t.Fatalf("%v", err)
	}
}

// --- ValidateBlueprint: expr_policy -------------------------------------

func TestValidateBlueprintExprPolicyBadJSON(t *testing.T) {
	bp := &NetworkBlueprint{Name: "net", ExprPolicy: json.RawMessage(`{not json`)}
	err := ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "expr_policy: invalid JSON") {
		t.Fatalf("%v", err)
	}
}

func TestValidateBlueprintExprPolicyUnsupportedVersion(t *testing.T) {
	bp := &NetworkBlueprint{Name: "net", ExprPolicy: json.RawMessage(`{"version":2,"rules":[1]}`)}
	err := ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "unsupported version 2") {
		t.Fatalf("%v", err)
	}
}

func TestValidateBlueprintExprPolicyMissingRules(t *testing.T) {
	// rules field absent → len(check.Rules)==0 → error
	bp := &NetworkBlueprint{Name: "net", ExprPolicy: json.RawMessage(`{"version":1}`)}
	err := ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "at least one rule is required") {
		t.Fatalf("absent-rules: %v", err)
	}
	// rules=null explicitly → string(check.Rules)=="null" → error
	bp = &NetworkBlueprint{Name: "net", ExprPolicy: json.RawMessage(`{"version":1,"rules":null}`)}
	err = ValidateBlueprint(bp)
	if err == nil || !strings.Contains(err.Error(), "at least one rule is required") {
		t.Fatalf("null-rules: %v", err)
	}
}

func TestValidateBlueprintExprPolicyHappy(t *testing.T) {
	bp := &NetworkBlueprint{
		Name:       "net",
		ExprPolicy: json.RawMessage(`{"version":1,"rules":[{"name":"allow-all","match":"true"}]}`),
	}
	if err := ValidateBlueprint(bp); err != nil {
		t.Fatalf("%v", err)
	}
}

// --- ValidateBlueprint: full happy path --------------------------------

func TestValidateBlueprintFullHappyPath(t *testing.T) {
	bp := &NetworkBlueprint{
		Name:       "acme-prod",
		JoinRule:   "token",
		JoinToken:  "t",
		Enterprise: true,
		Policy:     &BlueprintPolicy{MaxMembers: 10, AllowedPorts: []uint16{80}, Description: "p"},
		ExprPolicy: json.RawMessage(`{"version":1,"rules":[{"name":"a"}]}`),
		Roles: []BlueprintRole{
			{ExternalID: "u1", Role: "owner"},
			{ExternalID: "u2", Role: "admin"},
			{ExternalID: "u3", Role: "member"},
		},
		IdentityProvider: &BlueprintIdentityProvider{Type: "oidc", URL: "https://idp/discovery", Issuer: "issu", ClientID: "cid"},
		Webhooks:         &BlueprintWebhooks{AuditURL: "https://a", IdentityURL: "https://i"},
		AuditExport:      &BlueprintAuditExport{Format: "splunk_hec", Endpoint: "https://sp", Token: "tok", Index: "idx", Source: "src"},
	}
	if err := ValidateBlueprint(bp); err != nil {
		t.Fatalf("full happy: %v", err)
	}
}

// --- ValidateBlueprint: empty expr_policy is OK (skip branch) -----------

func TestValidateBlueprintEmptyExprPolicyIsOK(t *testing.T) {
	// len(bp.ExprPolicy)==0 → skip the expr_policy validation entirely.
	bp := &NetworkBlueprint{Name: "net", ExprPolicy: nil}
	if err := ValidateBlueprint(bp); err != nil {
		t.Fatalf("nil ExprPolicy: %v", err)
	}
	bp = &NetworkBlueprint{Name: "net", ExprPolicy: json.RawMessage("")}
	if err := ValidateBlueprint(bp); err != nil {
		t.Fatalf("empty ExprPolicy: %v", err)
	}
}

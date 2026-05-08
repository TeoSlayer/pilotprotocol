// SPDX-License-Identifier: AGPL-3.0-or-later

package wire

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/TeoSlayer/pilotprotocol/pkg/urlvalidate"
)

// NetworkBlueprint defines a declarative configuration for provisioning
// an enterprise network. Enterprises apply blueprints via the registry
// protocol or the pilotctl CLI to create and configure networks in one shot.
type NetworkBlueprint struct {
	// Network settings
	Name       string `json:"name"`
	JoinRule   string `json:"join_rule,omitempty"`  // "open", "token", "invite" (default: "open")
	JoinToken  string `json:"join_token,omitempty"` // required if join_rule = "token"
	Enterprise bool   `json:"enterprise,omitempty"` // enable enterprise features

	// Policy
	Policy     *BlueprintPolicy `json:"policy,omitempty"`
	ExprPolicy json.RawMessage  `json:"expr_policy,omitempty"`

	// RBAC pre-assignments (by external_id)
	Roles []BlueprintRole `json:"roles,omitempty"`

	// Identity provider configuration
	IdentityProvider *BlueprintIdentityProvider `json:"identity_provider,omitempty"`

	// Observability
	Webhooks *BlueprintWebhooks `json:"webhooks,omitempty"`

	// Audit export
	AuditExport *BlueprintAuditExport `json:"audit_export,omitempty"`

	// Per-network admin token (optional override)
	NetworkAdminToken string `json:"network_admin_token,omitempty"`
}

// BlueprintPolicy defines the network policy section of a blueprint.
type BlueprintPolicy struct {
	MaxMembers   int      `json:"max_members,omitempty"`
	AllowedPorts []uint16 `json:"allowed_ports,omitempty"`
	Description  string   `json:"description,omitempty"`
}

// BlueprintRole pre-assigns RBAC roles by external identity.
type BlueprintRole struct {
	ExternalID string `json:"external_id"`
	Role       string `json:"role"` // "owner", "admin", "member"
}

// BlueprintIdentityProvider configures external identity verification.
type BlueprintIdentityProvider struct {
	Type     string `json:"type"`                // "oidc", "saml", "webhook", "entra_id", "ldap"
	URL      string `json:"url"`                 // verification endpoint
	Issuer   string `json:"issuer,omitempty"`    // OIDC issuer URL
	ClientID string `json:"client_id,omitempty"` // OIDC client ID
	TenantID string `json:"tenant_id,omitempty"` // Azure AD / Entra ID tenant
	Domain   string `json:"domain,omitempty"`    // LDAP domain
}

// BlueprintWebhooks configures webhook endpoints for the network.
type BlueprintWebhooks struct {
	AuditURL    string `json:"audit_url,omitempty"`    // audit event webhook
	IdentityURL string `json:"identity_url,omitempty"` // identity verification webhook
}

// BlueprintAuditExport configures external audit log export.
type BlueprintAuditExport struct {
	Format   string `json:"format"`           // "json", "splunk_hec", "syslog_cef"
	Endpoint string `json:"endpoint"`         // destination URL or address
	Token    string `json:"token,omitempty"`  // auth token (e.g., Splunk HEC token)
	Index    string `json:"index,omitempty"`  // Splunk index
	Source   string `json:"source,omitempty"` // source identifier
}

// LoadBlueprint reads a network blueprint from a JSON file.
func LoadBlueprint(path string) (*NetworkBlueprint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read blueprint: %w", err)
	}
	var bp NetworkBlueprint
	if err := json.Unmarshal(data, &bp); err != nil {
		return nil, fmt.Errorf("parse blueprint: %w", err)
	}
	if bp.Name == "" {
		return nil, fmt.Errorf("blueprint: name is required")
	}
	return &bp, nil
}

// ValidateBlueprint checks a blueprint for configuration errors.
func ValidateBlueprint(bp *NetworkBlueprint) error {
	if bp.Name == "" {
		return fmt.Errorf("name is required")
	}
	switch bp.JoinRule {
	case "", "open", "token", "invite":
	default:
		return fmt.Errorf("invalid join_rule %q (must be open, token, or invite)", bp.JoinRule)
	}
	if bp.JoinRule == "token" && bp.JoinToken == "" {
		return fmt.Errorf("join_token is required when join_rule is token")
	}
	for _, r := range bp.Roles {
		if r.ExternalID == "" {
			return fmt.Errorf("role entry: external_id is required")
		}
		switch r.Role {
		case "owner", "admin", "member":
		default:
			return fmt.Errorf("invalid role %q for %s", r.Role, r.ExternalID)
		}
	}
	if bp.IdentityProvider != nil {
		switch bp.IdentityProvider.Type {
		case "oidc", "saml", "webhook", "entra_id", "ldap":
		default:
			return fmt.Errorf("invalid identity_provider type %q", bp.IdentityProvider.Type)
		}
		if bp.IdentityProvider.URL == "" {
			return fmt.Errorf("identity_provider.url is required")
		}
		if err := urlvalidate.Validate(bp.IdentityProvider.URL); err != nil {
			return fmt.Errorf("identity_provider.url: %w", err)
		}
	}
	if bp.Webhooks != nil {
		if bp.Webhooks.AuditURL != "" {
			if err := urlvalidate.Validate(bp.Webhooks.AuditURL); err != nil {
				return fmt.Errorf("webhooks.audit_url: %w", err)
			}
		}
		if bp.Webhooks.IdentityURL != "" {
			if err := urlvalidate.Validate(bp.Webhooks.IdentityURL); err != nil {
				return fmt.Errorf("webhooks.identity_url: %w", err)
			}
		}
	}
	if bp.AuditExport != nil {
		switch bp.AuditExport.Format {
		case "json", "splunk_hec", "syslog_cef":
		default:
			return fmt.Errorf("invalid audit_export format %q", bp.AuditExport.Format)
		}
		if bp.AuditExport.Endpoint == "" {
			return fmt.Errorf("audit_export.endpoint is required")
		}
		// syslog_cef sinks accept raw host:port targets; only the HTTP(S)
		// formats need SSRF validation.
		if bp.AuditExport.Format == "json" || bp.AuditExport.Format == "splunk_hec" {
			if err := urlvalidate.Validate(bp.AuditExport.Endpoint); err != nil {
				return fmt.Errorf("audit_export.endpoint: %w", err)
			}
		}
	}
	if len(bp.ExprPolicy) > 0 {
		var check struct {
			Version int             `json:"version"`
			Rules   json.RawMessage `json:"rules"`
		}
		if err := json.Unmarshal(bp.ExprPolicy, &check); err != nil {
			return fmt.Errorf("expr_policy: invalid JSON: %w", err)
		}
		if check.Version != 1 {
			return fmt.Errorf("expr_policy: unsupported version %d (want 1)", check.Version)
		}
		if len(check.Rules) == 0 || string(check.Rules) == "null" {
			return fmt.Errorf("expr_policy: at least one rule is required")
		}
	}
	return nil
}

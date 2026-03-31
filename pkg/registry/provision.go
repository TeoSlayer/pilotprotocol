package registry

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

// NetworkBlueprint defines a declarative configuration for provisioning
// an enterprise network. Enterprises apply blueprints via the registry
// protocol or the pilotctl CLI to create and configure networks in one shot.
type NetworkBlueprint struct {
	// Network settings
	Name       string `json:"name"`
	JoinRule   string `json:"join_rule,omitempty"`   // "open", "token", "invite" (default: "open")
	JoinToken  string `json:"join_token,omitempty"`  // required if join_rule = "token"
	Enterprise bool   `json:"enterprise,omitempty"`  // enable enterprise features

	// Policy
	Policy *BlueprintPolicy `json:"policy,omitempty"`

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
	Type     string `json:"type"`               // "oidc", "saml", "webhook", "entra_id", "ldap"
	URL      string `json:"url"`                // verification endpoint
	Issuer   string `json:"issuer,omitempty"`   // OIDC issuer URL
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
	Format   string `json:"format"`             // "json", "splunk_hec", "syslog_cef"
	Endpoint string `json:"endpoint"`           // destination URL or address
	Token    string `json:"token,omitempty"`     // auth token (e.g., Splunk HEC token)
	Index    string `json:"index,omitempty"`     // Splunk index
	Source   string `json:"source,omitempty"`    // source identifier
}

// ProvisionResult describes what the provisioning operation did.
type ProvisionResult struct {
	NetworkID uint16   `json:"network_id"`
	Name      string   `json:"name"`
	Created   bool     `json:"created"`   // true if network was created (vs updated)
	Actions   []string `json:"actions"`   // human-readable list of actions taken
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
	}
	return nil
}

// ApplyBlueprint provisions a network from a blueprint. It creates the network
// if it doesn't exist, then applies policy, RBAC, webhooks, and audit config.
// The adminToken is the global registry admin token.
func (s *Server) ApplyBlueprint(bp *NetworkBlueprint, adminToken string) (*ProvisionResult, error) {
	if err := ValidateBlueprint(bp); err != nil {
		return nil, fmt.Errorf("invalid blueprint: %w", err)
	}

	result := &ProvisionResult{Name: bp.Name}

	// Step 1: Find or create network
	netID, created, err := s.findOrCreateNetwork(bp, adminToken)
	if err != nil {
		return nil, fmt.Errorf("provision network: %w", err)
	}
	result.NetworkID = netID
	result.Created = created
	if created {
		result.Actions = append(result.Actions, fmt.Sprintf("created network %d (%s)", netID, bp.Name))
	} else {
		result.Actions = append(result.Actions, fmt.Sprintf("found existing network %d (%s)", netID, bp.Name))
	}

	// Step 2: Enable enterprise if requested
	if bp.Enterprise {
		s.mu.Lock()
		net, ok := s.networks[netID]
		if ok && !net.Enterprise {
			net.Enterprise = true
			s.save()
			result.Actions = append(result.Actions, "enabled enterprise features")
		}
		s.mu.Unlock()
	}

	// Step 3: Apply policy
	if bp.Policy != nil {
		if err := s.applyBlueprintPolicy(netID, bp.Policy); err != nil {
			return nil, fmt.Errorf("apply policy: %w", err)
		}
		result.Actions = append(result.Actions, "applied network policy")
	}

	// Step 4: Configure identity provider
	if bp.IdentityProvider != nil {
		url := bp.IdentityProvider.URL
		s.SetIdentityWebhookURL(url)
		result.Actions = append(result.Actions, fmt.Sprintf("configured %s identity provider", bp.IdentityProvider.Type))
		s.storeIdentityProviderConfig(bp.IdentityProvider)
	}

	// Step 5: Configure webhooks
	if bp.Webhooks != nil {
		if bp.Webhooks.AuditURL != "" {
			s.SetWebhookURL(bp.Webhooks.AuditURL)
			result.Actions = append(result.Actions, "configured audit webhook")
		}
		if bp.Webhooks.IdentityURL != "" {
			s.SetIdentityWebhookURL(bp.Webhooks.IdentityURL)
			result.Actions = append(result.Actions, "configured identity webhook")
		}
	}

	// Step 6: Configure audit export
	if bp.AuditExport != nil {
		s.configureAuditExport(bp.AuditExport)
		result.Actions = append(result.Actions, fmt.Sprintf("configured %s audit export to %s", bp.AuditExport.Format, bp.AuditExport.Endpoint))
	}

	// Step 7: Store RBAC pre-assignments for future node joins
	if len(bp.Roles) > 0 {
		s.storeRBACPreAssignments(netID, bp.Roles)
		result.Actions = append(result.Actions, fmt.Sprintf("stored %d RBAC pre-assignments", len(bp.Roles)))
	}

	s.metrics.provisionsTotal.Inc()
	s.audit("network.provisioned", "network_id", netID, "name", bp.Name,
		"enterprise", bp.Enterprise, "actions", len(result.Actions))

	slog.Info("network provisioned from blueprint",
		"network_id", netID, "name", bp.Name, "actions", len(result.Actions))
	return result, nil
}

// findOrCreateNetwork looks up a network by name, or creates it if not found.
func (s *Server) findOrCreateNetwork(bp *NetworkBlueprint, adminToken string) (uint16, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Search by name
	for _, net := range s.networks {
		if net.Name == bp.Name {
			return net.ID, false, nil
		}
	}

	// Create new network
	if s.adminToken == "" {
		return 0, false, fmt.Errorf("network creation disabled (no admin token)")
	}
	if err := s.checkAdminToken(map[string]interface{}{"admin_token": adminToken}, s.adminToken); err != nil {
		return 0, false, err
	}
	if err := validateNetworkName(bp.Name); err != nil {
		return 0, false, err
	}

	netID := s.nextNet
	s.nextNet++

	joinRule := bp.JoinRule
	if joinRule == "" {
		joinRule = "open"
	}

	net := &NetworkInfo{
		ID:          netID,
		Name:        bp.Name,
		Enterprise:  bp.Enterprise,
		Members:     nil,
		MemberRoles: make(map[uint32]Role),
		JoinRule:    joinRule,
		Created:     time.Now(),
	}
	if bp.JoinToken != "" {
		net.Token = bp.JoinToken
	}
	if bp.NetworkAdminToken != "" {
		net.AdminToken = bp.NetworkAdminToken
	}
	s.networks[netID] = net
	s.save()

	return netID, true, nil
}

// applyBlueprintPolicy sets the network policy from a blueprint.
func (s *Server) applyBlueprintPolicy(netID uint16, pol *BlueprintPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	net, ok := s.networks[netID]
	if !ok {
		return fmt.Errorf("network %d not found", netID)
	}
	if pol.MaxMembers > 0 {
		net.Policy.MaxMembers = pol.MaxMembers
	}
	if len(pol.AllowedPorts) > 0 {
		net.Policy.AllowedPorts = pol.AllowedPorts
	}
	if pol.Description != "" {
		net.Policy.Description = pol.Description
	}
	s.save()
	return nil
}

// storeIdentityProviderConfig saves the identity provider config for inspection.
func (s *Server) storeIdentityProviderConfig(idp *BlueprintIdentityProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idpConfig = idp
}

// storeRBACPreAssignments saves role pre-assignments that will be applied when
// nodes with matching external_ids join the network.
func (s *Server) storeRBACPreAssignments(netID uint16, roles []BlueprintRole) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rbacPreAssign == nil {
		s.rbacPreAssign = make(map[uint16][]BlueprintRole)
	}
	s.rbacPreAssign[netID] = roles
}

// configureAuditExport sets up an audit export adapter based on the config.
func (s *Server) configureAuditExport(cfg *BlueprintAuditExport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditExportConfig = cfg
	// Close existing exporter if any
	if s.auditExporter != nil {
		s.auditExporter.Close()
	}
	s.auditExporter = newAuditExporter(cfg)
	slog.Info("audit export configured", "format", cfg.Format, "endpoint", cfg.Endpoint)
}

// applyRBACPreAssignmentLocked checks if a newly joined node matches any
// pre-assigned roles. Caller must hold s.mu.
func (s *Server) applyRBACPreAssignmentLocked(netID uint16, nodeID uint32) {
	roles, ok := s.rbacPreAssign[netID]
	if !ok {
		return
	}
	node, ok := s.nodes[nodeID]
	if !ok || node.ExternalID == "" {
		return
	}
	for _, r := range roles {
		if strings.EqualFold(r.ExternalID, node.ExternalID) {
			net, ok := s.networks[netID]
			if !ok {
				return
			}
			var role Role
			switch r.Role {
			case "owner":
				role = RoleOwner
			case "admin":
				role = RoleAdmin
			default:
				role = RoleMember
			}
			net.MemberRoles[nodeID] = role
			s.save()
			s.metrics.rbacPreAssignments.Inc()
			slog.Info("RBAC pre-assignment applied",
				"network_id", netID, "node_id", nodeID,
				"external_id", node.ExternalID, "role", r.Role)
			return
		}
	}
}

// handleProvisionNetwork handles the "provision_network" protocol command.
func (s *Server) handleProvisionNetwork(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}

	bpJSON, _ := msg["blueprint"].(map[string]interface{})
	if bpJSON == nil {
		return nil, fmt.Errorf("blueprint is required")
	}

	// Marshal/unmarshal to parse into the struct
	raw, err := json.Marshal(bpJSON)
	if err != nil {
		return nil, fmt.Errorf("marshal blueprint: %w", err)
	}
	var bp NetworkBlueprint
	if err := json.Unmarshal(raw, &bp); err != nil {
		return nil, fmt.Errorf("parse blueprint: %w", err)
	}

	adminToken, _ := msg["admin_token"].(string)
	result, err := s.ApplyBlueprint(&bp, adminToken)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"type":       "provision_network_ok",
		"network_id": result.NetworkID,
		"name":       result.Name,
		"created":    result.Created,
		"actions":    result.Actions,
	}, nil
}

// GetIdentityProviderConfig returns the current identity provider config. Thread-safe.
func (s *Server) GetIdentityProviderConfig() *BlueprintIdentityProvider {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.idpConfig
}

// GetAuditExportConfig returns the current audit export config. Thread-safe.
func (s *Server) GetAuditExportConfig() *BlueprintAuditExport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.auditExportConfig
}

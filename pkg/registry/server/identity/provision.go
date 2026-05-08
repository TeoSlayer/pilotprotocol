// SPDX-License-Identifier: AGPL-3.0-or-later

// Provision logic for the identity sub-package. Extracted from
// pkg/registry/server/provision.go as part of the R7.2 registry
// decomposition: blueprint provisioning, RBAC pre-assignment, and
// audit-export configuration belong here because they configure
// the identity layer and are initiated through the same admin path.

package identity

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

// Blueprint type aliases. The canonical definitions live in
// pkg/registry/wire so plugin tests and the client can validate
// blueprints without importing the server. Aliases keep existing
// callers readable.
type (
	NetworkBlueprint     = wire.NetworkBlueprint
	BlueprintPolicy      = wire.BlueprintPolicy
	BlueprintRole        = wire.BlueprintRole
	BlueprintWebhooks    = wire.BlueprintWebhooks
	BlueprintAuditExport = wire.BlueprintAuditExport
)

// LoadBlueprint and ValidateBlueprint are re-exported for callers that
// historically imported them from pkg/registry/server.
var (
	LoadBlueprint     = wire.LoadBlueprint
	ValidateBlueprint = wire.ValidateBlueprint
)

// ProvisionResult describes what the provisioning operation did.
type ProvisionResult struct {
	NetworkID uint16   `json:"network_id"`
	Name      string   `json:"name"`
	Created   bool     `json:"created"` // true if network was created (vs updated)
	Actions   []string `json:"actions"` // human-readable list of actions taken
}

// ---------------------------------------------------------------------------
// ProvisionCallbacks — injected by the parent Server per ApplyBlueprint call.
// All functions must be safe for concurrent use. Nil callbacks are no-ops.
// ---------------------------------------------------------------------------

// ProvisionCallbacks holds the server-owned operations that ApplyBlueprint
// needs. They are passed per-call rather than stored on the Store so that
// provisioning can be called with different server contexts in tests.
type ProvisionCallbacks struct {
	// FindOrCreateNetwork looks up a network by name; if not found it creates
	// one using the supplied blueprint fields. Returns (networkID, created, err).
	FindOrCreateNetwork func(name string, enterprise bool, joinRule, joinToken, networkAdminToken, adminToken string) (uint16, bool, error)

	// EnableEnterprise sets the Enterprise flag on network netID if not already set.
	EnableEnterprise func(netID uint16)

	// ApplyNetworkPolicy sets the structural policy on a network.
	ApplyNetworkPolicy func(netID uint16, pol *BlueprintPolicy) error

	// ApplyExprPolicy sets the programmable (expr) policy on a network.
	ApplyExprPolicy func(netID uint16, data json.RawMessage) error

	// SetAuditWebhookURL configures the server's audit webhook URL.
	SetAuditWebhookURL func(url string)

	// StoreRBACPreAssignments saves pre-assignments for future node joins.
	StoreRBACPreAssignments func(netID uint16, roles []BlueprintRole)

	// ConfigureAuditExport sets up the audit exporter.
	ConfigureAuditExport func(cfg *BlueprintAuditExport)

	// IncProvisionsTotal increments the provisions counter.
	IncProvisionsTotal func()
}

// ---------------------------------------------------------------------------
// ApplyBlueprint — main provisioning entry point on identity.Store
// ---------------------------------------------------------------------------

// ApplyBlueprint provisions a network from a blueprint. It creates the network
// if it doesn't exist, then applies policy, RBAC, webhooks, and audit config.
// adminToken is the global registry admin token.
//
// The provision callbacks (pcb) provide access to server-owned state. Nil
// callbacks are silently skipped, except FindOrCreateNetwork which is required.
func (st *Store) ApplyBlueprint(bp *NetworkBlueprint, adminToken string, pcb ProvisionCallbacks) (*ProvisionResult, error) {
	if err := ValidateBlueprint(bp); err != nil {
		return nil, fmt.Errorf("invalid blueprint: %w", err)
	}

	result := &ProvisionResult{Name: bp.Name}

	// Step 1: Find or create network.
	if pcb.FindOrCreateNetwork == nil {
		return nil, fmt.Errorf("ApplyBlueprint: FindOrCreateNetwork callback is required")
	}
	netID, created, err := pcb.FindOrCreateNetwork(
		bp.Name, bp.Enterprise, bp.JoinRule, bp.JoinToken, bp.NetworkAdminToken, adminToken,
	)
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

	// Step 2: Enable enterprise if requested.
	if bp.Enterprise && pcb.EnableEnterprise != nil {
		pcb.EnableEnterprise(netID)
		result.Actions = append(result.Actions, "enabled enterprise features")
	}

	// Step 3: Apply structural policy.
	if bp.Policy != nil && pcb.ApplyNetworkPolicy != nil {
		if err := pcb.ApplyNetworkPolicy(netID, bp.Policy); err != nil {
			return nil, fmt.Errorf("apply policy: %w", err)
		}
		result.Actions = append(result.Actions, "applied network policy")
	}

	// Step 3b: Apply programmable policy.
	if len(bp.ExprPolicy) > 0 && pcb.ApplyExprPolicy != nil {
		if err := pcb.ApplyExprPolicy(netID, bp.ExprPolicy); err != nil {
			return nil, fmt.Errorf("apply expr_policy: %w", err)
		}
		result.Actions = append(result.Actions, "applied expr policy")
	}

	// Step 4: Configure identity provider.
	if bp.IdentityProvider != nil {
		st.SetWebhookURL(bp.IdentityProvider.URL)
		st.SetIDPConfig(bp.IdentityProvider)
		result.Actions = append(result.Actions, fmt.Sprintf("configured %s identity provider", bp.IdentityProvider.Type))
	}

	// Step 5: Configure webhooks.
	if bp.Webhooks != nil {
		if bp.Webhooks.AuditURL != "" && pcb.SetAuditWebhookURL != nil {
			pcb.SetAuditWebhookURL(bp.Webhooks.AuditURL)
			result.Actions = append(result.Actions, "configured audit webhook")
		}
		if bp.Webhooks.IdentityURL != "" {
			st.SetWebhookURL(bp.Webhooks.IdentityURL)
			result.Actions = append(result.Actions, "configured identity webhook")
		}
	}

	// Step 6: Configure audit export.
	if bp.AuditExport != nil && pcb.ConfigureAuditExport != nil {
		pcb.ConfigureAuditExport(bp.AuditExport)
		result.Actions = append(result.Actions, fmt.Sprintf("configured %s audit export to %s", bp.AuditExport.Format, bp.AuditExport.Endpoint))
	}

	// Step 7: Store RBAC pre-assignments for future node joins.
	if len(bp.Roles) > 0 && pcb.StoreRBACPreAssignments != nil {
		pcb.StoreRBACPreAssignments(netID, bp.Roles)
		result.Actions = append(result.Actions, fmt.Sprintf("stored %d RBAC pre-assignments", len(bp.Roles)))
	}

	if pcb.IncProvisionsTotal != nil {
		pcb.IncProvisionsTotal()
	}
	if st.cb.Audit != nil {
		st.cb.Audit("network.provisioned", "network_id", netID, "name", bp.Name,
			"enterprise", bp.Enterprise, "actions", len(result.Actions))
	}

	slog.Info("network provisioned from blueprint",
		"network_id", netID, "name", bp.Name, "actions", len(result.Actions))
	return result, nil
}

// HandleProvisionNetwork handles the "provision_network" protocol command.
// adminToken is the global registry admin token (from s.authz.AdminToken()).
// pcb provides the server-owned operation callbacks.
func (st *Store) HandleProvisionNetwork(msg map[string]interface{}, adminToken string, pcb ProvisionCallbacks) (map[string]interface{}, error) {
	if err := st.nodes.CheckAdminToken(msg); err != nil {
		return nil, err
	}

	bpJSON, _ := msg["blueprint"].(map[string]interface{})
	if bpJSON == nil {
		return nil, fmt.Errorf("blueprint is required")
	}

	// Marshal/unmarshal to parse into the struct.
	raw, err := json.Marshal(bpJSON)
	if err != nil {
		return nil, fmt.Errorf("marshal blueprint: %w", err)
	}
	var bp NetworkBlueprint
	if err := json.Unmarshal(raw, &bp); err != nil {
		return nil, fmt.Errorf("parse blueprint: %w", err)
	}

	msgAdminToken, _ := msg["admin_token"].(string)
	if adminToken == "" {
		adminToken = msgAdminToken
	}
	result, err := st.ApplyBlueprint(&bp, adminToken, pcb)
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

// ---------------------------------------------------------------------------
// ApplyRBACPreAssignment — called when a node joins a network
// ---------------------------------------------------------------------------

// RBACPreAssignCallbacks holds the state-access callbacks needed by
// ApplyRBACPreAssignment.
type RBACPreAssignCallbacks struct {
	// GetRoles returns the pre-assigned roles for netID and the node's
	// ExternalID. found is false if there are no pre-assignments or the
	// node doesn't exist.
	GetRoles func(netID uint16, nodeID uint32) (roles []BlueprintRole, externalID string, found bool)

	// CommitRole sets the member's role in the network.
	CommitRole func(netID uint16, nodeID uint32, role string)

	// IncCounter increments the RBAC pre-assignment metric counter.
	IncCounter func()
}

// ApplyRBACPreAssignment checks if a newly joined node matches any pre-assigned
// roles and applies the first match. Caller must NOT hold the server's global
// mutex (GetRoles and CommitRole acquire their own locks internally).
func (st *Store) ApplyRBACPreAssignment(netID uint16, nodeID uint32, rcb RBACPreAssignCallbacks) {
	if rcb.GetRoles == nil {
		return
	}
	roles, externalID, found := rcb.GetRoles(netID, nodeID)
	if !found || externalID == "" {
		return
	}
	for _, r := range roles {
		if strings.EqualFold(r.ExternalID, externalID) {
			if rcb.CommitRole != nil {
				rcb.CommitRole(netID, nodeID, r.Role)
			}
			if rcb.IncCounter != nil {
				rcb.IncCounter()
			}
			slog.Info("RBAC pre-assignment applied",
				"network_id", netID, "node_id", nodeID,
				"external_id", externalID, "role", r.Role)
			return
		}
	}
}

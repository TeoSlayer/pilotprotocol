package registry

import (
	"fmt"
	"strings"
	"time"
)

// DirectoryEntry represents a user from an enterprise directory (AD, Entra ID, LDAP).
type DirectoryEntry struct {
	ExternalID  string   `json:"external_id"`            // unique ID from directory (OIDC sub, email, GUID)
	DisplayName string   `json:"display_name,omitempty"`
	Email       string   `json:"email,omitempty"`
	Groups      []string `json:"groups,omitempty"`        // directory groups
	Role        string   `json:"role,omitempty"`          // desired pilot role: "owner", "admin", "member"
	Disabled    bool     `json:"disabled,omitempty"`      // deprovisioned users
}

// DirectorySyncRequest is the protocol payload for directory sync.
type DirectorySyncRequest struct {
	NetworkID uint16           `json:"network_id"`
	Entries   []DirectoryEntry `json:"entries"`
	// If true, nodes whose external_id is not in the entries list will be kicked.
	RemoveUnlisted bool `json:"remove_unlisted,omitempty"`
}

// DirectorySyncResult describes what the sync operation did.
type DirectorySyncResult struct {
	Updated  int      `json:"updated"`  // roles updated
	Disabled int      `json:"disabled"` // nodes disabled (kicked)
	Mapped   int      `json:"mapped"`   // entries mapped to existing nodes
	Unmapped int      `json:"unmapped"` // entries with no matching node
	Actions  []string `json:"actions"`
}

// handleDirectorySync processes a directory sync request. Requires admin token.
// It maps directory entries to registered nodes by external_id, updates RBAC roles,
// and optionally removes nodes not in the directory.
func (s *Server) handleDirectorySync(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}

	netID := jsonUint16(msg, "network_id")
	if netID == 0 {
		return nil, fmt.Errorf("network_id is required")
	}

	removeUnlisted, _ := msg["remove_unlisted"].(bool)

	entriesRaw, ok := msg["entries"].([]interface{})
	if !ok || len(entriesRaw) == 0 {
		return nil, fmt.Errorf("entries array is required")
	}

	var entries []DirectoryEntry
	for _, e := range entriesRaw {
		m, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		de := DirectoryEntry{
			ExternalID:  strField(m, "external_id"),
			DisplayName: strField(m, "display_name"),
			Email:       strField(m, "email"),
			Role:        strField(m, "role"),
			Disabled:    boolField(m, "disabled"),
		}
		if groupsRaw, ok := m["groups"].([]interface{}); ok {
			for _, g := range groupsRaw {
				if gs, ok := g.(string); ok {
					de.Groups = append(de.Groups, gs)
				}
			}
		}
		if de.ExternalID == "" {
			continue
		}
		entries = append(entries, de)
	}

	result, err := s.applyDirectorySync(netID, entries, removeUnlisted)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"type":     "directory_sync_ok",
		"updated":  result.Updated,
		"disabled": result.Disabled,
		"mapped":   result.Mapped,
		"unmapped": result.Unmapped,
		"actions":  result.Actions,
	}, nil
}

func (s *Server) applyDirectorySync(netID uint16, entries []DirectoryEntry, removeUnlisted bool) (*DirectorySyncResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	net, ok := s.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d not found", netID)
	}
	if !net.Enterprise {
		return nil, fmt.Errorf("directory sync requires enterprise network")
	}

	result := &DirectorySyncResult{}

	// Build index: external_id -> nodeID for current members
	extToNode := make(map[string]uint32)
	for _, memberID := range net.Members {
		node, ok := s.nodes[memberID]
		if !ok {
			continue
		}
		if node.ExternalID != "" {
			extToNode[strings.ToLower(node.ExternalID)] = memberID
		}
	}

	// Track which external_ids are in the directory
	directoryIDs := make(map[string]bool)

	for _, entry := range entries {
		directoryIDs[strings.ToLower(entry.ExternalID)] = true

		nodeID, exists := extToNode[strings.ToLower(entry.ExternalID)]
		if !exists {
			result.Unmapped++
			// Store as RBAC pre-assignment for future join
			if entry.Role != "" {
				s.storeRBACPreAssignmentLocked(netID, entry.ExternalID, entry.Role)
			}
			continue
		}
		result.Mapped++

		// Handle disabled users
		if entry.Disabled {
			s.removeMemberLocked(net, nodeID)
			result.Disabled++
			result.Actions = append(result.Actions, fmt.Sprintf("disabled %s (node %d)", entry.ExternalID, nodeID))
			continue
		}

		// Update role if specified
		if entry.Role != "" {
			var targetRole Role
			switch entry.Role {
			case "owner":
				targetRole = RoleOwner
			case "admin":
				targetRole = RoleAdmin
			default:
				targetRole = RoleMember
			}
			currentRole := net.MemberRoles[nodeID]
			if currentRole != targetRole {
				net.MemberRoles[nodeID] = targetRole
				result.Updated++
				result.Actions = append(result.Actions, fmt.Sprintf("role %s: %s → %s (node %d)",
					entry.ExternalID, currentRole, targetRole, nodeID))
			}
		}

		// Update display name as hostname if set
		if entry.DisplayName != "" {
			if node, ok := s.nodes[nodeID]; ok && node.Hostname == "" {
				node.Hostname = entry.DisplayName
			}
		}
	}

	// Remove unlisted members — collect IDs first to avoid mutating slice during iteration
	if removeUnlisted {
		var toRemove []uint32
		for _, memberID := range net.Members {
			node, ok := s.nodes[memberID]
			if !ok {
				continue
			}
			if node.ExternalID == "" {
				continue // skip nodes without external_id
			}
			if !directoryIDs[strings.ToLower(node.ExternalID)] {
				toRemove = append(toRemove, memberID)
			}
		}
		for _, memberID := range toRemove {
			node := s.nodes[memberID]
			s.removeMemberLocked(net, memberID)
			result.Disabled++
			result.Actions = append(result.Actions, fmt.Sprintf("removed unlisted %s (node %d)", node.ExternalID, memberID))
		}
	}

	s.save()
	s.audit("directory.synced", "network_id", netID,
		"mapped", result.Mapped, "updated", result.Updated,
		"disabled", result.Disabled, "unmapped", result.Unmapped)

	return result, nil
}

// storeRBACPreAssignmentLocked adds a single role pre-assignment. Caller must hold s.mu.
func (s *Server) storeRBACPreAssignmentLocked(netID uint16, externalID, role string) {
	if s.rbacPreAssign == nil {
		s.rbacPreAssign = make(map[uint16][]BlueprintRole)
	}
	// Avoid duplicates
	for _, r := range s.rbacPreAssign[netID] {
		if strings.EqualFold(r.ExternalID, externalID) {
			return
		}
	}
	s.rbacPreAssign[netID] = append(s.rbacPreAssign[netID], BlueprintRole{
		ExternalID: externalID,
		Role:       role,
	})
}

// removeMemberLocked removes a node from a network. Caller must hold s.mu.
func (s *Server) removeMemberLocked(net *NetworkInfo, nodeID uint32) {
	// Remove from member list
	for i, m := range net.Members {
		if m == nodeID {
			net.Members = append(net.Members[:i], net.Members[i+1:]...)
			break
		}
	}
	delete(net.MemberRoles, nodeID)

	// Remove network from node's network list
	if node, ok := s.nodes[nodeID]; ok {
		for i, n := range node.Networks {
			if n == net.ID {
				node.Networks = append(node.Networks[:i], node.Networks[i+1:]...)
				break
			}
		}
	}
}

// strField safely extracts a string field from a map.
func strField(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}

// boolField safely extracts a bool field from a map.
func boolField(m map[string]interface{}, key string) bool {
	v, _ := m[key].(bool)
	return v
}

// handleGetDirectoryStatus returns the directory sync status for a network.
func (s *Server) handleGetDirectoryStatus(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}

	netID := jsonUint16(msg, "network_id")
	if netID == 0 {
		return nil, fmt.Errorf("network_id is required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	net, ok := s.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d not found", netID)
	}

	// Count members with/without external_id
	mapped := 0
	unmapped := 0
	for _, memberID := range net.Members {
		if node, ok := s.nodes[memberID]; ok {
			if node.ExternalID != "" {
				mapped++
			} else {
				unmapped++
			}
		}
	}

	resp := map[string]interface{}{
		"type":       "directory_status_ok",
		"network_id": netID,
		"total":      len(net.Members),
		"mapped":     mapped,
		"unmapped":   unmapped,
		"enterprise": net.Enterprise,
	}
	if roles, ok := s.rbacPreAssign[netID]; ok {
		resp["pre_assignments"] = len(roles)
	}

	// Last sync time from audit log
	s.auditMu.Lock()
	for i := len(s.auditLog) - 1; i >= 0; i-- {
		if s.auditLog[i].Action == "directory.synced" && s.auditLog[i].NetworkID == netID {
			resp["last_sync"] = s.auditLog[i].Timestamp
			break
		}
	}
	s.auditMu.Unlock()

	return resp, nil
}

// SyncTimestamp returns the last directory sync time for a network.
func (s *Server) SyncTimestamp(netID uint16) time.Time {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	for i := len(s.auditLog) - 1; i >= 0; i-- {
		if s.auditLog[i].Action == "directory.synced" && s.auditLog[i].NetworkID == netID {
			if t, err := time.Parse(time.RFC3339, s.auditLog[i].Timestamp); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}

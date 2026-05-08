// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"fmt"
	"time"

	replpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/replication"
)

// DirectoryEntry is an alias for replpkg.DirectoryEntry.
// Kept here so existing server code and any external callers are unchanged.
type DirectoryEntry = replpkg.DirectoryEntry

// DirectorySyncRequest is an alias for replpkg.DirectorySyncRequest.
type DirectorySyncRequest = replpkg.DirectorySyncRequest

// DirectorySyncResult is an alias for replpkg.DirectorySyncResult.
type DirectorySyncResult = replpkg.DirectorySyncResult

// handleDirectorySync processes a directory sync request. Requires admin token.
// It maps directory entries to registered nodes by external_id, updates RBAC
// roles, and optionally removes nodes not in the directory.
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

	entries := replpkg.ParseDirectoryEntries(entriesRaw)

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
			extToNode[replpkg.NormalizeExternalID(node.ExternalID)] = memberID
		}
	}

	// Track which external_ids are in the directory
	directoryIDs := make(map[string]bool)

	for _, entry := range entries {
		directoryIDs[replpkg.NormalizeExternalID(entry.ExternalID)] = true

		nodeID, exists := extToNode[replpkg.NormalizeExternalID(entry.ExternalID)]
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

		// Update display name as hostname if set (check uniqueness first)
		if entry.DisplayName != "" {
			if node, ok := s.nodes[nodeID]; ok && node.Hostname == "" {
				if existingID, taken := s.hostnameIdx[entry.DisplayName]; !taken || existingID == nodeID {
					node.Hostname = entry.DisplayName
					s.hostnameIdx[entry.DisplayName] = nodeID
				}
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
			if !directoryIDs[replpkg.NormalizeExternalID(node.ExternalID)] {
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
		if replpkg.NormalizeExternalID(r.ExternalID) == replpkg.NormalizeExternalID(externalID) {
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

// strField is a package-level alias for replpkg.StrField, kept for
// backward-compatibility with white-box tests in package server.
func strField(m map[string]interface{}, key string) string {
	return replpkg.StrField(m, key)
}

// boolField is a package-level alias for replpkg.BoolField, kept for
// backward-compatibility with white-box tests in package server.
func boolField(m map[string]interface{}, key string) bool {
	return replpkg.BoolField(m, key)
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

	// Last sync time from audit log — use the synchronous ring buffer so the
	// entry is visible immediately after handleDirectorySync returns.
	s.auditMu.Lock()
	auditEntries := make([]AuditEntry, len(s.auditLog))
	copy(auditEntries, s.auditLog)
	s.auditMu.Unlock()
	for i := len(auditEntries) - 1; i >= 0; i-- {
		if auditEntries[i].Action == "directory.synced" && auditEntries[i].NetworkID == netID {
			resp["last_sync"] = auditEntries[i].Timestamp
			break
		}
	}

	return resp, nil
}

// SyncTimestamp returns the last directory sync time for a network.
func (s *Server) SyncTimestamp(netID uint16) time.Time {
	s.auditMu.Lock()
	entries := make([]AuditEntry, len(s.auditLog))
	copy(entries, s.auditLog)
	s.auditMu.Unlock()
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].Action == "directory.synced" && entries[i].NetworkID == netID {
			if t, err := time.Parse(time.RFC3339, entries[i].Timestamp); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}


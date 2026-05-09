// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"time"

	auditpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/audit"
	authzpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/authz"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry/server/events"
)

// hashOwner returns a truncated SHA-256 hash of the owner for safe logging.
func hashOwner(owner string) string {
	if owner == "" {
		return ""
	}
	h := sha256.Sum256([]byte(owner))
	return fmt.Sprintf("sha256:%x", h[:4])
}

// requireAdminToken validates the admin_token field in a message.
// Delegates to s.authz.RequireAdminTokenWith, copying the token under RLock.
func (s *Server) requireAdminToken(msg map[string]interface{}) error {
	s.mu.RLock()
	tok := s.authz.AdminToken()
	s.mu.RUnlock()
	return s.authz.RequireAdminTokenWith(msg, tok)
}

// requireAdminTokenLocked is like requireAdminToken but for use when s.mu is already held.
func (s *Server) requireAdminTokenLocked(msg map[string]interface{}) error {
	return s.authz.RequireAdminTokenWith(msg, s.authz.AdminToken())
}

// checkAdminToken is a convenience wrapper used by inline handlers that have
// already copied the admin token under a lock. Delegates to authz.
func (s *Server) checkAdminToken(msg map[string]interface{}, adminToken string) error {
	return s.authz.RequireAdminTokenWith(msg, adminToken)
}

// requireNetworkRole checks if the message sender has one of the allowed roles
// in the specified network. Delegates to s.authz.RequireNetworkRole. Caller
// must NOT hold s.mu.
func (s *Server) requireNetworkRole(msg map[string]interface{}, netID uint16, allowedRoles ...Role) error {
	strRoles := make([]authzpkg.Role, len(allowedRoles))
	for i, r := range allowedRoles {
		strRoles[i] = string(r)
	}
	return s.authz.RequireNetworkRole(msg, netID, (*serverNetworkReader)(s), strRoles...)
}

// serverNetworkReader is a thin adapter that satisfies authzpkg.NetworkReader
// by reading from Server.networks under s.mu.RLock.
type serverNetworkReader Server

func (r *serverNetworkReader) GetNetworkAdminToken(netID uint16) (string, bool) {
	s := (*Server)(r)
	s.mu.RLock()
	net, ok := s.networks[netID]
	s.mu.RUnlock()
	if !ok {
		return "", false
	}
	return net.AdminToken, true
}

func (r *serverNetworkReader) GetMemberRole(netID uint16, nodeID uint32) (authzpkg.Role, bool) {
	s := (*Server)(r)
	s.mu.RLock()
	net, ok := s.networks[netID]
	s.mu.RUnlock()
	if !ok {
		return "", false
	}
	s.mu.RLock()
	role, has := net.MemberRoles[nodeID]
	s.mu.RUnlock()
	return authzpkg.Role(role), has
}

func (r *serverNetworkReader) IsEnterpriseNetwork(netID uint16) (bool, bool) {
	s := (*Server)(r)
	s.mu.RLock()
	net, ok := s.networks[netID]
	s.mu.RUnlock()
	if !ok {
		return false, false
	}
	return net.Enterprise, true
}

// audit emits a structured audit log entry for registry mutations.
// When log-format=json, these are filterable via jq 'select(.msg=="audit")'.
// The entry is written synchronously to the in-process ring buffer (s.auditLog)
// and also published as an "audit.entry" bus event for the async exporter fan-out.
func (s *Server) audit(action string, attrs ...any) {
	slog.Info("audit", append([]any{"audit_action", action}, attrs...)...)
	s.metrics.AuditEventsTotal.Inc()

	// Synchronous ring-buffer write (tested by white-box tests in this package).
	entry := s.appendAudit(action, 0, 0, attrs...)

	// Async exporter fan-out via bus ("audit.entry" → auditStore → AuditExporter).
	if entry != nil {
		payload := map[string]any{
			"action":     entry.Action,
			"network_id": entry.NetworkID,
			"node_id":    entry.NodeID,
			"details":    entry.Details,
			"timestamp":  entry.Timestamp,
		}
		s.bus.Publish(events.Event{Source: "server", Type: "audit.entry", Payload: payload})
	}

	// Webhook fan-out (synchronous, existing behaviour).
	details := make(map[string]interface{}, len(attrs)/2)
	for i := 0; i+1 < len(attrs); i += 2 {
		if key, ok := attrs[i].(string); ok {
			details[key] = attrs[i+1]
		}
	}
	s.webhook.Emit(action, details)
}

// requireEnterprise checks that the given network has the Enterprise flag.
// Delegates to s.authz.RequireEnterprise.
func (s *Server) requireEnterprise(netID uint16) error {
	return s.authz.RequireEnterprise(netID, (*serverNetworkReader)(s))
}

// isEnterpriseNode returns true if the node belongs to at least one enterprise network.
// Delegates to s.authz.IsEnterpriseNode.
func (s *Server) isEnterpriseNode(nodeID uint32) bool {
	return s.authz.IsEnterpriseNode(nodeID, (*serverNodeReader)(s), (*serverNetworkReader)(s))
}

// serverNodeReader adapts Server to authzpkg.NodeReader.
type serverNodeReader Server

func (r *serverNodeReader) GetNodeNetworks(nodeID uint32) ([]uint16, bool) {
	s := (*Server)(r)
	s.mu.RLock()
	node, ok := s.nodes[nodeID]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return node.Networks, true
}

// auditEnterprise emits an audit log only for enterprise networks.
// Non-enterprise networks silently skip the audit entry.
func (s *Server) auditEnterprise(netID uint16, action string, attrs ...any) {
	s.mu.RLock()
	net, ok := s.networks[netID]
	s.mu.RUnlock()
	if !ok || !net.Enterprise {
		return
	}
	slog.Info("audit", append([]any{"audit_action", action}, attrs...)...)
	// Write to the synchronous ring buffer (for white-box tests that read s.auditLog).
	s.appendAudit(action, netID, 0, attrs...)
	// Also publish to bus for auditStore fan-out.
	e := auditpkg.BuildEntry(action, netID, 0, attrs...)
	payload := map[string]any{
		"action":     e.Action,
		"network_id": e.NetworkID,
		"node_id":    e.NodeID,
		"details":    e.Details,
		"timestamp":  e.Timestamp,
	}
	s.bus.Publish(events.Event{Source: "server", Type: "audit.entry", Payload: payload})
}

// maxAuditEntries is the ring-buffer cap for the in-process audit log.
// The production fanout (auditStore) has its own cap; this constant is kept
// for white-box tests in package server that inspect s.auditLog directly.
const maxAuditEntries = 1000

// appendAudit adds an entry to the in-memory audit ring buffer.
// It is kept as a Server method so that white-box tests in package server can
// call it directly. Production code emits via s.bus ("audit.entry") instead.
func (s *Server) appendAudit(action string, netID uint16, nodeID uint32, attrs ...any) *AuditEntry {
	e := auditpkg.BuildEntry(action, netID, nodeID, attrs...)
	entry := AuditEntry{
		Timestamp: e.Timestamp,
		Action:    e.Action,
		NetworkID: e.NetworkID,
		NodeID:    e.NodeID,
		Details:   e.Details,
	}
	s.auditMu.Lock()
	if len(s.auditLog) >= maxAuditEntries {
		s.auditLog = s.auditLog[1:]
	}
	s.auditLog = append(s.auditLog, entry)
	s.auditMu.Unlock()
	return &entry
}

// invalidateListNodesCacheForNetwork drops the cached pre-marshalled response
// for the given network so the next list_nodes call rebuilds. Call it after
// any mutation to network.Members (join, leave, kick, invite-accept, admin
// add/remove). Cheap — just deletes the per-net cache state.
func (s *Server) invalidateListNodesCacheForNetwork(netID uint16) {
	s.listNodesPerNetMu.Lock()
	delete(s.listNodesPerNet, netID)
	s.listNodesPerNetMu.Unlock()
}

// publishMembershipChanged publishes a "membership.changed" event on the
// internal event bus. The subscriber wired in NewWithStore will call
// invalidateListNodesCacheForNetwork; handlers also call that helper directly
// for synchronous-invalidation guarantees on existing code paths.
func (s *Server) publishMembershipChanged(netID uint16) {
	s.bus.Publish(events.Event{
		Source: "membership",
		Type:   "membership.changed",
		Payload: map[string]any{
			"net_id": netID,
		},
	})
}

// invalidateAdminListNodesCache forces the next adminListNodesCached() call
// to rebuild instead of serving the cached body. Call it after any mutation
// to s.nodes (register, deregister, reap). Cheap — just zeroes builtAt.
func (s *Server) invalidateAdminListNodesCache() {
	c := &s.listNodesCache
	c.Mu.Lock()
	c.BuiltAt = time.Time{}
	c.Mu.Unlock()
}

// verifyNodeSignature checks a signature for a registry write operation (H3 fix).
// If the node has a public key, the signature is required and verified.
// If the node has no public key (old registration), unsigned requests are allowed.
// Caller must hold s.mu (reads s.authz.AdminToken which is written by SetAdminToken under lock).
func (s *Server) verifyNodeSignature(node *NodeInfo, msg map[string]interface{}, challenge string) error {
	return authzpkg.VerifyNodeSignature(node.PublicKey, s.authz.AdminToken(), msg, challenge)
}

// verifyHeartbeatSignature verifies a signature using a detached public key and
// a pre-copied admin token. All values are copied under RLock before calling,
// so this method requires no lock and is safe for concurrent heartbeat processing.
// Delegates to authzpkg.VerifyHeartbeatSignature.
func (s *Server) verifyHeartbeatSignature(pubKey []byte, adminToken string, msg map[string]interface{}, challenge string) error {
	return authzpkg.VerifyHeartbeatSignature(pubKey, adminToken, msg, challenge)
}

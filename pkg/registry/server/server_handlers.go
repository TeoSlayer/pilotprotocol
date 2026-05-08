// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"fmt"
	"log/slog"
	"strconv"

	acceptpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/accept"
	"github.com/TeoSlayer/pilotprotocol/pkg/urlvalidate"
)

// sanitizeListenAddr delegates to acceptpkg.SanitizeListenAddr.
// Kept as a package-level alias so callers inside this package are unchanged.
func sanitizeListenAddr(remoteAddr, clientAddr string) string {
	return acceptpkg.SanitizeListenAddr(remoteAddr, clientAddr)
}

// handleRegister delegates to the directory sub-package (R4.2).
func (s *Server) handleRegister(msg map[string]interface{}, remoteAddr string) (map[string]interface{}, error) {
	setExternalID := func(nodeID uint32, externalID string) {
		s.mu.Lock()
		if node, exists := s.nodes[nodeID]; exists {
			node.ExternalID = externalID
			s.save()
		}
		s.mu.Unlock()
	}
	return s.directory.HandleRegister(msg, remoteAddr, s.identity.VerifyToken, setExternalID)
}

// handleGetAuditLog returns recent audit entries, optionally filtered by network_id.
func (s *Server) handleGetAuditLog(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}

	filterNetID := jsonUint16(msg, "network_id")
	limit := 100
	if l, ok := msg["limit"].(float64); ok && l > 0 && l <= 1000 {
		limit = int(l)
	}

	s.auditMu.Lock()
	all := make([]AuditEntry, len(s.auditLog))
	copy(all, s.auditLog)
	s.auditMu.Unlock()

	// Filter and reverse (newest first)
	var entries []map[string]interface{}
	for i := len(all) - 1; i >= 0 && len(entries) < limit; i-- {
		e := all[i]
		if filterNetID != 0 && e.NetworkID != filterNetID {
			continue
		}
		m := map[string]interface{}{
			"timestamp": e.Timestamp,
			"action":    e.Action,
		}
		if e.NetworkID != 0 {
			m["network_id"] = e.NetworkID
		}
		if e.NodeID != 0 {
			m["node_id"] = e.NodeID
		}
		if e.Details != "" {
			m["details"] = e.Details
		}
		entries = append(entries, m)
	}
	if entries == nil {
		entries = []map[string]interface{}{}
	}
	return map[string]interface{}{
		"type":    "get_audit_log_ok",
		"entries": entries,
	}, nil
}

// handleSetWebhook configures the registry webhook URL. Requires admin token.
func (s *Server) handleSetWebhook(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}
	url, _ := msg["url"].(string)
	if url != "" {
		if err := urlvalidate.Validate(url); err != nil {
			return nil, fmt.Errorf("set_webhook: %w", err)
		}
	}
	return s.webhook.HandleSetWebhook(url), nil
}

// handleGetWebhook returns the current webhook configuration. Requires admin token.
func (s *Server) handleGetWebhook(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}
	return s.webhook.HandleGetWebhook(), nil
}

// handleGetWebhookDLQ returns the dead letter queue (failed webhook events).
func (s *Server) handleGetWebhookDLQ(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}
	return s.webhook.HandleGetWebhookDLQ(), nil
}

// handleSetIdentityWebhook delegates to s.identity (R2.3).
// URL validation (SSRF prevention) is performed here before delegation.
func (s *Server) handleSetIdentityWebhook(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}
	url, _ := msg["url"].(string)
	if url != "" {
		if err := urlvalidate.Validate(url); err != nil {
			return nil, fmt.Errorf("set_identity_webhook: %w", err)
		}
	}
	return s.identity.HandleSetIdentityWebhook(msg)
}

// handleSetAuditExport configures the audit export adapter. Requires admin token.
func (s *Server) handleSetAuditExport(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}
	format, _ := msg["format"].(string)
	endpoint, _ := msg["endpoint"].(string)
	token, _ := msg["token"].(string)
	index, _ := msg["index"].(string)
	source, _ := msg["source"].(string)

	if format == "" || endpoint == "" {
		// Disable export — SetExporter(nil) closes the old exporter.
		s.auditStore.SetExporter(nil)
		return map[string]interface{}{
			"type":   "set_audit_export_ok",
			"status": "disabled",
		}, nil
	}

	// SSRF prevention: the syslog_cef format uses a raw host:port and is not
	// covered here — only http(s) endpoints go through URL validation. The
	// other two formats (json, splunk_hec) post to an HTTP(S) endpoint.
	if format == "json" || format == "splunk_hec" {
		if err := urlvalidate.Validate(endpoint); err != nil {
			return nil, fmt.Errorf("set_audit_export: %w", err)
		}
	}

	cfg := &BlueprintAuditExport{
		Format:   format,
		Endpoint: endpoint,
		Token:    token,
		Index:    index,
		Source:   source,
	}
	s.auditStore.SetExporter(cfg)

	s.audit("audit_export.configured", "format", format, "endpoint", endpoint)
	return map[string]interface{}{
		"type":     "set_audit_export_ok",
		"status":   "enabled",
		"format":   format,
		"endpoint": endpoint,
	}, nil
}

// handleGetAuditExport returns the current audit export configuration.
// Delegates to the audit sub-package store (R1.2).
func (s *Server) handleGetAuditExport(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}
	return s.auditStore.HandleGetAuditExport(msg)
}

// handleSetIDPConfig delegates to s.identity (R2.3).
// URL validation (SSRF prevention) is performed here before delegation.
func (s *Server) handleSetIDPConfig(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}
	url, _ := msg["url"].(string)
	if url != "" {
		if err := urlvalidate.Validate(url); err != nil {
			return nil, fmt.Errorf("set_idp_config: %w", err)
		}
	}
	return s.identity.HandleSetIDPConfig(msg)
}

// handleGetIDPConfig returns the current identity provider configuration.
func (s *Server) handleGetIDPConfig(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}
	cfg := s.GetIdentityProviderConfig()
	resp := map[string]interface{}{
		"type":       "get_idp_config_ok",
		"configured": cfg != nil,
	}
	if cfg != nil {
		resp["idp_type"] = cfg.Type
		resp["url"] = cfg.URL
		if cfg.Issuer != "" {
			resp["issuer"] = cfg.Issuer
		}
		if cfg.ClientID != "" {
			resp["client_id"] = cfg.ClientID
		}
		if cfg.TenantID != "" {
			resp["tenant_id"] = cfg.TenantID
		}
		if cfg.Domain != "" {
			resp["domain"] = cfg.Domain
		}
	}
	return resp, nil
}

// handleGetProvisionStatus delegates to s.identity (R2.3).
func (s *Server) handleGetProvisionStatus(msg map[string]interface{}) (map[string]interface{}, error) {
	networkSummary := func() []map[string]interface{} {
		s.mu.RLock()
		defer s.mu.RUnlock()
		var networks []map[string]interface{}
		for _, net := range s.networks {
			if net.ID == 0 {
				continue // skip backbone
			}
			entry := map[string]interface{}{
				"network_id": net.ID,
				"name":       net.Name,
				"enterprise": net.Enterprise,
				"members":    len(net.Members),
				"join_rule":  net.JoinRule,
			}
			if net.Policy.MaxMembers > 0 {
				entry["max_members"] = net.Policy.MaxMembers
			}
			if len(net.Policy.AllowedPorts) > 0 {
				entry["allowed_ports"] = net.Policy.AllowedPorts
			}
			if roles, ok := s.rbacPreAssign[net.ID]; ok {
				entry["rbac_pre_assignments"] = len(roles)
			}
			networks = append(networks, entry)
		}
		return networks
	}
	auditExportFormat := ""
	if cfg := s.auditStore.ExporterConfig(); cfg != nil {
		auditExportFormat = cfg.Format
	}
	whInfo := s.webhook.HandleGetWebhook()
	webhookEnabled, _ := whInfo["enabled"].(bool)
	return s.identity.HandleGetProvisionStatus(msg, networkSummary, webhookEnabled, auditExportFormat)
}

// handleBeaconRegister delegates to the routing sub-package (R1.4).
func (s *Server) handleBeaconRegister(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}
	resp, err := s.routing.HandleBeaconRegister(msg)
	if err != nil {
		return nil, err
	}
	// Audit remains in the server layer (routing has no audit dependency).
	addr, _ := msg["addr"].(string)
	beaconID := jsonUint32(msg, "beacon_id")
	s.audit("beacon.registered", "beacon_id", beaconID, "addr", addr)
	return resp, nil
}

// setNodeHostname sets the hostname on a node atomically. Must be called with s.mu held.
// Per-node field write (node.Hostname) is bracketed by the per-node shard lock so
// concurrent readers in handleLookup (which read node.Hostname under shard.RLock,
// having already released s.mu.RLock) observe a consistent value.
func (s *Server) setNodeHostname(node *NodeInfo, hostname string, resp map[string]interface{}) {
	if hostname == "" {
		return
	}
	if existingID, taken := s.hostnameIdx[hostname]; taken && existingID != node.ID {
		resp["hostname_error"] = fmt.Sprintf("hostname %q already in use", hostname)
		return // hostname taken by another node
	}
	sh := s.nodeShard(node.ID)
	sh.Lock()
	if node.Hostname != "" {
		delete(s.hostnameIdx, node.Hostname)
	}
	node.Hostname = hostname
	s.hostnameIdx[hostname] = node.ID
	sh.Unlock()
	resp["hostname"] = hostname
	slog.Debug("hostname set during registration", "node_id", node.ID, "hostname", hostname)
}

// trustPairKey returns the canonical "min:max" key for a symmetric trust pair.
// Thin wrapper kept in the server package so tests and snapshot code can
// generate the correct key format without importing the trust sub-package.
func trustPairKey(a, b uint32) string {
	if a > b {
		a, b = b, a
	}
	return fmt.Sprintf("%d:%d", a, b)
}

// cleanupNode removes transient state for a departed node. Caller must hold s.mu.
// Trust pairs and handshake inboxes are preserved — trust is identity-to-identity
// and must survive disconnections. Only explicit revoke_trust removes trust pairs.
func (s *Server) cleanupNode(nodeID uint32) {
	// Trust pairs: intentionally preserved (identity-level, survive disconnect)
	// Handshake inboxes/responses: intentionally preserved (node may reconnect)
}

// Pre-built fragments for the heartbeat-ok response. Go's json.Marshal sorts
// map keys alphabetically, so the wire shape is:
//
//	without warning: {"time":<int>,"type":"heartbeat_ok"}
//	with    warning: {"key_expiry_warning":true,"time":<int>,"type":"heartbeat_ok"}
//
// Pre-building the static prefix/suffix and only sprintf'ing the timestamp
// saves the ~8% of remaining CPU spent in json.Marshal on the heartbeat
// response — this is the single most-frequent message in the system.
var (
	heartbeatOkPrefixNoWarn   = []byte(`{"time":`)
	heartbeatOkPrefixWithWarn = []byte(`{"key_expiry_warning":true,"time":`)
	heartbeatOkSuffix         = []byte(`,"type":"heartbeat_ok"}`)
)

// buildHeartbeatOk emits bytes byte-identical to json.Marshal of the
// equivalent map[string]interface{}. Locked down by
// TestBuildHeartbeatOkMatchesJSONMarshal.
func buildHeartbeatOk(timeUnix int64, keyExpiryWarning bool) []byte {
	// Bound: prefix(34) + int64-digits(20) + suffix(23) = 77; cap at 96.
	b := make([]byte, 0, 96)
	if keyExpiryWarning {
		b = append(b, heartbeatOkPrefixWithWarn...)
	} else {
		b = append(b, heartbeatOkPrefixNoWarn...)
	}
	b = strconv.AppendInt(b, timeUnix, 10)
	b = append(b, heartbeatOkSuffix...)
	return b
}

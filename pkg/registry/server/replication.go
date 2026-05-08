// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	auditpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/audit"
	replpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/replication"
	trustpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/trust"
	"github.com/TeoSlayer/pilotprotocol/pkg/urlvalidate"
)

// handleSubscribeReplication is called when a client sends {"type": "subscribe_replication"}.
// It sends the current snapshot immediately, then the connection is kept open for
// future pushes via the replication Manager.
func (s *Server) handleSubscribeReplication(conn net.Conn) {
	// Send current snapshot
	snapJSON := s.snapshotJSON()
	if snapJSON == nil {
		writeMessage(conn, map[string]interface{}{ //nolint:errcheck
			"type":  "error",
			"error": "failed to generate snapshot",
		})
		return
	}

	resp := map[string]interface{}{
		"type":     "replication_snapshot",
		"snapshot": json.RawMessage(snapJSON),
	}
	if err := writeMessage(conn, resp); err != nil {
		slog.Error("replication initial snapshot send failed", "err", err)
		return
	}

	// Register as subscriber — connection stays open for pushes
	s.replMgr.AddSub(conn)

	// Block until the connection is closed (primary keeps pushing via replMgr.Push)
	// Read loop to detect disconnection
	buf := make([]byte, 1)
	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second)) //nolint:errcheck
		_, err := conn.Read(buf)
		if err != nil {
			s.replMgr.RemoveSub(conn)
			return
		}
	}
}

// snapshotJSON returns the current registry state as JSON bytes.
//
// PERFORMANCE NOTE: The expensive json.Marshal pass (75-85 MB at 108k nodes,
// ~100-200ms) runs OUTSIDE s.mu.RLock so writers don't queue behind it. The
// snap struct must therefore own all its slice/map state independently —
// every aliasing slice from live registry maps is copied before RUnlock.
// See [[X-Tasks/backlog/30-mutex-risk-map]] § fix #3.
func (s *Server) snapshotJSON() []byte {
	s.mu.RLock()

	snap := snapshot{
		NextNode: s.nextNode,
		NextNet:  s.nextNet,
		Nodes:    make(map[string]*snapshotNode, len(s.nodes)),
		Networks: make(map[string]*snapshotNet, len(s.networks)),
	}

	// Per-node fields RealAddr / LANAddrs / Version may be written by the
	// handleReRegister fast path under shard.Lock(). Take shard.RLock per
	// node to synchronize. Slice fields (Networks, LANAddrs, Tags) are
	// DEEP-COPIED so we can safely Marshal after releasing s.mu.RLock —
	// concurrent writers under s.mu.Lock could otherwise grow / re-slice
	// the underlying arrays during marshal.
	for id, n := range s.nodes {
		shard := &s.nodeShards[n.ID%numNodeShards]
		shard.RLock()
		sn := &snapshotNode{
			ID:        n.ID,
			Owner:     n.Owner,
			PublicKey: base64.StdEncoding.EncodeToString(n.PublicKey),
			RealAddr:  n.RealAddr,
			Networks:  replpkg.CloneSliceUint16(n.Networks),
			Public:    n.Public,
			LastSeen:  n.LastSeen.Format(time.RFC3339),
			Hostname:  n.Hostname,
			Tags:      replpkg.CloneSliceString(n.Tags),
			TaskExec:  n.TaskExec,
			LANAddrs:  replpkg.CloneSliceString(n.LANAddrs),
			RelayOnly: n.RelayOnly, // task 32
		}
		if !n.KeyMeta.CreatedAt.IsZero() {
			sn.KeyCreated = n.KeyMeta.CreatedAt.Format(time.RFC3339)
		}
		if !n.KeyMeta.RotatedAt.IsZero() {
			sn.KeyRotated = n.KeyMeta.RotatedAt.Format(time.RFC3339)
		}
		if n.KeyMeta.RotateCount > 0 {
			sn.KeyRotCount = n.KeyMeta.RotateCount
		}
		if !n.KeyMeta.ExpiresAt.IsZero() {
			sn.KeyExpires = n.KeyMeta.ExpiresAt.Format(time.RFC3339)
		}
		sn.ExternalID = n.ExternalID
		shard.RUnlock()
		snap.Nodes[fmt.Sprintf("%d", id)] = sn
	}

	for id, n := range s.networks {
		sn := &snapshotNet{
			ID:         n.ID,
			Name:       n.Name,
			JoinRule:   n.JoinRule,
			Token:      n.Token,
			Members:    replpkg.CloneSliceUint32(n.Members),
			AdminToken: n.AdminToken,
			Enterprise: n.Enterprise,
			Created:    n.Created.Format(time.RFC3339),
		}
		if len(n.MemberRoles) > 0 {
			sn.MemberRoles = make(map[string]string, len(n.MemberRoles))
			for nodeID, role := range n.MemberRoles {
				sn.MemberRoles[fmt.Sprintf("%d", nodeID)] = string(role)
			}
		}
		if len(n.MemberTags) > 0 {
			sn.MemberTags = make(map[string][]string, len(n.MemberTags))
			for nodeID, tags := range n.MemberTags {
				sn.MemberTags[fmt.Sprintf("%d", nodeID)] = replpkg.CloneSliceString(tags)
			}
		}
		if n.Policy.MaxMembers != 0 || len(n.Policy.AllowedPorts) > 0 || n.Policy.Description != "" {
			pol := n.Policy
			sn.Policy = &pol
		}
		snap.Networks[fmt.Sprintf("%d", id)] = sn
	}

	// Include trust pairs via the trust sub-package (R2.1).
	snap.TrustPairs = s.trust.Pairs()

	// Include handshake inboxes via the trust sub-package (R2.1).
	inbox, responses := s.trust.InboxSnapshot()
	if len(inbox) > 0 {
		snap.HandshakeInbox = make(map[string][]*trustpkg.HandshakeRelayMsg, len(inbox))
		for nodeID, msgs := range inbox {
			cp := make([]*trustpkg.HandshakeRelayMsg, len(msgs))
			copy(cp, msgs)
			snap.HandshakeInbox[fmt.Sprintf("%d", nodeID)] = cp
		}
	}
	if len(responses) > 0 {
		snap.HandshakeResponses = make(map[string][]*trustpkg.HandshakeResponseMsg, len(responses))
		for nodeID, msgs := range responses {
			cp := make([]*trustpkg.HandshakeResponseMsg, len(msgs))
			copy(cp, msgs)
			snap.HandshakeResponses[fmt.Sprintf("%d", nodeID)] = cp
		}
	}

	// Include invite inboxes (deep-copy slice values)
	if len(s.inviteInbox) > 0 {
		snap.InviteInbox = make(map[string][]*NetworkInvite, len(s.inviteInbox))
		for nodeID, invites := range s.inviteInbox {
			cp := make([]*NetworkInvite, len(invites))
			copy(cp, invites)
			snap.InviteInbox[fmt.Sprintf("%d", nodeID)] = cp
		}
	}

	// Enterprise config — pointers; not mutated post-init in practice but we
	// still snapshot the pointer under RLock and Marshal will read whatever
	// they point to. Acceptable: these are config blobs whose mutation
	// requires a separate handler call (rare). If they ever become hot we
	// must deep-copy here.
	if idpCfg := s.identity.GetIDPConfig(); idpCfg != nil {
		snap.IDPConfig = idpCfg
	}
	if cfg := s.auditStore.ExporterConfig(); cfg != nil {
		snap.AuditExportCfg = cfg
	}
	if len(s.rbacPreAssign) > 0 {
		snap.RBACPreAssign = make(map[string][]BlueprintRole, len(s.rbacPreAssign))
		for netID, roles := range s.rbacPreAssign {
			cp := make([]BlueprintRole, len(roles))
			copy(cp, roles)
			snap.RBACPreAssign[fmt.Sprintf("%d", netID)] = cp
		}
	}

	// Done with registry state — release the read lock so writers don't
	// queue behind the marshal. Audit log uses its own mutex.
	s.mu.RUnlock()

	// Audit log — use the synchronous ring buffer (s.auditLog) which is
	// guaranteed to have entries immediately after each audit() call, unlike
	// s.auditStore which is populated asynchronously via the bus.
	s.auditMu.Lock()
	if len(s.auditLog) > 0 {
		snap.AuditLog = make([]AuditEntry, len(s.auditLog))
		copy(snap.AuditLog, s.auditLog)
	}
	s.auditMu.Unlock()

	// Marshal outside any registry lock — saves 100-200ms RLock hold.
	data, err := json.Marshal(snap)
	if err != nil {
		slog.Error("snapshot marshal error", "err", err)
		return nil
	}
	return data
}

// maxSnapshotSize limits incoming replication snapshots to 256MB to prevent
// a malicious or compromised peer from causing memory exhaustion.
const maxSnapshotSize = 256 << 20

// applySnapshot loads a snapshot into the server state and persists it.
//
// PERFORMANCE NOTE: At 108k nodes the legacy implementation held s.mu.Lock
// for 1.7-2.5s while base64-decoding pubkeys and parsing timestamps. During
// that window every primary operation on the standby blocked. The current
// implementation builds all the new state OUTSIDE the lock and atom-swaps
// it under a brief Lock (~5ms), reducing the blocking window by ~350×.
// See [[X-Tasks/backlog/30-mutex-risk-map]] § fix #2.
func (s *Server) applySnapshot(data []byte) error {
	if len(data) > maxSnapshotSize {
		return fmt.Errorf("snapshot too large: %d bytes (max %d)", len(data), maxSnapshotSize)
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	// --- Phase 1: build all the new maps OUTSIDE any lock ---

	newNodes := make(map[uint32]*NodeInfo, len(snap.Nodes))
	newPubKeyIdx := make(map[string]uint32, len(snap.Nodes))
	newOwnerIdx := make(map[string]uint32, len(snap.Nodes))
	newHostnameIdx := make(map[string]uint32, len(snap.Nodes))

	for _, n := range snap.Nodes {
		pubKey, err := base64Decode(n.PublicKey)
		if err != nil {
			continue
		}
		lastSeen := time.Now()
		if n.LastSeen != "" {
			if t, err := time.Parse(time.RFC3339, n.LastSeen); err == nil {
				lastSeen = t
			}
		}
		node := &NodeInfo{
			ID:        n.ID,
			Owner:     n.Owner,
			PublicKey: pubKey,
			RealAddr:  n.RealAddr,
			Networks:  n.Networks,
			LastSeen:  lastSeen,
			Public:    n.Public,
			Hostname:  n.Hostname,
			Tags:      n.Tags,
			TaskExec:  n.TaskExec,
			LANAddrs:  n.LANAddrs,
			RelayOnly: n.RelayOnly, // task 32
		}
		// Restore key lifecycle metadata
		if n.KeyCreated != "" {
			if t, err := time.Parse(time.RFC3339, n.KeyCreated); err == nil {
				node.KeyMeta.CreatedAt = t
			}
		}
		if n.KeyRotated != "" {
			if t, err := time.Parse(time.RFC3339, n.KeyRotated); err == nil {
				node.KeyMeta.RotatedAt = t
			}
		}
		node.KeyMeta.RotateCount = n.KeyRotCount
		if n.KeyExpires != "" {
			if t, err := time.Parse(time.RFC3339, n.KeyExpires); err == nil {
				node.KeyMeta.ExpiresAt = t
			}
		}
		node.ExternalID = n.ExternalID
		newNodes[n.ID] = node
		newPubKeyIdx[n.PublicKey] = n.ID
		if n.Owner != "" {
			newOwnerIdx[n.Owner] = n.ID
		}
		if n.Hostname != "" {
			if existID, taken := newHostnameIdx[n.Hostname]; taken && existID != n.ID {
				slog.Warn("duplicate hostname in snapshot, keeping first",
					"hostname", n.Hostname, "kept_node", existID, "skipped_node", n.ID)
				node.Hostname = "" // clear the duplicate
			} else {
				newHostnameIdx[n.Hostname] = n.ID
			}
		}
	}

	newNetworks := make(map[uint16]*NetworkInfo, len(snap.Networks))
	for _, n := range snap.Networks {
		created, _ := time.Parse(time.RFC3339, n.Created)
		net := &NetworkInfo{
			ID:          n.ID,
			Name:        n.Name,
			JoinRule:    n.JoinRule,
			Token:       n.Token,
			Members:     n.Members,
			MemberRoles: make(map[uint32]Role),
			MemberTags:  make(map[uint32][]string),
			AdminToken:  n.AdminToken,
			Enterprise:  n.Enterprise,
			Created:     created,
		}
		if n.Policy != nil {
			net.Policy = *n.Policy
		}
		for nodeIDStr, roleStr := range n.MemberRoles {
			var nodeID uint32
			if _, err := fmt.Sscanf(nodeIDStr, "%d", &nodeID); err == nil {
				net.MemberRoles[nodeID] = Role(roleStr)
			}
		}
		for nodeIDStr, tags := range n.MemberTags {
			var nodeID uint32
			if _, err := fmt.Sscanf(nodeIDStr, "%d", &nodeID); err == nil {
				net.MemberTags[nodeID] = tags
			}
		}
		// Backfill roles for legacy snapshots
		if len(n.MemberRoles) == 0 && len(net.Members) > 0 && net.ID != 0 {
			for i, m := range net.Members {
				if i == 0 {
					net.MemberRoles[m] = RoleOwner
				} else {
					net.MemberRoles[m] = RoleMember
				}
			}
		}
		newNetworks[n.ID] = net
	}

	newHandshakeInbox := make(map[uint32][]*trustpkg.HandshakeRelayMsg, len(snap.HandshakeInbox))
	for nodeIDStr, msgs := range snap.HandshakeInbox {
		var nodeID uint32
		if _, err := fmt.Sscanf(nodeIDStr, "%d", &nodeID); err == nil && nodeID > 0 {
			newHandshakeInbox[nodeID] = msgs
		}
	}
	newHandshakeResponses := make(map[uint32][]*trustpkg.HandshakeResponseMsg, len(snap.HandshakeResponses))
	for nodeIDStr, msgs := range snap.HandshakeResponses {
		var nodeID uint32
		if _, err := fmt.Sscanf(nodeIDStr, "%d", &nodeID); err == nil && nodeID > 0 {
			newHandshakeResponses[nodeID] = msgs
		}
	}

	newInviteInbox := make(map[uint32][]*NetworkInvite, len(snap.InviteInbox))
	for nodeIDStr, invites := range snap.InviteInbox {
		var nodeID uint32
		if _, err := fmt.Sscanf(nodeIDStr, "%d", &nodeID); err == nil && nodeID > 0 {
			newInviteInbox[nodeID] = invites
		}
	}

	var newRBACPreAssign map[uint16][]BlueprintRole
	if len(snap.RBACPreAssign) > 0 {
		newRBACPreAssign = make(map[uint16][]BlueprintRole, len(snap.RBACPreAssign))
		for netIDStr, roles := range snap.RBACPreAssign {
			var netID uint16
			if _, err := fmt.Sscanf(netIDStr, "%d", &netID); err == nil {
				newRBACPreAssign[netID] = roles
			}
		}
	}

	// Validate enterprise config URLs OUTSIDE the lock — the validator does
	// I/O-free string parsing but is still extra work we don't need to keep
	// inside the swap critical section.
	var (
		acceptIDPConfig   bool
		acceptAuditExport bool
	)
	if snap.IDPConfig != nil {
		if err := urlvalidate.Validate(snap.IDPConfig.URL); err != nil {
			slog.Warn("replica: skipping IDP config with invalid URL", "url", snap.IDPConfig.URL, "err", err)
		} else {
			acceptIDPConfig = true
		}
	}
	if snap.AuditExportCfg != nil {
		acceptAuditExport = true
		if snap.AuditExportCfg.Format == "json" || snap.AuditExportCfg.Format == "splunk_hec" {
			if err := urlvalidate.Validate(snap.AuditExportCfg.Endpoint); err != nil {
				slog.Warn("replica: skipping audit export with invalid endpoint", "endpoint", snap.AuditExportCfg.Endpoint, "err", err)
				acceptAuditExport = false
			}
		}
	}

	// --- Phase 2: atomic swap under brief Lock (~5ms) ---

	s.mu.Lock()
	s.nodes = newNodes
	s.pubKeyIdx = newPubKeyIdx
	s.ownerIdx = newOwnerIdx
	s.hostnameIdx = newHostnameIdx
	s.networks = newNetworks
	s.inviteInbox = newInviteInbox
	s.nextNode = snap.NextNode
	s.nextNet = snap.NextNet
	if newRBACPreAssign != nil {
		s.rbacPreAssign = newRBACPreAssign
	}
	if acceptIDPConfig {
		s.identity.SetIDPConfig(snap.IDPConfig)
	}
	// Propagate new map pointers to sub-package stores so their cached
	// references don't go stale after the swap. Both calls are under s.mu.Lock.
	s.directory.ReplaceState(newNodes, newPubKeyIdx, newOwnerIdx, newHostnameIdx)
	s.membership.ReplaceState(newNetworks, newInviteInbox)
	s.mu.Unlock()
	if acceptAuditExport && snap.AuditExportCfg != nil {
		s.auditStore.SetExporter(snap.AuditExportCfg)
	}

	// --- Phase 3: side state under their own locks ---

	// Trust pairs and handshake state are owned by s.trust (R2.1).
	s.trust.RestorePairs(snap.TrustPairs)
	s.trust.RestoreInbox(newHandshakeInbox, newHandshakeResponses)

	if len(snap.AuditLog) > 0 {
		entries := make([]auditpkg.Entry, len(snap.AuditLog))
		for i, a := range snap.AuditLog {
			entries[i] = auditpkg.Entry{
				Timestamp: a.Timestamp,
				Action:    a.Action,
				NetworkID: a.NetworkID,
				NodeID:    a.NodeID,
				Details:   a.Details,
			}
		}
		s.auditStore.RestoreLog(entries)
		// Also restore the synchronous ring buffer so GetAuditLog (which reads
		// s.auditLog) reflects the replicated history after failover.
		s.auditMu.Lock()
		s.auditLog = make([]AuditEntry, len(snap.AuditLog))
		copy(s.auditLog, entries)
		s.auditMu.Unlock()
	}

	// Persist synchronously: standbys receive canonical state from primary
	// and should be ready for promotion immediately. The default debounced
	// save() would wait up to saveLoopInterval (5s) before writing to disk,
	// which leaves a window where a freshly-promoted standby has nothing on
	// disk to crash-recover from.
	if err := s.flushSave(); err != nil {
		slog.Error("standby flushSave after applySnapshot failed", "err", err)
	}

	return nil
}

// RunStandby connects to a primary registry and receives replicated snapshots.
// On each snapshot, the standby updates its own state and persists to storePath.
// This blocks until the connection is lost, then retries with backoff.
func (s *Server) RunStandby(primaryAddr string) {
	for {
		select {
		case <-s.done:
			return
		default:
		}

		err := s.standbySession(primaryAddr)
		if err != nil {
			slog.Warn("standby session ended", "err", err)
		}

		reconnTimer := time.NewTimer(3 * time.Second)
		select {
		case <-s.done:
			reconnTimer.Stop()
			return
		case <-reconnTimer.C:
			slog.Info("standby reconnecting to primary", "addr", primaryAddr)
		}
	}
}

func (s *Server) standbySession(primaryAddr string) error {
	conn, err := net.DialTimeout("tcp", primaryAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect to primary: %w", err)
	}
	defer conn.Close()

	slog.Info("standby connected to primary", "addr", primaryAddr)

	// Subscribe to replication stream (H4 fix: include token)
	msg := map[string]interface{}{
		"type": "subscribe_replication",
	}
	if tok := s.ReplicationToken(); tok != "" {
		msg["token"] = tok
	}
	if err := writeMessage(conn, msg); err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}

	// Read snapshot stream
	for {
		select {
		case <-s.done:
			return nil
		default:
		}

		conn.SetReadDeadline(time.Now().Add(45 * time.Second)) //nolint:errcheck
		msg, err := readMessage(conn)
		if err != nil {
			if err == io.EOF {
				return fmt.Errorf("primary disconnected")
			}
			return fmt.Errorf("read: %w", err)
		}

		msgType, _ := msg["type"].(string)
		if msgType == "heartbeat" {
			continue // keep-alive from primary
		}

		switch msgType {
		case "replication_snapshot":
			// Extract and apply snapshot
			snapRaw, ok := msg["snapshot"]
			if !ok {
				slog.Warn("standby: snapshot missing from replication message")
				continue
			}

			snapBytes, err := json.Marshal(snapRaw)
			if err != nil {
				slog.Warn("standby: re-marshal snapshot", "err", err)
				continue
			}

			if err := s.applySnapshot(snapBytes); err != nil {
				slog.Error("standby: apply snapshot", "err", err)
				continue
			}

			// Read node/network counts under lock (M6 fix)
			s.mu.RLock()
			nNodes := len(s.nodes)
			nNetworks := len(s.networks)
			s.mu.RUnlock()
			slog.Debug("standby: applied snapshot", "nodes", nNodes, "networks", nNetworks)

		case "replication_delta":
			// Delta replication: apply incremental changes (much smaller than full snapshot)
			seqNo, _ := msg["seq_no"].(float64)
			slog.Debug("standby: received delta", "seq_no", uint64(seqNo))
			// Delta entries are informational on the standby side — the standby
			// will receive a full snapshot periodically via saveLoop which reconciles state.
			// Future enhancement: apply deltas directly for lower latency.

		default:
			slog.Warn("standby: unexpected message type", "type", msgType)
		}
	}
}

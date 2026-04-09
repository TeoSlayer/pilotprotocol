package registry

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// connWriter wraps a net.Conn with a write mutex to prevent interleaved writes
// from concurrent push() and heartbeat() goroutines (H1 fix).
type connWriter struct {
	conn net.Conn
	wmu  sync.Mutex
}

// replicationManager handles push-based replication from primary to standbys.
// Standbys connect to the primary and subscribe; the primary pushes snapshots
// after every state mutation.
type replicationManager struct {
	mu   sync.Mutex
	subs map[net.Conn]*connWriter
}

func newReplicationManager() *replicationManager {
	return &replicationManager{
		subs: make(map[net.Conn]*connWriter),
	}
}

// addSub registers a connection as a replication subscriber.
func (rm *replicationManager) addSub(conn net.Conn) {
	rm.mu.Lock()
	rm.subs[conn] = &connWriter{conn: conn}
	total := len(rm.subs)
	rm.mu.Unlock()
	slog.Info("replication subscriber added", "remote", conn.RemoteAddr(), "total", total)
}

// removeSub removes a disconnected subscriber.
func (rm *replicationManager) removeSub(conn net.Conn) {
	rm.mu.Lock()
	delete(rm.subs, conn)
	total := len(rm.subs)
	rm.mu.Unlock()
	slog.Info("replication subscriber removed", "remote", conn.RemoteAddr(), "total", total)
}

// push sends a snapshot to all subscribers. Failed subscribers are removed.
// Each write is serialized per-connection via connWriter.wmu (H1 fix).
func (rm *replicationManager) push(snapJSON []byte) {
	rm.mu.Lock()
	if len(rm.subs) == 0 {
		rm.mu.Unlock()
		return
	}
	// Copy subscriber list to avoid holding lock during writes
	writers := make([]*connWriter, 0, len(rm.subs))
	for _, cw := range rm.subs {
		writers = append(writers, cw)
	}
	rm.mu.Unlock()

	msg := map[string]interface{}{
		"type":     "replication_snapshot",
		"snapshot": json.RawMessage(snapJSON),
	}

	var failed []net.Conn
	for _, cw := range writers {
		cw.wmu.Lock()
		cw.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		err := writeMessage(cw.conn, msg)
		cw.wmu.Unlock()
		if err != nil {
			slog.Warn("replication push failed", "remote", cw.conn.RemoteAddr(), "err", err)
			failed = append(failed, cw.conn)
		}
	}

	if len(failed) > 0 {
		rm.mu.Lock()
		for _, c := range failed {
			delete(rm.subs, c)
			c.Close()
		}
		rm.mu.Unlock()
	}
}

// pushDelta sends delta entries to all subscribers. This is much smaller than
// a full snapshot (~1KB vs ~50MB at 100K+ nodes). Standbys that fall behind
// the delta window will be sent a full snapshot on next push().
func (rm *replicationManager) pushDelta(entries []DeltaEntry, seqNo uint64) {
	rm.mu.Lock()
	if len(rm.subs) == 0 {
		rm.mu.Unlock()
		return
	}
	writers := make([]*connWriter, 0, len(rm.subs))
	for _, cw := range rm.subs {
		writers = append(writers, cw)
	}
	rm.mu.Unlock()

	msg := map[string]interface{}{
		"type":    "replication_delta",
		"entries": entries,
		"seq_no":  seqNo,
	}

	var failed []net.Conn
	for _, cw := range writers {
		cw.wmu.Lock()
		cw.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		err := writeMessage(cw.conn, msg)
		cw.wmu.Unlock()
		if err != nil {
			slog.Warn("replication delta push failed", "remote", cw.conn.RemoteAddr(), "err", err)
			failed = append(failed, cw.conn)
		}
	}

	if len(failed) > 0 {
		rm.mu.Lock()
		for _, c := range failed {
			delete(rm.subs, c)
			c.Close()
		}
		rm.mu.Unlock()
	}
}

// startReplicationHeartbeat sends periodic heartbeat messages to all replication
// subscribers so standbys can detect primary failure within ~30s.
func (rm *replicationManager) startHeartbeat(done <-chan struct{}) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			rm.mu.Lock()
			if len(rm.subs) == 0 {
				rm.mu.Unlock()
				continue
			}
			writers := make([]*connWriter, 0, len(rm.subs))
			for _, cw := range rm.subs {
				writers = append(writers, cw)
			}
			rm.mu.Unlock()

			msg := map[string]interface{}{"type": "heartbeat"}
			var failed []net.Conn
			for _, cw := range writers {
				cw.wmu.Lock()
				cw.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				err := writeMessage(cw.conn, msg)
				cw.wmu.Unlock()
				if err != nil {
					failed = append(failed, cw.conn)
				}
			}
			if len(failed) > 0 {
				rm.mu.Lock()
				for _, c := range failed {
					delete(rm.subs, c)
					c.Close()
				}
				rm.mu.Unlock()
			}
		}
	}
}

// handleSubscribeReplication is called when a client sends {"type": "subscribe_replication"}.
// It sends the current snapshot immediately, then the connection is kept open for
// future pushes via the replicationManager.
func (s *Server) handleSubscribeReplication(conn net.Conn) {
	// Send current snapshot
	snapJSON := s.snapshotJSON()
	if snapJSON == nil {
		writeMessage(conn, map[string]interface{}{
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
	s.replMgr.addSub(conn)

	// Block until the connection is closed (primary keeps pushing via replMgr.push)
	// Read loop to detect disconnection
	buf := make([]byte, 1)
	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		_, err := conn.Read(buf)
		if err != nil {
			s.replMgr.removeSub(conn)
			return
		}
	}
}

// snapshotJSON returns the current registry state as JSON bytes.
func (s *Server) snapshotJSON() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snap := snapshot{
		NextNode: s.nextNode,
		NextNet:  s.nextNet,
		Nodes:    make(map[string]*snapshotNode, len(s.nodes)),
		Networks: make(map[string]*snapshotNet, len(s.networks)),
	}

	for id, n := range s.nodes {
		sn := &snapshotNode{
			ID:        n.ID,
			Owner:     n.Owner,
			PublicKey: base64.StdEncoding.EncodeToString(n.PublicKey),
			RealAddr:  n.RealAddr,
			Networks:  n.Networks,
			Public:    n.Public,
			LastSeen:  n.LastSeen.Format(time.RFC3339),
			Hostname:  n.Hostname,
			Tags:      n.Tags,
			PoloScore: n.PoloScore,
			TaskExec:  n.TaskExec,
			LANAddrs:  n.LANAddrs,
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
		snap.Nodes[fmt.Sprintf("%d", id)] = sn
	}

	for id, n := range s.networks {
		sn := &snapshotNet{
			ID:         n.ID,
			Name:       n.Name,
			JoinRule:   n.JoinRule,
			Token:      n.Token,
			Members:    n.Members,
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
				sn.MemberTags[fmt.Sprintf("%d", nodeID)] = tags
			}
		}
		if n.Policy.MaxMembers != 0 || len(n.Policy.AllowedPorts) > 0 || n.Policy.Description != "" {
			pol := n.Policy
			sn.Policy = &pol
		}
		snap.Networks[fmt.Sprintf("%d", id)] = sn
	}

	// Include trust pairs
	for key := range s.trustPairs {
		snap.TrustPairs = append(snap.TrustPairs, key)
	}

	// Include handshake inboxes
	if len(s.handshakeInbox) > 0 {
		snap.HandshakeInbox = make(map[string][]*HandshakeRelayMsg, len(s.handshakeInbox))
		for nodeID, msgs := range s.handshakeInbox {
			snap.HandshakeInbox[fmt.Sprintf("%d", nodeID)] = msgs
		}
	}
	if len(s.handshakeResponses) > 0 {
		snap.HandshakeResponses = make(map[string][]*HandshakeResponseMsg, len(s.handshakeResponses))
		for nodeID, msgs := range s.handshakeResponses {
			snap.HandshakeResponses[fmt.Sprintf("%d", nodeID)] = msgs
		}
	}

	// Include invite inboxes
	if len(s.inviteInbox) > 0 {
		snap.InviteInbox = make(map[string][]*NetworkInvite, len(s.inviteInbox))
		for nodeID, invites := range s.inviteInbox {
			snap.InviteInbox[fmt.Sprintf("%d", nodeID)] = invites
		}
	}

	// Include audit log (separate lock — not nested under s.mu)
	s.auditMu.Lock()
	if len(s.auditLog) > 0 {
		snap.AuditLog = make([]AuditEntry, len(s.auditLog))
		copy(snap.AuditLog, s.auditLog)
	}
	s.auditMu.Unlock()

	// Enterprise config persistence
	if s.idpConfig != nil {
		snap.IDPConfig = s.idpConfig
	}
	if s.auditExportConfig != nil {
		snap.AuditExportCfg = s.auditExportConfig
	}
	if len(s.rbacPreAssign) > 0 {
		snap.RBACPreAssign = make(map[string][]BlueprintRole, len(s.rbacPreAssign))
		for netID, roles := range s.rbacPreAssign {
			snap.RBACPreAssign[fmt.Sprintf("%d", netID)] = roles
		}
	}

	data, err := json.Marshal(snap)
	if err != nil {
		slog.Error("snapshot marshal error", "err", err)
		return nil
	}
	return data
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
	s.mu.RLock()
	if s.replToken != "" {
		msg["token"] = s.replToken
	}
	s.mu.RUnlock()
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

		conn.SetReadDeadline(time.Now().Add(45 * time.Second))
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

// applySnapshot loads a snapshot into the server state and persists it.
func (s *Server) applySnapshot(data []byte) error {
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Clear current state
	s.nodes = make(map[uint32]*NodeInfo)
	s.pubKeyIdx = make(map[string]uint32)
	s.ownerIdx = make(map[string]uint32)
	s.hostnameIdx = make(map[string]uint32)
	s.networks = make(map[uint16]*NetworkInfo)
	s.nextNode = snap.NextNode
	s.nextNet = snap.NextNet

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
			PoloScore: n.PoloScore,
			TaskExec:  n.TaskExec,
			LANAddrs:  n.LANAddrs,
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
		s.nodes[n.ID] = node
		s.pubKeyIdx[n.PublicKey] = n.ID
		if n.Owner != "" {
			s.ownerIdx[n.Owner] = n.ID
		}
		if n.Hostname != "" {
			if existID, taken := s.hostnameIdx[n.Hostname]; taken && existID != n.ID {
				slog.Warn("duplicate hostname in snapshot, keeping first",
					"hostname", n.Hostname, "kept_node", existID, "skipped_node", n.ID)
				node.Hostname = "" // clear the duplicate
			} else {
				s.hostnameIdx[n.Hostname] = n.ID
			}
		}
	}

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
		s.networks[n.ID] = net
	}

	// Restore trust pairs (H2 fix — previously dropped on replication)
	s.trustPairs = make(map[string]bool)
	for _, key := range snap.TrustPairs {
		s.trustPairs[key] = true
	}

	// Restore handshake inboxes (S20 fix — match load() behavior)
	s.handshakeInbox = make(map[uint32][]*HandshakeRelayMsg)
	s.handshakeResponses = make(map[uint32][]*HandshakeResponseMsg)
	for nodeIDStr, msgs := range snap.HandshakeInbox {
		var nodeID uint32
		if _, err := fmt.Sscanf(nodeIDStr, "%d", &nodeID); err == nil && nodeID > 0 {
			s.handshakeInbox[nodeID] = msgs
		}
	}
	for nodeIDStr, msgs := range snap.HandshakeResponses {
		var nodeID uint32
		if _, err := fmt.Sscanf(nodeIDStr, "%d", &nodeID); err == nil && nodeID > 0 {
			s.handshakeResponses[nodeID] = msgs
		}
	}

	// Restore invite inboxes
	s.inviteInbox = make(map[uint32][]*NetworkInvite)
	for nodeIDStr, invites := range snap.InviteInbox {
		var nodeID uint32
		if _, err := fmt.Sscanf(nodeIDStr, "%d", &nodeID); err == nil && nodeID > 0 {
			s.inviteInbox[nodeID] = invites
		}
	}

	// Restore audit log
	if len(snap.AuditLog) > 0 {
		s.auditMu.Lock()
		s.auditLog = snap.AuditLog
		s.auditMu.Unlock()
	}

	// Restore enterprise config
	if snap.IDPConfig != nil {
		s.idpConfig = snap.IDPConfig
		s.identityWebhookURL = snap.IDPConfig.URL
	}
	if snap.AuditExportCfg != nil {
		s.auditExportConfig = snap.AuditExportCfg
		if s.auditExporter != nil {
			s.auditExporter.Close()
		}
		s.auditExporter = newAuditExporter(snap.AuditExportCfg)
	}
	if len(snap.RBACPreAssign) > 0 {
		s.rbacPreAssign = make(map[uint16][]BlueprintRole)
		for netIDStr, roles := range snap.RBACPreAssign {
			var netID uint16
			if _, err := fmt.Sscanf(netIDStr, "%d", &netID); err == nil {
				s.rbacPreAssign[netID] = roles
			}
		}
	}

	// Persist to local disk for crash recovery
	s.save()

	return nil
}

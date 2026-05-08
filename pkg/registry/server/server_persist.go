// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/fsutil"
	dashpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/dashboard"
	trustpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/trust"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
	"github.com/TeoSlayer/pilotprotocol/pkg/urlvalidate"
)

// rawNodeCopy holds raw node fields copied under RLock (no encoding).
// base64/time.Format happens outside the lock to minimize lock hold time.
type rawNodeCopy struct {
	id         uint32
	owner      string
	publicKey  []byte
	realAddr   string
	networks   []uint16
	lastSeen   time.Time
	public     bool
	hostname   string
	tags       []string
	taskExec   bool
	lanAddrs   []string
	keyMeta    KeyInfo
	externalID string
	version    string
	relayOnly  bool // task 32
}

// save signals that state has changed and should be persisted AND pushed
// to replicas. Non-blocking: actual serialization happens in saveLoop
// (disk) and replicaPushLoop (replicas), each on its own cadence.
// Caller must hold s.mu (read or write lock).
// Delegated to walStore (R6.1).
func (s *Server) save() {
	s.walStore.TriggerSave()
}

// flushSave serializes the full registry state and writes it to disk.
// Phase 1 (RLock): copy raw values only — no encoding.
// Phase 2 (no lock): base64, time.Format, JSON marshal.
func (s *Server) flushSave() error {
	// Phase 1: RLock — copy raw values (pointer copies, integer copies only)
	s.mu.RLock()
	nextNode := s.nextNode
	nextNet := s.nextNet

	// Copy node raw values (no encoding under lock). Slice fields that can be
	// mutated in place elsewhere (Networks/Tags/LANAddrs are append-grown) are
	// deep-copied so Phase 2 sees a stable snapshot after the lock is released.
	//
	// Per-node fields RealAddr / LANAddrs / Version may be written by the
	// handleReRegister fast path under shard.Lock() (without s.mu.Lock).
	// Take shard.RLock per node here to establish happens-before with those
	// writers — otherwise this loop has a torn-string-read race against the
	// fast path. Cost: ~100k RLock acquisitions per save tick (~5ms total).
	rawNodes := make([]rawNodeCopy, 0, len(s.nodes))
	for _, n := range s.nodes {
		shard := &s.nodeShards[n.ID%numNodeShards]
		shard.RLock()
		rawNodes = append(rawNodes, rawNodeCopy{
			id:         n.ID,
			owner:      n.Owner,
			publicKey:  n.PublicKey,
			realAddr:   n.RealAddr,
			networks:   append([]uint16(nil), n.Networks...),
			lastSeen:   n.GetLastSeen(),
			public:     n.Public,
			hostname:   n.Hostname,
			tags:     append([]string(nil), n.Tags...),
			taskExec: n.TaskExec,
			lanAddrs:   append([]string(nil), n.LANAddrs...),
			keyMeta:    n.KeyMeta,
			externalID: n.ExternalID,
			version:    n.Version,
			relayOnly:  n.RelayOnly, // task 32
		})
		shard.RUnlock()
	}

	// Copy network data. Members/MemberRoles/MemberTags mutate in place
	// (handleRegister/handleDeregister append-grow Members, map writes add/remove
	// roles and tags), so Phase 2 must see deep copies rather than live pointers.
	type rawNetCopy struct {
		id           uint16
		name         string
		joinRule     string
		token        string
		members      []uint32
		memberRoles  map[uint32]Role
		memberTags   map[uint32][]string
		adminToken   string
		policy       NetworkPolicy
		rules        *wire.NetworkRules
		exprPolicy   json.RawMessage
		enterprise   bool
		created      time.Time
		requestCount int64
	}
	rawNets := make([]rawNetCopy, 0, len(s.networks))
	for _, n := range s.networks {
		rc := rawNetCopy{
			id:           n.ID,
			name:         n.Name,
			joinRule:     n.JoinRule,
			token:        n.Token,
			members:      append([]uint32(nil), n.Members...),
			adminToken:   n.AdminToken,
			policy:       n.Policy,
			rules:        n.Rules,
			exprPolicy:   n.ExprPolicy,
			enterprise:   n.Enterprise,
			created:      n.Created,
			requestCount: n.RequestCount.Load(),
		}
		if len(n.Policy.AllowedPorts) > 0 {
			rc.policy.AllowedPorts = append([]uint16(nil), n.Policy.AllowedPorts...)
		}
		if len(n.MemberRoles) > 0 {
			rc.memberRoles = make(map[uint32]Role, len(n.MemberRoles))
			for k, v := range n.MemberRoles {
				rc.memberRoles[k] = v
			}
		}
		if len(n.MemberTags) > 0 {
			rc.memberTags = make(map[uint32][]string, len(n.MemberTags))
			for k, v := range n.MemberTags {
				rc.memberTags[k] = append([]string(nil), v...)
			}
		}
		rawNets = append(rawNets, rc)
	}

	var pubKeyIdx map[string]uint32
	if len(s.pubKeyIdx) > 0 {
		pubKeyIdx = make(map[string]uint32, len(s.pubKeyIdx))
		for key, id := range s.pubKeyIdx {
			pubKeyIdx[key] = id
		}
	}

	// Copy trust pairs and handshake inboxes from the trust sub-package (R2.1).
	trustPairs := s.trust.Pairs()
	handshakeInbox, handshakeResponses := s.trust.InboxSnapshot()
	var inviteInbox map[uint32][]*NetworkInvite
	if len(s.inviteInbox) > 0 {
		inviteInbox = make(map[uint32][]*NetworkInvite, len(s.inviteInbox))
		for nodeID, invites := range s.inviteInbox {
			inviteInbox[nodeID] = invites
		}
	}

	totalRequests := s.requestCount.Load()
	startTime := s.startTime

	idpConfig := s.identity.GetIDPConfig()
	auditExportConfig := s.auditStore.ExporterConfig()
	var rbacPreAssign map[uint16][]BlueprintRole
	if len(s.rbacPreAssign) > 0 {
		rbacPreAssign = make(map[uint16][]BlueprintRole, len(s.rbacPreAssign))
		for netID, roles := range s.rbacPreAssign {
			rbacPreAssign[netID] = roles
		}
	}

	nodeCount := len(s.nodes)
	netCount := len(s.networks)
	trustCount := s.trust.Count()

	hourlyHistory := s.hourlyHistory
	dailyHistory := s.dailyHistory
	hourlyIdx := s.hourlyIdx
	dailyIdx := s.dailyIdx
	netHourlyCopy := make(map[uint16]*netHistoryRing, len(s.netHourly))
	for id, ring := range s.netHourly {
		cp := *ring
		netHourlyCopy[id] = &cp
	}
	netDailyCopy := make(map[uint16]*netHistoryRing, len(s.netDaily))
	for id, ring := range s.netDaily {
		cp := *ring
		netDailyCopy[id] = &cp
	}
	s.mu.RUnlock()

	// Phase 2: no lock — all encoding (base64, time.Format, JSON) happens here
	snap := snapshot{
		Version:  1,
		NextNode: nextNode,
		NextNet:  nextNet,
		Nodes:    make(map[string]*snapshotNode, len(rawNodes)),
		Networks: make(map[string]*snapshotNet, len(rawNets)),
	}

	// Convert raw node copies to snapshot nodes (base64 + time.Format outside lock)
	onlineThreshold := time.Now().Add(-s.StaleNodeThreshold())
	onlineCount := 0
	taskExecCount := 0
	tagSet := make(map[string]bool)
	for i := range rawNodes {
		rn := &rawNodes[i]
		sn := &snapshotNode{
			ID:        rn.id,
			Owner:     rn.owner,
			PublicKey: base64.StdEncoding.EncodeToString(rn.publicKey),
			RealAddr:  rn.realAddr,
			Networks:  rn.networks,
			Public:    rn.public,
			LastSeen:  rn.lastSeen.Format(time.RFC3339),
			Hostname:  rn.hostname,
			Tags:      rn.tags,
			TaskExec:  rn.taskExec,
			LANAddrs:  rn.lanAddrs,
			RelayOnly: rn.relayOnly, // task 32
		}
		if !rn.keyMeta.CreatedAt.IsZero() {
			sn.KeyCreated = rn.keyMeta.CreatedAt.Format(time.RFC3339)
		}
		if !rn.keyMeta.RotatedAt.IsZero() {
			sn.KeyRotated = rn.keyMeta.RotatedAt.Format(time.RFC3339)
		}
		if rn.keyMeta.RotateCount > 0 {
			sn.KeyRotCount = rn.keyMeta.RotateCount
		}
		if !rn.keyMeta.ExpiresAt.IsZero() {
			sn.KeyExpires = rn.keyMeta.ExpiresAt.Format(time.RFC3339)
		}
		sn.ExternalID = rn.externalID
		sn.Version = rn.version
		snap.Nodes[fmt.Sprintf("%d", rn.id)] = sn

		// Dashboard metrics (computed outside lock)
		if rn.lastSeen.After(onlineThreshold) {
			onlineCount++
		}
		if rn.taskExec {
			taskExecCount++
		}
		for _, tag := range rn.tags {
			tagSet[tag] = true
		}
	}

	for i := range rawNets {
		rn := &rawNets[i]
		sn := &snapshotNet{
			ID:           rn.id,
			Name:         rn.name,
			JoinRule:     rn.joinRule,
			Token:        rn.token,
			Members:      rn.members,
			AdminToken:   rn.adminToken,
			Enterprise:   rn.enterprise,
			RequestCount: rn.requestCount,
			Created:      rn.created.Format(time.RFC3339),
		}
		if len(rn.memberRoles) > 0 {
			sn.MemberRoles = make(map[string]string, len(rn.memberRoles))
			for nodeID, role := range rn.memberRoles {
				sn.MemberRoles[fmt.Sprintf("%d", nodeID)] = string(role)
			}
		}
		if len(rn.memberTags) > 0 {
			sn.MemberTags = make(map[string][]string, len(rn.memberTags))
			for nodeID, tags := range rn.memberTags {
				sn.MemberTags[fmt.Sprintf("%d", nodeID)] = tags
			}
		}
		if rn.policy.MaxMembers != 0 || len(rn.policy.AllowedPorts) > 0 || rn.policy.Description != "" {
			pol := rn.policy
			sn.Policy = &pol
		}
		sn.Rules = rn.rules
		sn.ExprPolicy = rn.exprPolicy
		snap.Networks[fmt.Sprintf("%d", rn.id)] = sn
	}

	snap.PubKeyIdx = pubKeyIdx
	snap.TrustPairs = trustPairs

	// Handshake inboxes
	if len(handshakeInbox) > 0 {
		snap.HandshakeInbox = make(map[string][]*trustpkg.HandshakeRelayMsg, len(handshakeInbox))
		for nodeID, msgs := range handshakeInbox {
			snap.HandshakeInbox[fmt.Sprintf("%d", nodeID)] = msgs
		}
	}
	if len(handshakeResponses) > 0 {
		snap.HandshakeResponses = make(map[string][]*trustpkg.HandshakeResponseMsg, len(handshakeResponses))
		for nodeID, msgs := range handshakeResponses {
			snap.HandshakeResponses[fmt.Sprintf("%d", nodeID)] = msgs
		}
	}
	if len(inviteInbox) > 0 {
		snap.InviteInbox = make(map[string][]*NetworkInvite, len(inviteInbox))
		for nodeID, invites := range inviteInbox {
			snap.InviteInbox[fmt.Sprintf("%d", nodeID)] = invites
		}
	}

	snap.TotalRequests = totalRequests
	snap.StartTime = startTime.Format(time.RFC3339)
	s.restartMu.Lock()
	if len(s.restartEvents) > 0 {
		snap.RestartEvents = append([]int64(nil), s.restartEvents...)
	}
	if len(s.downtimeIntervals) > 0 {
		snap.DowntimeIntervals = append([][2]int64(nil), s.downtimeIntervals...)
	}
	s.restartMu.Unlock()
	snap.LastHeartbeat = s.lastHeartbeatMs.Load()

	// Snapshot probe states from dashboard Handler (R5.1).
	snap.ProbeStates = s.dashboard.GetProbeStates()
	snap.TotalNodes = nodeCount
	snap.OnlineNodes = onlineCount
	snap.TrustLinks = trustCount
	snap.UniqueTags = len(tagSet)
	snap.TaskExecutors = taskExecCount

	if idpConfig != nil {
		snap.IDPConfig = idpConfig
	}
	if auditExportConfig != nil {
		snap.AuditExportCfg = auditExportConfig
	}
	if len(rbacPreAssign) > 0 {
		snap.RBACPreAssign = make(map[string][]BlueprintRole, len(rbacPreAssign))
		for netID, roles := range rbacPreAssign {
			snap.RBACPreAssign[fmt.Sprintf("%d", netID)] = roles
		}
	}

	// Persist history ring buffers (chronological, non-zero only)
	for i := 0; i < 24; i++ {
		idx := (hourlyIdx + i) % 24
		if hourlyHistory[idx].Timestamp != 0 {
			snap.HourlyHistory = append(snap.HourlyHistory, hourlyHistory[idx])
		}
	}
	for i := 0; i < len(dailyHistory); i++ {
		idx := (dailyIdx + i) % len(dailyHistory)
		if dailyHistory[idx].Timestamp != 0 {
			snap.DailyHistory = append(snap.DailyHistory, dailyHistory[idx])
		}
	}
	// Per-network history
	if len(netHourlyCopy) > 0 {
		snap.NetHourlyHistory = make(map[string][]NetworkSampleEntry, len(netHourlyCopy))
		for id, ring := range netHourlyCopy {
			if entries := ring.Read(); len(entries) > 0 {
				snap.NetHourlyHistory[fmt.Sprintf("%d", id)] = entries
			}
		}
	}
	if len(netDailyCopy) > 0 {
		snap.NetDailyHistory = make(map[string][]NetworkSampleEntry, len(netDailyCopy))
		for id, ring := range netDailyCopy {
			if entries := ring.Read(); len(entries) > 0 {
				snap.NetDailyHistory[fmt.Sprintf("%d", id)] = entries
			}
		}
	}

	// Persist audit log (separate mutex from s.mu).
	s.auditMu.Lock()
	if len(s.auditLog) > 0 {
		snap.AuditLog = make([]AuditEntry, len(s.auditLog))
		copy(snap.AuditLog, s.auditLog)
	}
	s.auditMu.Unlock()

	// Compute checksum: marshal once without checksum (omitempty omits it), hash,
	// then inject the checksum into the JSON without a second marshal.
	snap.Checksum = ""
	data, err := json.Marshal(snap)
	if err != nil {
		slog.Error("registry save marshal error", "err", err)
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	hash := sha256.Sum256(data)
	checksum := hex.EncodeToString(hash[:])
	// Insert "checksum":"<hex>" before the closing brace. json.Marshal of a struct
	// always produces a JSON object ending with '}' (no trailing whitespace).
	if len(data) == 0 || data[len(data)-1] != '}' {
		return fmt.Errorf("marshal snapshot: unexpected JSON format (expected trailing '}')")
	}
	data = append(data[:len(data)-1], []byte(`,"checksum":"`+checksum+`"}`)...)

	// Persist to disk atomically
	if s.storePath != "" {
		if err := fsutil.AtomicWrite(s.storePath, data); err != nil {
			slog.Error("registry save error", "err", err)
			return fmt.Errorf("write snapshot: %w", err)
		}
		// Truncate WAL after successful snapshot (compaction).
		if w := s.walStore.WAL(); w != nil {
			if err := w.Truncate(); err != nil {
				slog.Error("WAL truncate after snapshot failed", "err", err)
			}
		}
	}

	// Replica push runs on its own ticker (replicaPushLoop) so this disk
	// flush no longer drives replication latency. Subscribers receive
	// updates within replicaPushInterval of any mutation.

	slog.Debug("registry state saved", "nodes", nodeCount, "networks", netCount)
	return nil
}

// load reads the registry state from disk.
func (s *Server) load() error {
	data, err := os.ReadFile(s.storePath)
	if err != nil {
		return err
	}

	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	// Check snapshot version — legacy snapshots have version 0 (field absent).
	if snap.Version == 0 {
		slog.Info("migrating legacy snapshot (version 0) to current format")
	}

	// Verify snapshot checksum if present
	if snap.Checksum != "" {
		savedChecksum := snap.Checksum
		snap.Checksum = ""
		verifyData, verifyErr := json.Marshal(snap)
		if verifyErr == nil {
			hash := sha256.Sum256(verifyData)
			computed := hex.EncodeToString(hash[:])
			if computed != savedChecksum {
				slog.Warn("snapshot checksum mismatch — data may be corrupted",
					"expected", savedChecksum, "computed", computed)
			} else {
				slog.Info("snapshot checksum verified")
			}
		}
		snap.Checksum = savedChecksum // restore for completeness
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextNode = snap.NextNode
	s.nextNet = snap.NextNet

	// Restore dashboard stats
	if snap.TotalRequests > 0 {
		s.requestCount.Store(snap.TotalRequests)
	}
	if snap.StartTime != "" {
		if startTime, err := time.Parse(time.RFC3339, snap.StartTime); err == nil {
			s.startTime = startTime
		}
		// This is a restart (not a fresh install) — record the event.
		now := time.Now().UnixMilli()
		cutoff := time.Now().AddDate(0, 0, -90).UnixMilli()
		kept := make([]int64, 0, len(snap.RestartEvents)+1)
		for _, t := range snap.RestartEvents {
			if t >= cutoff {
				kept = append(kept, t)
			}
		}
		kept = append(kept, now)

		// Prune persisted downtime intervals to the 90-day window.
		keptDown := make([][2]int64, 0, len(snap.DowntimeIntervals)+1)
		for _, iv := range snap.DowntimeIntervals {
			if iv[1] >= cutoff {
				keptDown = append(keptDown, iv)
			}
		}
		// If the prior process persisted a last_heartbeat and the gap to now
		// is wider than a grace window, treat the gap as real downtime.
		const downtimeGraceMs = 15 * 1000
		if snap.LastHeartbeat > 0 && now-snap.LastHeartbeat > downtimeGraceMs {
			keptDown = append(keptDown, [2]int64{snap.LastHeartbeat, now})
		}

		s.restartMu.Lock()
		s.restartEvents = kept
		s.downtimeIntervals = keptDown
		s.restartMu.Unlock()

		// Restore per-probe state into the dashboard Handler and account for the
		// downtime gap between the prior last-success timestamp and now (R5.1).
		if len(snap.ProbeStates) > 0 {
			probeCutoff := time.Now().Add(-dashpkg.ProbeRetention).UnixMilli()
			restored := make(map[string]*dashpkg.ProbeState, len(snap.ProbeStates))
			for name, ps := range snap.ProbeStates {
				if ps == nil {
					continue
				}
				cp := *ps
				if len(ps.DowntimeIntervals) > 0 {
					kept := make([][2]int64, 0, len(ps.DowntimeIntervals)+1)
					for _, iv := range ps.DowntimeIntervals {
						if iv[1] >= probeCutoff {
							kept = append(kept, iv)
						}
					}
					cp.DowntimeIntervals = kept
				}
				// If the process died while this probe was down, close that
				// interval at `now`; otherwise the gap from LastSuccess→now is
				// real downtime.
				if cp.CurrentDownStart > 0 {
					cp.DowntimeIntervals = append(cp.DowntimeIntervals, [2]int64{cp.CurrentDownStart, now})
					cp.CurrentDownStart = 0
				} else if cp.LastSuccess > 0 && now-cp.LastSuccess > downtimeGraceMs {
					cp.DowntimeIntervals = append(cp.DowntimeIntervals, [2]int64{cp.LastSuccess, now})
				}
				restored[name] = &cp
			}
			s.dashboard.SetProbeStates(restored)
		}
	}

	// Log all restored dashboard stats for verification
	if snap.TotalRequests > 0 || snap.StartTime != "" {
		slog.Info("restored dashboard stats",
			"total_requests", snap.TotalRequests,
			"total_nodes", snap.TotalNodes,
			"online_nodes", snap.OnlineNodes,
			"trust_links", snap.TrustLinks,
			"unique_tags", snap.UniqueTags,
			"task_executors", snap.TaskExecutors,
			"start_time", snap.StartTime)
	}

	for _, n := range snap.Nodes {
		pubKey, err := base64.StdEncoding.DecodeString(n.PublicKey)
		if err != nil {
			slog.Warn("registry load: skip node with bad public key", "node_id", n.ID, "err", err)
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
		node.LastSeenNano.Store(lastSeen.UnixNano())
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
		node.Version = n.Version
		s.nodes[n.ID] = node
		s.pubKeyIdx[n.PublicKey] = n.ID
		if n.Owner != "" {
			s.ownerIdx[n.Owner] = n.ID
		}
		if n.Hostname != "" {
			s.hostnameIdx[n.Hostname] = n.ID
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
		if n.RequestCount > 0 {
			net.RequestCount.Store(n.RequestCount)
		}
		if n.Policy != nil {
			net.Policy = *n.Policy
		}
		net.Rules = n.Rules
		net.ExprPolicy = n.ExprPolicy
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
		// Backfill roles for legacy snapshots: members without roles get RoleMember,
		// and the first member (creator) gets RoleOwner if no owner exists.
		if len(n.MemberRoles) == 0 && len(net.Members) > 0 && net.ID != 0 {
			for i, m := range net.Members {
				if i == 0 {
					net.MemberRoles[m] = RoleOwner
				} else {
					net.MemberRoles[m] = RoleMember
				}
			}
			slog.Info("backfilled RBAC roles for legacy network", "network_id", net.ID, "name", net.Name, "members", len(net.Members))
		}
		s.networks[n.ID] = net
	}

	// Restore trust pairs (R2.1: delegate to trust sub-package)
	s.trust.RestorePairs(snap.TrustPairs)
	if len(snap.TrustPairs) > 0 {
		slog.Info("loaded trust pairs", "count", len(snap.TrustPairs))
	}

	// Restore persisted pubKeyIdx (entries for reaped nodes that aren't in snap.Nodes)
	for key, id := range snap.PubKeyIdx {
		if _, exists := s.pubKeyIdx[key]; !exists {
			s.pubKeyIdx[key] = id
		}
	}
	if len(snap.PubKeyIdx) > 0 {
		slog.Info("loaded pub_key_idx", "persisted", len(snap.PubKeyIdx), "total", len(s.pubKeyIdx))
	}

	// Restore handshake inboxes (R2.1: delegate to trust sub-package)
	{
		inboxMap := make(map[uint32][]*trustpkg.HandshakeRelayMsg, len(snap.HandshakeInbox))
		respMap := make(map[uint32][]*trustpkg.HandshakeResponseMsg, len(snap.HandshakeResponses))
		for nodeIDStr, msgs := range snap.HandshakeInbox {
			var nodeID uint32
			if _, err := fmt.Sscanf(nodeIDStr, "%d", &nodeID); err == nil && nodeID > 0 {
				inboxMap[nodeID] = msgs
			}
		}
		for nodeIDStr, msgs := range snap.HandshakeResponses {
			var nodeID uint32
			if _, err := fmt.Sscanf(nodeIDStr, "%d", &nodeID); err == nil && nodeID > 0 {
				respMap[nodeID] = msgs
			}
		}
		s.trust.RestoreInbox(inboxMap, respMap)
		if len(inboxMap)+len(respMap) > 0 {
			slog.Info("loaded handshake inboxes", "request_queues", len(inboxMap), "response_queues", len(respMap))
		}
	}

	// Restore invite inboxes
	for nodeIDStr, invites := range snap.InviteInbox {
		var nodeID uint32
		if _, err := fmt.Sscanf(nodeIDStr, "%d", &nodeID); err == nil && nodeID > 0 {
			s.inviteInbox[nodeID] = invites
		}
	}
	if len(s.inviteInbox) > 0 {
		slog.Info("loaded invite inboxes", "queues", len(s.inviteInbox))
	}

	// Restore time-series history ring buffers (deduplicate by bucket)
	if len(snap.HourlyHistory) > 0 {
		deduped := deduplicateSamples(snap.HourlyHistory, 3600, 24)
		for i, sample := range deduped {
			s.hourlyHistory[i] = sample
		}
		s.hourlyIdx = len(deduped)
		slog.Info("loaded hourly history", "samples", len(deduped))
	}
	if len(snap.DailyHistory) > 0 {
		deduped := deduplicateSamples(snap.DailyHistory, 86400, len(s.dailyHistory))
		for i, sample := range deduped {
			s.dailyHistory[i] = sample
		}
		s.dailyIdx = len(deduped)
		slog.Info("loaded daily history", "samples", len(deduped))
	}
	// Restore per-network history (deduplicated)
	for netIDStr, entries := range snap.NetHourlyHistory {
		var netID uint16
		if _, err := fmt.Sscanf(netIDStr, "%d", &netID); err == nil {
			deduped := deduplicateNetSamples(entries, 3600, 24)
			ring := dashpkg.NewNetHistoryRing(24)
			for i, e := range deduped {
				ring.Samples[i] = e
			}
			ring.Idx = len(deduped)
			s.netHourly[netID] = ring
		}
	}
	for netIDStr, entries := range snap.NetDailyHistory {
		var netID uint16
		if _, err := fmt.Sscanf(netIDStr, "%d", &netID); err == nil {
			deduped := deduplicateNetSamples(entries, 86400, 30)
			ring := dashpkg.NewNetHistoryRing(30)
			for i, e := range deduped {
				ring.Samples[i] = e
			}
			ring.Idx = len(deduped) % 30
			s.netDaily[netID] = ring
		}
	}

	// Restore audit log (separate mutex from s.mu).
	if len(snap.AuditLog) > 0 {
		s.auditMu.Lock()
		s.auditLog = snap.AuditLog
		s.auditMu.Unlock()
		slog.Info("loaded audit log", "entries", len(snap.AuditLog))
	}

	// Restore enterprise config (IDP, audit export, RBAC pre-assignments).
	// Validate the persisted URL even though the setter would have validated it
	// at configuration time — snapshots predating the urlvalidate extraction
	// (commit a318fe4) may contain URLs that would be rejected today, and a
	// compromised primary in replication scenarios could write hostile values.
	if snap.IDPConfig != nil {
		if err := urlvalidate.Validate(snap.IDPConfig.URL); err != nil {
			slog.Warn("skipping restored IDP config with invalid URL", "url", snap.IDPConfig.URL, "err", err)
		} else {
			s.identity.SetIDPConfig(snap.IDPConfig)
			slog.Info("loaded identity provider config", "type", snap.IDPConfig.Type)
		}
	}
	if snap.AuditExportCfg != nil {
		acceptExport := true
		if snap.AuditExportCfg.Format == "json" || snap.AuditExportCfg.Format == "splunk_hec" {
			if err := urlvalidate.Validate(snap.AuditExportCfg.Endpoint); err != nil {
				slog.Warn("skipping restored audit export with invalid endpoint", "endpoint", snap.AuditExportCfg.Endpoint, "err", err)
				acceptExport = false
			}
		}
		if acceptExport {
			s.auditStore.SetExporter(snap.AuditExportCfg)
			slog.Info("loaded audit export config", "format", snap.AuditExportCfg.Format,
				"endpoint", snap.AuditExportCfg.Endpoint)
		}
	}
	if len(snap.RBACPreAssign) > 0 {
		s.rbacPreAssign = make(map[uint16][]BlueprintRole)
		for netIDStr, roles := range snap.RBACPreAssign {
			var netID uint16
			if _, err := fmt.Sscanf(netIDStr, "%d", &netID); err == nil {
				s.rbacPreAssign[netID] = roles
			}
		}
		slog.Info("loaded RBAC pre-assignments", "networks", len(s.rbacPreAssign))
	}

	// Ensure store directory exists for future saves
	dir := filepath.Dir(s.storePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create store directory %s: %w", dir, err)
	}

	return nil
}

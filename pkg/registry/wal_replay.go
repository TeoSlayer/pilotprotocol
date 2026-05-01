// SPDX-License-Identifier: AGPL-3.0-or-later

package registry

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// WAL wiring overview
//
// The WAL closes the data-loss window between snapshot saves. flushSave
// runs on saveLoopInterval (5s); a crash between saves would otherwise
// drop every mutation in that window. Each low-frequency mutation
// (registration, network create/delete, membership change, key rotation)
// records a delta to the WAL synchronously. On startup we load the
// snapshot, then replay any post-snapshot WAL entries on top of it.
//
// We deliberately do NOT WAL the high-frequency mutations:
//   - heartbeat (recovered on the very next heartbeat from the daemon)
//   - re-registration of an existing node (the daemon will reconnect
//     and re-register, hitting the same node_id via the pubKeyIdx)
//   - polo score updates (re-asserted by peer reports)
//
// fsync per Append is real (~ms on SSD), so this design serializes
// at ~hundreds of mutations/sec — comfortable for network ops but
// would fall over if heartbeats joined.

// --- Delta payload shapes (one struct per DeltaType we WAL) ---

// registerDelta carries the full state needed to recreate a new-node
// registration. Captured at the new-node assignment site (handleRegister)
// so a crash before flushSave doesn't reassign the same identity to a
// different node_id.
type registerDelta struct {
	NodeID    uint32   `json:"node_id"`
	Owner     string   `json:"owner,omitempty"`
	PublicKey string   `json:"public_key"` // base64
	RealAddr  string   `json:"real_addr,omitempty"`
	Hostname  string   `json:"hostname,omitempty"`
	LANAddrs  []string `json:"lan_addrs,omitempty"`
	Version   string   `json:"version,omitempty"`
	CreatedAt string   `json:"created_at,omitempty"` // RFC3339
}

// deregisterDelta marks a node as removed.
type deregisterDelta struct {
	NodeID uint32 `json:"node_id"`
}

// networkCreateDelta captures the parameters of a freshly-created network.
// Member set is empty at creation; the creator is added by a separate
// join delta if applicable.
type networkCreateDelta struct {
	NetworkID         uint16 `json:"network_id"`
	Name              string `json:"name"`
	JoinRule          string `json:"join_rule"`
	Token             string `json:"token,omitempty"`
	AdminToken        string `json:"admin_token,omitempty"`
	Enterprise        bool   `json:"enterprise,omitempty"`
	CreatorNodeID     uint32 `json:"creator_node_id,omitempty"`
	CreatedAt         string `json:"created_at"` // RFC3339
}

// networkDeleteDelta marks a network as removed.
type networkDeleteDelta struct {
	NetworkID uint16 `json:"network_id"`
}

// networkMembershipDelta covers join AND leave; direction encoded in the
// DeltaType (DeltaNetworkJoin / DeltaNetworkLeave).
type networkMembershipDelta struct {
	NodeID    uint32 `json:"node_id"`
	NetworkID uint16 `json:"network_id"`
}

// keyRotationDelta records a key rotation so the new pubkey survives a crash.
type keyRotationDelta struct {
	NodeID       uint32 `json:"node_id"`
	NewPublicKey string `json:"new_public_key"` // base64
	RotatedAt    string `json:"rotated_at"`     // RFC3339
}

// --- WAL helpers ---

// recordWAL appends a delta entry to the WAL. The data argument is
// JSON-marshalled and stored in the entry's Data field. Failures are
// LOGGED but not propagated — WAL is best-effort durability layered on
// top of the periodic snapshot. A failed Append leaves the in-memory
// mutation intact; the next successful flushSave still persists it.
//
// The entry's SeqNo is 0 here (WAL replays use the file order, not the
// SeqNo). The deltaLog separately assigns its own seqno for replication.
func (s *Server) recordWAL(typ DeltaType, nodeID uint32, data interface{}) {
	if s.wal == nil {
		return
	}
	raw, err := json.Marshal(data)
	if err != nil {
		slog.Warn("WAL: marshal failed (delta dropped)", "type", typ, "err", err)
		return
	}
	entry := DeltaEntry{
		Type:   typ,
		NodeID: nodeID,
		Data:   raw,
	}
	if err := s.wal.Append(entry); err != nil {
		// ErrWALFull is the size-cap path; it's a separate signal from
		// real I/O failures so operators can alert on each independently.
		// Log under a different sampling key and surface to the metric.
		if err == ErrWALFull {
			s.metrics.walFull.Inc()
			if shouldLog, suppressed := s.logSampler.shouldLog("wal-full"); shouldLog {
				slog.Warn("WAL: at size cap, dropping delta until next flushSave truncates",
					"type", typ, "wal_size", s.wal.Size(), "suppressed", suppressed)
			}
			return
		}
		s.metrics.walErrors.Inc()
		slog.Warn("WAL: append failed (delta dropped)", "type", typ, "err", err)
	}
}

// replayWAL applies any WAL entries written since the last flushSave on
// top of the freshly-loaded snapshot state. Caller must NOT hold s.mu —
// applyDelta acquires it internally. Replay is best-effort: a corrupt or
// unparseable entry is logged and skipped; subsequent entries continue.
func (s *Server) replayWAL() {
	if s.wal == nil {
		return
	}
	count, err := s.wal.Replay(s.applyDelta)
	if err != nil {
		slog.Warn("WAL: replay encountered error (continuing with what was applied)", "err", err, "applied", count)
	} else if count > 0 {
		slog.Info("WAL: replayed post-snapshot mutations", "count", count)
	}
}

// applyDelta dispatches a single WAL entry against current server state.
// Each branch is idempotent — a snapshot may already include the mutation
// if it landed inside the same flush window, so applyDelta tolerates
// "already exists" / "already a member" / "not found on deregister"
// without erroring.
func (s *Server) applyDelta(entry DeltaEntry) error {
	switch entry.Type {
	case DeltaRegister:
		return s.applyRegisterDelta(entry.Data)
	case DeltaDeregister:
		return s.applyDeregisterDelta(entry.Data)
	case DeltaNetworkCreate:
		return s.applyNetworkCreateDelta(entry.Data)
	case DeltaNetworkDelete:
		return s.applyNetworkDeleteDelta(entry.Data)
	case DeltaNetworkJoin:
		return s.applyNetworkMembershipDelta(entry.Data, true)
	case DeltaNetworkLeave:
		return s.applyNetworkMembershipDelta(entry.Data, false)
	case DeltaKeyRotation:
		return s.applyKeyRotationDelta(entry.Data)
	default:
		// Unknown delta types (newer registry writing types older registry
		// doesn't recognize, or types we deliberately don't WAL like heartbeat).
		// Log at debug; not an error.
		slog.Debug("WAL: skipping unknown/unhandled delta type", "type", entry.Type)
		return nil
	}
}

func (s *Server) applyRegisterDelta(data json.RawMessage) error {
	var d registerDelta
	if err := json.Unmarshal(data, &d); err != nil {
		return fmt.Errorf("register delta: %w", err)
	}
	if d.NodeID == 0 || d.PublicKey == "" {
		return fmt.Errorf("register delta: missing node_id or public_key")
	}
	pubKey, err := base64.StdEncoding.DecodeString(d.PublicKey)
	if err != nil {
		return fmt.Errorf("register delta: bad public_key: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Idempotent: if the snapshot already contains this node, leave it.
	if _, exists := s.nodes[d.NodeID]; exists {
		return nil
	}

	createdAt := time.Now()
	if d.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, d.CreatedAt); err == nil {
			createdAt = t
		}
	}

	node := &NodeInfo{
		ID:        d.NodeID,
		Owner:     d.Owner,
		PublicKey: pubKey,
		RealAddr:  d.RealAddr,
		Networks:  []uint16{0}, // backbone — same as handleRegister default
		Hostname:  d.Hostname,
		LANAddrs:  d.LANAddrs,
		Version:   d.Version,
		KeyMeta:   KeyInfo{CreatedAt: createdAt},
	}
	node.setLastSeen(createdAt)
	s.nodes[d.NodeID] = node
	s.pubKeyIdx[d.PublicKey] = d.NodeID
	if d.Owner != "" {
		s.ownerIdx[d.Owner] = d.NodeID
	}
	if d.Hostname != "" {
		s.hostnameIdx[d.Hostname] = d.NodeID
	}
	// Add to backbone unless already present.
	if backbone, ok := s.networks[0]; ok {
		found := false
		for _, m := range backbone.Members {
			if m == d.NodeID {
				found = true
				break
			}
		}
		if !found {
			backbone.Members = append(backbone.Members, d.NodeID)
		}
	}
	if s.nextNode <= d.NodeID {
		s.nextNode = d.NodeID + 1
	}
	return nil
}

func (s *Server) applyDeregisterDelta(data json.RawMessage) error {
	var d deregisterDelta
	if err := json.Unmarshal(data, &d); err != nil {
		return fmt.Errorf("deregister delta: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	node, ok := s.nodes[d.NodeID]
	if !ok {
		return nil // idempotent
	}
	pkB64 := base64.StdEncoding.EncodeToString(node.PublicKey)
	delete(s.pubKeyIdx, pkB64)
	if node.Owner != "" {
		delete(s.ownerIdx, node.Owner)
	}
	if node.Hostname != "" {
		delete(s.hostnameIdx, node.Hostname)
	}
	delete(s.nodes, d.NodeID)
	// Remove from any networks they were in.
	for _, netID := range node.Networks {
		if net, ok := s.networks[netID]; ok {
			for i, m := range net.Members {
				if m == d.NodeID {
					net.Members = append(net.Members[:i], net.Members[i+1:]...)
					break
				}
			}
			delete(net.MemberRoles, d.NodeID)
		}
	}
	return nil
}

func (s *Server) applyNetworkCreateDelta(data json.RawMessage) error {
	var d networkCreateDelta
	if err := json.Unmarshal(data, &d); err != nil {
		return fmt.Errorf("network create delta: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.networks[d.NetworkID]; exists {
		return nil // idempotent
	}
	created := time.Now()
	if d.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, d.CreatedAt); err == nil {
			created = t
		}
	}
	net := &NetworkInfo{
		ID:          d.NetworkID,
		Name:        d.Name,
		JoinRule:    d.JoinRule,
		Token:       d.Token,
		AdminToken:  d.AdminToken,
		Enterprise:  d.Enterprise,
		Members:     []uint32{},
		MemberRoles: make(map[uint32]Role),
		MemberTags:  make(map[uint32][]string),
		Created:     created,
	}
	if d.CreatorNodeID != 0 {
		net.Members = append(net.Members, d.CreatorNodeID)
		net.MemberRoles[d.CreatorNodeID] = RoleOwner
		// Add to creator's networks list if the node exists in the snapshot.
		if creator, ok := s.nodes[d.CreatorNodeID]; ok {
			already := false
			for _, n := range creator.Networks {
				if n == d.NetworkID {
					already = true
					break
				}
			}
			if !already {
				creator.Networks = append(creator.Networks, d.NetworkID)
			}
		}
	}
	s.networks[d.NetworkID] = net
	if s.nextNet <= d.NetworkID {
		s.nextNet = d.NetworkID + 1
	}
	return nil
}

func (s *Server) applyNetworkDeleteDelta(data json.RawMessage) error {
	var d networkDeleteDelta
	if err := json.Unmarshal(data, &d); err != nil {
		return fmt.Errorf("network delete delta: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	net, ok := s.networks[d.NetworkID]
	if !ok {
		return nil // idempotent
	}
	for _, memberID := range net.Members {
		if node, ok := s.nodes[memberID]; ok {
			for i, n := range node.Networks {
				if n == d.NetworkID {
					node.Networks = append(node.Networks[:i], node.Networks[i+1:]...)
					break
				}
			}
		}
	}
	delete(s.networks, d.NetworkID)
	return nil
}

func (s *Server) applyNetworkMembershipDelta(data json.RawMessage, join bool) error {
	var d networkMembershipDelta
	if err := json.Unmarshal(data, &d); err != nil {
		return fmt.Errorf("membership delta: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	net, ok := s.networks[d.NetworkID]
	if !ok {
		return nil
	}
	node, ok := s.nodes[d.NodeID]
	if !ok {
		return nil
	}
	if join {
		// Append if not already a member.
		isMember := false
		for _, m := range net.Members {
			if m == d.NodeID {
				isMember = true
				break
			}
		}
		if !isMember {
			net.Members = append(net.Members, d.NodeID)
			if net.MemberRoles == nil {
				net.MemberRoles = make(map[uint32]Role)
			}
			net.MemberRoles[d.NodeID] = RoleMember
		}
		alreadyInNode := false
		for _, n := range node.Networks {
			if n == d.NetworkID {
				alreadyInNode = true
				break
			}
		}
		if !alreadyInNode {
			node.Networks = append(node.Networks, d.NetworkID)
		}
	} else {
		// Remove from network.Members and MemberRoles.
		for i, m := range net.Members {
			if m == d.NodeID {
				net.Members = append(net.Members[:i], net.Members[i+1:]...)
				break
			}
		}
		delete(net.MemberRoles, d.NodeID)
		// Remove from node.Networks.
		for i, n := range node.Networks {
			if n == d.NetworkID {
				node.Networks = append(node.Networks[:i], node.Networks[i+1:]...)
				break
			}
		}
	}
	return nil
}

func (s *Server) applyKeyRotationDelta(data json.RawMessage) error {
	var d keyRotationDelta
	if err := json.Unmarshal(data, &d); err != nil {
		return fmt.Errorf("key rotation delta: %w", err)
	}
	if d.NodeID == 0 || d.NewPublicKey == "" {
		return fmt.Errorf("key rotation delta: missing fields")
	}
	newPubKey, err := base64.StdEncoding.DecodeString(d.NewPublicKey)
	if err != nil {
		return fmt.Errorf("key rotation delta: bad new_public_key: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	node, ok := s.nodes[d.NodeID]
	if !ok {
		return nil
	}
	oldPubKeyB64 := base64.StdEncoding.EncodeToString(node.PublicKey)
	delete(s.pubKeyIdx, oldPubKeyB64)
	node.PublicKey = newPubKey
	s.pubKeyIdx[d.NewPublicKey] = d.NodeID
	if d.RotatedAt != "" {
		if t, err := time.Parse(time.RFC3339, d.RotatedAt); err == nil {
			node.KeyMeta.RotatedAt = t
		}
	}
	node.KeyMeta.RotateCount++
	return nil
}

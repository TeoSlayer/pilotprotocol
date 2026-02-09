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
		snap.Nodes[fmt.Sprintf("%d", id)] = &snapshotNode{
			ID:        n.ID,
			Owner:     n.Owner,
			PublicKey: base64.StdEncoding.EncodeToString(n.PublicKey),
			RealAddr:  n.RealAddr,
			Networks:  n.Networks,
			Public:    n.Public,
			LastSeen:  n.LastSeen.Format(time.RFC3339),
			Hostname:  n.Hostname,
		}
	}

	for id, n := range s.networks {
		snap.Networks[fmt.Sprintf("%d", id)] = &snapshotNet{
			ID:       n.ID,
			Name:     n.Name,
			JoinRule: n.JoinRule,
			Token:    n.Token,
			Members:  n.Members,
			Created:  n.Created.Format(time.RFC3339),
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

		select {
		case <-s.done:
			return
		case <-time.After(3 * time.Second):
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
		if msgType != "replication_snapshot" {
			slog.Warn("standby: unexpected message type", "type", msgType)
			continue
		}

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
		}
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
			ID:       n.ID,
			Name:     n.Name,
			JoinRule: n.JoinRule,
			Token:    n.Token,
			Members:  n.Members,
			Created:  created,
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

	// Persist to local disk for crash recovery
	s.save()

	return nil
}

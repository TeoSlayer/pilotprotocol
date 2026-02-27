package daemon

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/internal/fsutil"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// Handshake message types
const (
	HandshakeRequest = "handshake_request"
	HandshakeAccept  = "handshake_accept"
	HandshakeReject  = "handshake_reject"
	HandshakeRevoke  = "handshake_revoke"
)

// HandshakeMsg is the wire format for handshake protocol messages on port 444.
type HandshakeMsg struct {
	Type          string `json:"type"`
	NodeID        uint32 `json:"node_id"`
	PublicKey     string `json:"public_key"`    // base64 Ed25519 public key
	Justification string `json:"justification"` // why the sender wants to connect
	Signature     string `json:"signature"`     // Ed25519 sig over "handshake:<node_id>:<peer_id>"
	Reason        string `json:"reason"`        // rejection reason
	Timestamp     int64  `json:"timestamp"`
}

// TrustRecord holds information about a trusted peer.
type TrustRecord struct {
	NodeID     uint32
	PublicKey  string // base64 Ed25519 pubkey
	ApprovedAt time.Time
	Mutual     bool   // true if both sides initiated
	Network    uint16 // non-zero if trust is via network membership
}

// PendingHandshake is an unapproved incoming request.
type PendingHandshake struct {
	NodeID        uint32
	PublicKey     string
	Justification string
	ReceivedAt    time.Time
}

// Handshake timing constants
const (
	handshakeMaxAge       = 5 * time.Minute        // replay protection: max message age
	handshakeMaxFuture    = 30 * time.Second       // replay protection: max clock skew
	handshakeReapInterval = 5 * time.Minute        // how often to reap stale replay entries
	handshakeRecvTimeout  = 10 * time.Second       // time to wait for handshake message
	handshakeCloseDelay   = 500 * time.Millisecond // delay before closing after send to let data flush
)

// HandshakeManager handles the trust handshake protocol on port 444.
type HandshakeManager struct {
	mu        sync.RWMutex
	daemon    *Daemon
	trusted   map[uint32]*TrustRecord      // approved peers
	pending   map[uint32]*PendingHandshake // incoming unapproved requests
	outgoing  map[uint32]bool              // nodes we've sent requests to
	storePath string                       // path to persist trust state (empty = no persistence)
	wg        sync.WaitGroup               // tracks background RPCs for clean shutdown
	reapStop  chan struct{}                // signals replay reaper to stop
	stopOnce  sync.Once                    // ensures reapStop is closed only once

	// Webhook
	webhook *WebhookClient

	// Replay protection
	replayMu  sync.Mutex
	replaySet map[[32]byte]time.Time // message hash → first seen
}

func NewHandshakeManager(d *Daemon) *HandshakeManager {
	hm := &HandshakeManager{
		daemon:    d,
		trusted:   make(map[uint32]*TrustRecord),
		pending:   make(map[uint32]*PendingHandshake),
		outgoing:  make(map[uint32]bool),
		replaySet: make(map[[32]byte]time.Time),
	}

	// Derive trust store path from identity path if available
	if d.config.IdentityPath != "" {
		dir := filepath.Dir(d.config.IdentityPath)
		hm.storePath = filepath.Join(dir, "trust.json")
		hm.loadTrust()
	}

	return hm
}

// SetWebhook configures the webhook client for event notifications.
func (hm *HandshakeManager) SetWebhook(wc *WebhookClient) {
	hm.webhook = wc
}

// Stop waits for all background RPCs to finish and stops the replay reaper.
func (hm *HandshakeManager) Stop() {
	hm.stopOnce.Do(func() {
		if hm.reapStop != nil {
			close(hm.reapStop)
		}
	})
	hm.wg.Wait()
}

// goRPC launches a tracked background goroutine.
func (hm *HandshakeManager) goRPC(fn func()) {
	hm.wg.Add(1)
	go func() {
		defer hm.wg.Done()
		fn()
	}()
}

// --- Trust persistence ---

type trustSnapshot struct {
	Trusted []trustSnapshotEntry   `json:"trusted"`
	Pending []pendingSnapshotEntry `json:"pending,omitempty"`
}

type trustSnapshotEntry struct {
	NodeID     uint32 `json:"node_id"`
	PublicKey  string `json:"public_key"`
	ApprovedAt string `json:"approved_at"`
	Mutual     bool   `json:"mutual"`
	Network    uint16 `json:"network,omitempty"`
}

type pendingSnapshotEntry struct {
	NodeID        uint32 `json:"node_id"`
	PublicKey     string `json:"public_key,omitempty"`
	Justification string `json:"justification,omitempty"`
	ReceivedAt    string `json:"received_at"`
}

func (hm *HandshakeManager) saveTrust() {
	if hm.storePath == "" {
		return
	}

	snap := trustSnapshot{}
	for _, r := range hm.trusted {
		snap.Trusted = append(snap.Trusted, trustSnapshotEntry{
			NodeID:     r.NodeID,
			PublicKey:  r.PublicKey,
			ApprovedAt: r.ApprovedAt.Format(time.RFC3339),
			Mutual:     r.Mutual,
			Network:    r.Network,
		})
	}
	for _, p := range hm.pending {
		snap.Pending = append(snap.Pending, pendingSnapshotEntry{
			NodeID:        p.NodeID,
			PublicKey:     p.PublicKey,
			Justification: p.Justification,
			ReceivedAt:    p.ReceivedAt.Format(time.RFC3339),
		})
	}

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		slog.Error("save trust state", "err", err)
		return
	}

	dir := filepath.Dir(hm.storePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		slog.Error("create trust state directory", "dir", dir, "err", err)
		return
	}

	if err := fsutil.AtomicWrite(hm.storePath, data); err != nil {
		slog.Error("write trust state", "err", err)
		return
	}
	slog.Debug("trust state saved", "peers", len(hm.trusted), "pending", len(hm.pending))
}

func (hm *HandshakeManager) loadTrust() {
	if hm.storePath == "" {
		return
	}

	data, err := os.ReadFile(hm.storePath)
	if err != nil {
		return // no file yet
	}

	var snap trustSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		slog.Warn("load trust state", "err", err)
		return
	}

	for _, e := range snap.Trusted {
		approved, _ := time.Parse(time.RFC3339, e.ApprovedAt)
		hm.trusted[e.NodeID] = &TrustRecord{
			NodeID:     e.NodeID,
			PublicKey:  e.PublicKey,
			ApprovedAt: approved,
			Mutual:     e.Mutual,
			Network:    e.Network,
		}
	}
	for _, e := range snap.Pending {
		received, _ := time.Parse(time.RFC3339, e.ReceivedAt)
		hm.pending[e.NodeID] = &PendingHandshake{
			NodeID:        e.NodeID,
			PublicKey:     e.PublicKey,
			Justification: e.Justification,
			ReceivedAt:    received,
		}
	}
	slog.Info("loaded trust state", "peers", len(hm.trusted), "pending", len(hm.pending))
}

// Start binds port 444 and begins handling handshake connections.
func (hm *HandshakeManager) Start() error {
	ln, err := hm.daemon.ports.Bind(protocol.PortHandshake)
	if err != nil {
		return err
	}

	go func() {
		for conn := range ln.AcceptCh {
			go hm.handleConnection(conn)
		}
	}()

	// Start periodic replay set reaper
	hm.reapStop = make(chan struct{})
	go func() {
		ticker := time.NewTicker(handshakeReapInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				hm.reapReplay()
			case <-hm.reapStop:
				return
			}
		}
	}()

	slog.Info("handshake service listening", "port", protocol.PortHandshake)
	return nil
}

// handleConnection processes a single handshake stream connection.
func (hm *HandshakeManager) handleConnection(conn *Connection) {
	// Read the handshake message from RecvBuf
	select {
	case data, ok := <-conn.RecvBuf:
		if !ok {
			return
		}
		var msg HandshakeMsg
		if err := json.Unmarshal(data, &msg); err != nil {
			slog.Error("invalid handshake message", "remote_addr", conn.RemoteAddr, "error", err)
			return
		}
		hm.processMessage(conn, &msg)
	case <-time.After(handshakeRecvTimeout):
		slog.Warn("handshake timeout waiting for message", "remote_addr", conn.RemoteAddr)
	}
}

// processMessage handles an incoming handshake message.
func (hm *HandshakeManager) processMessage(conn *Connection, msg *HandshakeMsg) {
	// Timestamp validation
	now := time.Now()
	msgTime := time.Unix(msg.Timestamp, 0)
	if now.Sub(msgTime) > handshakeMaxAge {
		slog.Warn("handshake message too old", "peer_node_id", msg.NodeID, "age", now.Sub(msgTime))
		return
	}
	if msgTime.Sub(now) > handshakeMaxFuture {
		slog.Warn("handshake message from future", "peer_node_id", msg.NodeID, "skew", msgTime.Sub(now))
		return
	}

	// Replay detection: hash the message and check set
	msgBytes, _ := json.Marshal(msg)
	msgHash := sha256.Sum256(msgBytes)
	hm.replayMu.Lock()
	if _, seen := hm.replaySet[msgHash]; seen {
		hm.replayMu.Unlock()
		slog.Warn("handshake replay detected", "peer_node_id", msg.NodeID)
		return
	}
	hm.replaySet[msgHash] = now
	hm.replayMu.Unlock()

	// M12 fix: verify P2P signature if the sender provides a public key
	if msg.PublicKey != "" {
		if msg.Signature == "" {
			slog.Warn("handshake: missing signature from authenticated node", "peer_node_id", msg.NodeID)
			return
		}
		challenge := fmt.Sprintf("handshake:%d:%d", msg.NodeID, hm.daemon.NodeID())
		pubKeyBytes, err := base64.StdEncoding.DecodeString(msg.PublicKey)
		if err != nil {
			slog.Warn("handshake: invalid public key encoding", "peer_node_id", msg.NodeID, "err", err)
			return
		}
		sigBytes, err := base64.StdEncoding.DecodeString(msg.Signature)
		if err != nil {
			slog.Warn("handshake: invalid signature encoding", "peer_node_id", msg.NodeID, "err", err)
			return
		}
		if !crypto.Verify(pubKeyBytes, []byte(challenge), sigBytes) {
			slog.Warn("handshake: P2P signature verification failed", "peer_node_id", msg.NodeID)
			return
		}
	}

	switch msg.Type {
	case HandshakeRequest:
		hm.handleRequest(conn, msg)
	case HandshakeAccept:
		hm.handleAccept(msg)
	case HandshakeReject:
		hm.handleRejectMsg(msg)
	case HandshakeRevoke:
		hm.handleRevokeMsg(msg)
	}
}

// reapReplay removes expired entries from the replay set.
func (hm *HandshakeManager) reapReplay() {
	hm.replayMu.Lock()
	defer hm.replayMu.Unlock()
	threshold := time.Now().Add(-2 * handshakeMaxAge)
	for hash, seen := range hm.replaySet {
		if seen.Before(threshold) {
			delete(hm.replaySet, hash)
		}
	}
}

// handleRequest processes an incoming handshake request.
func (hm *HandshakeManager) handleRequest(conn *Connection, msg *HandshakeMsg) {
	peerNodeID := msg.NodeID
	slog.Info("handshake request received", "peer_node_id", peerNodeID, "justification", msg.Justification)
	hm.webhook.Emit("handshake.received", map[string]interface{}{
		"peer_node_id": peerNodeID, "justification": msg.Justification,
	})

	hm.mu.Lock()
	defer hm.mu.Unlock()

	// Already trusted?
	if _, ok := hm.trusted[peerNodeID]; ok {
		slog.Debug("node already trusted", "peer_node_id", peerNodeID)
		hm.sendAcceptLocked(peerNodeID)
		return
	}

	// Check if we have an outgoing request to this peer (mutual handshake)
	if hm.outgoing[peerNodeID] {
		// Mutual! Auto-approve
		delete(hm.outgoing, peerNodeID)
		hm.trusted[peerNodeID] = &TrustRecord{
			NodeID:     peerNodeID,
			PublicKey:  msg.PublicKey,
			ApprovedAt: time.Now(),
			Mutual:     true,
		}
		slog.Info("mutual handshake auto-approved", "peer_node_id", peerNodeID)
		hm.webhook.Emit("handshake.auto_approved", map[string]interface{}{
			"peer_node_id": peerNodeID, "reason": "mutual",
		})
		hm.saveTrust()
		hm.sendAcceptLocked(peerNodeID)
		// Report trust to registry
		if hm.daemon.regConn != nil {
			hm.goRPC(func() { hm.daemon.regConn.ReportTrust(hm.daemon.NodeID(), peerNodeID) })
		}
		return
	}

	// Check if peers are on the same network (network trust)
	if hm.sameNetwork(peerNodeID) {
		hm.trusted[peerNodeID] = &TrustRecord{
			NodeID:     peerNodeID,
			PublicKey:  msg.PublicKey,
			ApprovedAt: time.Now(),
			Network:    hm.sharedNetwork(peerNodeID),
		}
		slog.Info("same network handshake auto-approved", "peer_node_id", peerNodeID)
		hm.webhook.Emit("handshake.auto_approved", map[string]interface{}{
			"peer_node_id": peerNodeID, "reason": "same_network",
		})
		hm.saveTrust()
		hm.sendAcceptLocked(peerNodeID)
		// Report trust to registry
		if hm.daemon.regConn != nil {
			hm.goRPC(func() { hm.daemon.regConn.ReportTrust(hm.daemon.NodeID(), peerNodeID) })
		}
		return
	}

	// Store as pending
	hm.pending[peerNodeID] = &PendingHandshake{
		NodeID:        peerNodeID,
		PublicKey:     msg.PublicKey,
		Justification: msg.Justification,
		ReceivedAt:    time.Now(),
	}
	hm.saveTrust()
	slog.Info("handshake request pending approval", "peer_node_id", peerNodeID)
	hm.webhook.Emit("handshake.pending", map[string]interface{}{
		"peer_node_id": peerNodeID, "justification": msg.Justification,
	})
}

// handleAccept processes a handshake acceptance from a peer.
func (hm *HandshakeManager) handleAccept(msg *HandshakeMsg) {
	peerNodeID := msg.NodeID
	slog.Info("handshake accepted by peer", "peer_node_id", peerNodeID)

	hm.mu.Lock()
	defer hm.mu.Unlock()

	delete(hm.outgoing, peerNodeID)
	hm.trusted[peerNodeID] = &TrustRecord{
		NodeID:     peerNodeID,
		PublicKey:  msg.PublicKey,
		ApprovedAt: time.Now(),
		Mutual:     true,
	}
	hm.saveTrust()

	// Report trust to registry
	if hm.daemon.regConn != nil {
		hm.goRPC(func() { hm.daemon.regConn.ReportTrust(hm.daemon.NodeID(), peerNodeID) })
	}
}

// handleRejectMsg processes a handshake rejection from a peer.
func (hm *HandshakeManager) handleRejectMsg(msg *HandshakeMsg) {
	slog.Warn("handshake rejected by peer", "peer_node_id", msg.NodeID, "reason", msg.Reason)

	hm.mu.Lock()
	delete(hm.outgoing, msg.NodeID)
	hm.mu.Unlock()
}

// SendRequest sends a handshake request to a remote node.
// First tries direct connection (port 444). If that fails (e.g. private node),
// falls back to relaying through the registry.
func (hm *HandshakeManager) SendRequest(peerNodeID uint32, justification string) error {
	hm.mu.Lock()
	if _, ok := hm.trusted[peerNodeID]; ok {
		hm.mu.Unlock()
		return nil // already trusted
	}
	hm.outgoing[peerNodeID] = true
	hm.mu.Unlock()

	pubKeyStr := ""
	if hm.daemon.identity != nil {
		pubKeyStr = crypto.EncodePublicKey(hm.daemon.identity.PublicKey)
	}

	msg := HandshakeMsg{
		Type:          HandshakeRequest,
		NodeID:        hm.daemon.NodeID(),
		PublicKey:     pubKeyStr,
		Justification: justification,
		Timestamp:     time.Now().Unix(),
	}

	// Try direct connection first
	err := hm.sendMessage(peerNodeID, &msg)
	if err == nil {
		return nil
	}

	// Direct failed (likely private node) — relay through registry
	slog.Info("direct handshake failed, relaying via registry", "peer_node_id", peerNodeID, "error", err)
	if hm.daemon.regConn != nil {
		sig := hm.signHandshakeChallenge(fmt.Sprintf("handshake:%d:%d", hm.daemon.NodeID(), peerNodeID))
		_, relayErr := hm.daemon.regConn.RequestHandshake(hm.daemon.NodeID(), peerNodeID, justification, sig)
		if relayErr != nil {
			return fmt.Errorf("handshake relay: %w", relayErr)
		}
		slog.Info("handshake relayed via registry", "peer_node_id", peerNodeID)
		return nil
	}
	return err
}

// processRelayedRequest handles a handshake request received via registry relay.
func (hm *HandshakeManager) processRelayedRequest(fromNodeID uint32, justification string) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	// Already trusted?
	if _, ok := hm.trusted[fromNodeID]; ok {
		slog.Debug("relayed request from already-trusted node", "peer_node_id", fromNodeID)
		// Respond via registry that we accept
		if hm.daemon.regConn != nil {
			nodeID, peerID := hm.daemon.NodeID(), fromNodeID
			sig := hm.signHandshakeChallenge(fmt.Sprintf("respond:%d:%d", nodeID, peerID))
			hm.goRPC(func() { hm.daemon.regConn.RespondHandshake(nodeID, peerID, true, sig) })
		}
		return
	}

	// Check if we have an outgoing request to this peer (mutual handshake)
	if hm.outgoing[fromNodeID] {
		delete(hm.outgoing, fromNodeID)
		hm.trusted[fromNodeID] = &TrustRecord{
			NodeID:     fromNodeID,
			ApprovedAt: time.Now(),
			Mutual:     true,
		}
		slog.Info("mutual relayed handshake auto-approved", "peer_node_id", fromNodeID)
		hm.saveTrust()
		// Respond via registry and backfill public key
		if hm.daemon.regConn != nil {
			nodeID, peerID := hm.daemon.NodeID(), fromNodeID
			sig := hm.signHandshakeChallenge(fmt.Sprintf("respond:%d:%d", nodeID, peerID))
			hm.goRPC(func() {
				hm.daemon.regConn.RespondHandshake(nodeID, peerID, true, sig)
				hm.backfillPeerKey(peerID)
			})
		}
		return
	}

	// Store as pending (for manual approval via pilotctl approve)
	hm.pending[fromNodeID] = &PendingHandshake{
		NodeID:        fromNodeID,
		Justification: justification,
		ReceivedAt:    time.Now(),
	}
	hm.saveTrust()
	slog.Info("relayed handshake request pending approval", "from_node_id", fromNodeID, "justification", justification)
}

// processRelayedApproval handles a handshake approval received via registry relay.
// This is called when the peer approved our outgoing request and the acceptance
// was relayed back through the registry (because direct dial to port 444 failed).
func (hm *HandshakeManager) processRelayedApproval(fromNodeID uint32) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	// Already trusted? Nothing to do.
	if _, ok := hm.trusted[fromNodeID]; ok {
		slog.Debug("relayed approval from already-trusted node", "peer_node_id", fromNodeID)
		return
	}

	delete(hm.outgoing, fromNodeID)
	hm.trusted[fromNodeID] = &TrustRecord{
		NodeID:     fromNodeID,
		ApprovedAt: time.Now(),
		Mutual:     true,
	}
	hm.saveTrust()
	slog.Info("trust established via relayed approval", "peer_node_id", fromNodeID)

	// Backfill public key from registry
	if hm.daemon.regConn != nil {
		peerID := fromNodeID
		hm.goRPC(func() { hm.backfillPeerKey(peerID) })
	}
}

// backfillPeerKey fetches a peer's public key from the registry and updates
// the trust record. Called asynchronously after relay-based trust establishment,
// where the P2P public key exchange didn't happen.
func (hm *HandshakeManager) backfillPeerKey(peerNodeID uint32) {
	if hm.daemon.regConn == nil {
		return
	}
	resp, err := hm.daemon.regConn.Lookup(peerNodeID)
	if err != nil {
		slog.Debug("backfill peer key lookup failed", "peer_node_id", peerNodeID, "error", err)
		return
	}
	pubKeyB64, _ := resp["public_key"].(string)
	if pubKeyB64 == "" {
		return
	}

	hm.mu.Lock()
	defer hm.mu.Unlock()
	if rec, ok := hm.trusted[peerNodeID]; ok && rec.PublicKey == "" {
		rec.PublicKey = pubKeyB64
		hm.saveTrust()
		slog.Debug("backfilled peer public key", "peer_node_id", peerNodeID)
	}
}

// processRelayedRejection handles a handshake rejection received via registry relay.
func (hm *HandshakeManager) processRelayedRejection(fromNodeID uint32) {
	hm.mu.Lock()
	delete(hm.outgoing, fromNodeID)
	hm.mu.Unlock()
	slog.Info("handshake rejected via relay", "peer_node_id", fromNodeID)
}

// ApproveHandshake approves a pending handshake request.
func (hm *HandshakeManager) ApproveHandshake(peerNodeID uint32) error {
	hm.mu.Lock()
	req, ok := hm.pending[peerNodeID]
	if !ok {
		hm.mu.Unlock()
		return nil
	}
	delete(hm.pending, peerNodeID)
	hm.trusted[peerNodeID] = &TrustRecord{
		NodeID:     peerNodeID,
		PublicKey:  req.PublicKey,
		ApprovedAt: time.Now(),
	}
	hm.saveTrust()
	hm.mu.Unlock()

	slog.Info("handshake approved", "peer_node_id", peerNodeID)
	hm.webhook.Emit("handshake.approved", map[string]interface{}{
		"peer_node_id": peerNodeID,
	})

	// Report trust to registry (creates the trust pair for resolve authorization)
	if hm.daemon.regConn != nil {
		nodeID := hm.daemon.NodeID()
		sig := hm.signHandshakeChallenge(fmt.Sprintf("respond:%d:%d", nodeID, peerNodeID))
		hm.goRPC(func() {
			hm.daemon.regConn.ReportTrust(nodeID, peerNodeID)
			// Also respond via registry relay in case the request was relayed
			hm.daemon.regConn.RespondHandshake(nodeID, peerNodeID, true, sig)
		})
	}

	// Try to send accept directly (may fail if peer is private, that's OK)
	hm.sendAccept(peerNodeID)
	return nil
}

// RejectHandshake rejects a pending handshake request.
func (hm *HandshakeManager) RejectHandshake(peerNodeID uint32, reason string) error {
	hm.mu.Lock()
	delete(hm.pending, peerNodeID)
	hm.saveTrust()
	hm.mu.Unlock()

	slog.Info("handshake rejected", "peer_node_id", peerNodeID, "reason", reason)
	hm.webhook.Emit("handshake.rejected", map[string]interface{}{
		"peer_node_id": peerNodeID, "reason": reason,
	})

	// Relay rejection via registry so the requester learns about it even behind NAT
	if hm.daemon.regConn != nil {
		nodeID := hm.daemon.NodeID()
		sig := hm.signHandshakeChallenge(fmt.Sprintf("respond:%d:%d", nodeID, peerNodeID))
		hm.goRPC(func() {
			hm.daemon.regConn.RespondHandshake(nodeID, peerNodeID, false, sig)
		})
	}

	// Also try direct notification (best-effort)
	pubKeyStr := ""
	if hm.daemon.identity != nil {
		pubKeyStr = crypto.EncodePublicKey(hm.daemon.identity.PublicKey)
	}

	msg := HandshakeMsg{
		Type:      HandshakeReject,
		NodeID:    hm.daemon.NodeID(),
		PublicKey: pubKeyStr,
		Reason:    reason,
		Timestamp: time.Now().Unix(),
	}

	hm.sendMessage(peerNodeID, &msg) // best-effort, ignore error
	return nil
}

// RevokeTrust removes a peer from the trusted set and notifies both the
// registry and the peer itself.  Either party can revoke unilaterally.
func (hm *HandshakeManager) RevokeTrust(peerNodeID uint32) error {
	hm.mu.Lock()
	_, wasTrusted := hm.trusted[peerNodeID]
	_, wasPending := hm.pending[peerNodeID]
	delete(hm.trusted, peerNodeID)
	delete(hm.pending, peerNodeID)
	delete(hm.outgoing, peerNodeID)
	if wasTrusted || wasPending {
		hm.saveTrust()
	}
	hm.mu.Unlock()

	if !wasTrusted {
		return fmt.Errorf("node %d was not trusted", peerNodeID)
	}

	slog.Info("trust revoked", "peer_node_id", peerNodeID)
	hm.webhook.Emit("trust.revoked", map[string]interface{}{
		"peer_node_id": peerNodeID,
	})

	// Tear down the tunnel to the revoked peer immediately
	hm.daemon.tunnels.RemovePeer(peerNodeID)

	// Revoke the trust pair at the registry so resolve is blocked again
	if hm.daemon.regConn != nil {
		hm.goRPC(func() { hm.daemon.regConn.RevokeTrust(hm.daemon.NodeID(), peerNodeID) })
	}

	// Best-effort: notify the peer so they can remove us from their trusted set
	hm.goRPC(func() {
		pubKeyStr := ""
		if hm.daemon.identity != nil {
			pubKeyStr = crypto.EncodePublicKey(hm.daemon.identity.PublicKey)
		}
		msg := HandshakeMsg{
			Type:      HandshakeRevoke,
			NodeID:    hm.daemon.NodeID(),
			PublicKey: pubKeyStr,
			Reason:    "trust revoked",
			Timestamp: time.Now().Unix(),
		}
		hm.sendMessage(peerNodeID, &msg)
	})

	return nil
}

// handleRevokeMsg processes an incoming trust revocation from a peer.
func (hm *HandshakeManager) handleRevokeMsg(msg *HandshakeMsg) {
	peerNodeID := msg.NodeID
	slog.Info("trust revoked by peer", "peer_node_id", peerNodeID)
	hm.webhook.Emit("trust.revoked_by_peer", map[string]interface{}{
		"peer_node_id": peerNodeID,
	})

	hm.mu.Lock()
	_, wasTrusted := hm.trusted[peerNodeID]
	_, wasPending := hm.pending[peerNodeID]
	delete(hm.trusted, peerNodeID)
	delete(hm.pending, peerNodeID)
	delete(hm.outgoing, peerNodeID)
	if wasTrusted || wasPending {
		hm.saveTrust()
	}
	hm.mu.Unlock()

	// Tear down the tunnel to the revoked peer immediately
	hm.daemon.tunnels.RemovePeer(peerNodeID)

	// Also remove from registry (in case peer's revoke_trust didn't reach registry)
	if wasTrusted && hm.daemon.regConn != nil {
		hm.goRPC(func() { hm.daemon.regConn.RevokeTrust(hm.daemon.NodeID(), peerNodeID) })
	}
}

// IsTrusted returns whether a peer has been approved.
func (hm *HandshakeManager) IsTrusted(nodeID uint32) bool {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	_, ok := hm.trusted[nodeID]
	return ok
}

// TrustedPeers returns all trusted peers.
func (hm *HandshakeManager) TrustedPeers() []TrustRecord {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	var list []TrustRecord
	for _, r := range hm.trusted {
		list = append(list, *r)
	}
	return list
}

// PendingRequests returns all pending handshake requests.
func (hm *HandshakeManager) PendingRequests() []PendingHandshake {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	var list []PendingHandshake
	for _, r := range hm.pending {
		list = append(list, *r)
	}
	return list
}

// sendAcceptLocked sends an accept message (caller must hold hm.mu).
func (hm *HandshakeManager) sendAcceptLocked(peerNodeID uint32) {
	hm.goRPC(func() {
		hm.sendAccept(peerNodeID)
	})
}

func (hm *HandshakeManager) sendAccept(peerNodeID uint32) error {
	pubKeyStr := ""
	if hm.daemon.identity != nil {
		pubKeyStr = crypto.EncodePublicKey(hm.daemon.identity.PublicKey)
	}
	msg := HandshakeMsg{
		Type:      HandshakeAccept,
		NodeID:    hm.daemon.NodeID(),
		PublicKey: pubKeyStr,
		Timestamp: time.Now().Unix(),
	}
	err := hm.sendMessage(peerNodeID, &msg)
	if err != nil {
		// Direct dial failed (peer may be private) — relay acceptance through registry
		slog.Info("direct accept failed, relaying via registry", "peer_node_id", peerNodeID, "error", err)
		if hm.daemon.regConn != nil {
			nodeID := hm.daemon.NodeID()
			sig := hm.signHandshakeChallenge(fmt.Sprintf("respond:%d:%d", nodeID, peerNodeID))
			_, relayErr := hm.daemon.regConn.RespondHandshake(nodeID, peerNodeID, true, sig)
			if relayErr != nil {
				return fmt.Errorf("accept relay: %w", relayErr)
			}
			return nil
		}
	}
	return err
}

// signHandshakeChallenge signs a handshake challenge string with the daemon's identity (M12 fix).
// Returns base64-encoded signature, or empty string if identity is unavailable.
func (hm *HandshakeManager) signHandshakeChallenge(challenge string) string {
	if hm.daemon.identity == nil {
		return ""
	}
	sig := hm.daemon.identity.Sign([]byte(challenge))
	return base64.StdEncoding.EncodeToString(sig)
}

// sendMessage dials port 444 on the peer and sends a JSON message.
// M12 fix: signs the message with the daemon identity before sending.
func (hm *HandshakeManager) sendMessage(peerNodeID uint32, msg *HandshakeMsg) error {
	// M12 fix: populate signature for P2P authentication
	if msg.Signature == "" {
		msg.Signature = hm.signHandshakeChallenge(fmt.Sprintf("handshake:%d:%d", msg.NodeID, peerNodeID))
	}

	peerAddr := protocol.Addr{Network: 0, Node: peerNodeID}
	conn, err := hm.daemon.DialConnection(peerAddr, protocol.PortHandshake)
	if err != nil {
		return err
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	if err := hm.daemon.SendData(conn, data); err != nil {
		hm.daemon.CloseConnection(conn)
		return fmt.Errorf("send handshake data: %w", err)
	}

	// Close after brief delay to let the data flush
	hm.goRPC(func() {
		time.Sleep(handshakeCloseDelay)
		hm.daemon.CloseConnection(conn)
	})

	return nil
}

// sameNetwork checks if the local node and peerNodeID share any non-backbone network.
func (hm *HandshakeManager) sameNetwork(peerNodeID uint32) bool {
	return hm.sharedNetwork(peerNodeID) != 0
}

// sharedNetwork returns the first shared non-backbone network ID, or 0 if none.
func (hm *HandshakeManager) sharedNetwork(peerNodeID uint32) uint16 {
	// Look up our networks and the peer's networks via registry
	if hm.daemon.regConn == nil {
		return 0
	}

	myResp, err := hm.daemon.regConn.Lookup(hm.daemon.NodeID())
	if err != nil {
		return 0
	}
	peerResp, err := hm.daemon.regConn.Lookup(peerNodeID)
	if err != nil {
		return 0
	}

	myNets, _ := myResp["networks"].([]interface{})
	peerNets, _ := peerResp["networks"].([]interface{})

	for _, mn := range myNets {
		mnf, ok := mn.(float64)
		if !ok {
			continue
		}
		myNetID := uint16(mnf)
		if myNetID == 0 {
			continue // skip backbone
		}
		for _, pn := range peerNets {
			pnf, ok := pn.(float64)
			if !ok {
				continue
			}
			peerNetID := uint16(pnf)
			if myNetID == peerNetID {
				return myNetID
			}
		}
	}
	return 0
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

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
	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// Handshake message types.
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

// Handshake timing constants.
const (
	handshakeMaxAge       = 5 * time.Minute        // replay protection: max message age
	handshakeMaxFuture    = 30 * time.Second       // replay protection: max clock skew
	handshakeReapInterval = 5 * time.Minute        // how often to reap stale replay entries
	handshakeRecvTimeout  = 10 * time.Second       // time to wait for handshake message
	handshakeCloseDelay   = 500 * time.Millisecond // delay before closing after send to let data flush
	maxReplaySetEntries   = 8192                   // cap replay set to prevent unbounded growth between reaps
	maxPendingHandshakes  = 256                    // cap pending (unapproved) handshake requests
)

// Manager handles the trust handshake protocol on port 444.
type Manager struct {
	mu        sync.RWMutex
	rt        Runtime
	ln        coreapi.Listener             // bound on PortHandshake; closed by Stop
	trusted   map[uint32]*TrustRecord      // approved peers
	pending   map[uint32]*PendingHandshake // incoming unapproved requests
	outgoing  map[uint32]time.Time         // nodes we've sent requests to → sent-at (for TTL reap)
	revoked   map[uint32]time.Time         // peer → cooldown-until (blocks stale relayed approvals)
	storePath string                       // path to persist trust state (empty = no persistence)
	stopping  bool                         // set under mu.Lock() before wg.Wait() in Stop
	wg        sync.WaitGroup               // tracks background RPCs for clean shutdown
	reapStop  chan struct{}                // signals replay reaper to stop
	stopOnce  sync.Once                    // ensures reapStop is closed only once

	// Replay protection
	replayMu  sync.Mutex
	replaySet map[[32]byte]time.Time // message hash → first seen

	// WaitForTrust notification: per-node list of channels closed when trust
	// transitions to granted. Separate mu from hm.mu (always taken AFTER hm.mu)
	// so that markTrustedLocked can fire notifications while holding hm.mu.
	trustWaitersMu sync.Mutex
	trustWaiters   map[uint32][]chan struct{}
}

// NewManager constructs a Manager bound to the given Runtime. Loads
// persisted trust state from disk if the runtime exposes an identity
// path; otherwise the manager is in-memory only.
func NewManager(rt Runtime) *Manager {
	hm := &Manager{
		rt:           rt,
		trusted:      make(map[uint32]*TrustRecord),
		pending:      make(map[uint32]*PendingHandshake),
		outgoing:     make(map[uint32]time.Time),
		revoked:      make(map[uint32]time.Time),
		replaySet:    make(map[[32]byte]time.Time),
		trustWaiters: make(map[uint32][]chan struct{}),
	}

	if path := rt.IdentityPath(); path != "" {
		dir := filepath.Dir(path)
		hm.storePath = filepath.Join(dir, "trust.json")
		hm.loadTrust()
	}

	return hm
}

// Stop waits for all background RPCs to finish and stops the replay reaper.
func (hm *Manager) Stop() {
	// Mark stopping under mu so goRPC cannot race wg.Add vs wg.Wait.
	// Any goRPC that holds mu.RLock() and sees stopping=false has already
	// called wg.Add(1), so Wait() will correctly count it.
	hm.mu.Lock()
	hm.stopping = true
	hm.mu.Unlock()

	hm.stopOnce.Do(func() {
		if hm.reapStop != nil {
			close(hm.reapStop)
		}
	})
	hm.wg.Wait()
}

// goRPC launches a tracked background goroutine.
// It takes mu.RLock() to atomically check stopping and call wg.Add(1) so
// that Stop()'s wg.Wait() never misses an in-flight goroutine.
func (hm *Manager) goRPC(fn func()) {
	hm.mu.RLock()
	if hm.stopping {
		hm.mu.RUnlock()
		return
	}
	hm.wg.Add(1)
	hm.mu.RUnlock()
	go func() {
		defer hm.wg.Done()
		fn()
	}()
}

// goRPCLocked is like goRPC but must be called while hm.mu is write-locked.
// Checks stopping without re-acquiring the lock to avoid same-goroutine deadlock.
func (hm *Manager) goRPCLocked(fn func()) {
	if hm.stopping {
		return
	}
	hm.wg.Add(1)
	go func() {
		defer hm.wg.Done()
		fn()
	}()
}

// markTrustedLocked sets hm.trusted[nodeID] = rec and wakes any goroutines
// blocked in WaitForTrust for that node. Caller MUST hold hm.mu.
//
// All trust-grant sites in this package funnel through here so WaitForTrust
// fires exactly once per transition. Notifying under hm.mu is safe — the
// channel close is non-blocking and trustWaitersMu is always taken AFTER
// hm.mu in this codebase.
func (hm *Manager) markTrustedLocked(nodeID uint32, rec *TrustRecord) {
	hm.trusted[nodeID] = rec
	hm.trustWaitersMu.Lock()
	waiters := hm.trustWaiters[nodeID]
	delete(hm.trustWaiters, nodeID)
	hm.trustWaitersMu.Unlock()
	for _, ch := range waiters {
		close(ch)
	}
}

// WaitForTrust blocks until the given peer transitions to trusted, or the
// timeout elapses. Returns true if trust was granted within the window,
// false on timeout. The fast path (already trusted) is a single map lookup
// under hm.mu — no goroutine, no channel allocation.
//
// Self is always trusted: a daemon trivially trusts itself, and gating
// loopback operations behind a non-existent trust record would block
// pilotctl self-pings and any plugin operating against the local node.
func (hm *Manager) WaitForTrust(nodeID uint32, timeout time.Duration) bool {
	if nodeID == hm.rt.NodeID() {
		return true
	}
	hm.mu.RLock()
	_, alreadyTrusted := hm.trusted[nodeID]
	hm.mu.RUnlock()
	if alreadyTrusted {
		return true
	}

	ch := make(chan struct{})
	hm.trustWaitersMu.Lock()
	hm.trustWaiters[nodeID] = append(hm.trustWaiters[nodeID], ch)
	hm.trustWaitersMu.Unlock()

	// Re-check after registering: closes the race window where trust was
	// granted between the first lookup and waiter registration.
	hm.mu.RLock()
	_, trustedNow := hm.trusted[nodeID]
	hm.mu.RUnlock()
	if trustedNow {
		hm.removeWaiter(nodeID, ch)
		return true
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ch:
		return true
	case <-timer.C:
		hm.removeWaiter(nodeID, ch)
		return false
	}
}

// removeWaiter drops a specific channel from the per-node waiters slice.
// Used on the timeout path and on the post-registration re-check fast path.
func (hm *Manager) removeWaiter(nodeID uint32, target chan struct{}) {
	hm.trustWaitersMu.Lock()
	defer hm.trustWaitersMu.Unlock()
	waiters := hm.trustWaiters[nodeID]
	for i, ch := range waiters {
		if ch == target {
			hm.trustWaiters[nodeID] = append(waiters[:i], waiters[i+1:]...)
			if len(hm.trustWaiters[nodeID]) == 0 {
				delete(hm.trustWaiters, nodeID)
			}
			return
		}
	}
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

func (hm *Manager) saveTrust() {
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

func (hm *Manager) loadTrust() {
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
func (hm *Manager) Start() error {
	ln, err := hm.rt.PortListener(protocol.PortHandshake)
	if err != nil {
		return err
	}
	hm.ln = ln

	go func() {
		for {
			stream, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go hm.handleConnection(stream)
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
				hm.reapOutgoingAndRevoked()
			case <-hm.reapStop:
				return
			}
		}
	}()

	slog.Info("handshake service listening", "port", protocol.PortHandshake)
	return nil
}

// handleConnection processes a single handshake stream connection.
//
// The handshake protocol is exactly one JSON message per connection; we do a
// single bounded Read rather than io.ReadAll so we return as soon as the
// message bytes land, without waiting for the sender to close the stream.
func (hm *Manager) handleConnection(stream coreapi.Stream) {
	const maxMsgSize = 64 * 1024

	type readResult struct {
		data []byte
		err  error
	}
	ch := make(chan readResult, 1)
	go func() {
		buf := make([]byte, maxMsgSize)
		n, err := stream.Read(buf)
		if err != nil {
			ch <- readResult{nil, err}
			return
		}
		ch <- readResult{buf[:n], nil}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			return
		}
		var msg HandshakeMsg
		if err := json.Unmarshal(res.data, &msg); err != nil {
			slog.Error("invalid handshake message", "remote_addr", stream.RemoteAddr(), "error", err)
			return
		}
		hm.processMessage(stream, &msg)
	case <-time.After(handshakeRecvTimeout):
		slog.Warn("handshake timeout waiting for message", "remote_addr", stream.RemoteAddr())
	}
}

// processMessage handles an incoming handshake message.
//
// On a successful (claimed pubkey == registry-registered pubkey) match
// we set registryBound = true and pass it to handleRequest. The
// trusted-agents auto-accept path requires that flag — without it,
// trusting a peer by node_id alone is unsafe (registry down or no
// record means we'd be relying on signature verification against a
// claimed pubkey that nothing has tied to the claimed node ID).
func (hm *Manager) processMessage(stream coreapi.Stream, msg *HandshakeMsg) {
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
	if len(hm.replaySet) >= maxReplaySetEntries {
		hm.replayMu.Unlock()
		slog.Warn("handshake replay set full, rejecting", "peer_node_id", msg.NodeID)
		return
	}
	hm.replaySet[msgHash] = now
	hm.replayMu.Unlock()

	// M12 fix: verify P2P signature if the sender provides a public key
	registryBound := false
	if msg.PublicKey != "" {
		if msg.Signature == "" {
			slog.Warn("handshake: missing signature from authenticated node", "peer_node_id", msg.NodeID)
			return
		}

		// M3 fix: verify claimed pubkey against registry-registered key
		verifyKey := msg.PublicKey
		if reg := hm.rt.Registry(); reg != nil {
			resp, err := reg.Lookup(msg.NodeID)
			if err == nil {
				if regPubKey, ok := resp["public_key"].(string); ok && regPubKey != "" {
					if regPubKey != msg.PublicKey {
						slog.Warn("handshake: pubkey mismatch with registry",
							"peer_node_id", msg.NodeID)
						return
					}
					verifyKey = regPubKey
					registryBound = true
				}
			}
		}

		challenge := fmt.Sprintf("handshake:%d:%d", msg.NodeID, hm.rt.NodeID())
		pubKeyBytes, err := base64.StdEncoding.DecodeString(verifyKey)
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
		hm.handleRequest(stream, msg, registryBound)
	case HandshakeAccept:
		hm.handleAccept(msg)
	case HandshakeReject:
		hm.handleRejectMsg(msg)
	case HandshakeRevoke:
		hm.handleRevokeMsg(msg)
	}
}

// reapReplay removes expired entries from the replay set.
func (hm *Manager) reapReplay() {
	hm.replayMu.Lock()
	defer hm.replayMu.Unlock()
	threshold := time.Now().Add(-2 * handshakeMaxAge)
	for hash, seen := range hm.replaySet {
		if seen.Before(threshold) {
			delete(hm.replaySet, hash)
		}
	}
}

// reapOutgoingAndRevoked evicts stale entries from the outgoing and revoked maps.
//
// outgoing: peers we sent a handshake request to but never heard back from.
// A peer that never responds (wrong address, dropped, ignore-listed) would
// otherwise hold a map entry forever. We evict after 2× handshakeMaxAge —
// long enough for any in-flight response to arrive.
//
// revoked: peers in post-revocation cooldown. The lazy-delete in handleRequest
// / handleRelayRequest only fires on the next *contact from that peer*, which
// may never happen. Proactive reaping prevents permanent accumulation.
func (hm *Manager) reapOutgoingAndRevoked() {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	now := time.Now()
	outgoingTTL := 2 * handshakeMaxAge
	for nodeID, sentAt := range hm.outgoing {
		if now.Sub(sentAt) > outgoingTTL {
			delete(hm.outgoing, nodeID)
		}
	}
	for nodeID, until := range hm.revoked {
		if now.After(until) {
			delete(hm.revoked, nodeID)
		}
	}
}

// handleRequest processes an incoming handshake request.
//
// registryBound is true iff processMessage confirmed the claimed
// (node_id, public_key) binding via a registry lookup that returned a
// non-empty pubkey matching the claimed one. It gates the trusted-
// agents auto-accept path; signature-only authentication is not
// enough to safely key on node_id.
func (hm *Manager) handleRequest(stream coreapi.Stream, msg *HandshakeMsg, registryBound bool) {
	_ = stream // reserved for future response-on-same-stream support
	peerNodeID := msg.NodeID
	slog.Info("handshake request received", "peer_node_id", peerNodeID, "justification", msg.Justification)
	hm.rt.PublishEvent("handshake.received", map[string]interface{}{
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
	if _, ok := hm.outgoing[peerNodeID]; ok {
		// Mutual! Auto-approve
		delete(hm.outgoing, peerNodeID)
		hm.markTrustedLocked(peerNodeID, &TrustRecord{
			NodeID:     peerNodeID,
			PublicKey:  msg.PublicKey,
			ApprovedAt: time.Now(),
			Mutual:     true,
		})
		slog.Info("mutual handshake auto-approved", "peer_node_id", peerNodeID)
		hm.rt.PublishEvent("handshake.auto_approved", map[string]interface{}{
			"peer_node_id": peerNodeID, "reason": "mutual",
		})
		hm.rt.PublishEvent("trust.changed", map[string]interface{}{
			"peer_node_id": peerNodeID, "state": "granted", "reason": "mutual",
		})
		hm.saveTrust()
		hm.sendAcceptLocked(peerNodeID)
		// Report trust to registry
		if reg := hm.rt.Registry(); reg != nil {
			selfID := hm.rt.NodeID()
			hm.goRPCLocked(func() { reg.ReportTrust(selfID, peerNodeID) })
		}
		return
	}

	// Check if peers are on the same network (network trust)
	if hm.sameNetwork(peerNodeID) {
		hm.markTrustedLocked(peerNodeID, &TrustRecord{
			NodeID:     peerNodeID,
			PublicKey:  msg.PublicKey,
			ApprovedAt: time.Now(),
			Network:    hm.sharedNetwork(peerNodeID),
		})
		slog.Info("same network handshake auto-approved", "peer_node_id", peerNodeID)
		hm.rt.PublishEvent("handshake.auto_approved", map[string]interface{}{
			"peer_node_id": peerNodeID, "reason": "same_network",
		})
		hm.rt.PublishEvent("trust.changed", map[string]interface{}{
			"peer_node_id": peerNodeID, "state": "granted", "reason": "same_network",
		})
		hm.saveTrust()
		hm.sendAcceptLocked(peerNodeID)
		// Report trust to registry
		if reg := hm.rt.Registry(); reg != nil {
			selfID := hm.rt.NodeID()
			hm.goRPCLocked(func() { reg.ReportTrust(selfID, peerNodeID) })
		}
		return
	}

	// Auto-approve when the peer is in the trusted-agents list AND the
	// registry confirmed the (node_id, public_key) binding. Without
	// registryBound a peer could claim any node ID with their own
	// pubkey, sign with their own key, pass signature verify, and slip
	// into auto-accept.
	if registryBound {
		// Trust gate via L10 TrustChecker. Nil → trust nothing.
		name, ok := hm.rt.IsTrusted(peerNodeID)
		if ok {
			hm.markTrustedLocked(peerNodeID, &TrustRecord{
				NodeID:     peerNodeID,
				PublicKey:  msg.PublicKey,
				ApprovedAt: time.Now(),
			})
			slog.Info("handshake auto-approved (trusted agent)",
				"peer_node_id", peerNodeID, "agent", name)
			hm.rt.PublishEvent("handshake.auto_approved", map[string]interface{}{
				"peer_node_id": peerNodeID, "reason": "trusted_agent", "agent": name,
			})
			hm.rt.PublishEvent("trust.changed", map[string]interface{}{
				"peer_node_id": peerNodeID, "state": "granted", "reason": "trusted_agent", "agent": name,
			})
			hm.saveTrust()
			hm.sendAcceptLocked(peerNodeID)
			if reg := hm.rt.Registry(); reg != nil {
				selfID := hm.rt.NodeID()
				hm.goRPCLocked(func() { reg.ReportTrust(selfID, peerNodeID) })
			}
			return
		}
	}

	// Auto-approve all requests when the daemon is configured to do so.
	if hm.rt.TrustAutoApprove() {
		hm.markTrustedLocked(peerNodeID, &TrustRecord{
			NodeID:     peerNodeID,
			PublicKey:  msg.PublicKey,
			ApprovedAt: time.Now(),
			Mutual:     false,
		})
		slog.Info("handshake auto-approved (trust-auto-approve enabled)", "peer_node_id", peerNodeID)
		hm.rt.PublishEvent("handshake.auto_approved", map[string]interface{}{
			"peer_node_id": peerNodeID, "reason": "auto_approve",
		})
		hm.rt.PublishEvent("trust.changed", map[string]interface{}{
			"peer_node_id": peerNodeID, "state": "granted", "reason": "auto_approve",
		})
		hm.saveTrust()
		hm.sendAcceptLocked(peerNodeID)
		if reg := hm.rt.Registry(); reg != nil {
			selfID := hm.rt.NodeID()
			hm.goRPCLocked(func() { reg.ReportTrust(selfID, peerNodeID) })
		}
		return
	}

	// Store as pending (cap to prevent unbounded growth from spam)
	if _, exists := hm.pending[peerNodeID]; !exists && len(hm.pending) >= maxPendingHandshakes {
		slog.Warn("pending handshake queue full, rejecting", "peer_node_id", peerNodeID)
		return
	}
	hm.pending[peerNodeID] = &PendingHandshake{
		NodeID:        peerNodeID,
		PublicKey:     msg.PublicKey,
		Justification: msg.Justification,
		ReceivedAt:    time.Now(),
	}
	hm.saveTrust()
	slog.Info("handshake request pending approval", "peer_node_id", peerNodeID)
	hm.rt.PublishEvent("handshake.pending", map[string]interface{}{
		"peer_node_id": peerNodeID, "justification": msg.Justification,
	})
}

// handleAccept processes a handshake acceptance from a peer.
func (hm *Manager) handleAccept(msg *HandshakeMsg) {
	peerNodeID := msg.NodeID
	slog.Info("handshake accepted by peer", "peer_node_id", peerNodeID)

	hm.mu.Lock()
	defer hm.mu.Unlock()

	// Recently revoked? Drop the stale acceptance.
	if until, ok := hm.revoked[peerNodeID]; ok {
		if time.Now().Before(until) {
			slog.Info("ignoring handshake acceptance from recently-revoked peer", "peer_node_id", peerNodeID)
			delete(hm.outgoing, peerNodeID)
			return
		}
		delete(hm.revoked, peerNodeID)
	}

	delete(hm.outgoing, peerNodeID)
	hm.markTrustedLocked(peerNodeID, &TrustRecord{
		NodeID:     peerNodeID,
		PublicKey:  msg.PublicKey,
		ApprovedAt: time.Now(),
		Mutual:     true,
	})
	hm.saveTrust()

	// Report trust to registry
	if reg := hm.rt.Registry(); reg != nil {
		selfID := hm.rt.NodeID()
		hm.goRPCLocked(func() { reg.ReportTrust(selfID, peerNodeID) })
	}
}

// handleRejectMsg processes a handshake rejection from a peer.
func (hm *Manager) handleRejectMsg(msg *HandshakeMsg) {
	slog.Warn("handshake rejected by peer", "peer_node_id", msg.NodeID, "reason", msg.Reason)

	hm.mu.Lock()
	delete(hm.outgoing, msg.NodeID)
	hm.mu.Unlock()
}

// SendRequest sends a handshake request to a remote node.
// First tries direct connection (port 444). If that fails (e.g. private node),
// falls back to relaying through the registry.
func (hm *Manager) SendRequest(peerNodeID uint32, justification string) error {
	hm.mu.Lock()
	if _, ok := hm.trusted[peerNodeID]; ok {
		hm.mu.Unlock()
		return nil // already trusted
	}
	// An explicit handshake clears any post-revoke cooldown for this
	// peer. The cooldown's purpose is to suppress stale registry-relayed
	// approvals after a local revoke; an explicit user-driven handshake
	// is by definition a fresh intent to re-trust, and should not be
	// blocked by the 5-min cooldown — otherwise the user can find
	// themselves locked out of a peer that was auto-pruned by policy
	// (trust-decay, etc.) with no clean recovery path.
	delete(hm.revoked, peerNodeID)
	hm.outgoing[peerNodeID] = time.Now()
	hm.mu.Unlock()

	pubKeyStr := ""
	if hm.rt.HasIdentity() {
		pubKeyStr = crypto.EncodePublicKey(hm.rt.PublicKey())
	}

	msg := HandshakeMsg{
		Type:          HandshakeRequest,
		NodeID:        hm.rt.NodeID(),
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
	if reg := hm.rt.Registry(); reg != nil {
		sig := hm.signHandshakeChallenge(fmt.Sprintf("handshake:%d:%d", hm.rt.NodeID(), peerNodeID))
		_, relayErr := reg.RequestHandshake(hm.rt.NodeID(), peerNodeID, justification, sig)
		if relayErr != nil {
			return fmt.Errorf("handshake relay: %w", relayErr)
		}
		slog.Info("handshake relayed via registry", "peer_node_id", peerNodeID)
		return nil
	}
	return err
}

// ProcessRelayedRequest handles a handshake request received via registry relay.
// Exported for daemon-side polling glue (Daemon.pollRelayedHandshakes).
func (hm *Manager) ProcessRelayedRequest(fromNodeID uint32, justification string) {
	hm.processRelayedRequest(fromNodeID, justification)
}

// processRelayedRequest handles a handshake request received via registry relay.
func (hm *Manager) processRelayedRequest(fromNodeID uint32, justification string) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	// Already trusted?
	if _, ok := hm.trusted[fromNodeID]; ok {
		slog.Debug("relayed request from already-trusted node", "peer_node_id", fromNodeID)
		// Respond via registry that we accept
		if reg := hm.rt.Registry(); reg != nil {
			nodeID, peerID := hm.rt.NodeID(), fromNodeID
			sig := hm.signHandshakeChallenge(fmt.Sprintf("respond:%d:%d", nodeID, peerID))
			hm.goRPCLocked(func() { reg.RespondHandshake(nodeID, peerID, true, sig) })
		}
		return
	}

	// Check if we have an outgoing request to this peer (mutual handshake)
	if _, ok := hm.outgoing[fromNodeID]; ok {
		delete(hm.outgoing, fromNodeID)
		hm.markTrustedLocked(fromNodeID, &TrustRecord{
			NodeID:     fromNodeID,
			ApprovedAt: time.Now(),
			Mutual:     true,
		})
		slog.Info("mutual relayed handshake auto-approved", "peer_node_id", fromNodeID)
		hm.saveTrust()
		// Respond via registry and backfill public key
		if reg := hm.rt.Registry(); reg != nil {
			nodeID, peerID := hm.rt.NodeID(), fromNodeID
			sig := hm.signHandshakeChallenge(fmt.Sprintf("respond:%d:%d", nodeID, peerID))
			hm.goRPCLocked(func() {
				reg.RespondHandshake(nodeID, peerID, true, sig)
				hm.backfillPeerKey(peerID)
			})
		}
		return
	}

	// Check if peers are on the same network (network trust)
	if hm.sameNetwork(fromNodeID) {
		hm.markTrustedLocked(fromNodeID, &TrustRecord{
			NodeID:     fromNodeID,
			ApprovedAt: time.Now(),
			Network:    hm.sharedNetwork(fromNodeID),
		})
		slog.Info("same network relayed handshake auto-approved", "peer_node_id", fromNodeID)
		hm.saveTrust()
		if reg := hm.rt.Registry(); reg != nil {
			nodeID, peerID := hm.rt.NodeID(), fromNodeID
			sig := hm.signHandshakeChallenge(fmt.Sprintf("respond:%d:%d", nodeID, peerID))
			hm.goRPCLocked(func() {
				reg.RespondHandshake(nodeID, peerID, true, sig)
				reg.ReportTrust(nodeID, peerID)
				hm.backfillPeerKey(peerID)
			})
		}
		return
	}

	// Auto-approve when the sender is in the embedded trusted-agents list.
	// The registry relay vouches for the sender's node_id (only authenticated
	// nodes can relay), so no separate registryBound check is needed here.
	if name, ok := hm.rt.IsTrusted(fromNodeID); ok {
		hm.markTrustedLocked(fromNodeID, &TrustRecord{
			NodeID:     fromNodeID,
			ApprovedAt: time.Now(),
		})
		slog.Info("relayed handshake auto-approved (trusted agent)",
			"peer_node_id", fromNodeID, "agent", name)
		hm.rt.PublishEvent("handshake.auto_approved", map[string]interface{}{
			"peer_node_id": fromNodeID, "reason": "trusted_agent", "agent": name,
		})
		hm.rt.PublishEvent("trust.changed", map[string]interface{}{
			"peer_node_id": fromNodeID, "state": "granted", "reason": "trusted_agent_relayed", "agent": name,
		})
		hm.saveTrust()
		if reg := hm.rt.Registry(); reg != nil {
			nodeID, peerID := hm.rt.NodeID(), fromNodeID
			sig := hm.signHandshakeChallenge(fmt.Sprintf("respond:%d:%d", nodeID, peerID))
			hm.goRPCLocked(func() {
				reg.RespondHandshake(nodeID, peerID, true, sig)
				reg.ReportTrust(nodeID, peerID)
				hm.backfillPeerKey(peerID)
			})
		}
		return
	}

	// Auto-approve all requests when the daemon is configured to do so.
	if hm.rt.TrustAutoApprove() {
		hm.markTrustedLocked(fromNodeID, &TrustRecord{
			NodeID:     fromNodeID,
			ApprovedAt: time.Now(),
			Mutual:     false,
		})
		slog.Info("relayed handshake auto-approved (trust-auto-approve enabled)", "peer_node_id", fromNodeID)
		hm.rt.PublishEvent("handshake.auto_approved", map[string]interface{}{
			"peer_node_id": fromNodeID, "reason": "auto_approve",
		})
		hm.rt.PublishEvent("trust.changed", map[string]interface{}{
			"peer_node_id": fromNodeID, "state": "granted", "reason": "auto_approve_relayed",
		})
		hm.saveTrust()
		if reg := hm.rt.Registry(); reg != nil {
			nodeID, peerID := hm.rt.NodeID(), fromNodeID
			sig := hm.signHandshakeChallenge(fmt.Sprintf("respond:%d:%d", nodeID, peerID))
			hm.goRPCLocked(func() {
				reg.RespondHandshake(nodeID, peerID, true, sig)
				reg.ReportTrust(nodeID, peerID)
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

// ProcessRelayedApproval handles a handshake approval received via registry relay.
// Exported for daemon-side polling glue.
func (hm *Manager) ProcessRelayedApproval(fromNodeID uint32) {
	hm.processRelayedApproval(fromNodeID)
}

// processRelayedApproval handles a handshake approval received via registry relay.
// This is called when the peer approved our outgoing request and the acceptance
// was relayed back through the registry (because direct dial to port 444 failed).
func (hm *Manager) processRelayedApproval(fromNodeID uint32) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	// Already trusted? Nothing to do.
	if _, ok := hm.trusted[fromNodeID]; ok {
		slog.Debug("relayed approval from already-trusted node", "peer_node_id", fromNodeID)
		return
	}

	// Recently revoked? Drop the stale relay rather than re-establishing trust.
	if until, ok := hm.revoked[fromNodeID]; ok {
		if time.Now().Before(until) {
			slog.Info("ignoring relayed approval for recently-revoked peer", "peer_node_id", fromNodeID)
			delete(hm.outgoing, fromNodeID)
			return
		}
		delete(hm.revoked, fromNodeID)
	}

	delete(hm.outgoing, fromNodeID)
	hm.markTrustedLocked(fromNodeID, &TrustRecord{
		NodeID:     fromNodeID,
		ApprovedAt: time.Now(),
		Mutual:     true,
	})
	hm.saveTrust()
	slog.Info("trust established via relayed approval", "peer_node_id", fromNodeID)

	// Backfill public key from registry
	if reg := hm.rt.Registry(); reg != nil {
		_ = reg
		peerID := fromNodeID
		hm.goRPCLocked(func() { hm.backfillPeerKey(peerID) })
	}
}

// backfillPeerKey fetches a peer's public key from the registry and updates
// the trust record. Called asynchronously after relay-based trust establishment,
// where the P2P public key exchange didn't happen.
func (hm *Manager) backfillPeerKey(peerNodeID uint32) {
	reg := hm.rt.Registry()
	if reg == nil {
		return
	}
	resp, err := reg.Lookup(peerNodeID)
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

// ProcessRelayedRejection handles a handshake rejection received via registry relay.
// Exported for daemon-side polling glue.
func (hm *Manager) ProcessRelayedRejection(fromNodeID uint32) {
	hm.processRelayedRejection(fromNodeID)
}

// processRelayedRejection handles a handshake rejection received via registry relay.
func (hm *Manager) processRelayedRejection(fromNodeID uint32) {
	hm.mu.Lock()
	delete(hm.outgoing, fromNodeID)
	hm.mu.Unlock()
	slog.Info("handshake rejected via relay", "peer_node_id", fromNodeID)
}

// ApproveHandshake approves a pending handshake request.
func (hm *Manager) ApproveHandshake(peerNodeID uint32) error {
	hm.mu.Lock()
	req, ok := hm.pending[peerNodeID]
	if !ok {
		hm.mu.Unlock()
		return nil
	}
	delete(hm.pending, peerNodeID)
	hm.markTrustedLocked(peerNodeID, &TrustRecord{
		NodeID:     peerNodeID,
		PublicKey:  req.PublicKey,
		ApprovedAt: time.Now(),
	})
	hm.saveTrust()
	hm.mu.Unlock()

	slog.Info("handshake approved", "peer_node_id", peerNodeID)
	hm.rt.PublishEvent("handshake.approved", map[string]interface{}{
		"peer_node_id": peerNodeID,
	})
	hm.rt.PublishEvent("trust.changed", map[string]interface{}{
		"peer_node_id": peerNodeID, "state": "granted", "reason": "approved",
	})

	// Report trust to registry (creates the trust pair for resolve authorization)
	if reg := hm.rt.Registry(); reg != nil {
		nodeID := hm.rt.NodeID()
		sig := hm.signHandshakeChallenge(fmt.Sprintf("respond:%d:%d", nodeID, peerNodeID))
		hm.goRPC(func() {
			reg.ReportTrust(nodeID, peerNodeID)
			// Also respond via registry relay in case the request was relayed
			reg.RespondHandshake(nodeID, peerNodeID, true, sig)
		})
	}

	// Try to send accept directly (may fail if peer is private, that's OK)
	hm.sendAccept(peerNodeID)
	return nil
}

// RejectHandshake rejects a pending handshake request.
func (hm *Manager) RejectHandshake(peerNodeID uint32, reason string) error {
	hm.mu.Lock()
	delete(hm.pending, peerNodeID)
	hm.saveTrust()
	hm.mu.Unlock()

	slog.Info("handshake rejected", "peer_node_id", peerNodeID, "reason", reason)
	hm.rt.PublishEvent("handshake.rejected", map[string]interface{}{
		"peer_node_id": peerNodeID, "reason": reason,
	})

	// Relay rejection via registry so the requester learns about it even behind NAT
	if reg := hm.rt.Registry(); reg != nil {
		nodeID := hm.rt.NodeID()
		sig := hm.signHandshakeChallenge(fmt.Sprintf("respond:%d:%d", nodeID, peerNodeID))
		hm.goRPC(func() {
			reg.RespondHandshake(nodeID, peerNodeID, false, sig)
		})
	}

	// Also try direct notification (best-effort)
	pubKeyStr := ""
	if hm.rt.HasIdentity() {
		pubKeyStr = crypto.EncodePublicKey(hm.rt.PublicKey())
	}

	msg := HandshakeMsg{
		Type:      HandshakeReject,
		NodeID:    hm.rt.NodeID(),
		PublicKey: pubKeyStr,
		Reason:    reason,
		Timestamp: time.Now().Unix(),
	}

	hm.sendMessage(peerNodeID, &msg) // best-effort, ignore error
	return nil
}

// RevokeTrust removes a peer from the trusted set and notifies both the
// registry and the peer itself.  Either party can revoke unilaterally.
func (hm *Manager) RevokeTrust(peerNodeID uint32) error {
	hm.mu.Lock()
	_, wasTrusted := hm.trusted[peerNodeID]
	_, wasPending := hm.pending[peerNodeID]
	delete(hm.trusted, peerNodeID)
	delete(hm.pending, peerNodeID)
	delete(hm.outgoing, peerNodeID)
	// Block stale relayed approvals still sitting in the registry inbox from
	// re-establishing trust right after a local revoke. 5-minute cooldown covers
	// the normal poll cycle many times over.
	hm.revoked[peerNodeID] = time.Now().Add(5 * time.Minute)
	if wasTrusted || wasPending {
		hm.saveTrust()
	}
	hm.mu.Unlock()

	if !wasTrusted {
		return fmt.Errorf("node %d was not trusted", peerNodeID)
	}

	slog.Info("trust revoked", "peer_node_id", peerNodeID)
	hm.rt.PublishEvent("trust.revoked", map[string]interface{}{
		"peer_node_id": peerNodeID,
	})
	hm.rt.PublishEvent("trust.changed", map[string]interface{}{
		"peer_node_id": peerNodeID, "state": "revoked", "reason": "local",
	})

	// Notify the peer BEFORE tearing down the tunnel — once we RemovePeer,
	// the tunnel crypto is gone and the notify can't reach them.
	pubKeyStr := ""
	if hm.rt.HasIdentity() {
		pubKeyStr = crypto.EncodePublicKey(hm.rt.PublicKey())
	}
	msg := HandshakeMsg{
		Type:      HandshakeRevoke,
		NodeID:    hm.rt.NodeID(),
		PublicKey: pubKeyStr,
		Reason:    "trust revoked",
		Timestamp: time.Now().Unix(),
	}
	hm.sendMessage(peerNodeID, &msg) // best-effort, ignore error

	// Tear down the tunnel to the revoked peer
	hm.rt.RemoveTunnelPeer(peerNodeID)

	// Revoke the trust pair at the registry so resolve is blocked again
	if reg := hm.rt.Registry(); reg != nil {
		selfID := hm.rt.NodeID()
		hm.goRPC(func() { reg.RevokeTrust(selfID, peerNodeID) })
	}

	return nil
}

// handleRevokeMsg processes an incoming trust revocation from a peer.
func (hm *Manager) handleRevokeMsg(msg *HandshakeMsg) {
	peerNodeID := msg.NodeID
	slog.Info("trust revoked by peer", "peer_node_id", peerNodeID)
	hm.rt.PublishEvent("trust.revoked_by_peer", map[string]interface{}{
		"peer_node_id": peerNodeID,
	})
	hm.rt.PublishEvent("trust.changed", map[string]interface{}{
		"peer_node_id": peerNodeID, "state": "revoked", "reason": "by_peer",
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
	hm.rt.RemoveTunnelPeer(peerNodeID)

	// Also remove from registry (in case peer's revoke_trust didn't reach registry)
	if wasTrusted {
		if reg := hm.rt.Registry(); reg != nil {
			selfID := hm.rt.NodeID()
			hm.goRPC(func() { reg.RevokeTrust(selfID, peerNodeID) })
		}
	}
}

// IsTrusted returns whether a peer has been approved.
func (hm *Manager) IsTrusted(nodeID uint32) bool {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	_, ok := hm.trusted[nodeID]
	return ok
}

// TrustedPeers returns all trusted peers.
func (hm *Manager) TrustedPeers() []TrustRecord {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	var list []TrustRecord
	for _, r := range hm.trusted {
		list = append(list, *r)
	}
	return list
}

// PendingRequests returns all pending handshake requests.
func (hm *Manager) PendingRequests() []PendingHandshake {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	var list []PendingHandshake
	for _, r := range hm.pending {
		list = append(list, *r)
	}
	return list
}

// PendingCount returns the number of pending handshake requests.
func (hm *Manager) PendingCount() int {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	return len(hm.pending)
}

// sendAcceptLocked sends an accept message (caller must hold hm.mu).
func (hm *Manager) sendAcceptLocked(peerNodeID uint32) {
	hm.goRPCLocked(func() {
		hm.sendAccept(peerNodeID)
	})
}

func (hm *Manager) sendAccept(peerNodeID uint32) error {
	pubKeyStr := ""
	if hm.rt.HasIdentity() {
		pubKeyStr = crypto.EncodePublicKey(hm.rt.PublicKey())
	}
	msg := HandshakeMsg{
		Type:      HandshakeAccept,
		NodeID:    hm.rt.NodeID(),
		PublicKey: pubKeyStr,
		Timestamp: time.Now().Unix(),
	}
	err := hm.sendMessage(peerNodeID, &msg)
	if err != nil {
		// Direct dial failed (peer may be private) — relay acceptance through registry
		slog.Info("direct accept failed, relaying via registry", "peer_node_id", peerNodeID, "error", err)
		if reg := hm.rt.Registry(); reg != nil {
			nodeID := hm.rt.NodeID()
			sig := hm.signHandshakeChallenge(fmt.Sprintf("respond:%d:%d", nodeID, peerNodeID))
			_, relayErr := reg.RespondHandshake(nodeID, peerNodeID, true, sig)
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
func (hm *Manager) signHandshakeChallenge(challenge string) string {
	if !hm.rt.HasIdentity() {
		return ""
	}
	sig := hm.rt.Sign([]byte(challenge))
	return base64.StdEncoding.EncodeToString(sig)
}

// sendMessage dials port 444 on the peer and sends a JSON message.
// M12 fix: signs the message with the daemon identity before sending.
func (hm *Manager) sendMessage(peerNodeID uint32, msg *HandshakeMsg) error {
	// M12 fix: populate signature for P2P authentication
	if msg.Signature == "" {
		msg.Signature = hm.signHandshakeChallenge(fmt.Sprintf("handshake:%d:%d", msg.NodeID, peerNodeID))
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return hm.rt.DialAndSend(peerNodeID, protocol.PortHandshake, data)
}

// sameNetwork checks if the local node and peerNodeID share any non-backbone network.
func (hm *Manager) sameNetwork(peerNodeID uint32) bool {
	return hm.sharedNetwork(peerNodeID) != 0
}

// sharedNetwork returns the first shared non-backbone network ID, or 0 if none.
func (hm *Manager) sharedNetwork(peerNodeID uint32) uint16 {
	// Look up our networks and the peer's networks via registry
	reg := hm.rt.Registry()
	if reg == nil {
		return 0
	}

	myResp, err := reg.Lookup(hm.rt.NodeID())
	if err != nil {
		return 0
	}
	peerResp, err := reg.Lookup(peerNodeID)
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

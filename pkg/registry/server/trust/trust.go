// SPDX-License-Identifier: AGPL-3.0-or-later

// Package trust implements the registry's trust-pair and handshake-relay
// store. It is extracted from pkg/registry/server as part of the R2.1
// registry decomposition.
//
// Thread safety: all exported methods are safe for concurrent use.
package trust

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// maxHandshakeInbox limits the number of pending handshake requests per node.
const maxHandshakeInbox = 100

// maxJustificationSize limits the justification field to prevent memory abuse.
const maxJustificationSize = 1024

// HandshakeRelayMsg is a handshake request stored in the registry's relay inbox.
type HandshakeRelayMsg struct {
	FromNodeID    uint32    `json:"from_node_id"`
	Justification string    `json:"justification"`
	Timestamp     time.Time `json:"timestamp"`
}

// HandshakeResponseMsg is a handshake approval/rejection stored for the original requester.
type HandshakeResponseMsg struct {
	FromNodeID uint32    `json:"from_node_id"` // the node that approved/rejected
	Accept     bool      `json:"accept"`
	Timestamp  time.Time `json:"timestamp"`
}

// NodeView is the read-only interface the Store uses to look up node data.
// Implementations must be safe for concurrent use.
type NodeView interface {
	// LookupNode returns the public key and network memberships for the
	// given node ID. ok is false when the node does not exist.
	LookupNode(id uint32) (pubKey []byte, networks []uint16, ok bool)

	// AdminToken returns the global admin token for the registry.
	// An empty string means administration is disabled.
	AdminToken() string
}

// Callbacks bundles the side-effect functions the Store calls on state changes.
// All functions must be safe for concurrent use.
type Callbacks struct {
	// Save triggers a debounced snapshot write.
	Save func()
	// Audit records an audit log entry.
	Audit func(action string, attrs ...any)
	// IncTrustReports increments the trust-reports counter.
	IncTrustReports func()
	// IncTrustRevocations increments the trust-revocations counter.
	IncTrustRevocations func()
	// IncHandshakeRequests increments the handshake-requests counter.
	IncHandshakeRequests func()
}

// Store holds all mutable trust-pair and handshake-relay state.
//
// LOCK ORDERING
//
//	mu (RWMutex) — protects trustPairs.
//	handshakeMu (Mutex) — protects handshakeInbox, handshakeResponses,
//	                       and pendingHandshakes.
//
// These two locks are independent; neither may be acquired while holding
// the other. No code path needs both simultaneously.
type Store struct {
	nodes NodeView
	cb    Callbacks

	mu         sync.RWMutex
	trustPairs map[string]bool

	handshakeMu        sync.Mutex
	handshakeInbox     map[uint32][]*HandshakeRelayMsg
	handshakeResponses map[uint32][]*HandshakeResponseMsg
	// pendingHandshakes tracks requests that have been sent but not yet
	// responded to.  Unlike handshakeInbox it is NOT cleared by poll, so
	// respond_handshake can verify a prior request existed even after the
	// recipient has polled the inbox.  Keyed as [responderID][requesterID].
	pendingHandshakes map[uint32]map[uint32]struct{}
}

// NewStore creates an empty, ready-to-use Store.
func NewStore(nodes NodeView, cb Callbacks) *Store {
	return &Store{
		nodes:              nodes,
		cb:                 cb,
		trustPairs:         make(map[string]bool),
		handshakeInbox:     make(map[uint32][]*HandshakeRelayMsg),
		handshakeResponses: make(map[uint32][]*HandshakeResponseMsg),
		pendingHandshakes:  make(map[uint32]map[uint32]struct{}),
	}
}

// --- TrustView implementation ---

// Count returns the total number of trust pairs currently stored.
func (st *Store) Count() int {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return len(st.trustPairs)
}

// IsTrusted reports whether nodes a and b have an established trust pair.
// The relation is symmetric: IsTrusted(a, b) == IsTrusted(b, a).
func (st *Store) IsTrusted(a, b uint32) bool {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.trustPairs[pairKey(a, b)]
}

// --- Snapshot / restore ---

// Pairs returns a snapshot of all trust-pair keys for serialisation.
// Each key is of the form "min:max" where min <= max.
func (st *Store) Pairs() []string {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]string, 0, len(st.trustPairs))
	for k := range st.trustPairs {
		out = append(out, k)
	}
	return out
}

// RestorePairs loads trust pairs from a snapshot during startup. It is
// NOT safe for concurrent use — call it before serving requests.
func (st *Store) RestorePairs(keys []string) {
	for _, key := range keys {
		st.trustPairs[key] = true
	}
}

// InboxSnapshot returns copies of the handshake inboxes for snapshot
// serialisation. Called during snapshot flush.
func (st *Store) InboxSnapshot() (
	inbox map[uint32][]*HandshakeRelayMsg,
	responses map[uint32][]*HandshakeResponseMsg,
) {
	st.handshakeMu.Lock()
	defer st.handshakeMu.Unlock()

	if len(st.handshakeInbox) > 0 {
		inbox = make(map[uint32][]*HandshakeRelayMsg, len(st.handshakeInbox))
		for id, msgs := range st.handshakeInbox {
			inbox[id] = msgs
		}
	}
	if len(st.handshakeResponses) > 0 {
		responses = make(map[uint32][]*HandshakeResponseMsg, len(st.handshakeResponses))
		for id, msgs := range st.handshakeResponses {
			responses[id] = msgs
		}
	}
	return
}

// RestoreInbox loads handshake inboxes from a snapshot during startup.
// NOT safe for concurrent use — call before serving requests.
func (st *Store) RestoreInbox(
	inbox map[uint32][]*HandshakeRelayMsg,
	responses map[uint32][]*HandshakeResponseMsg,
) {
	st.handshakeMu.Lock()
	defer st.handshakeMu.Unlock()
	for id, msgs := range inbox {
		st.handshakeInbox[id] = msgs
		// Rebuild pendingHandshakes from the restored inbox so that
		// respond_handshake validation works correctly after a restart.
		for _, msg := range msgs {
			if st.pendingHandshakes[id] == nil {
				st.pendingHandshakes[id] = make(map[uint32]struct{})
			}
			st.pendingHandshakes[id][msg.FromNodeID] = struct{}{}
		}
	}
	for id, msgs := range responses {
		st.handshakeResponses[id] = msgs
	}
}

// InboxSize returns the total number of pending handshake requests and
// responses (for metrics gauges).
func (st *Store) InboxSize() (requests, responses int) {
	st.handshakeMu.Lock()
	defer st.handshakeMu.Unlock()
	for _, msgs := range st.handshakeInbox {
		requests += len(msgs)
	}
	for _, msgs := range st.handshakeResponses {
		responses += len(msgs)
	}
	return
}

// --- Handlers ---

// HandleReportTrust registers a mutual trust pair between two nodes.
//
//	func (s *Server) handleReportTrust(req map[string]interface{}) (map[string]interface{}, error) {
//	    return s.trust.HandleReportTrust(req)
//	}
func (st *Store) HandleReportTrust(req map[string]interface{}) (map[string]interface{}, error) {
	nodeA := jsonUint32(req, "node_id")
	nodeB := jsonUint32(req, "peer_id")

	// Phase 1: look up pubkey + adminToken for verification
	pubKey, _, ok := st.nodes.LookupNode(nodeA)
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeA, protocol.ErrNodeNotFound)
	}
	if _, _, ok := st.nodes.LookupNode(nodeB); !ok {
		return nil, fmt.Errorf("node %d: %w", nodeB, protocol.ErrNodeNotFound)
	}
	adminToken := st.nodes.AdminToken()

	// Phase 2: signature verification outside any lock (CPU-bound ~28µs)
	if err := verifyHeartbeatSignature(pubKey, adminToken, req, fmt.Sprintf("report_trust:%d:%d", nodeA, nodeB)); err != nil {
		return nil, err
	}

	// Phase 3: re-check nodes exist, then write the trust pair
	if _, _, ok := st.nodes.LookupNode(nodeA); !ok {
		return nil, fmt.Errorf("node %d: %w", nodeA, protocol.ErrNodeNotFound)
	}
	if _, _, ok := st.nodes.LookupNode(nodeB); !ok {
		return nil, fmt.Errorf("node %d: %w", nodeB, protocol.ErrNodeNotFound)
	}

	key := pairKey(nodeA, nodeB)
	st.mu.Lock()
	st.trustPairs[key] = true
	st.mu.Unlock()

	st.cb.Save()
	st.cb.IncTrustReports()

	slog.Info("trust pair registered", "node_a", nodeA, "node_b", nodeB)
	st.cb.Audit("trust.created", "node_a", nodeA, "node_b", nodeB)

	return map[string]interface{}{
		"type": "report_trust_ok",
	}, nil
}

// HandleRevokeTrust removes a trust pair between two nodes.
func (st *Store) HandleRevokeTrust(req map[string]interface{}) (map[string]interface{}, error) {
	nodeA := jsonUint32(req, "node_id")
	nodeB := jsonUint32(req, "peer_id")

	// Phase 1: look up pubkey for verification
	pubKey, _, ok := st.nodes.LookupNode(nodeA)
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeA, protocol.ErrNodeNotFound)
	}
	adminToken := st.nodes.AdminToken()

	// Phase 2: signature verification outside any lock
	if err := verifyHeartbeatSignature(pubKey, adminToken, req, fmt.Sprintf("revoke_trust:%d:%d", nodeA, nodeB)); err != nil {
		return nil, err
	}

	// Phase 3: re-check node exists, then delete the trust pair
	if _, _, ok := st.nodes.LookupNode(nodeA); !ok {
		return nil, fmt.Errorf("node %d: %w", nodeA, protocol.ErrNodeNotFound)
	}

	key := pairKey(nodeA, nodeB)
	st.mu.Lock()
	if !st.trustPairs[key] {
		st.mu.Unlock()
		return nil, fmt.Errorf("no trust pair between %d and %d", nodeA, nodeB)
	}
	delete(st.trustPairs, key)
	st.mu.Unlock()

	st.cb.Save()
	st.cb.IncTrustRevocations()

	slog.Info("trust pair revoked", "node_a", nodeA, "node_b", nodeB)
	st.cb.Audit("trust.revoked", "node_a", nodeA, "node_b", nodeB)

	return map[string]interface{}{
		"type": "revoke_trust_ok",
	}, nil
}

// HandleCheckTrust reports whether a trust pair exists between two nodes, or
// whether they share a non-backbone network.
func (st *Store) HandleCheckTrust(req map[string]interface{}) (map[string]interface{}, error) {
	nodeA := jsonUint32(req, "node_id")
	nodeB := jsonUint32(req, "peer_id")

	st.mu.RLock()
	trusted := st.trustPairs[pairKey(nodeA, nodeB)]
	st.mu.RUnlock()

	if !trusted {
		_, netsA, okA := st.nodes.LookupNode(nodeA)
		_, netsB, okB := st.nodes.LookupNode(nodeB)
		if okA && okB {
		outer:
			for _, aNet := range netsA {
				if aNet == 0 {
					continue
				}
				for _, bNet := range netsB {
					if aNet == bNet {
						trusted = true
						break outer
					}
				}
			}
		}
	}

	return map[string]interface{}{
		"type":    "check_trust_ok",
		"trusted": trusted,
	}, nil
}

// HandleRequestHandshake relays a handshake request to a target node's inbox.
// M12 fix: verifies sender signature to prevent spoofed handshake requests.
func (st *Store) HandleRequestHandshake(req map[string]interface{}) (map[string]interface{}, error) {
	fromNodeID := jsonUint32(req, "from_node_id")
	toNodeID := jsonUint32(req, "to_node_id")
	justification, _ := req["justification"].(string)
	if len(justification) > maxJustificationSize {
		return nil, fmt.Errorf("justification too large: %d bytes (max %d)", len(justification), maxJustificationSize)
	}

	// Phase 1: look up sender pubkey for verification
	fromPubKey, _, ok := st.nodes.LookupNode(fromNodeID)
	if !ok {
		return nil, fmt.Errorf("node %d: %w", fromNodeID, protocol.ErrNodeNotFound)
	}
	if _, _, ok := st.nodes.LookupNode(toNodeID); !ok {
		return nil, fmt.Errorf("node %d: %w", toNodeID, protocol.ErrNodeNotFound)
	}

	// Phase 2: M12 fix: verify sender signature without lock (CPU-bound)
	if fromPubKey != nil {
		sigB64, _ := req["signature"].(string)
		if sigB64 == "" {
			return nil, fmt.Errorf("handshake request requires signature")
		}
		sig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			return nil, fmt.Errorf("invalid signature encoding: %w", err)
		}
		challenge := fmt.Sprintf("handshake:%d:%d", fromNodeID, toNodeID)
		if !crypto.Verify(fromPubKey, []byte(challenge), sig) {
			return nil, fmt.Errorf("handshake request signature verification failed")
		}
	}

	// Phase 3a: re-check both nodes still exist
	if _, _, ok := st.nodes.LookupNode(fromNodeID); !ok {
		return nil, fmt.Errorf("node %d: %w", fromNodeID, protocol.ErrNodeNotFound)
	}
	if _, _, ok := st.nodes.LookupNode(toNodeID); !ok {
		return nil, fmt.Errorf("node %d: %w", toNodeID, protocol.ErrNodeNotFound)
	}

	// Phase 3b: inbox mutation under handshakeMu
	st.handshakeMu.Lock()
	defer st.handshakeMu.Unlock()

	if len(st.handshakeInbox[toNodeID]) >= maxHandshakeInbox {
		return nil, fmt.Errorf("handshake inbox full for node %d", toNodeID)
	}
	for _, existing := range st.handshakeInbox[toNodeID] {
		if existing.FromNodeID == fromNodeID {
			return nil, fmt.Errorf("handshake request already pending from node %d", fromNodeID)
		}
	}

	st.handshakeInbox[toNodeID] = append(st.handshakeInbox[toNodeID], &HandshakeRelayMsg{
		FromNodeID:    fromNodeID,
		Justification: justification,
		Timestamp:     time.Now(),
	})
	if st.pendingHandshakes[toNodeID] == nil {
		st.pendingHandshakes[toNodeID] = make(map[uint32]struct{})
	}
	st.pendingHandshakes[toNodeID][fromNodeID] = struct{}{}

	st.cb.IncHandshakeRequests()

	slog.Info("handshake request relayed", "from", fromNodeID, "to", toNodeID)
	st.cb.Audit("handshake.relayed", "from_node_id", fromNodeID, "to_node_id", toNodeID)

	return map[string]interface{}{
		"type":   "request_handshake_ok",
		"status": "delivered",
	}, nil
}

// HandlePollHandshakes returns and clears a node's handshake inbox.
//
// Uses the 3-phase pattern: look up node + copy pubkey, release, verify
// signature without any lock (CPU-bound ~28µs), then swap inbox maps.
func (st *Store) HandlePollHandshakes(req map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(req, "node_id")

	// Phase 1: look up pubkey + adminToken for verification
	pubKey, _, ok := st.nodes.LookupNode(nodeID)
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}
	adminToken := st.nodes.AdminToken()

	// Phase 2: H3 fix: verify signature without lock (CPU-bound)
	if err := verifyHeartbeatSignature(pubKey, adminToken, req, fmt.Sprintf("poll_handshakes:%d", nodeID)); err != nil {
		return nil, err
	}

	// Phase 3: handshakeMu protects only handshake state
	st.handshakeMu.Lock()
	inbox := st.handshakeInbox[nodeID]
	delete(st.handshakeInbox, nodeID)
	respInbox := st.handshakeResponses[nodeID]
	delete(st.handshakeResponses, nodeID)
	st.handshakeMu.Unlock()

	requests := make([]map[string]interface{}, len(inbox))
	for i, r := range inbox {
		requests[i] = map[string]interface{}{
			"from_node_id":  r.FromNodeID,
			"justification": r.Justification,
			"timestamp":     r.Timestamp.Unix(),
		}
	}

	responses := make([]map[string]interface{}, len(respInbox))
	for i, r := range respInbox {
		responses[i] = map[string]interface{}{
			"from_node_id": r.FromNodeID,
			"accept":       r.Accept,
			"timestamp":    r.Timestamp.Unix(),
		}
	}

	return map[string]interface{}{
		"type":      "poll_handshakes_ok",
		"requests":  requests,
		"responses": responses,
	}, nil
}

// HandleRespondHandshake processes a handshake response (approve/reject).
// If approved, creates a mutual trust pair.
// M12 fix: verifies responder signature to prevent spoofed trust approvals.
//
// 3-phase pattern: look up pubkey, verify signature without lock, then
// write trust pair + response inbox.
func (st *Store) HandleRespondHandshake(req map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(req, "node_id") // responder
	peerID := jsonUint32(req, "peer_id") // original requester
	accept, _ := req["accept"].(bool)

	// Phase 1: look up responder's pubkey for verification
	respPubKey, _, ok := st.nodes.LookupNode(nodeID)
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}
	if _, _, ok := st.nodes.LookupNode(peerID); !ok {
		return nil, fmt.Errorf("node %d: %w", peerID, protocol.ErrNodeNotFound)
	}

	// Phase 2: M12 fix: verify responder signature without lock (CPU-bound)
	if respPubKey != nil {
		sigB64, _ := req["signature"].(string)
		if sigB64 == "" {
			return nil, fmt.Errorf("handshake response requires signature")
		}
		sig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			return nil, fmt.Errorf("invalid signature encoding: %w", err)
		}
		challenge := fmt.Sprintf("respond:%d:%d", nodeID, peerID)
		if !crypto.Verify(respPubKey, []byte(challenge), sig) {
			return nil, fmt.Errorf("handshake response signature verification failed")
		}
	}

	// Phase 3a: re-check both nodes still exist
	if _, _, ok := st.nodes.LookupNode(nodeID); !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}
	if _, _, ok := st.nodes.LookupNode(peerID); !ok {
		return nil, fmt.Errorf("node %d: %w", peerID, protocol.ErrNodeNotFound)
	}

	// Phase 3b: verify pending request, write trust pair.
	// pendingHandshakes is populated by HandleRequestHandshake and survives
	// poll drains, so this check holds even after the recipient has polled.
	if accept {
		st.handshakeMu.Lock()
		pending := st.pendingHandshakes[nodeID]
		_, found := pending[peerID]
		if found {
			delete(pending, peerID)
			if len(pending) == 0 {
				delete(st.pendingHandshakes, nodeID)
			}
		}
		st.handshakeMu.Unlock()
		if !found {
			return nil, fmt.Errorf("no pending handshake request from node %d", peerID)
		}

		key := pairKey(nodeID, peerID)
		st.mu.Lock()
		st.trustPairs[key] = true
		st.mu.Unlock()
		st.cb.Save()
		slog.Info("handshake approved via relay, trust pair created", "node", nodeID, "peer", peerID)
	} else {
		slog.Info("handshake rejected via relay", "node", nodeID, "peer", peerID)
	}
	st.cb.Audit("handshake.responded", "node_id", nodeID, "peer_id", peerID, "accept", accept)

	// Phase 3c: response inbox append under handshakeMu
	st.handshakeMu.Lock()
	st.handshakeResponses[peerID] = append(st.handshakeResponses[peerID], &HandshakeResponseMsg{
		FromNodeID: nodeID,
		Accept:     accept,
		Timestamp:  time.Now(),
	})
	st.handshakeMu.Unlock()

	return map[string]interface{}{
		"type":    "respond_handshake_ok",
		"accept":  accept,
		"peer_id": peerID,
	}, nil
}

// --- private helpers ---

// pairKey returns a canonical, symmetric key for a trust pair.
func pairKey(a, b uint32) string {
	if a > b {
		a, b = b, a
	}
	return fmt.Sprintf("%d:%d", a, b)
}

// jsonUint32 extracts a uint32 from a JSON-decoded map (float64 wire type).
func jsonUint32(msg map[string]interface{}, key string) uint32 {
	if v, ok := msg[key].(float64); ok {
		if v < 0 || v > float64(^uint32(0)) {
			return 0
		}
		return uint32(v)
	}
	return 0
}

// verifyHeartbeatSignature validates the message signature against the given
// Ed25519 public key and challenge string. Falls back to admin-token auth
// when pubKey is nil.
func verifyHeartbeatSignature(pubKey []byte, adminToken string, msg map[string]interface{}, challenge string) error {
	if pubKey == nil {
		if err := checkAdminToken(msg, adminToken); err != nil {
			return fmt.Errorf("node has no public key: signature or admin token required")
		}
		return nil
	}
	sigB64, _ := msg["signature"].(string)
	if sigB64 == "" {
		return fmt.Errorf("signature required for authenticated node")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	if !crypto.Verify(pubKey, []byte(challenge), sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// checkAdminToken validates the "admin_token" field against the expected value.
func checkAdminToken(msg map[string]interface{}, adminToken string) error {
	if adminToken == "" {
		return fmt.Errorf("no admin token configured")
	}
	token, _ := msg["admin_token"].(string)
	if token != adminToken {
		return fmt.Errorf("invalid admin token")
	}
	return nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

// Package directory implements the registry's node directory: registration,
// lookup, resolve, deregister, heartbeat, list-nodes, hostname/tag/visibility
// management, and the stale-node reaper. It is extracted from
// pkg/registry/server as part of the R4.2 registry decomposition.
//
// Thread safety: all exported Handler* methods are safe for concurrent use.
// Locking is delegated to the server through mu (shared with Server) and
// callback functions that acquire whatever locks are needed internally.
package directory

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
	"github.com/pilot-protocol/common/crypto"
)

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

const (
	// NumNodeShards must match the value in server.go.
	NumNodeShards = 256

	// ReapChunkSize is how many nodes to process per reap tick.
	ReapChunkSize = 10000

	// AdminListNodesTTL is how long an admin list_nodes response is cached.
	AdminListNodesTTL = 1 * time.Second

	// RawResponseKey is the sentinel map key for pre-marshalled responses.
	RawResponseKey = "_pilot_raw_body"
)

// --------------------------------------------------------------------------
// KeyInfo and NodeInfo — defined here; aliased back in server.go
// --------------------------------------------------------------------------

// KeyInfo holds key lifecycle metadata for a node.
type KeyInfo struct {
	CreatedAt   time.Time `json:"created_at"`
	RotatedAt   time.Time `json:"rotated_at,omitempty"`
	RotateCount int       `json:"rotate_count"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

// NodeInfo holds the in-memory state for a single registered node.
type NodeInfo struct {
	ID         uint32
	Owner      string
	PublicKey  []byte
	RealAddr   string
	Networks   []uint16
	LastSeen   time.Time
	Public     bool
	Hostname   string
	Tags       []string
	TaskExec   bool
	LANAddrs   []string
	KeyMeta    KeyInfo
	ExternalID string
	Version    string
	RelayOnly  bool

	// LastSeenNano stores time.UnixNano() for lock-free heartbeat updates.
	LastSeenNano atomic.Int64
	// LastVerifiedNano stores the last Ed25519 verify time. Used by verify-skip.
	LastVerifiedNano atomic.Int64
}

// GetLastSeen returns the most recent last-seen time, preferring the atomic value.
func (n *NodeInfo) GetLastSeen() time.Time {
	if nano := n.LastSeenNano.Load(); nano > 0 {
		return time.Unix(0, nano)
	}
	return n.LastSeen
}

// SetLastSeen updates both the struct field and the atomic value.
// Caller must hold s.mu.Lock().
func (n *NodeInfo) SetLastSeen(t time.Time) {
	n.LastSeen = t
	n.LastSeenNano.Store(t.UnixNano())
}

// --------------------------------------------------------------------------
// Hostname / tag validation
// --------------------------------------------------------------------------

var hostnameRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
var tagRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
var reservedHostnames = map[string]bool{
	"localhost": true,
	"backbone":  true,
	"broadcast": true,
}

// ValidateHostname checks that a hostname is valid for registration.
func ValidateHostname(name string) error {
	if len(name) == 0 {
		return nil
	}
	if len(name) > 63 {
		return fmt.Errorf("hostname too long (max 63 chars)")
	}
	if !hostnameRegex.MatchString(name) {
		return fmt.Errorf("hostname must be lowercase alphanumeric with hyphens, start/end with alphanumeric")
	}
	if reservedHostnames[name] {
		return fmt.Errorf("hostname %q is reserved", name)
	}
	return nil
}

// --------------------------------------------------------------------------
// ListNodesCacheState
// --------------------------------------------------------------------------

// ListNodesCacheState is the per-network singleflight + TTL cache entry for
// list_nodes responses.
type ListNodesCacheState struct {
	Mu            sync.Mutex
	FullBody      []byte
	BuiltAt       time.Time
	Building      bool
	Cond          *sync.Cond
	LastBuildErr  error
	CacheHits     uint64
	CacheWaits    uint64
	CacheRebuilds uint64
}

// --------------------------------------------------------------------------
// NodeShards type alias
// --------------------------------------------------------------------------

// NodeShards is the fixed-size per-node striped mutex array.
type NodeShards = [NumNodeShards]sync.RWMutex

// --------------------------------------------------------------------------
// Callbacks
// --------------------------------------------------------------------------

// NetworkMemberView carries the per-node membership data needed for list_nodes.
type NetworkMemberView struct {
	Members     []uint32
	MemberRoles map[uint32]string
	MemberTags  map[uint32][]string
}

// Callbacks collects the cross-package effects that directory handlers need
// to trigger without importing the full server package.
type Callbacks struct {
	// Save triggers a debounced snapshot write.
	Save func()
	// Audit records an audit log entry.
	Audit func(action string, attrs ...any)
	// RecordWALRegister records a new-node WAL entry.
	RecordWALRegister func(nodeID uint32, owner, pubKeyB64, realAddr, hostname string, lanAddrs []string, version, createdAt string)
	// RecordWALDeregister records a deregistration WAL entry.
	RecordWALDeregister func(nodeID uint32)
	// InvalidateListNodesCache drops the per-network list_nodes cache.
	InvalidateListNodesCache func(netID uint16)
	// InvalidateAdminListNodesCache drops the backbone admin list_nodes cache.
	InvalidateAdminListNodesCache func()
	// PublishMembershipChanged publishes a membership.changed bus event.
	PublishMembershipChanged func(netID uint16)
	// RemoveFromNetworks removes a node from all its networks in the server's
	// network map. The nodeID and its current Networks slice are passed.
	// Caller holds mu.Lock. Returns the networks that lost an owner.
	RemoveFromNetworks func(nodeID uint32, networks []uint16) (lostOwnerNets []uint16)
	// ClearInviteInbox removes all pending invites for the given node.
	ClearInviteInbox func(nodeID uint32)
	// RequireAdminToken validates the admin_token field in a message.
	RequireAdminToken func(msg map[string]interface{}) error
	// RequireAdminTokenLocked is like RequireAdminToken but mu is already held.
	RequireAdminTokenLocked func(msg map[string]interface{}) error
	// AdminToken returns the current admin token.
	AdminToken func() string
	// VerifyNodeSignature verifies an Ed25519 (or admin-token) signature.
	VerifyNodeSignature func(pubKey []byte, adminToken string, msg map[string]interface{}, challenge string) error
	// IsTrusted returns true if nodeA and nodeB have a mutual trust pair.
	IsTrusted func(nodeA, nodeB uint32) bool
	// BeaconAddr returns the current beacon address.
	BeaconAddr func() string
	// IncRegistrations increments the registration counter.
	IncRegistrations func()
	// IncDeregistrations increments the deregistration counter.
	IncDeregistrations func()
	// IncRequestsTotal increments the named request counter.
	IncRequestsTotal func(label string)
	// IncErrorsTotal increments the named error counter.
	IncErrorsTotal func(label string)
	// ObserveRequestDuration records a request duration histogram sample.
	ObserveRequestDuration func(label string, seconds float64)
	// Now returns the current time (injectable for tests).
	Now func() time.Time
	// AddNodeToBackbone adds a node to the backbone (network 0) Members list.
	// Called when a new node is registered or a reaped node is reclaimed.
	// Caller holds mu.Lock.
	AddNodeToBackbone func(nodeID uint32)
	// ScanNetworkMemberships returns the set of non-backbone networkIDs that
	// still list nodeID as a member. Used to restore network memberships after
	// a reaped node reclaims its old identity. Caller holds mu.Lock.
	ScanNetworkMemberships func(nodeID uint32) []uint16
}

// --------------------------------------------------------------------------
// Store
// --------------------------------------------------------------------------

// Store holds the node directory handler logic. The actual data maps (nodes,
// indices, etc.) are owned by the parent server and shared via pointer.
type Store struct {
	mu          *sync.RWMutex
	nodeShards  *NodeShards
	nodes       map[uint32]*NodeInfo
	pubKeyIdx   map[string]uint32
	ownerIdx    map[string]uint32
	hostnameIdx map[string]uint32
	nextNode    *uint32
	maxNodes    *int
	reapCursor  *uint32

	// list_nodes cache state (shared with server for snapshot compat)
	listNodesCache    *ListNodesCacheState
	listNodesPerNetMu *sync.Mutex
	listNodesPerNet   *map[uint16]*ListNodesCacheState

	// getNetworkView returns membership data for a network without holding mu.
	// Caller must hold mu.RLock before calling.
	getNetworkView func(netID uint16) (NetworkMemberView, bool)

	cb Callbacks
}

// NewStore creates a ready-to-use directory Store. All pointer parameters are
// shared with the parent server and must not be nil.
func NewStore(
	mu *sync.RWMutex,
	nodeShards *NodeShards,
	nodes map[uint32]*NodeInfo,
	pubKeyIdx map[string]uint32,
	ownerIdx map[string]uint32,
	hostnameIdx map[string]uint32,
	nextNode *uint32,
	maxNodes *int,
	reapCursor *uint32,
	listNodesCache *ListNodesCacheState,
	listNodesPerNetMu *sync.Mutex,
	listNodesPerNet *map[uint16]*ListNodesCacheState,
	getNetworkView func(netID uint16) (NetworkMemberView, bool),
	cb Callbacks,
) *Store {
	if cb.Now == nil {
		cb.Now = time.Now
	}
	return &Store{
		mu:                mu,
		nodeShards:        nodeShards,
		nodes:             nodes,
		pubKeyIdx:         pubKeyIdx,
		ownerIdx:          ownerIdx,
		hostnameIdx:       hostnameIdx,
		nextNode:          nextNode,
		maxNodes:          maxNodes,
		reapCursor:        reapCursor,
		listNodesCache:    listNodesCache,
		listNodesPerNetMu: listNodesPerNetMu,
		listNodesPerNet:   listNodesPerNet,
		getNetworkView:    getNetworkView,
		cb:                cb,
	}
}

// --------------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------------

func (st *Store) nodeShard(nodeID uint32) *sync.RWMutex {
	return &st.nodeShards[nodeID%NumNodeShards]
}

// setNodeHostname sets the hostname for a node during registration.
// Caller must hold mu.Lock().
func (st *Store) setNodeHostname(node *NodeInfo, hostname string, resp map[string]interface{}) {
	if hostname == "" {
		return
	}
	if existingID, taken := st.hostnameIdx[hostname]; taken && existingID != node.ID {
		resp["hostname_error"] = fmt.Sprintf("hostname %q already in use", hostname)
		return
	}
	sh := st.nodeShard(node.ID)
	sh.Lock()
	if node.Hostname != "" {
		delete(st.hostnameIdx, node.Hostname)
	}
	node.Hostname = hostname
	st.hostnameIdx[hostname] = node.ID
	sh.Unlock()
	resp["hostname"] = hostname
	slog.Debug("hostname set during registration", "node_id", node.ID, "hostname", hostname)
}

// cleanupNode removes transient state for a departed node. Caller must hold mu.
func (st *Store) cleanupNode(_ uint32) {
	// Trust pairs and handshake inboxes are preserved (identity-level).
}

func jsonUint32(msg map[string]interface{}, key string) uint32 {
	if v, ok := msg[key].(float64); ok {
		if v < 0 || v > float64(^uint32(0)) {
			return 0
		}
		return uint32(v)
	}
	return 0
}

func jsonUint16(msg map[string]interface{}, key string) uint16 {
	if v, ok := msg[key].(float64); ok {
		if v < 0 || v > float64(^uint16(0)) {
			return 0
		}
		return uint16(v)
	}
	return 0
}

// --------------------------------------------------------------------------
// Cache helpers
// --------------------------------------------------------------------------

// InvalidateListNodesCacheForNetwork drops the cached response for a network.
func (st *Store) InvalidateListNodesCacheForNetwork(netID uint16) {
	st.listNodesPerNetMu.Lock()
	delete(*st.listNodesPerNet, netID)
	st.listNodesPerNetMu.Unlock()
}

// InvalidateAdminListNodesCache forces the next AdminListNodesCached() to rebuild.
func (st *Store) InvalidateAdminListNodesCache() {
	c := st.listNodesCache
	c.Mu.Lock()
	c.BuiltAt = time.Time{}
	c.Mu.Unlock()
}

func wrapListNodesBody(nodesArr []byte) []byte {
	const prefix = `{"type":"list_nodes_ok","nodes":`
	out := make([]byte, 0, len(prefix)+len(nodesArr)+1)
	out = append(out, prefix...)
	out = append(out, nodesArr...)
	out = append(out, '}')
	return out
}

// PerNetworkListNodesCached returns the FULL pre-marshalled list_nodes response
// for a per-network request using singleflight + 1s TTL semantics.
func (st *Store) PerNetworkListNodesCached(netID uint16) ([]byte, error) {
	st.listNodesPerNetMu.Lock()
	c, ok := (*st.listNodesPerNet)[netID]
	if !ok {
		c = &ListNodesCacheState{}
		c.Cond = sync.NewCond(&c.Mu)
		(*st.listNodesPerNet)[netID] = c
	}
	st.listNodesPerNetMu.Unlock()

	c.Mu.Lock()
	if c.FullBody != nil && time.Since(c.BuiltAt) < AdminListNodesTTL {
		body := c.FullBody
		c.CacheHits++
		c.Mu.Unlock()
		return body, nil
	}
	if c.Building {
		for c.Building {
			c.Cond.Wait()
		}
		body := c.FullBody
		buildErr := c.LastBuildErr
		c.CacheWaits++
		c.Mu.Unlock()
		if buildErr != nil {
			return nil, buildErr
		}
		if body == nil {
			return nil, fmt.Errorf("list_nodes cache rebuild failed")
		}
		return body, nil
	}
	c.Building = true
	c.CacheRebuilds++
	c.Mu.Unlock()

	st.mu.RLock()
	view, networkOK := st.getNetworkView(netID)
	if !networkOK {
		st.mu.RUnlock()
		err := fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
		c.Mu.Lock()
		c.Building = false
		c.LastBuildErr = err
		c.Cond.Broadcast()
		c.Mu.Unlock()
		return nil, err
	}

	nodes := make([]map[string]interface{}, 0, len(view.Members))
	for _, nid := range view.Members {
		if node, ok := st.nodes[nid]; ok {
			shard := &st.nodeShards[nid%NumNodeShards]
			shard.RLock()
			entry := map[string]interface{}{
				"node_id": node.ID,
				"address": protocol.Addr{Network: netID, Node: node.ID}.String(),
				"public":  node.Public,
			}
			if role, ok := view.MemberRoles[nid]; ok {
				entry["role"] = role
			}
			if mt, ok := view.MemberTags[nid]; ok && len(mt) > 0 {
				entry["member_tags"] = mt
			}
			if node.Hostname != "" {
				entry["hostname"] = node.Hostname
			}
			if node.TaskExec {
				entry["task_exec"] = true
			}
			if node.Public {
				entry["real_addr"] = node.RealAddr
			}
			if len(node.Tags) > 0 {
				entry["tags"] = node.Tags
			}
			if node.ExternalID != "" {
				entry["external_id"] = node.ExternalID
			}
			if node.Version != "" {
				entry["version"] = node.Version
			}
			entry["last_seen"] = node.GetLastSeen().Format(time.RFC3339)
			shard.RUnlock()
			nodes = append(nodes, entry)
		} else {
			entry := map[string]interface{}{
				"node_id": nid,
				"address": protocol.Addr{Network: netID, Node: nid}.String(),
				"offline": true,
			}
			if role, ok := view.MemberRoles[nid]; ok {
				entry["role"] = role
			}
			if mt, ok := view.MemberTags[nid]; ok && len(mt) > 0 {
				entry["member_tags"] = mt
			}
			nodes = append(nodes, entry)
		}
	}
	st.mu.RUnlock()

	nodesRaw, marshalErr := json.Marshal(nodes)
	var fullBody []byte
	if marshalErr == nil {
		fullBody = wrapListNodesBody(nodesRaw)
	}

	c.Mu.Lock()
	c.LastBuildErr = nil
	if marshalErr == nil {
		c.FullBody = fullBody
		c.BuiltAt = time.Now()
	} else {
		c.LastBuildErr = fmt.Errorf("list_nodes marshal: %w", marshalErr)
	}
	c.Building = false
	c.Cond.Broadcast()
	c.Mu.Unlock()

	if marshalErr != nil {
		return nil, fmt.Errorf("list_nodes marshal: %w", marshalErr)
	}
	return fullBody, nil
}

// AdminListNodesCached returns the FULL pre-marshalled admin list_nodes response.
func (st *Store) AdminListNodesCached() ([]byte, error) {
	c := st.listNodesCache

	c.Mu.Lock()
	if c.FullBody != nil && time.Since(c.BuiltAt) < AdminListNodesTTL {
		body := c.FullBody
		c.CacheHits++
		c.Mu.Unlock()
		return body, nil
	}
	if c.Building {
		for c.Building {
			c.Cond.Wait()
		}
		body := c.FullBody
		c.CacheWaits++
		c.Mu.Unlock()
		if body == nil {
			return nil, fmt.Errorf("list_nodes cache rebuild failed")
		}
		return body, nil
	}
	c.Building = true
	c.CacheRebuilds++
	c.Mu.Unlock()

	st.mu.RLock()
	nodes := make([]map[string]interface{}, 0, len(st.nodes))
	for _, node := range st.nodes {
		shard := &st.nodeShards[node.ID%NumNodeShards]
		shard.RLock()
		entry := map[string]interface{}{
			"node_id": node.ID,
			"address": protocol.Addr{Network: 0, Node: node.ID}.String(),
			"public":  node.Public,
		}
		if node.Hostname != "" {
			entry["hostname"] = node.Hostname
		}
		if node.TaskExec {
			entry["task_exec"] = true
		}
		if node.Public {
			entry["real_addr"] = node.RealAddr
		}
		if len(node.Tags) > 0 {
			entry["tags"] = node.Tags
		}
		if node.ExternalID != "" {
			entry["external_id"] = node.ExternalID
		}
		if node.Version != "" {
			entry["version"] = node.Version
		}
		entry["last_seen"] = node.GetLastSeen().Format(time.RFC3339)
		shard.RUnlock()
		nodes = append(nodes, entry)
	}
	st.mu.RUnlock()

	nodesRaw, marshalErr := json.Marshal(nodes)
	var fullBody []byte
	if marshalErr == nil {
		fullBody = wrapListNodesBody(nodesRaw)
	}

	c.Mu.Lock()
	if marshalErr == nil {
		c.FullBody = fullBody
		c.BuiltAt = time.Now()
	}
	c.Building = false
	c.Cond.Broadcast()
	c.Mu.Unlock()

	if marshalErr != nil {
		return nil, fmt.Errorf("list_nodes marshal: %w", marshalErr)
	}
	return fullBody, nil
}

// --------------------------------------------------------------------------
// Reaper
// --------------------------------------------------------------------------

// ReapStaleNodes removes nodes whose last heartbeat is older than threshold.
func (st *Store) ReapStaleNodes(threshold time.Time) {
	st.mu.Lock()
	defer st.mu.Unlock()

	nodeIDs := make([]uint32, 0, len(st.nodes))
	for id := range st.nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Slice(nodeIDs, func(i, j int) bool { return nodeIDs[i] < nodeIDs[j] })

	startIdx := 0
	for startIdx < len(nodeIDs) && nodeIDs[startIdx] < *st.reapCursor {
		startIdx++
	}

	processed := 0
	reaped := false
	for i := 0; i < len(nodeIDs) && processed < ReapChunkSize; i++ {
		idx := (startIdx + i) % len(nodeIDs)
		id := nodeIDs[idx]
		processed++

		node := st.nodes[id]
		lastSeen := node.GetLastSeen()
		if lastSeen.Before(threshold) {
			staleDuration := time.Since(lastSeen).Round(time.Second)
			slog.Info("registry reaping stale node", "node_id", id, "last_seen_ago", staleDuration)
			st.cb.Audit("node.reaped", "node_id", id, "reason", "stale_heartbeat",
				"last_seen_ago", staleDuration.String(), "networks", len(node.Networks))
			if node.Hostname != "" {
				delete(st.hostnameIdx, node.Hostname)
			}
			st.cleanupNode(id)
			delete(st.nodes, id)
			st.cb.InvalidateAdminListNodesCache()
			reaped = true
		}

		*st.reapCursor = id + 1
	}

	if processed >= len(nodeIDs) {
		*st.reapCursor = 0
	}

	if reaped {
		st.cb.Save()
	}
}

// --------------------------------------------------------------------------
// Handler: register / re-register
// --------------------------------------------------------------------------

// HandleRegister processes a register message.
func (st *Store) HandleRegister(
	msg map[string]interface{},
	remoteAddr string,
	verifyToken func(token string) (externalID string, err error),
	setExternalID func(nodeID uint32, externalID string),
) (map[string]interface{}, error) {
	clientAddr, _ := msg["listen_addr"].(string)
	listenAddr := sanitizeListenAddr(remoteAddr, clientAddr)
	owner, _ := msg["owner"].(string)
	hostname, _ := msg["hostname"].(string)
	clientVersion, _ := msg["version"].(string)
	identityToken, _ := msg["identity_token"].(string)

	var externalID string
	if identityToken != "" && verifyToken != nil {
		var err error
		externalID, err = verifyToken(identityToken)
		if err != nil {
			return nil, err
		}
	}

	// Warn if client reports a newer protocol version than the server supports.
	if clientVer, ok := msg["protocol_version"]; ok {
		if cv, ok := clientVer.(float64); ok && int(cv) > int(protocol.Version) {
			slog.Warn("client protocol version newer than server",
				"client_version", int(cv),
				"server_version", protocol.Version,
				"remote", remoteAddr)
		}
	}

	var lanAddrs []string
	if rawAddrs, ok := msg["lan_addrs"].([]interface{}); ok {
		for _, raw := range rawAddrs {
			if addr, ok := raw.(string); ok && addr != "" {
				lanAddrs = append(lanAddrs, addr)
			}
		}
	}

	relayOnly, _ := msg["relay_only"].(bool)

	pubKeyB64, ok := msg["public_key"].(string)
	if !ok || pubKeyB64 == "" {
		return nil, fmt.Errorf("registration requires public_key")
	}

	if hostname != "" {
		if err := ValidateHostname(hostname); err != nil {
			resp, regErr := st.HandleReRegister(pubKeyB64, listenAddr, owner, "", lanAddrs, clientVersion, relayOnly)
			if regErr != nil {
				return resp, regErr
			}
			st.cb.IncRegistrations()
			resp["hostname_error"] = err.Error()
			resp["observed_addr"] = listenAddr
			resp["protocol_version"] = int(protocol.Version)
			return resp, nil
		}
	}

	resp, err := st.HandleReRegister(pubKeyB64, listenAddr, owner, hostname, lanAddrs, clientVersion, relayOnly)
	if err == nil {
		st.cb.IncRegistrations()
		resp["observed_addr"] = listenAddr
		resp["protocol_version"] = int(protocol.Version)
		if externalID != "" && setExternalID != nil {
			var nid uint32
			switch v := resp["node_id"].(type) {
			case uint32:
				nid = v
			case float64:
				nid = uint32(v)
			}
			if nid != 0 {
				setExternalID(nid, externalID)
				resp["external_id"] = externalID
			}
		}
	}
	return resp, err
}

// HandleReRegister handles a node presenting an existing public key.
// Fast path for known-key reconnects; slow path for new nodes and index mutations.
func (st *Store) HandleReRegister(pubKeyB64, listenAddr, owner, hostname string, lanAddrs []string, version string, relayOnly bool) (map[string]interface{}, error) {
	pubKey, err := crypto.DecodePublicKey(pubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	// FAST PATH: shard-locked endpoint refresh for the common case.
	st.mu.RLock()
	fpNodeID, fpPubKeyKnown := st.pubKeyIdx[pubKeyB64]
	var fpNode *NodeInfo
	var fpNodeAlive bool
	if fpPubKeyKnown {
		if n, exists := st.nodes[fpNodeID]; exists {
			fpNode = n
			fpNodeAlive = true
		}
	}
	st.mu.RUnlock()

	if fpPubKeyKnown && fpNodeAlive {
		shard := &st.nodeShards[fpNodeID%NumNodeShards]
		shard.RLock()
		currentOwner := fpNode.Owner
		currentHostname := fpNode.Hostname
		shard.RUnlock()

		ownerNeedsIndex := owner != "" && currentOwner == ""
		hostnameNeedsIndex := hostname != "" && hostname != currentHostname

		if !ownerNeedsIndex && !hostnameNeedsIndex {
			now := time.Now()
			shard.Lock()
			fpNode.RealAddr = listenAddr
			fpNode.LastSeenNano.Store(now.UnixNano())
			fpNode.LANAddrs = lanAddrs
			if version != "" {
				fpNode.Version = version
			}
			fpNode.RelayOnly = relayOnly
			shard.Unlock()

			addr := protocol.Addr{Network: 0, Node: fpNodeID}
			resp := map[string]interface{}{
				"type":       "register_ok",
				"node_id":    fpNodeID,
				"network_id": 0,
				"address":    addr.String(),
				"public_key": pubKeyB64,
			}
			if currentHostname != "" {
				resp["hostname"] = currentHostname
			}
			st.cb.Save()
			slog.Debug("registered node", "node_id", fpNodeID, "listen", listenAddr, "addr", addr, "mode", "fast_path_endpoint_refresh")
			st.cb.Audit("node.re_registered", "node_id", fpNodeID, "mode", "fast_path_endpoint_refresh")
			return resp, nil
		}
	}

	// SLOW PATH: global write lock.
	st.mu.Lock()
	defer st.mu.Unlock()

	if nodeID, ok := st.pubKeyIdx[pubKeyB64]; ok {
		if node, exists := st.nodes[nodeID]; exists {
			sh := st.nodeShard(nodeID)
			sh.Lock()
			node.RealAddr = listenAddr
			node.SetLastSeen(time.Now())
			node.LANAddrs = lanAddrs
			if version != "" {
				node.Version = version
			}
			node.RelayOnly = relayOnly
			if owner != "" && node.Owner == "" {
				node.Owner = owner
				st.ownerIdx[owner] = nodeID
			}
			sh.Unlock()

			addr := protocol.Addr{Network: 0, Node: nodeID}
			resp := map[string]interface{}{
				"type":       "register_ok",
				"node_id":    nodeID,
				"network_id": 0,
				"address":    addr.String(),
				"public_key": pubKeyB64,
			}
			st.setNodeHostname(node, hostname, resp)
			st.cb.Save()
			slog.Debug("registered node", "node_id", nodeID, "listen", listenAddr, "addr", addr, "mode", "existing_identity")
			st.cb.Audit("node.re_registered", "node_id", nodeID, "mode", "existing_identity")
			return resp, nil
		}

		// Node reaped but key known — reclaim same ID.
		// Restore network memberships by scanning which networks still list this node.
		networks := []uint16{0}
		if st.cb.ScanNetworkMemberships != nil {
			for _, netID := range st.cb.ScanNetworkMemberships(nodeID) {
				networks = append(networks, netID)
			}
		}
		now := time.Now()
		node := &NodeInfo{
			ID:        nodeID,
			Owner:     owner,
			PublicKey: pubKey,
			RealAddr:  listenAddr,
			Networks:  networks,
			LastSeen:  now,
			LANAddrs:  lanAddrs,
			KeyMeta:   KeyInfo{CreatedAt: now},
			Version:   version,
			RelayOnly: relayOnly,
		}
		node.LastSeenNano.Store(now.UnixNano())
		st.nodes[nodeID] = node
		st.cb.InvalidateAdminListNodesCache()
		if owner != "" {
			st.ownerIdx[owner] = nodeID
		}
		// Ensure backbone membership (may already be there if reaped node was never kicked).
		if st.cb.AddNodeToBackbone != nil {
			st.cb.AddNodeToBackbone(nodeID)
		}
		addr := protocol.Addr{Network: 0, Node: nodeID}
		resp := map[string]interface{}{
			"type":       "register_ok",
			"node_id":    nodeID,
			"network_id": 0,
			"address":    addr.String(),
			"public_key": pubKeyB64,
		}
		st.setNodeHostname(node, hostname, resp)
		st.cb.Save()
		slog.Debug("registered node", "node_id", nodeID, "listen", listenAddr, "addr", addr, "mode", "reclaimed_identity")
		st.cb.Audit("node.re_registered", "node_id", nodeID, "mode", "reclaimed_identity")
		return resp, nil
	}

	// Owner-based reclaim
	if owner != "" {
		if existingID, ok := st.ownerIdx[owner]; ok {
			if existingNode, exists := st.nodes[existingID]; exists {
				oldPubKeyB64 := crypto.EncodePublicKey(existingNode.PublicKey)
				delete(st.pubKeyIdx, oldPubKeyB64)
				sh := st.nodeShard(existingID)
				sh.Lock()
				existingNode.PublicKey = pubKey
				existingNode.RealAddr = listenAddr
				existingNode.SetLastSeen(time.Now())
				existingNode.LANAddrs = lanAddrs
				if version != "" {
					existingNode.Version = version
				}
				existingNode.RelayOnly = relayOnly
				sh.Unlock()
				st.pubKeyIdx[pubKeyB64] = existingID

				addr := protocol.Addr{Network: 0, Node: existingID}
				resp := map[string]interface{}{
					"type":       "register_ok",
					"node_id":    existingID,
					"network_id": 0,
					"address":    addr.String(),
					"public_key": pubKeyB64,
				}
				st.setNodeHostname(existingNode, hostname, resp)
				st.cb.Save()
				slog.Debug("registered node", "node_id", existingID, "listen", listenAddr, "addr", addr, "mode", "owner_key_update")
				st.cb.Audit("node.re_registered", "node_id", existingID, "mode", "owner_key_update")
				return resp, nil
			}

			// Owner node reaped — reclaim with new key
			st.pubKeyIdx[pubKeyB64] = existingID
			now := time.Now()
			node := &NodeInfo{
				ID:        existingID,
				Owner:     owner,
				PublicKey: pubKey,
				RealAddr:  listenAddr,
				Networks:  []uint16{0},
				LastSeen:  now,
				LANAddrs:  lanAddrs,
				KeyMeta:   KeyInfo{CreatedAt: now},
				Version:   version,
				RelayOnly: relayOnly,
			}
			node.LastSeenNano.Store(now.UnixNano())
			st.nodes[existingID] = node
			st.cb.InvalidateAdminListNodesCache()
			if st.cb.AddNodeToBackbone != nil {
				st.cb.AddNodeToBackbone(existingID)
			}
			addr := protocol.Addr{Network: 0, Node: existingID}
			resp := map[string]interface{}{
				"type":       "register_ok",
				"node_id":    existingID,
				"network_id": 0,
				"address":    addr.String(),
				"public_key": pubKeyB64,
			}
			st.setNodeHostname(node, hostname, resp)
			st.cb.Save()
			slog.Debug("registered node", "node_id", existingID, "listen", listenAddr, "addr", addr, "mode", "owner_reclaim")
			st.cb.Audit("node.re_registered", "node_id", existingID, "mode", "owner_reclaim")
			return resp, nil
		}
	}

	// New node
	if *st.maxNodes > 0 && len(st.nodes) >= *st.maxNodes {
		return nil, fmt.Errorf("registry full")
	}
	if *st.nextNode == 0 {
		return nil, fmt.Errorf("node ID space exhausted")
	}
	nodeID := *st.nextNode
	*st.nextNode++

	st.pubKeyIdx[pubKeyB64] = nodeID
	if owner != "" {
		st.ownerIdx[owner] = nodeID
	}

	now := time.Now()
	node := &NodeInfo{
		ID:        nodeID,
		Owner:     owner,
		PublicKey: pubKey,
		RealAddr:  listenAddr,
		Networks:  []uint16{0},
		LastSeen:  now,
		LANAddrs:  lanAddrs,
		KeyMeta:   KeyInfo{CreatedAt: now},
		Version:   version,
		RelayOnly: relayOnly,
	}
	node.LastSeenNano.Store(now.UnixNano())
	st.nodes[nodeID] = node
	st.cb.InvalidateAdminListNodesCache()
	if st.cb.AddNodeToBackbone != nil {
		st.cb.AddNodeToBackbone(nodeID)
	}

	addr := protocol.Addr{Network: 0, Node: nodeID}
	resp := map[string]interface{}{
		"type":       "register_ok",
		"node_id":    nodeID,
		"network_id": 0,
		"address":    addr.String(),
		"public_key": pubKeyB64,
	}
	st.setNodeHostname(node, hostname, resp)
	createdAt := now.UTC().Format(time.RFC3339)
	st.cb.RecordWALRegister(nodeID, owner, pubKeyB64, listenAddr, node.Hostname, lanAddrs, version, createdAt)
	st.cb.Save()
	slog.Info("registered node", "node_id", nodeID, "listen", listenAddr, "addr", addr, "mode", "new_node")
	st.cb.Audit("node.registered", "node_id", nodeID, "mode", "new_node")
	return resp, nil
}

// --------------------------------------------------------------------------
// Handler: lookup
// --------------------------------------------------------------------------

// HandleLookup handles a lookup message.
func (st *Store) HandleLookup(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")

	st.mu.RLock()
	node, ok := st.nodes[nodeID]
	st.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	sh := st.nodeShard(nodeID)
	sh.RLock()
	defer sh.RUnlock()

	beaconAddr := ""
	if st.cb.BeaconAddr != nil {
		beaconAddr = st.cb.BeaconAddr()
	}

	resp := map[string]interface{}{
		"type":       "lookup_ok",
		"node_id":    node.ID,
		"address":    protocol.Addr{Network: 0, Node: node.ID}.String(),
		"networks":   node.Networks,
		"public_key": crypto.EncodePublicKey(node.PublicKey),
		"public":     node.Public,
	}
	if node.Hostname != "" {
		resp["hostname"] = node.Hostname
	}
	if len(node.Tags) > 0 {
		resp["tags"] = node.Tags
	}
	if node.TaskExec {
		resp["task_exec"] = true
	}
	if node.Public {
		if node.RelayOnly {
			resp["real_addr"] = beaconAddr
			resp["endpoint"] = beaconAddr
			resp["relay_only"] = true
		} else {
			resp["real_addr"] = node.RealAddr
			resp["endpoint"] = node.RealAddr
		}
	}
	if node.ExternalID != "" {
		resp["external_id"] = node.ExternalID
	}
	if node.Version != "" {
		resp["version"] = node.Version
	}
	return resp, nil
}

// --------------------------------------------------------------------------
// Handler: binary lookup
// --------------------------------------------------------------------------

// HandleBinaryLookup processes a native binary lookup request.
func (st *Store) HandleBinaryLookup(conn net.Conn, payload []byte) {
	nodeID, err := wire.DecodeLookupReq(payload)
	if err != nil {
		wire.WriteFrame(conn, wire.MsgError, wire.EncodeError(err.Error()))
		return
	}

	start := time.Now()
	st.cb.IncRequestsTotal("lookup")
	defer func() {
		st.cb.ObserveRequestDuration("lookup", time.Since(start).Seconds())
	}()

	st.mu.RLock()
	node, ok := st.nodes[nodeID]
	st.mu.RUnlock()
	if !ok {
		st.cb.IncErrorsTotal("lookup")
		wire.WriteFrame(conn, wire.MsgError, wire.EncodeError(fmt.Sprintf("node %d: not found", nodeID)))
		return
	}

	beaconAddr := ""
	if st.cb.BeaconAddr != nil {
		beaconAddr = st.cb.BeaconAddr()
	}

	sh := st.nodeShard(nodeID)
	sh.RLock()
	realAddr := ""
	if node.Public {
		if node.RelayOnly {
			realAddr = beaconAddr
		} else {
			realAddr = node.RealAddr
		}
	}
	resp := wire.EncodeLookupResp(
		node.ID, node.Public, node.TaskExec,
		node.Networks, node.PublicKey, node.Hostname, node.Tags,
		realAddr, node.ExternalID,
	)
	sh.RUnlock()

	wire.WriteFrame(conn, wire.MsgLookupOK, resp)
}

// --------------------------------------------------------------------------
// Handler: resolve
// --------------------------------------------------------------------------

// HandleResolve handles a resolve message.
func (st *Store) HandleResolve(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	requesterID := jsonUint32(msg, "requester_id")

	st.mu.RLock()
	requester, ok := st.nodes[requesterID]
	if !ok {
		st.mu.RUnlock()
		return nil, fmt.Errorf("resolve denied: requester node %d is not registered", requesterID)
	}
	requesterPubKey := requester.PublicKey
	adminToken := st.cb.AdminToken()
	st.mu.RUnlock()

	if err := st.cb.VerifyNodeSignature(requesterPubKey, adminToken, msg, fmt.Sprintf("resolve:%d:%d", requesterID, nodeID)); err != nil {
		return nil, err
	}

	st.mu.RLock()
	requester, ok = st.nodes[requesterID]
	if !ok {
		st.mu.RUnlock()
		return nil, fmt.Errorf("resolve denied: requester node %d is not registered", requesterID)
	}
	node, ok := st.nodes[nodeID]
	if !ok {
		st.mu.RUnlock()
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}
	trustOK := st.cb.IsTrusted(requesterID, nodeID)

	if !node.Public {
		allowed := trustOK
		if !allowed {
			for _, rNet := range requester.Networks {
				if rNet == 0 {
					continue
				}
				for _, tNet := range node.Networks {
					if rNet == tNet {
						allowed = true
						break
					}
				}
				if allowed {
					break
				}
			}
		}
		if !allowed {
			st.mu.RUnlock()
			return nil, fmt.Errorf("resolve denied: node %d is private (establish mutual trust first)", nodeID)
		}
	}
	st.mu.RUnlock()

	beaconAddr := ""
	if st.cb.BeaconAddr != nil {
		beaconAddr = st.cb.BeaconAddr()
	}

	tSh := st.nodeShard(nodeID)
	tSh.RLock()
	defer tSh.RUnlock()

	realAddr := node.RealAddr
	lanAddrs := node.LANAddrs
	relayOnly := node.RelayOnly
	if relayOnly {
		realAddr = beaconAddr
		lanAddrs = nil
	}

	resp := map[string]interface{}{
		"type":      "resolve_ok",
		"node_id":   node.ID,
		"real_addr": realAddr,
	}
	if len(lanAddrs) > 0 {
		resp["lan_addrs"] = lanAddrs
	}
	if relayOnly {
		resp["relay_only"] = true
	}

	keyStart := node.KeyMeta.CreatedAt
	if !node.KeyMeta.RotatedAt.IsZero() {
		keyStart = node.KeyMeta.RotatedAt
	}
	if !keyStart.IsZero() {
		resp["key_age_days"] = int(time.Since(keyStart).Hours() / 24)
	}

	return resp, nil
}

// --------------------------------------------------------------------------
// Handler: binary resolve
// --------------------------------------------------------------------------

// HandleBinaryResolve processes a native binary resolve request.
func (st *Store) HandleBinaryResolve(conn net.Conn, payload []byte) {
	nodeID, requesterID, sig, err := wire.DecodeResolveReq(payload)
	if err != nil {
		wire.WriteFrame(conn, wire.MsgError, wire.EncodeError(err.Error()))
		return
	}

	start := time.Now()
	st.cb.IncRequestsTotal("resolve")
	defer func() {
		st.cb.ObserveRequestDuration("resolve", time.Since(start).Seconds())
	}()

	st.mu.RLock()
	requester, ok := st.nodes[requesterID]
	if !ok {
		st.mu.RUnlock()
		st.cb.IncErrorsTotal("resolve")
		wire.WriteFrame(conn, wire.MsgError, wire.EncodeError(fmt.Sprintf("resolve denied: requester node %d is not registered", requesterID)))
		return
	}
	requesterPubKey := requester.PublicKey
	st.mu.RUnlock()

	if requesterPubKey == nil {
		st.cb.IncErrorsTotal("resolve")
		wire.WriteFrame(conn, wire.MsgError, wire.EncodeError("requester has no public key"))
		return
	}
	challenge := fmt.Sprintf("resolve:%d:%d", requesterID, nodeID)
	if !crypto.Verify(requesterPubKey, []byte(challenge), sig) {
		st.cb.IncErrorsTotal("resolve")
		wire.WriteFrame(conn, wire.MsgError, wire.EncodeError("signature verification failed"))
		return
	}

	st.mu.RLock()
	requester, ok = st.nodes[requesterID]
	if !ok {
		st.mu.RUnlock()
		st.cb.IncErrorsTotal("resolve")
		wire.WriteFrame(conn, wire.MsgError, wire.EncodeError(fmt.Sprintf("resolve denied: requester node %d is not registered", requesterID)))
		return
	}
	node, ok := st.nodes[nodeID]
	if !ok {
		st.mu.RUnlock()
		st.cb.IncErrorsTotal("resolve")
		wire.WriteFrame(conn, wire.MsgError, wire.EncodeError(fmt.Sprintf("node %d: not found", nodeID)))
		return
	}
	trustOK := st.cb.IsTrusted(requesterID, nodeID)
	st.mu.RUnlock()

	rSh := st.nodeShard(requesterID)
	rSh.RLock()
	requesterNetworks := make([]uint16, len(requester.Networks))
	copy(requesterNetworks, requester.Networks)
	rSh.RUnlock()

	tSh := st.nodeShard(nodeID)
	tSh.RLock()

	if !node.Public {
		allowed := trustOK
		if !allowed {
			for _, rNet := range requesterNetworks {
				if rNet == 0 {
					continue
				}
				for _, tNet := range node.Networks {
					if rNet == tNet {
						allowed = true
						break
					}
				}
				if allowed {
					break
				}
			}
		}
		if !allowed {
			tSh.RUnlock()
			st.cb.IncErrorsTotal("resolve")
			wire.WriteFrame(conn, wire.MsgError, wire.EncodeError(fmt.Sprintf("resolve denied: node %d is private (establish mutual trust first)", nodeID)))
			return
		}
	}

	keyAgeDays := -1
	keyStart := node.KeyMeta.CreatedAt
	if !node.KeyMeta.RotatedAt.IsZero() {
		keyStart = node.KeyMeta.RotatedAt
	}
	if !keyStart.IsZero() {
		keyAgeDays = int(time.Since(keyStart).Hours() / 24)
	}

	beaconAddr := ""
	if st.cb.BeaconAddr != nil {
		beaconAddr = st.cb.BeaconAddr()
	}

	respRealAddr := node.RealAddr
	respLANAddrs := node.LANAddrs
	if node.RelayOnly {
		respRealAddr = beaconAddr
		respLANAddrs = nil
	}
	resp := wire.EncodeResolveResp(node.ID, respRealAddr, respLANAddrs, keyAgeDays)
	tSh.RUnlock()

	wire.WriteFrame(conn, wire.MsgResolveOK, resp)
}

// --------------------------------------------------------------------------
// Handler: resolve hostname
// --------------------------------------------------------------------------

// HandleResolveHostname resolves a node by its hostname.
func (st *Store) HandleResolveHostname(msg map[string]interface{}) (map[string]interface{}, error) {
	hostname, _ := msg["hostname"].(string)
	if hostname == "" {
		return nil, fmt.Errorf("hostname required")
	}

	st.mu.RLock()
	defer st.mu.RUnlock()

	nodeID, ok := st.hostnameIdx[hostname]
	if !ok {
		return nil, fmt.Errorf("hostname %q not found", hostname)
	}

	node, ok := st.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("hostname %q maps to missing node %d", hostname, nodeID)
	}

	if !node.Public {
		requesterID := jsonUint32(msg, "requester_id")
		allowed := false

		if requesterID == nodeID {
			allowed = true
		}
		if !allowed && st.cb.IsTrusted(requesterID, nodeID) {
			allowed = true
		}
		if !allowed {
			if requester, rOk := st.nodes[requesterID]; rOk {
				for _, rNet := range requester.Networks {
					if rNet == 0 {
						continue
					}
					for _, tNet := range node.Networks {
						if rNet == tNet {
							allowed = true
							break
						}
					}
					if allowed {
						break
					}
				}
			}
		}
		if !allowed {
			return nil, fmt.Errorf("hostname %q not found", hostname)
		}
	}

	return map[string]interface{}{
		"type":     "resolve_hostname_ok",
		"node_id":  node.ID,
		"address":  protocol.Addr{Network: 0, Node: node.ID}.String(),
		"public":   node.Public,
		"hostname": node.Hostname,
	}, nil
}

// --------------------------------------------------------------------------
// Handler: list nodes
// --------------------------------------------------------------------------

// HandleListNodes handles a list_nodes message.
func (st *Store) HandleListNodes(msg map[string]interface{}, requireAdminToken func(msg map[string]interface{}) error) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")

	if netID == 0 {
		if err := requireAdminToken(msg); err != nil {
			return nil, fmt.Errorf("listing backbone nodes is not permitted (use lookup with a specific node_id)")
		}
		body, err := st.AdminListNodesCached()
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{RawResponseKey: body}, nil
	}

	body, err := st.PerNetworkListNodesCached(netID)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{RawResponseKey: body}, nil
}

// --------------------------------------------------------------------------
// Handler: set visibility
// --------------------------------------------------------------------------

// HandleSetVisibility handles a set_visibility message.
func (st *Store) HandleSetVisibility(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	public, _ := msg["public"].(bool)

	st.mu.RLock()
	node, ok := st.nodes[nodeID]
	if !ok {
		st.mu.RUnlock()
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}
	pubKey := node.PublicKey
	adminToken := st.cb.AdminToken()
	st.mu.RUnlock()

	if sigErr := st.cb.VerifyNodeSignature(pubKey, adminToken, msg, fmt.Sprintf("set_visibility:%d", nodeID)); sigErr != nil {
		// Admin token bypass
		tok, _ := msg["admin_token"].(string)
		if adminToken == "" || tok != adminToken {
			return nil, sigErr
		}
	}

	st.mu.Lock()
	node, ok = st.nodes[nodeID]
	if !ok {
		st.mu.Unlock()
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}
	sh := st.nodeShard(nodeID)
	sh.Lock()
	oldPublic := node.Public
	node.Public = public
	st.cb.Save()
	sh.Unlock()
	st.mu.Unlock()

	visibility := "private"
	if public {
		visibility = "public"
	}
	slog.Info("node visibility changed", "node_id", nodeID, "visibility", visibility)
	st.cb.Audit("visibility.changed", "node_id", nodeID, "old_public", oldPublic, "new_public", public)

	return map[string]interface{}{
		"type":       "set_visibility_ok",
		"node_id":    nodeID,
		"visibility": visibility,
	}, nil
}

// --------------------------------------------------------------------------
// Handler: set hostname
// --------------------------------------------------------------------------

// HandleSetHostname handles a set_hostname message.
func (st *Store) HandleSetHostname(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	hostname, _ := msg["hostname"].(string)

	if err := ValidateHostname(hostname); err != nil {
		return nil, fmt.Errorf("invalid hostname: %w", err)
	}

	st.mu.RLock()
	node, ok := st.nodes[nodeID]
	if !ok {
		st.mu.RUnlock()
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}
	pubKey := node.PublicKey
	adminToken := st.cb.AdminToken()
	st.mu.RUnlock()

	if sigErr := st.cb.VerifyNodeSignature(pubKey, adminToken, msg, fmt.Sprintf("set_hostname:%d", nodeID)); sigErr != nil {
		tok, _ := msg["admin_token"].(string)
		if adminToken == "" || tok != adminToken {
			return nil, sigErr
		}
	}

	st.mu.Lock()
	node, ok = st.nodes[nodeID]
	if !ok {
		st.mu.Unlock()
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	if hostname != "" {
		if existingID, taken := st.hostnameIdx[hostname]; taken && existingID != nodeID {
			st.mu.Unlock()
			return nil, fmt.Errorf("hostname %q already in use by node %d", hostname, existingID)
		}
	}

	sh := st.nodeShard(nodeID)
	sh.Lock()
	oldHostname := node.Hostname
	if node.Hostname != "" {
		delete(st.hostnameIdx, node.Hostname)
	}
	node.Hostname = hostname
	if hostname != "" {
		st.hostnameIdx[hostname] = nodeID
	}
	st.cb.Save()
	sh.Unlock()
	st.mu.Unlock()

	slog.Debug("hostname set", "node_id", nodeID, "hostname", hostname)
	st.cb.Audit("hostname.changed", "node_id", nodeID, "old_hostname", oldHostname, "new_hostname", hostname)

	return map[string]interface{}{
		"type":     "set_hostname_ok",
		"node_id":  nodeID,
		"hostname": hostname,
	}, nil
}

// --------------------------------------------------------------------------
// Handler: set tags
// --------------------------------------------------------------------------

// HandleSetTags handles a set_tags message.
func (st *Store) HandleSetTags(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")

	var tags []string
	if rawTags, ok := msg["tags"].([]interface{}); ok {
		for _, rt := range rawTags {
			if t, ok := rt.(string); ok {
				tags = append(tags, t)
			}
		}
	}

	for i, t := range tags {
		if len(t) > 0 && t[0] == '#' {
			tags[i] = t[1:]
		}
	}

	seen := make(map[string]bool, len(tags))
	deduped := tags[:0]
	for _, t := range tags {
		if !seen[t] {
			seen[t] = true
			deduped = append(deduped, t)
		}
	}
	tags = deduped

	if len(tags) > 10 {
		return nil, fmt.Errorf("too many tags (max 10)")
	}
	for _, t := range tags {
		if len(t) == 0 {
			return nil, fmt.Errorf("empty tag not allowed")
		}
		if len(t) > 32 {
			return nil, fmt.Errorf("tag %q too long (max 32 chars)", t)
		}
		if !tagRegex.MatchString(t) {
			return nil, fmt.Errorf("tag %q must be lowercase alphanumeric with hyphens", t)
		}
	}

	st.mu.RLock()
	node, ok := st.nodes[nodeID]
	if !ok {
		st.mu.RUnlock()
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}
	pubKey := node.PublicKey
	adminToken := st.cb.AdminToken()
	st.mu.RUnlock()

	if sigErr := st.cb.VerifyNodeSignature(pubKey, adminToken, msg, fmt.Sprintf("set_tags:%d", nodeID)); sigErr != nil {
		tok, _ := msg["admin_token"].(string)
		if adminToken == "" || tok != adminToken {
			return nil, sigErr
		}
	}

	st.mu.Lock()
	node, ok = st.nodes[nodeID]
	if !ok {
		st.mu.Unlock()
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}
	sh := st.nodeShard(nodeID)
	sh.Lock()
	oldTags := node.Tags
	node.Tags = tags
	st.cb.Save()
	sh.Unlock()
	st.mu.Unlock()

	slog.Debug("tags set", "node_id", nodeID, "tags", tags)
	st.cb.Audit("tags.changed", "node_id", nodeID, "old_tags_count", len(oldTags), "new_tags_count", len(tags))

	return map[string]interface{}{
		"type":    "set_tags_ok",
		"node_id": nodeID,
		"tags":    tags,
	}, nil
}

// --------------------------------------------------------------------------
// Handler: deregister
// --------------------------------------------------------------------------

// HandleDeregister handles a deregister message.
// Cascade: removes from all networks (via callback), clears invite inbox,
// invalidates caches, records WAL, signals save.
func (st *Store) HandleDeregister(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")

	st.mu.Lock()
	defer st.mu.Unlock()

	node, ok := st.nodes[nodeID]
	if !ok {
		return map[string]interface{}{"type": "deregister_ok"}, nil
	}

	adminToken := st.cb.AdminToken()
	if sigErr := st.cb.VerifyNodeSignature(node.PublicKey, adminToken, msg, fmt.Sprintf("deregister:%d", nodeID)); sigErr != nil {
		if err := st.cb.RequireAdminTokenLocked(msg); err != nil {
			return nil, sigErr
		}
	}

	// Step 2: Remove from all networks (cascades into membership store via callback).
	// The callback also handles RBAC owner-lost tracking and per-network invalidation.
	lostOwnerNets := st.cb.RemoveFromNetworks(nodeID, node.Networks)

	// Invalidate caches for each network the node was in.
	for _, netID := range node.Networks {
		st.cb.InvalidateListNodesCache(netID)
		st.cb.PublishMembershipChanged(netID)
	}

	// Step 3: Clear invite inbox.
	st.cb.ClearInviteInbox(nodeID)

	// Step 1 (node map): clean indices, remove from map.
	if node.Hostname != "" {
		delete(st.hostnameIdx, node.Hostname)
	}
	st.cleanupNode(nodeID)
	delete(st.nodes, nodeID)
	st.cb.InvalidateAdminListNodesCache()

	// Steps 5-6: WAL + save.
	st.cb.RecordWALDeregister(nodeID)
	st.cb.Save()
	st.cb.IncDeregistrations()

	slog.Info("deregistered node", "node_id", nodeID, "networks", len(node.Networks))
	st.cb.Audit("node.deregistered", "node_id", nodeID, "networks", len(node.Networks))

	for _, netID := range lostOwnerNets {
		st.cb.Audit("network.owner_lost", "network_id", netID, "former_owner", nodeID)
	}

	return map[string]interface{}{
		"type": "deregister_ok",
	}, nil
}

// --------------------------------------------------------------------------
// Handler: heartbeat
// --------------------------------------------------------------------------

// HandleHeartbeat handles a JSON heartbeat message.
func (st *Store) HandleHeartbeat(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")

	st.mu.RLock()
	node, ok := st.nodes[nodeID]
	if !ok {
		st.mu.RUnlock()
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}
	pubKey := node.PublicKey
	expiresAt := node.KeyMeta.ExpiresAt
	adminToken := st.cb.AdminToken()
	st.mu.RUnlock()

	now := st.cb.Now()

	lastVerified := node.LastVerifiedNano.Load()
	skipVerify := lastVerified > 0 && (now.UnixNano()-lastVerified) < int64(120*time.Second)

	if !skipVerify {
		if err := st.cb.VerifyNodeSignature(pubKey, adminToken, msg, fmt.Sprintf("heartbeat:%d", nodeID)); err != nil {
			return nil, err
		}
		node.LastVerifiedNano.Store(now.UnixNano())
	}

	if !expiresAt.IsZero() && expiresAt.Before(now) {
		st.cb.Audit("key.expired_heartbeat_blocked", "node_id", nodeID)
		return nil, fmt.Errorf("node %d: key expired at %s", nodeID, expiresAt.Format(time.RFC3339))
	}

	node.LastSeenNano.Store(now.UnixNano())

	keyExpiryWarning := !expiresAt.IsZero() && expiresAt.Before(now.Add(24*time.Hour))
	return map[string]interface{}{
		RawResponseKey: buildHeartbeatOk(now.Unix(), keyExpiryWarning),
	}, nil
}

// --------------------------------------------------------------------------
// Handler: binary heartbeat
// --------------------------------------------------------------------------

// HandleBinaryHeartbeat processes a native binary heartbeat request.
func (st *Store) HandleBinaryHeartbeat(conn net.Conn, payload []byte) {
	req, err := wire.DecodeHeartbeatReq(payload)
	if err != nil {
		wire.WriteFrame(conn, wire.MsgError, wire.EncodeError(err.Error()))
		return
	}

	start := time.Now()
	st.cb.IncRequestsTotal("heartbeat")
	defer func() {
		st.cb.ObserveRequestDuration("heartbeat", time.Since(start).Seconds())
	}()

	st.mu.RLock()
	node, ok := st.nodes[req.NodeID]
	if !ok {
		st.mu.RUnlock()
		st.cb.IncErrorsTotal("heartbeat")
		wire.WriteFrame(conn, wire.MsgError, wire.EncodeError(fmt.Sprintf("node %d: not found", req.NodeID)))
		return
	}
	pubKey := node.PublicKey
	expiresAt := node.KeyMeta.ExpiresAt
	st.mu.RUnlock()

	now := st.cb.Now()

	lastVerified := node.LastVerifiedNano.Load()
	skipVerify := lastVerified > 0 && (now.UnixNano()-lastVerified) < int64(120*time.Second)

	if !skipVerify {
		if pubKey == nil {
			st.cb.IncErrorsTotal("heartbeat")
			wire.WriteFrame(conn, wire.MsgError, wire.EncodeError("node has no public key: binary heartbeat requires key"))
			return
		}
		challenge := fmt.Sprintf("heartbeat:%d", req.NodeID)
		if !crypto.Verify(pubKey, []byte(challenge), req.Signature[:]) {
			st.cb.IncErrorsTotal("heartbeat")
			wire.WriteFrame(conn, wire.MsgError, wire.EncodeError("signature verification failed"))
			return
		}
		node.LastVerifiedNano.Store(now.UnixNano())
	}

	if !expiresAt.IsZero() && expiresAt.Before(now) {
		st.cb.IncErrorsTotal("heartbeat")
		wire.WriteFrame(conn, wire.MsgError, wire.EncodeError(fmt.Sprintf("node %d: key expired at %s", req.NodeID, expiresAt.Format(time.RFC3339))))
		return
	}

	node.LastSeenNano.Store(now.UnixNano())

	keyExpiryWarning := !expiresAt.IsZero() && expiresAt.Before(now.Add(24*time.Hour))
	wire.WriteFrame(conn, wire.MsgHeartbeatOK, wire.EncodeHeartbeatResp(now.Unix(), keyExpiryWarning))
}

// --------------------------------------------------------------------------
// Heartbeat response builder
// --------------------------------------------------------------------------

var (
	heartbeatOkPrefixNoWarn   = []byte(`{"time":`)
	heartbeatOkPrefixWithWarn = []byte(`{"key_expiry_warning":true,"time":`)
	heartbeatOkSuffix         = []byte(`,"type":"heartbeat_ok"}`)
)

func buildHeartbeatOk(timeUnix int64, keyExpiryWarning bool) []byte {
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

// --------------------------------------------------------------------------
// sanitizeListenAddr
// --------------------------------------------------------------------------

func sanitizeListenAddr(remoteAddr, clientAddr string) string {
	if clientAddr == "" {
		return remoteAddr
	}
	host, port, err := net.SplitHostPort(clientAddr)
	if err != nil {
		return clientAddr
	}
	ip := net.ParseIP(host)
	// Replace wildcard or private/loopback/link-local IPs with the registry-
	// observed TCP source IP. Keep the client-reported port (the daemon's UDP
	// listen port, which differs from the ephemeral TCP source port).
	if host == "" || host == "0.0.0.0" || host == "::" ||
		(ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())) {
		remoteHost, _, _ := net.SplitHostPort(remoteAddr)
		if remoteHost != "" {
			return net.JoinHostPort(remoteHost, port)
		}
	}
	return clientAddr
}

// suppress unused import warning for atomic
var _ = (*atomic.Int64)(nil)

// ReplaceState atomically swaps the directory's node maps and indices with the
// provided replacement values. Called by the server after a replication snapshot
// is applied so the directory's pointers don't go stale. Must be called with
// s.mu held (Lock).
func (st *Store) ReplaceState(
	nodes map[uint32]*NodeInfo,
	pubKeyIdx map[string]uint32,
	ownerIdx map[string]uint32,
	hostnameIdx map[string]uint32,
) {
	st.nodes = nodes
	st.pubKeyIdx = pubKeyIdx
	st.ownerIdx = ownerIdx
	st.hostnameIdx = hostnameIdx
}

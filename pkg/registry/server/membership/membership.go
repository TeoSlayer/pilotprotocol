// SPDX-License-Identifier: AGPL-3.0-or-later

// Package membership implements the registry's network membership handlers:
// create, delete, rename, join, leave, invite, kick, promote, demote,
// transfer-ownership, role query, member-tags, task-exec, and list-networks.
// It is extracted from pkg/registry/server as part of the R4.1 registry
// decomposition.
//
// Thread safety: all exported Handler* methods are safe for concurrent use.
// Locking is delegated to the server through mu (shared with Server) and
// callback functions that acquire whatever locks are needed internally.
package membership

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

// --------------------------------------------------------------------------
// Types
// --------------------------------------------------------------------------

// Role represents a member's permission level within a network.
type Role string

const (
	RoleOwner  Role = "owner"  // created the network, full control
	RoleAdmin  Role = "admin"  // can invite, remove members, change settings
	RoleMember Role = "member" // can communicate, cannot manage
)

// NetworkPolicy defines constraints and metadata for a network.
type NetworkPolicy struct {
	MaxMembers   int      `json:"max_members"`
	AllowedPorts []uint16 `json:"allowed_ports"`
	Description  string   `json:"description"`
}

// NetworkInfo holds the in-memory state for a single network.
type NetworkInfo struct {
	ID           uint16
	Name         string
	JoinRule     string
	Token        string // for token-gated networks
	Members      []uint32
	MemberRoles  map[uint32]Role     // per-member RBAC roles
	MemberTags   map[uint32][]string // admin-assigned per-member tags (e.g. "service")
	AdminToken   string              // per-network admin token (optional)
	Policy       NetworkPolicy       // network policy (membership limits, port restrictions)
	Rules        *wire.NetworkRules  // managed network rules (nil = normal network)
	ExprPolicy   json.RawMessage     // programmable policy engine document (nil = none)
	Enterprise   bool                // enterprise network (gates Phase 2-5 features)
	Created      time.Time
	RequestCount atomic.Int64 // per-network request counter (dashboard stats)
}

// NetworkInvite is a pending network invitation stored in the invite inbox.
type NetworkInvite struct {
	NetworkID uint16    `json:"network_id"`
	InviterID uint32    `json:"inviter_id"`
	Timestamp time.Time `json:"timestamp"`
}

const (
	// MaxInviteInbox limits the number of pending invites per node.
	MaxInviteInbox = 100
	// InviteTTL is the maximum age of a pending invite.
	InviteTTL = 30 * 24 * time.Hour
)

// networkNameRegex validates network name format: lowercase alphanumeric + hyphens, 1-63 chars.
var networkNameRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// reservedNetworkNames are not allowed as network names.
var reservedNetworkNames = map[string]bool{
	"backbone": true,
}

// tagRegex validates tag format: lowercase alphanumeric + hyphens, 1-32 chars.
var tagRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// ValidateNetworkName checks that a network name is valid.
func ValidateNetworkName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("network name required")
	}
	if len(name) > 63 {
		return fmt.Errorf("network name too long (max 63 chars)")
	}
	if !networkNameRegex.MatchString(name) {
		return fmt.Errorf("network name must be lowercase alphanumeric with hyphens, start/end with alphanumeric")
	}
	if reservedNetworkNames[name] {
		return fmt.Errorf("network name %q is reserved", name)
	}
	return nil
}

// --------------------------------------------------------------------------
// Callbacks & Store
// --------------------------------------------------------------------------

// Callbacks bundles the side-effect functions the Store calls on state changes.
// All functions must be safe for concurrent use.
type Callbacks struct {
	// Save triggers a debounced snapshot write.
	Save func()
	// Audit records an audit log entry.
	Audit func(action string, attrs ...any)
	// RecordWALNetworkCreate records a network-create WAL entry.
	RecordWALNetworkCreate func(netID uint16, name, joinRule, token, adminToken string, enterprise bool, creatorNodeID uint32, createdAt string)
	// RecordWALNetworkJoin records a network-join WAL entry.
	RecordWALNetworkJoin func(nodeID uint32, netID uint16)
	// RecordWALNetworkLeave records a network-leave WAL entry.
	RecordWALNetworkLeave func(nodeID uint32, netID uint16)
	// RecordWALNetworkDelete records a network-delete WAL entry.
	RecordWALNetworkDelete func(netID uint16)
	// InvalidateListNodesCache drops the per-network list_nodes cache.
	InvalidateListNodesCache func(netID uint16)
	// PublishMembershipChanged publishes a membership.changed bus event.
	PublishMembershipChanged func(netID uint16)
	// ApplyRBACPreAssignment checks and applies any pre-assigned roles.
	// Caller must hold the global write lock.
	ApplyRBACPreAssignment func(netID uint16, nodeID uint32)
	// RequireAdminToken validates the admin_token field in a message.
	RequireAdminToken func(msg map[string]interface{}) error
	// RequireNetworkRole checks RBAC role for network operations.
	RequireNetworkRole func(msg map[string]interface{}, netID uint16, roles ...Role) error
	// RequireEnterprise checks that the given network has the Enterprise flag.
	RequireEnterprise func(netID uint16) error
	// VerifyNodeSignature verifies an Ed25519 signature for a node write.
	// Takes pubKey and adminToken (already copied under RLock by caller).
	VerifyNodeSignature func(pubKey []byte, adminToken string, msg map[string]interface{}, challenge string) error
	// AdminToken returns the current admin token (caller must not hold write lock).
	AdminToken func() string
	// NodeExists returns true if nodeID is registered. Caller must hold mu.RLock
	// or mu.Lock before calling.
	NodeExists func(nodeID uint32) bool
	// GetNodeForRead returns node fields needed before write lock.
	// Returns (pubKey, ok). Caller must hold mu.RLock.
	GetNodePubKey func(nodeID uint32) (pubKey []byte, ok bool)
	// GetNode returns a node's key fields. Caller must hold mu (read or write).
	GetNode func(nodeID uint32) (pubKey []byte, networks []uint16, externalID string, ok bool)
	// NodeNetworks returns a copy of node.Networks. Caller must hold mu.
	NodeNetworks func(nodeID uint32) ([]uint16, bool)
	// AppendNodeNetwork appends netID to the node's Networks slice under its shard lock.
	// Caller must hold mu.Lock.
	AppendNodeNetwork func(nodeID uint32, netID uint16)
	// RemoveNodeNetwork removes netID from the node's Networks slice under its shard lock.
	// Caller must hold mu.Lock. Returns false if the node was not in the network.
	RemoveNodeNetwork func(nodeID uint32, netID uint16) bool
	// IncInvitesSent increments the invites_sent_total counter.
	IncInvitesSent func()
	// IncInvitesAccepted increments the invites_accepted_total counter.
	IncInvitesAccepted func()
	// IncInvitesRejected increments the invites_rejected_total counter.
	IncInvitesRejected func()
	// IncRbacOps increments the rbac_operations_total{op=label} counter.
	IncRbacOps func(op string)
}

// Store holds membership handler logic. The actual data maps (networks,
// inviteInbox, nextNet) are owned by the parent server and shared via the
// mu pointer. This is intentional for the R4.1 phase — locking semantics
// are preserved by using the same mutex as the server.
type Store struct {
	mu          *sync.RWMutex // SHARED with Server
	networks    map[uint16]*NetworkInfo
	inviteInbox map[uint32][]*NetworkInvite
	nextNet     *uint16 // pointer into Server.nextNet — mutations propagate back
	cb          Callbacks
	now         func() time.Time
}

// NewStore creates a ready-to-use membership Store. All pointer parameters
// are shared with the parent server and must not be nil.
func NewStore(
	mu *sync.RWMutex,
	networks map[uint16]*NetworkInfo,
	inviteInbox map[uint32][]*NetworkInvite,
	nextNet *uint16,
	cb Callbacks,
	now func() time.Time,
) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{
		mu:          mu,
		networks:    networks,
		inviteInbox: inviteInbox,
		nextNet:     nextNet,
		cb:          cb,
		now:         now,
	}
}

// --------------------------------------------------------------------------
// JSON helpers (private; duplicated from server to avoid import cycle)
// --------------------------------------------------------------------------

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
		if v < 0 || v > 65535 {
			return 0
		}
		return uint16(v)
	}
	return 0
}

// --------------------------------------------------------------------------
// Handlers
// --------------------------------------------------------------------------

// HandleCreateNetwork implements the "create_network" protocol command.
func (st *Store) HandleCreateNetwork(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := st.cb.RequireAdminToken(msg); err != nil {
		return nil, err
	}

	nodeID := jsonUint32(msg, "node_id")
	name, _ := msg["name"].(string)
	joinRule, _ := msg["join_rule"].(string)
	token, _ := msg["token"].(string)
	networkAdminToken, _ := msg["network_admin_token"].(string)
	enterprise, _ := msg["enterprise"].(bool)

	var rules *wire.NetworkRules
	if rulesRaw, ok := msg["rules"].(string); ok && rulesRaw != "" {
		var err error
		rules, err = wire.ParseRules(rulesRaw)
		if err != nil {
			return nil, err
		}
	} else if rulesMap, ok := msg["rules"].(map[string]interface{}); ok {
		b, _ := json.Marshal(rulesMap)
		var err error
		rules, err = wire.ParseRules(string(b))
		if err != nil {
			return nil, err
		}
	}

	var exprPolicy json.RawMessage
	if v, ok := msg["expr_policy"].(string); ok && v != "" {
		exprPolicy = json.RawMessage(v)
		var check struct {
			Version int `json:"version"`
		}
		if err := json.Unmarshal(exprPolicy, &check); err != nil {
			return nil, fmt.Errorf("expr_policy: invalid JSON: %w", err)
		}
		if check.Version != 1 {
			return nil, fmt.Errorf("expr_policy: unsupported version %d (want 1)", check.Version)
		}
	} else if v, ok := msg["expr_policy"].(map[string]interface{}); ok {
		b, _ := json.Marshal(v)
		exprPolicy = json.RawMessage(b)
		var check struct {
			Version int `json:"version"`
		}
		if err := json.Unmarshal(exprPolicy, &check); err != nil {
			return nil, fmt.Errorf("expr_policy: invalid JSON: %w", err)
		}
		if check.Version != 1 {
			return nil, fmt.Errorf("expr_policy: unsupported version %d (want 1)", check.Version)
		}
	}

	if err := ValidateNetworkName(name); err != nil {
		return nil, err
	}
	if joinRule == "" {
		joinRule = "open"
	}

	if joinRule == "invite" && !enterprise {
		return nil, fmt.Errorf("enterprise feature: invite-only networks require the enterprise flag")
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if !st.cb.NodeExists(nodeID) {
		return nil, fmt.Errorf("node %d not registered", nodeID)
	}

	if *st.nextNet == 0 {
		return nil, fmt.Errorf("network ID space exhausted (max 65535 networks)")
	}

	for _, n := range st.networks {
		if n.Name == name {
			return nil, fmt.Errorf("network %q already exists", name)
		}
	}

	netID := *st.nextNet
	*st.nextNet++

	net := &NetworkInfo{
		ID:          netID,
		Name:        name,
		JoinRule:    joinRule,
		Token:       token,
		Members:     []uint32{nodeID},
		MemberRoles: map[uint32]Role{nodeID: RoleOwner},
		MemberTags:  make(map[uint32][]string),
		AdminToken:  networkAdminToken,
		Rules:       rules,
		ExprPolicy:  exprPolicy,
		Enterprise:  enterprise,
		Created:     st.now(),
	}
	st.networks[netID] = net

	st.cb.AppendNodeNetwork(nodeID, netID)
	st.cb.RecordWALNetworkCreate(netID, name, joinRule, token, networkAdminToken, enterprise, nodeID, net.Created.UTC().Format(time.RFC3339))
	st.cb.Save()
	st.cb.InvalidateListNodesCache(netID)
	st.cb.PublishMembershipChanged(netID)

	managed := rules != nil
	slog.Info("created network", "network_id", netID, "name", name, "creator", nodeID, "rule", joinRule, "enterprise", enterprise, "managed", managed)
	st.cb.Audit("network.created", "network_id", netID, "name", name, "join_rule", joinRule, "creator_node_id", nodeID, "enterprise", enterprise, "managed", managed)

	resp := map[string]interface{}{
		"type":       "create_network_ok",
		"network_id": netID,
		"name":       name,
		"enterprise": enterprise,
	}
	if rules != nil {
		resp["managed"] = true
	}
	return resp, nil
}

// HandleJoinNetwork implements the "join_network" protocol command.
func (st *Store) HandleJoinNetwork(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	netID := jsonUint16(msg, "network_id")
	token, _ := msg["token"].(string)

	if netID == 0 {
		return nil, fmt.Errorf("cannot join the backbone network")
	}

	// Phase 1: read-lock to copy fields for verification
	st.mu.RLock()
	pubKey, _, _, ok := st.cb.GetNode(nodeID)
	adminToken := st.cb.AdminToken()
	st.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("node %d not registered", nodeID)
	}
	sigErr := st.cb.VerifyNodeSignature(pubKey, adminToken, msg, fmt.Sprintf("join_network:%d:%d", nodeID, netID))
	if sigErr != nil {
		if err := st.cb.RequireAdminToken(msg); err != nil {
			return nil, sigErr
		}
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	// Re-check node under write lock
	if !st.cb.NodeExists(nodeID) {
		return nil, fmt.Errorf("node %d not registered", nodeID)
	}

	network, ok := st.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	switch network.JoinRule {
	case "open":
		// anyone can join
	case "token":
		if subtle.ConstantTimeCompare([]byte(token), []byte(network.Token)) != 1 {
			return nil, fmt.Errorf("invalid token for network %d", netID)
		}
	case "invite":
		return nil, fmt.Errorf("invite-only networks require invite_to_network + respond_invite flow")
	default:
		return nil, fmt.Errorf("unknown join rule: %s", network.JoinRule)
	}

	if network.Policy.MaxMembers > 0 && len(network.Members) >= network.Policy.MaxMembers {
		return nil, fmt.Errorf("network membership limit reached")
	}

	nodeNets, _ := st.cb.NodeNetworks(nodeID)
	for _, n := range nodeNets {
		if n == netID {
			return nil, fmt.Errorf("node %d already in network %d", nodeID, netID)
		}
	}

	network.Members = append(network.Members, nodeID)
	if network.MemberRoles == nil {
		network.MemberRoles = make(map[uint32]Role)
	}
	network.MemberRoles[nodeID] = RoleMember
	st.cb.AppendNodeNetwork(nodeID, netID)
	st.cb.RecordWALNetworkJoin(nodeID, netID)
	st.cb.Save()
	st.cb.InvalidateListNodesCache(netID)
	st.cb.PublishMembershipChanged(netID)

	st.cb.ApplyRBACPreAssignment(netID, nodeID)

	addr := protocol.Addr{Network: netID, Node: nodeID}

	slog.Info("node joined network", "node_id", nodeID, "network_id", netID, "name", network.Name)
	st.cb.Audit("network.joined", "node_id", nodeID, "network_id", netID)

	resp := map[string]interface{}{
		"type":       "join_network_ok",
		"network_id": netID,
		"address":    addr.String(),
	}
	if network.Rules != nil {
		resp["rules"] = network.Rules
	}
	if len(network.ExprPolicy) > 0 {
		resp["expr_policy"] = json.RawMessage(network.ExprPolicy)
	}
	return resp, nil
}

// HandleLeaveNetwork implements the "leave_network" protocol command.
func (st *Store) HandleLeaveNetwork(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	netID := jsonUint16(msg, "network_id")

	if netID == 0 {
		return nil, fmt.Errorf("cannot leave the backbone network")
	}

	// Phase 1: read-lock to copy fields for verification
	st.mu.RLock()
	pubKey, _, _, ok := st.cb.GetNode(nodeID)
	adminToken := st.cb.AdminToken()
	st.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("node %d not registered", nodeID)
	}
	sigErr := st.cb.VerifyNodeSignature(pubKey, adminToken, msg, fmt.Sprintf("leave_network:%d:%d", nodeID, netID))
	if sigErr != nil {
		if err := st.cb.RequireAdminToken(msg); err != nil {
			return nil, sigErr
		}
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if !st.cb.NodeExists(nodeID) {
		return nil, fmt.Errorf("node %d not registered", nodeID)
	}

	network, ok := st.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	if network.Enterprise && network.MemberRoles[nodeID] == RoleOwner {
		return nil, fmt.Errorf("cannot leave network: owner must transfer ownership first")
	}

	found := st.cb.RemoveNodeNetwork(nodeID, netID)
	if !found {
		return nil, fmt.Errorf("node %d is not a member of network %d", nodeID, netID)
	}

	for i, m := range network.Members {
		if m == nodeID {
			network.Members = append(network.Members[:i], network.Members[i+1:]...)
			break
		}
	}
	delete(network.MemberRoles, nodeID)
	st.cb.InvalidateListNodesCache(netID)
	st.cb.PublishMembershipChanged(netID)
	st.cb.RecordWALNetworkLeave(nodeID, netID)

	if invites, ok := st.inviteInbox[nodeID]; ok {
		remaining := make([]*NetworkInvite, 0, len(invites))
		for _, inv := range invites {
			if inv.NetworkID != netID {
				remaining = append(remaining, inv)
			}
		}
		if len(remaining) == 0 {
			delete(st.inviteInbox, nodeID)
		} else {
			st.inviteInbox[nodeID] = remaining
		}
	}

	for targetID, invites := range st.inviteInbox {
		remaining := make([]*NetworkInvite, 0, len(invites))
		for _, inv := range invites {
			if !(inv.NetworkID == netID && inv.InviterID == nodeID) {
				remaining = append(remaining, inv)
			}
		}
		if len(remaining) == 0 {
			delete(st.inviteInbox, targetID)
		} else if len(remaining) < len(invites) {
			st.inviteInbox[targetID] = remaining
		}
	}

	st.cb.Save()

	slog.Info("node left network", "node_id", nodeID, "network_id", netID, "name", network.Name)
	st.cb.Audit("network.left", "node_id", nodeID, "network_id", netID)

	return map[string]interface{}{
		"type":       "leave_network_ok",
		"network_id": netID,
	}, nil
}

// HandleDeleteNetwork implements the "delete_network" protocol command.
func (st *Store) HandleDeleteNetwork(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")

	if netID == 0 {
		return nil, fmt.Errorf("cannot delete the backbone network")
	}

	if err := st.cb.RequireNetworkRole(msg, netID, RoleOwner); err != nil {
		return nil, err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	network, ok := st.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	for _, memberID := range network.Members {
		st.cb.RemoveNodeNetwork(memberID, netID)
	}

	for nodeID, invites := range st.inviteInbox {
		remaining := make([]*NetworkInvite, 0, len(invites))
		for _, inv := range invites {
			if inv.NetworkID != netID {
				remaining = append(remaining, inv)
			}
		}
		if len(remaining) == 0 {
			delete(st.inviteInbox, nodeID)
		} else {
			st.inviteInbox[nodeID] = remaining
		}
	}

	name := network.Name
	delete(st.networks, netID)
	st.cb.InvalidateListNodesCache(netID)
	st.cb.PublishMembershipChanged(netID)
	st.cb.RecordWALNetworkDelete(netID)
	st.cb.Save()

	slog.Info("deleted network", "network_id", netID, "name", name, "members", len(network.Members))
	st.cb.Audit("network.deleted", "network_id", netID, "name", network.Name,
		"members", len(network.Members), "enterprise", network.Enterprise)

	return map[string]interface{}{
		"type":       "delete_network_ok",
		"network_id": netID,
	}, nil
}

// HandleRenameNetwork implements the "rename_network" protocol command.
func (st *Store) HandleRenameNetwork(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")

	if netID == 0 {
		return nil, fmt.Errorf("cannot rename the backbone network")
	}

	if err := st.cb.RequireNetworkRole(msg, netID, RoleOwner, RoleAdmin); err != nil {
		return nil, err
	}
	name, _ := msg["name"].(string)

	if err := ValidateNetworkName(name); err != nil {
		return nil, err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	network, ok := st.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	for _, n := range st.networks {
		if n.ID != netID && n.Name == name {
			return nil, fmt.Errorf("network %q already exists", name)
		}
	}

	oldName := network.Name
	network.Name = name
	st.cb.Save()

	slog.Info("renamed network", "network_id", netID, "name", name)
	st.cb.Audit("network.renamed", "network_id", netID, "old_name", oldName, "new_name", name)

	return map[string]interface{}{
		"type":       "rename_network_ok",
		"network_id": netID,
		"name":       name,
	}, nil
}

// HandleSetNetworkEnterprise implements the "set_network_enterprise" command.
func (st *Store) HandleSetNetworkEnterprise(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")
	enterprise, _ := msg["enterprise"].(bool)

	if netID == 0 {
		return nil, fmt.Errorf("cannot set enterprise on the backbone network")
	}

	if err := st.cb.RequireAdminToken(msg); err != nil {
		return nil, fmt.Errorf("set_network_enterprise requires admin token")
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	network, ok := st.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	network.Enterprise = enterprise

	if !enterprise && network.MemberRoles != nil {
		network.MemberRoles = nil
	}

	if enterprise && len(network.Members) > 0 {
		if network.MemberRoles == nil {
			network.MemberRoles = make(map[uint32]Role)
		}
		hasOwner := false
		for _, role := range network.MemberRoles {
			if role == RoleOwner {
				hasOwner = true
				break
			}
		}
		for _, memberID := range network.Members {
			if _, ok := network.MemberRoles[memberID]; !ok {
				if !hasOwner {
					network.MemberRoles[memberID] = RoleOwner
					hasOwner = true
				} else {
					network.MemberRoles[memberID] = RoleMember
				}
			}
		}
	}

	st.cb.Save()

	slog.Info("set network enterprise", "network_id", netID, "enterprise", enterprise)
	st.cb.Audit("network.enterprise_changed", "network_id", netID, "enterprise", enterprise,
		"members", len(network.Members))

	return map[string]interface{}{
		"type":       "set_network_enterprise_ok",
		"network_id": netID,
		"enterprise": enterprise,
	}, nil
}

// HandleListNetworks implements the "list_networks" protocol command.
func (st *Store) HandleListNetworks(msg map[string]interface{}) (map[string]interface{}, error) {
	includeMembers := st.cb.RequireAdminToken(msg) == nil

	st.mu.RLock()
	defer st.mu.RUnlock()

	nets := make([]map[string]interface{}, 0, len(st.networks))
	for _, n := range st.networks {
		entry := map[string]interface{}{
			"id":         n.ID,
			"name":       n.Name,
			"join_rule":  n.JoinRule,
			"enterprise": n.Enterprise,
			"created":    n.Created.Unix(),
		}
		if includeMembers {
			entry["members"] = len(n.Members)
		}
		if n.Enterprise {
			if n.Policy.MaxMembers > 0 {
				entry["max_members"] = n.Policy.MaxMembers
			}
			if n.Policy.Description != "" {
				entry["description"] = n.Policy.Description
			}
		}
		if n.Rules != nil {
			entry["managed"] = true
			entry["rules"] = n.Rules
		}
		if len(n.ExprPolicy) > 0 {
			entry["has_expr_policy"] = true
		}
		nets = append(nets, entry)
	}

	return map[string]interface{}{
		"type":     "list_networks_ok",
		"networks": nets,
	}, nil
}

// HandleInviteToNetwork implements the "invite_to_network" protocol command.
func (st *Store) HandleInviteToNetwork(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")
	inviterID := jsonUint32(msg, "inviter_id")
	targetNodeID := jsonUint32(msg, "target_node_id")

	if inviterID == targetNodeID {
		return nil, fmt.Errorf("cannot invite yourself")
	}

	// Phase 1: read-lock to copy fields for verification
	st.mu.RLock()
	inviterPubKey, _, _, inviterOK := st.cb.GetNode(inviterID)
	adminToken := st.cb.AdminToken()
	st.mu.RUnlock()
	if !inviterOK {
		return nil, fmt.Errorf("inviter node %d: %w", inviterID, protocol.ErrNodeNotFound)
	}
	sigErr := st.cb.VerifyNodeSignature(inviterPubKey, adminToken, msg, fmt.Sprintf("invite:%d:%d:%d", inviterID, netID, targetNodeID))
	if sigErr != nil {
		if err := st.cb.RequireAdminToken(msg); err != nil {
			return nil, sigErr
		}
	}
	isAdmin := st.cb.RequireAdminToken(msg) == nil

	// Per-network admin token check
	if !isAdmin {
		token, _ := msg["admin_token"].(string)
		st.mu.RLock()
		net, netOK := st.networks[netID]
		st.mu.RUnlock()
		if netOK && net.AdminToken != "" && token != "" {
			if subtle.ConstantTimeCompare([]byte(token), []byte(net.AdminToken)) == 1 {
				isAdmin = true
			}
		}
	}

	if err := st.cb.RequireEnterprise(netID); err != nil {
		return nil, err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	network, ok := st.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}
	if !network.Enterprise {
		return nil, fmt.Errorf("enterprise feature: requires enterprise network")
	}
	if network.JoinRule != "invite" {
		return nil, fmt.Errorf("network %d is not invite-only (rule: %s)", netID, network.JoinRule)
	}

	if !isAdmin {
		inviterIsMember := false
		for _, m := range network.Members {
			if m == inviterID {
				inviterIsMember = true
				break
			}
		}
		if !inviterIsMember {
			return nil, fmt.Errorf("inviter %d is not a member of network %d", inviterID, netID)
		}
		inviterRole := network.MemberRoles[inviterID]
		if inviterRole != RoleOwner && inviterRole != RoleAdmin {
			return nil, fmt.Errorf("rbac: inviter %d has role %q, requires owner or admin", inviterID, inviterRole)
		}
	}

	if !st.cb.NodeExists(targetNodeID) {
		return nil, fmt.Errorf("target node %d: %w", targetNodeID, protocol.ErrNodeNotFound)
	}

	targetNets, _ := st.cb.NodeNetworks(targetNodeID)
	for _, n := range targetNets {
		if n == netID {
			return nil, fmt.Errorf("node %d is already a member of network %d", targetNodeID, netID)
		}
	}

	// Deduplicate: only one invite per network per target
	for _, inv := range st.inviteInbox[targetNodeID] {
		if inv.NetworkID == netID {
			return map[string]interface{}{
				"type":           "invite_to_network_ok",
				"network_id":     netID,
				"target_node_id": targetNodeID,
				"status":         "already_invited",
			}, nil
		}
	}

	if len(st.inviteInbox[targetNodeID]) >= MaxInviteInbox {
		return nil, fmt.Errorf("invite inbox full for node %d", targetNodeID)
	}

	st.inviteInbox[targetNodeID] = append(st.inviteInbox[targetNodeID], &NetworkInvite{
		NetworkID: netID,
		InviterID: inviterID,
		Timestamp: st.now(),
	})
	st.cb.Save()

	slog.Info("network invite stored", "network_id", netID, "inviter_id", inviterID, "target_node_id", targetNodeID)
	st.cb.Audit("invite.created", "network_id", netID, "inviter_id", inviterID, "target_node_id", targetNodeID)
	st.cb.IncInvitesSent()

	return map[string]interface{}{
		"type":           "invite_to_network_ok",
		"network_id":     netID,
		"target_node_id": targetNodeID,
	}, nil
}

// HandlePollInvites implements the "poll_invites" protocol command.
func (st *Store) HandlePollInvites(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")

	st.mu.Lock()
	defer st.mu.Unlock()

	pubKey, _, _, ok := st.cb.GetNode(nodeID)
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	adminToken := st.cb.AdminToken()
	if err := st.cb.VerifyNodeSignature(pubKey, adminToken, msg, fmt.Sprintf("poll_invites:%d", nodeID)); err != nil {
		return nil, err
	}

	inbox := st.inviteInbox[nodeID]
	now := st.now()

	var active []*NetworkInvite
	var expired int
	for _, inv := range inbox {
		if now.Sub(inv.Timestamp) > InviteTTL {
			expired++
			continue
		}
		active = append(active, inv)
	}
	if expired > 0 {
		st.inviteInbox[nodeID] = active
		st.cb.Save()
		st.cb.Audit("invite.expired_cleanup", "node_id", nodeID, "expired_count", expired)
	}

	invites := make([]map[string]interface{}, len(active))
	for i, inv := range active {
		invites[i] = map[string]interface{}{
			"network_id": inv.NetworkID,
			"inviter_id": inv.InviterID,
			"timestamp":  inv.Timestamp.Unix(),
		}
	}

	return map[string]interface{}{
		"type":    "poll_invites_ok",
		"invites": invites,
	}, nil
}

// HandleRespondInvite implements the "respond_invite" protocol command.
func (st *Store) HandleRespondInvite(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	netID := jsonUint16(msg, "network_id")
	accept, _ := msg["accept"].(bool)

	if err := st.cb.RequireEnterprise(netID); err != nil {
		return nil, err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	pubKey, nodeNets, _, ok := st.cb.GetNode(nodeID)
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	adminToken := st.cb.AdminToken()
	if err := st.cb.VerifyNodeSignature(pubKey, adminToken, msg, fmt.Sprintf("respond_invite:%d:%d", nodeID, netID)); err != nil {
		return nil, err
	}

	inviteFound := false
	now := st.now()
	for _, inv := range st.inviteInbox[nodeID] {
		if inv.NetworkID == netID {
			if now.Sub(inv.Timestamp) > InviteTTL {
				return nil, fmt.Errorf("invite for node %d to network %d has expired", nodeID, netID)
			}
			inviteFound = true
			break
		}
	}
	if !inviteFound {
		return nil, fmt.Errorf("no pending invite for node %d to network %d", nodeID, netID)
	}

	if accept {
		network, ok := st.networks[netID]
		if !ok {
			return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
		}
		if !network.Enterprise {
			return nil, fmt.Errorf("enterprise feature: requires enterprise network")
		}

		if network.Policy.MaxMembers > 0 && len(network.Members) >= network.Policy.MaxMembers {
			return nil, fmt.Errorf("network membership limit reached")
		}

		for _, n := range nodeNets {
			if n == netID {
				return nil, fmt.Errorf("node %d is already a member of network %d", nodeID, netID)
			}
		}

		network.Members = append(network.Members, nodeID)
		if network.MemberRoles == nil {
			network.MemberRoles = make(map[uint32]Role)
		}
		network.MemberRoles[nodeID] = RoleMember
		st.cb.AppendNodeNetwork(nodeID, netID)
		st.cb.InvalidateListNodesCache(netID)
		st.cb.PublishMembershipChanged(netID)

		slog.Info("invite accepted, node joined network", "node_id", nodeID, "network_id", netID, "name", network.Name)
	} else {
		slog.Info("invite rejected", "node_id", nodeID, "network_id", netID)
	}

	remaining := make([]*NetworkInvite, 0, len(st.inviteInbox[nodeID]))
	for _, inv := range st.inviteInbox[nodeID] {
		if inv.NetworkID != netID {
			remaining = append(remaining, inv)
		}
	}
	if len(remaining) == 0 {
		delete(st.inviteInbox, nodeID)
	} else {
		st.inviteInbox[nodeID] = remaining
	}

	st.cb.Save()
	st.cb.Audit("invite.responded", "node_id", nodeID, "network_id", netID, "accepted", accept)
	if accept {
		st.cb.IncInvitesAccepted()
	} else {
		st.cb.IncInvitesRejected()
	}

	return map[string]interface{}{
		"type":       "respond_invite_ok",
		"accepted":   accept,
		"network_id": netID,
	}, nil
}

// HandleKickMember implements the "kick_member" protocol command.
func (st *Store) HandleKickMember(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")
	targetNodeID := jsonUint32(msg, "target_node_id")

	if netID == 0 {
		return nil, fmt.Errorf("cannot kick from the backbone network")
	}

	if err := st.cb.RequireNetworkRole(msg, netID, RoleOwner, RoleAdmin); err != nil {
		return nil, err
	}

	if err := st.cb.RequireEnterprise(netID); err != nil {
		return nil, err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	network, ok := st.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	if network.MemberRoles[targetNodeID] == RoleOwner {
		return nil, fmt.Errorf("cannot kick the network owner")
	}

	found := false
	for i, m := range network.Members {
		if m == targetNodeID {
			network.Members = append(network.Members[:i], network.Members[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("node %d is not a member of network %d", targetNodeID, netID)
	}
	st.cb.InvalidateListNodesCache(netID)
	st.cb.PublishMembershipChanged(netID)

	kickedRole := network.MemberRoles[targetNodeID]
	delete(network.MemberRoles, targetNodeID)

	st.cb.RemoveNodeNetwork(targetNodeID, netID)

	if invites, ok := st.inviteInbox[targetNodeID]; ok {
		remaining := make([]*NetworkInvite, 0, len(invites))
		for _, inv := range invites {
			if inv.NetworkID != netID {
				remaining = append(remaining, inv)
			}
		}
		if len(remaining) == 0 {
			delete(st.inviteInbox, targetNodeID)
		} else {
			st.inviteInbox[targetNodeID] = remaining
		}
	}

	for nodeID, invites := range st.inviteInbox {
		remaining := make([]*NetworkInvite, 0, len(invites))
		for _, inv := range invites {
			if !(inv.NetworkID == netID && inv.InviterID == targetNodeID) {
				remaining = append(remaining, inv)
			}
		}
		if len(remaining) == 0 {
			delete(st.inviteInbox, nodeID)
		} else if len(remaining) < len(invites) {
			st.inviteInbox[nodeID] = remaining
		}
	}

	st.cb.Save()

	slog.Info("member kicked from network", "target_node_id", targetNodeID, "network_id", netID, "role", string(kickedRole))
	st.cb.Audit("member.kicked", "target_node_id", targetNodeID, "network_id", netID, "role", string(kickedRole))
	st.cb.IncRbacOps("kick")

	return map[string]interface{}{
		"type":           "kick_member_ok",
		"network_id":     netID,
		"target_node_id": targetNodeID,
	}, nil
}

// HandlePromoteMember implements the "promote_member" protocol command.
func (st *Store) HandlePromoteMember(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")
	targetNodeID := jsonUint32(msg, "target_node_id")

	if err := st.cb.RequireNetworkRole(msg, netID, RoleOwner); err != nil {
		return nil, err
	}

	if err := st.cb.RequireEnterprise(netID); err != nil {
		return nil, err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	network, ok := st.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	currentRole, hasRole := network.MemberRoles[targetNodeID]
	if !hasRole {
		return nil, fmt.Errorf("node %d is not a member of network %d", targetNodeID, netID)
	}
	if currentRole == RoleOwner {
		return nil, fmt.Errorf("cannot promote the owner")
	}
	if currentRole == RoleAdmin {
		return nil, fmt.Errorf("node %d is already an admin", targetNodeID)
	}

	network.MemberRoles[targetNodeID] = RoleAdmin
	st.cb.Save()
	st.cb.InvalidateListNodesCache(netID)
	st.cb.PublishMembershipChanged(netID)

	slog.Info("member promoted to admin", "target_node_id", targetNodeID, "network_id", netID)
	st.cb.Audit("member.promoted", "target_node_id", targetNodeID, "network_id", netID,
		"old_role", string(currentRole), "new_role", "admin")
	st.cb.IncRbacOps("promote")

	return map[string]interface{}{
		"type":           "promote_member_ok",
		"network_id":     netID,
		"target_node_id": targetNodeID,
		"role":           string(RoleAdmin),
	}, nil
}

// HandleDemoteMember implements the "demote_member" protocol command.
func (st *Store) HandleDemoteMember(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")
	targetNodeID := jsonUint32(msg, "target_node_id")

	if err := st.cb.RequireNetworkRole(msg, netID, RoleOwner); err != nil {
		return nil, err
	}

	if err := st.cb.RequireEnterprise(netID); err != nil {
		return nil, err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	network, ok := st.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	currentRole, hasRole := network.MemberRoles[targetNodeID]
	if !hasRole {
		return nil, fmt.Errorf("node %d is not a member of network %d", targetNodeID, netID)
	}
	if currentRole == RoleOwner {
		return nil, fmt.Errorf("cannot demote the owner")
	}
	if currentRole == RoleMember {
		return nil, fmt.Errorf("node %d is already a member", targetNodeID)
	}

	network.MemberRoles[targetNodeID] = RoleMember
	st.cb.Save()
	st.cb.InvalidateListNodesCache(netID)
	st.cb.PublishMembershipChanged(netID)

	slog.Info("admin demoted to member", "target_node_id", targetNodeID, "network_id", netID)
	st.cb.Audit("member.demoted", "target_node_id", targetNodeID, "network_id", netID,
		"old_role", string(currentRole), "new_role", "member")
	st.cb.IncRbacOps("demote")

	return map[string]interface{}{
		"type":           "demote_member_ok",
		"network_id":     netID,
		"target_node_id": targetNodeID,
		"role":           string(RoleMember),
	}, nil
}

// HandleTransferOwnership implements the "transfer_ownership" protocol command.
func (st *Store) HandleTransferOwnership(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")
	newOwnerID := jsonUint32(msg, "new_owner_id")
	if newOwnerID == 0 {
		return nil, fmt.Errorf("new_owner_id is required")
	}

	if err := st.cb.RequireNetworkRole(msg, netID, RoleOwner); err != nil {
		return nil, err
	}

	if err := st.cb.RequireEnterprise(netID); err != nil {
		return nil, err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	network, ok := st.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	var currentOwnerID uint32
	for memberID, role := range network.MemberRoles {
		if role == RoleOwner {
			currentOwnerID = memberID
			break
		}
	}
	if currentOwnerID == 0 {
		return nil, fmt.Errorf("network %d has no owner", netID)
	}

	if newOwnerID == currentOwnerID {
		return nil, fmt.Errorf("node %d is already the owner", newOwnerID)
	}

	newOwnerRole, isMember := network.MemberRoles[newOwnerID]
	if !isMember {
		return nil, fmt.Errorf("node %d is not a member of network %d", newOwnerID, netID)
	}

	network.MemberRoles[currentOwnerID] = RoleAdmin
	network.MemberRoles[newOwnerID] = RoleOwner
	st.cb.Save()
	st.cb.InvalidateListNodesCache(netID)
	st.cb.PublishMembershipChanged(netID)

	slog.Info("ownership transferred", "network_id", netID,
		"old_owner", currentOwnerID, "new_owner", newOwnerID)
	st.cb.Audit("network.ownership_transferred", "network_id", netID,
		"old_owner", currentOwnerID, "new_owner", newOwnerID,
		"new_owner_old_role", string(newOwnerRole))
	st.cb.IncRbacOps("transfer_ownership")

	return map[string]interface{}{
		"type":       "transfer_ownership_ok",
		"network_id": netID,
		"old_owner":  currentOwnerID,
		"new_owner":  newOwnerID,
	}, nil
}

// HandleGetMemberRole implements the "get_member_role" protocol command.
func (st *Store) HandleGetMemberRole(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")
	targetNodeID := jsonUint32(msg, "target_node_id")

	st.mu.RLock()
	defer st.mu.RUnlock()

	network, ok := st.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	role, hasRole := network.MemberRoles[targetNodeID]
	if !hasRole {
		return nil, fmt.Errorf("node %d is not a member of network %d", targetNodeID, netID)
	}

	return map[string]interface{}{
		"type":           "get_member_role_ok",
		"network_id":     netID,
		"target_node_id": targetNodeID,
		"role":           string(role),
	}, nil
}

// HandleSetMemberTags implements the "set_member_tags" protocol command.
func (st *Store) HandleSetMemberTags(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")
	targetNodeID := jsonUint32(msg, "target_node_id")

	if err := st.cb.RequireNetworkRole(msg, netID, RoleOwner, RoleAdmin); err != nil {
		return nil, err
	}

	var tags []string
	if rawTags, ok := msg["tags"].([]interface{}); ok {
		for _, rt := range rawTags {
			if t, ok := rt.(string); ok {
				tags = append(tags, t)
			}
		}
	}

	if len(tags) > 10 {
		return nil, fmt.Errorf("too many member tags (max 10)")
	}
	for _, t := range tags {
		if len(t) == 0 {
			return nil, fmt.Errorf("empty tag not allowed")
		}
		if !tagRegex.MatchString(t) {
			return nil, fmt.Errorf("tag %q must be lowercase alphanumeric with hyphens", t)
		}
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	network, ok := st.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	isMember := false
	for _, m := range network.Members {
		if m == targetNodeID {
			isMember = true
			break
		}
	}
	if !isMember {
		return nil, fmt.Errorf("node %d is not a member of network %d", targetNodeID, netID)
	}

	if network.MemberTags == nil {
		network.MemberTags = make(map[uint32][]string)
	}
	if len(tags) == 0 {
		delete(network.MemberTags, targetNodeID)
	} else {
		network.MemberTags[targetNodeID] = tags
	}
	st.cb.Save()
	st.cb.InvalidateListNodesCache(netID)
	st.cb.PublishMembershipChanged(netID)

	slog.Info("member tags set", "network_id", netID, "target_node", targetNodeID, "tags", tags)
	st.cb.Audit("member_tags.changed", "network_id", netID, "target_node", targetNodeID, "tags", tags)

	return map[string]interface{}{
		"type":           "set_member_tags_ok",
		"network_id":     netID,
		"target_node_id": targetNodeID,
		"tags":           tags,
	}, nil
}

// HandleGetMemberTags implements the "get_member_tags" protocol command.
func (st *Store) HandleGetMemberTags(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")
	targetNodeID := jsonUint32(msg, "target_node_id") // 0 = all members

	st.mu.RLock()
	defer st.mu.RUnlock()

	network, ok := st.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	if targetNodeID != 0 {
		tags := network.MemberTags[targetNodeID]
		if tags == nil {
			tags = []string{}
		}
		return map[string]interface{}{
			"type":           "get_member_tags_ok",
			"network_id":     netID,
			"target_node_id": targetNodeID,
			"tags":           tags,
		}, nil
	}

	allTags := make(map[string]interface{}, len(network.Members))
	for _, m := range network.Members {
		tags := network.MemberTags[m]
		if tags == nil {
			tags = []string{}
		}
		allTags[fmt.Sprintf("%d", m)] = tags
	}
	return map[string]interface{}{
		"type":       "get_member_tags_ok",
		"network_id": netID,
		"members":    allTags,
	}, nil
}

// ReplaceState atomically swaps the membership store's network and invite maps
// with replacement values. Called by the server after applying a replication
// snapshot so the store's internal map pointers stay current. Must be called
// with s.mu held (Lock).
func (st *Store) ReplaceState(networks map[uint16]*NetworkInfo, inviteInbox map[uint32][]*NetworkInvite) {
	st.networks = networks
	st.inviteInbox = inviteInbox
}

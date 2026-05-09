// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wal — this file defines the snapshot serialization types used by
// flushSave and load in the registry Server. They are moved here as part of
// R6.2 to co-locate all persistence-layer types in the wal sub-package.
//
// Snapshot intentionally imports sibling sub-packages (audit, dashboard,
// membership, trust) to serialize their state. This is structural coupling
// required for full-state persistence, not domain coupling: wal → others,
// never the reverse.

package wal

import (
	"encoding/json"

	auditpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/audit"
	dashpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/dashboard"
	membpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/membership"
	trustpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/trust"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

// SnapshotNode is the JSON-serializable form of a single registry node.
// All binary/time fields are encoded as strings (base64 / RFC3339) so the
// snapshot is human-readable and forward-compatible.
type SnapshotNode struct {
	ID          uint32   `json:"id"`
	Owner       string   `json:"owner,omitempty"`
	PublicKey   string   `json:"public_key"`
	RealAddr    string   `json:"real_addr,omitempty"`
	Networks    []uint16 `json:"networks"`
	Public      bool     `json:"public,omitempty"`
	LastSeen    string   `json:"last_seen,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	TaskExec    bool     `json:"task_exec,omitempty"`
	LANAddrs    []string `json:"lan_addrs,omitempty"`
	KeyCreated  string   `json:"key_created,omitempty"`
	KeyRotated  string   `json:"key_rotated,omitempty"`
	KeyRotCount int      `json:"key_rot_count,omitempty"`
	KeyExpires  string   `json:"key_expires,omitempty"`
	ExternalID  string   `json:"external_id,omitempty"`
	Version     string   `json:"version,omitempty"`
	RelayOnly   bool     `json:"relay_only,omitempty"` // preserve flag across snapshots
}

// SnapshotNet is the JSON-serializable form of a single registry network.
type SnapshotNet struct {
	ID           uint16                 `json:"id"`
	Name         string                 `json:"name"`
	JoinRule     string                 `json:"join_rule"`
	Token        string                 `json:"token,omitempty"`
	Members      []uint32               `json:"members"`
	MemberRoles  map[string]string      `json:"member_roles,omitempty"` // nodeID -> role
	MemberTags   map[string][]string    `json:"member_tags,omitempty"`  // nodeID -> admin-assigned tags
	AdminToken   string                 `json:"admin_token,omitempty"`  // per-network admin token
	Policy       *membpkg.NetworkPolicy `json:"policy,omitempty"`       // network policy
	Rules        *wire.NetworkRules     `json:"rules,omitempty"`        // managed network rules
	ExprPolicy   json.RawMessage        `json:"expr_policy,omitempty"`  // programmable policy engine document
	Enterprise   bool                   `json:"enterprise,omitempty"`   // enterprise network flag
	RequestCount int64                  `json:"request_count,omitempty"`
	Created      string                 `json:"created"`
}

// Snapshot is the JSON-serializable full registry state written by flushSave
// and read by load. Version 0 is the legacy (pre-checksum) format; version 1
// includes the Checksum field for integrity verification.
type Snapshot struct {
	Version            int                                         `json:"version"`
	NextNode           uint32                                      `json:"next_node"`
	NextNet            uint16                                      `json:"next_net"`
	Nodes              map[string]*SnapshotNode                    `json:"nodes"`
	Networks           map[string]*SnapshotNet                     `json:"networks"`
	TrustPairs         []string                                    `json:"trust_pairs,omitempty"`
	PubKeyIdx          map[string]uint32                           `json:"pub_key_idx,omitempty"`
	HandshakeInbox     map[string][]*trustpkg.HandshakeRelayMsg    `json:"handshake_inbox,omitempty"`
	HandshakeResponses map[string][]*trustpkg.HandshakeResponseMsg `json:"handshake_responses,omitempty"`
	InviteInbox        map[string][]*membpkg.NetworkInvite         `json:"invite_inbox,omitempty"`
	// Dashboard stats persistence (explicit counters for validation)
	TotalRequests int64  `json:"total_requests,omitempty"`
	TotalNodes    int    `json:"total_nodes,omitempty"`
	OnlineNodes   int    `json:"online_nodes,omitempty"`
	TrustLinks    int    `json:"trust_links,omitempty"`
	UniqueTags    int    `json:"unique_tags,omitempty"`
	TaskExecutors int    `json:"task_executors,omitempty"`
	StartTime     string `json:"start_time,omitempty"` // RFC3339 format
	// Restart events: unix-millis of each process start after first. Lets the
	// dashboard show brief redeploy "blips" while preserving cumulative uptime.
	RestartEvents     []int64                        `json:"restart_events,omitempty"`
	DowntimeIntervals [][2]int64                     `json:"downtime_intervals,omitempty"`
	LastHeartbeat     int64                          `json:"last_heartbeat,omitempty"`
	ProbeStates       map[string]*dashpkg.ProbeState `json:"probe_states,omitempty"`
	// Time-series history for dashboard charts
	HourlyHistory    []dashpkg.StatsSample                   `json:"hourly_history,omitempty"`
	DailyHistory     []dashpkg.StatsSample                   `json:"daily_history,omitempty"`
	NetHourlyHistory map[string][]dashpkg.NetworkSampleEntry `json:"net_hourly_history,omitempty"`
	NetDailyHistory  map[string][]dashpkg.NetworkSampleEntry `json:"net_daily_history,omitempty"`
	// Audit log persistence (most recent entries, capped at maxAuditEntries)
	AuditLog []auditpkg.Entry `json:"audit_log,omitempty"`
	// Enterprise config persistence
	IDPConfig      *wire.BlueprintIdentityProvider `json:"idp_config,omitempty"`
	AuditExportCfg *wire.BlueprintAuditExport      `json:"audit_export_config,omitempty"`
	RBACPreAssign  map[string][]wire.BlueprintRole `json:"rbac_pre_assign,omitempty"` // networkID -> roles
	// Integrity: SHA256 hex digest of all fields except Checksum
	Checksum string `json:"checksum,omitempty"`
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"sync"
	"sync/atomic"
	"time"

	acceptpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/accept"
	auditpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/audit"
	authzpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/authz"
	dashpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/dashboard"
	dirpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/directory"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry/server/events"
	metrpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/metrics"
	membpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/membership"
	policypkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/policy"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry/server/routing"
	identpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/identity"
	replpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/replication"
	trustpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/trust"
	walpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/wal"
	webhookpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/webhook"
)

// LOCK ORDERING INVARIANTS — read this before adding a new lock.
//
// The registry has several mutexes covering different scopes. Running
// signature verification (~28µs Ed25519) while holding s.mu.Lock allows
// the contention queue to grow without bound under load. This comment
// block exists so the rule is impossible to miss when adding a new handler.
//
// Tier 1 (RWMutex):
//   Server.mu — global state (nodes, networks, indices, trustPairs).
//
// Tier 2 (nested under Tier 1, NEVER reversed):
//   Server.nodeShards[256] — per-node fields (RealAddr, LANAddrs, Version).
//     Acquired under s.mu.Lock in the slow path, under s.mu.RLock in
//     snapshotJSON / flushSave Phase 1. Never acquire s.mu while holding a
//     shard lock.
//
// Tier 3 (independent or nested under Tier 1):
//   Server.handshakeMu — handshake inbox / responses.
//     Acquired AFTER s.mu.RUnlock OR nested inside s.mu.RLock.
//   Server.auditMu — audit log. Same pattern as handshakeMu.
//   Server.restartMu — must be acquired ONLY AFTER s.mu.RUnlock (never nested before).
//   dashboard.Handler.{probeMu,pulseMu,bannerMu} — independent (no Server lock nesting).
//
// Tier 4 (fully independent):
//   replicationManager.mu — subscriber state.
//   listNodesPerNetMu → listNodesCacheState.mu — singleflight cache.
//
// FORBIDDEN PATTERNS (would deadlock or race):
//   ❌ restartMu.Lock()  → s.mu.Lock()      (deadlock)
//   ❌ shard.Lock()      → s.mu.Lock()      (deadlock)
//   ❌ handshakeMu.Lock without s.mu.RLock guard on inbox reads (race)
//
// CORRECTNESS RULE — DO NOT BREAK:
//   No signature verification, no JSON marshal, no encoding/decoding, no
//   network I/O while holding s.mu.Lock OR s.mu.RLock. CPU work goes
//   OUTSIDE the lock. The 3-phase pattern (RLock → snapshot fields →
//   RUnlock → CPU work outside lock → Lock for mutation) is the canonical
//   shape; see handleRequestHandshake / handlePollHandshakes /
//   handleRespondHandshake for working examples.

// numNodeShards is the number of per-node striped locks. Each shard protects
// field-level access to nodes where nodeID % numNodeShards == shardIndex.
// Hot-path readers (lookup, resolve) hold a shard RLock instead of the global
// s.mu.RLock during response construction, reducing global lock hold time from
// ~2μs to ~100ns and allowing write-lock acquisitions to prevent that.
const numNodeShards = 256

type Server struct {
	mu           sync.RWMutex
	nodeShards   [numNodeShards]sync.RWMutex // per-node field locks (nodeID % N)
	nodes        map[uint32]*NodeInfo
	maxNodes     int // max registered nodes (0 = unlimited); prevents memory exhaustion
	startTime         time.Time
	restartEvents     []int64    // unix-millis of each process start after the first
	downtimeIntervals [][2]int64 // [start,end] unix-millis pairs, pruned to last 30d
	restartMu         sync.Mutex
	lastHeartbeatMs   atomic.Int64 // updated each heartbeat tick, persisted
	requestCount      atomic.Int64

	// dashboard owns probe state, pulse ring, maintenance banner, and the HTTP mux.
	// Extracted to pkg/registry/server/dashboard (R5.1).
	dashboard *dashpkg.Handler

	networks map[uint16]*NetworkInfo
	pubKeyIdx    map[string]uint32 // base64(pubkey) -> nodeID for re-registration
	ownerIdx     map[string]uint32 // owner -> nodeID for key rotation
	hostnameIdx  map[string]uint32 // hostname -> nodeID (unique index)
	nextNode     uint32
	nextNet      uint16
	readyCh      chan struct{}

	// accept manages the TCP accept loop, TLS config, rate limiting, and
	// log sampling. Extracted to pkg/registry/server/accept (R3.2).
	accept *acceptpkg.Acceptor


	// Beacon coordination
	beaconAddr string

	// Persistence and WAL lifecycle. walStore owns the save/replica-push
	// goroutines, the WAL file handle, the standby flag, and the
	// replication token. Extracted to pkg/registry/server/wal (R6.1).
	walStore  *walpkg.Store
	storePath string // empty = no persistence (mirror kept for flushSave / load)

	// trust holds the trust-pair store and handshake-relay inboxes.
	// Extracted to pkg/registry/server/trust (R2.1).
	trust *trustpkg.Store

	// policy holds the network-policy and expression-policy handlers.
	// Extracted to pkg/registry/server/policy (R2.4).
	policy *policypkg.Store

	// membership holds the 18 network-membership and invite handlers.
	// Extracted to pkg/registry/server/membership (R4.1).
	// The underlying data maps (networks, inviteInbox, nextNet) remain on
	// Server for snapshot/WAL/provision compat; the Store accesses them via
	// the shared mu pointer and callback closures.
	membership *membpkg.Store

	// directory holds the 14 node-directory handlers (register, lookup,
	// resolve, heartbeat, deregister, list-nodes, hostname/tag/visibility).
	// Extracted to pkg/registry/server/directory (R4.2).
	// The underlying data maps (nodes, pubKeyIdx, ownerIdx, hostnameIdx)
	// remain on Server for snapshot/WAL compat; Store accesses them via the
	// shared mu pointer and callback closures.
	directory *dirpkg.Store

	// Network invite inbox: target nodeID -> pending invites
	inviteInbox map[uint32][]*NetworkInvite

	// Replication push manager (subscriber list + push methods). Standby flag
	// and replication token are now owned by walStore (R6.1).
	// Extracted to pkg/registry/server/replication (R7.1).
	replMgr *replpkg.Manager

	// authz holds the authorization checker (admin/dashboard tokens, role gates,
	// enterprise gates, signature verification). Extracted to pkg/registry/server/authz (R3.1).
	authz *authzpkg.Checker

	// Optional pluggable beacon stats provider — set by the host
	// (cmd/rendezvous) so /api/stats can surface relay forward counters
	// without coupling the registry directly to pkg/beacon.
	beaconStats BeaconStatsProvider

	// Delta log for incremental replication
	deltaLog *deltaLog

	// Beacon cluster: beacon instances register themselves for peer discovery.
	// Kept as a nil placeholder; live state is owned by s.routing (R1.4).
	beacons map[uint32]*beaconEntry

	// routing holds the extracted beacon/punch routing handlers (R1.4).
	routing *routing.Store

	// Prometheus metrics
	metrics *metrpkg.Store

	// GitHub release poller (nil when disabled)
	releasePoller *releasePoller

	// Webhook dispatcher (nil = disabled)
	webhook *webhookpkg.Store

	// identity holds the identity, key-lifecycle, and IDP handler state (R2.3).
	// Extracted from pkg/registry/server as part of the registry decomposition.
	identity *identpkg.Store

	// identityWebhookURL is kept in the Server struct for snapshot compat and
	// white-box tests. It mirrors identity.identityWebhookURL. Both are updated
	// together by SetIdentityWebhookURL.
	identityWebhookURL string

	// idpConfig holds the active identity-provider config for snapshot/replication
	// compat. Mirrors identity.idpConfig; updated together by SetIDPConfig.
	idpConfig *BlueprintIdentityProvider

	// auditExportConfig is kept for snapshot and replication compat.
	// The actual export is owned by auditStore.
	auditExportConfig *BlueprintAuditExport

	// Audit store: ring buffer + optional external exporter (R1.2).
	// The sub-package owns the async ring-buffer and exporter fan-out;
	// server.audit() publishes "audit.entry" events consumed by auditStore.
	auditStore *auditpkg.Store

	// RBAC pre-assignments: networkID -> roles that auto-apply when matching nodes join
	rbacPreAssign map[uint16][]BlueprintRole

	// Clock (overridable for testing)
	now func() time.Time

	// staleNodeThreshold controls how long since last heartbeat a node is
	// considered online for dashboard / reap purposes. Defaults to
	// defaultStaleNodeThreshold; settable via SetStaleNodeThreshold or the
	// rendezvous -stale-threshold flag. Read via atomic load on the read
	// paths; updates are rare (config-time only) so a plain int64 nanos
	// load + atomic store is enough.
	staleNodeThresholdNs atomic.Int64

	// Event bus for internal cross-layer communication (R0.2+).
	// Publish "membership.changed" with payload map[string]any{"net_id": uint16}
	// after any mutation to network membership or roles.
	bus events.Bus

	// Shutdown
	done chan struct{}

	// Chunked reap: cursor for iterating through nodes across ticks
	reapCursor uint32

	// Audit ring buffer — kept for white-box tests in package server.
	// Production fan-out goes through s.auditStore (R1.2 sub-package).
	auditMu  sync.Mutex
	auditLog []AuditEntry

	// Time-series history ring buffers for dashboard charts
	hourlyHistory [24]StatsSample // last 24 hours, one sample per hour
	dailyHistory  [30]StatsSample // last 30 days, one sample per day
	hourlyIdx     int             // next write index for hourly ring
	dailyIdx      int             // next write index for daily ring

	// Per-network history ring buffers (keyed by network ID)
	netHourly map[uint16]*netHistoryRing
	netDaily  map[uint16]*netHistoryRing

	// list_nodes cache. Admin-backbone (netID=0) and large per-network
	// listings ("data-exchange" 45k members, "high-trust-society" 28k) all
	// route through the same singleflight + 1s-TTL cache. Each network
	// (and the admin path, key=0) has its own state inside listNodesPerNet.
	listNodesCache    listNodesCacheState            // legacy backbone admin cache
	listNodesPerNetMu sync.Mutex                     // guards the map itself
	listNodesPerNet   map[uint16]*listNodesCacheState
}

// listNodesCacheState is defined in the directory sub-package (R4.2).
// Type alias keeps all existing code and tests compiling unchanged.
type listNodesCacheState = dirpkg.ListNodesCacheState

// rawResponseKey is a sentinel map key. When a handler returns a response
// map containing this key with a []byte value, writeMessage skips
// json.Marshal entirely and writes the bytes verbatim (preceded by the
// standard 4-byte length prefix). Used by the list_nodes cache to bypass
// the encoder's appendCompact validation pass on already-valid cached JSON.
const rawResponseKey = "_pilot_raw_body"

// AuditEntry is an alias for audit.Entry, kept here so existing code and
// tests in package server can reference AuditEntry without import changes.
type AuditEntry = auditpkg.Entry

// ProbeState is an alias for dashboard.ProbeState, kept here so the snapshot
// struct and tests in package server can reference ProbeState without changes.
type ProbeState = dashpkg.ProbeState

// beaconEntry tracks a registered beacon instance.
type beaconEntry struct {
	ID       uint32
	Addr     string
	LastSeen time.Time
}

// beaconTTL is how long a beacon registration is valid without re-register.
const beaconTTL = 60 * time.Second

// defaultStaleNodeThreshold is the default time since last heartbeat before a
// node is considered stale/offline. At 60s heartbeat interval, this tolerates
// ~30 missed heartbeats before reaping — enough grace for client reconnect
// storms and rendezvous transient overload to clear without evicting healthy
// daemons whose heartbeats land late. Operators can override per-Server via
// SetStaleNodeThreshold (or the rendezvous -stale-threshold flag); a smaller
// value (e.g. 5m) gives faster dashboard reflection of disconnects at the
// cost of less tolerance for reconnect storms.
const defaultStaleNodeThreshold = 30 * time.Minute

// saveLoopInterval is how often saveLoop flushes dirty state to disk.
// Replica push runs on its own faster ticker (replicaPushInterval) so
// raising this interval does not delay replication propagation.
const saveLoopInterval = 5 * time.Second

// replicaPushInterval is how often replicaPushLoop builds + pushes a
// fresh snapshot to replication subscribers when state is dirty. This
// is decoupled from the disk save cadence (saveLoopInterval) so replicas
// stay near-current even when disk I/O is debounced longer.
const replicaPushInterval = 1 * time.Second

// shutdownDrainTimeout caps how long Close() waits for background loops
// (saveLoop, replicaPushLoop) to finish their final iteration. A stuck
// fsync or slow peer must not wedge the process indefinitely on shutdown;
// 10s is generous enough for a clean final flush but bounded enough that
// a misbehaving environment surfaces in process-supervisor timeouts.
const shutdownDrainTimeout = 10 * time.Second

// defaultMaxConnections is the maximum concurrent connections the server will accept.
const defaultMaxConnections int64 = 1100000

// (The maximum allowed wire message size lives in pkg/registry/wire as
// wire.MaxMessageSize. It's referenced through the wire package now.)


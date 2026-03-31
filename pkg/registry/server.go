package registry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/internal/fsutil"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// hashOwner returns a truncated SHA-256 hash of the owner for safe logging.
func hashOwner(owner string) string {
	if owner == "" {
		return ""
	}
	h := sha256.Sum256([]byte(owner))
	return fmt.Sprintf("sha256:%x", h[:4])
}

// requireAdminToken validates the admin_token field in a message.
func (s *Server) requireAdminToken(msg map[string]interface{}) error {
	s.mu.RLock()
	adminToken := s.adminToken
	s.mu.RUnlock()
	return s.checkAdminToken(msg, adminToken)
}

// requireAdminTokenLocked is like requireAdminToken but for use when s.mu is already held.
func (s *Server) requireAdminTokenLocked(msg map[string]interface{}) error {
	return s.checkAdminToken(msg, s.adminToken)
}

func (s *Server) checkAdminToken(msg map[string]interface{}, adminToken string) error {
	if adminToken == "" {
		return fmt.Errorf("network creation is disabled")
	}
	token, _ := msg["admin_token"].(string)
	if subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) != 1 {
		return fmt.Errorf("invalid admin token")
	}
	return nil
}

// requireNetworkRole checks if the message sender has one of the allowed roles
// in the specified network. It also accepts the global admin token or the
// per-network admin token as an override. Caller must NOT hold s.mu.
func (s *Server) requireNetworkRole(msg map[string]interface{}, netID uint16, allowedRoles ...Role) error {
	// Global admin token always authorizes
	if s.requireAdminToken(msg) == nil {
		return nil
	}

	// Per-network admin token check
	token, _ := msg["admin_token"].(string)
	s.mu.RLock()
	network, ok := s.networks[netID]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}
	if network.AdminToken != "" && token != "" {
		if subtle.ConstantTimeCompare([]byte(token), []byte(network.AdminToken)) == 1 {
			return nil
		}
	}

	// RBAC role check: look up the requesting node's role
	nodeID := jsonUint32(msg, "node_id")
	if nodeID == 0 {
		return fmt.Errorf("rbac: node_id required for role-based authorization")
	}
	s.mu.RLock()
	role, hasRole := network.MemberRoles[nodeID]
	s.mu.RUnlock()
	if !hasRole {
		return fmt.Errorf("rbac: node %d has no role in network %d", nodeID, netID)
	}
	for _, allowed := range allowedRoles {
		if role == allowed {
			return nil
		}
	}
	return fmt.Errorf("rbac: node %d has role %q, requires one of %v", nodeID, role, allowedRoles)
}

// audit emits a structured audit log entry for registry mutations.
// When log-format=json, these are filterable via jq 'select(.msg=="audit")'.
func (s *Server) audit(action string, attrs ...any) {
	slog.Info("audit", append([]any{"audit_action", action}, attrs...)...)
	entry := s.appendAudit(action, 0, 0, attrs...)
	s.metrics.auditEventsTotal.Inc()
	if s.webhook != nil {
		details := make(map[string]interface{}, len(attrs)/2)
		for i := 0; i+1 < len(attrs); i += 2 {
			if key, ok := attrs[i].(string); ok {
				details[key] = attrs[i+1]
			}
		}
		s.webhook.Emit(action, details)
	}
	if s.auditExporter != nil && entry != nil {
		s.auditExporter.Export(entry)
	}
}

// requireEnterprise checks that the given network has the Enterprise flag.
// Returns a clear error for non-enterprise networks attempting enterprise features.
func (s *Server) requireEnterprise(netID uint16) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	net, ok := s.networks[netID]
	if !ok {
		return fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}
	if !net.Enterprise {
		return fmt.Errorf("enterprise feature: requires enterprise network")
	}
	return nil
}

// isEnterpriseNode returns true if the node belongs to at least one enterprise network.
func (s *Server) isEnterpriseNode(nodeID uint32) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	node, ok := s.nodes[nodeID]
	if !ok {
		return false
	}
	for _, netID := range node.Networks {
		if net, ok := s.networks[netID]; ok && net.Enterprise {
			return true
		}
	}
	return false
}

// auditEnterprise emits an audit log only for enterprise networks.
// Non-enterprise networks silently skip the audit entry.
func (s *Server) auditEnterprise(netID uint16, action string, attrs ...any) {
	s.mu.RLock()
	net, ok := s.networks[netID]
	s.mu.RUnlock()
	if !ok || !net.Enterprise {
		return
	}
	slog.Info("audit", append([]any{"audit_action", action}, attrs...)...)
	s.appendAudit(action, netID, 0, attrs...)
}

const maxAuditEntries = 1000

// appendAudit adds an entry to the in-memory audit ring buffer.
func (s *Server) appendAudit(action string, netID uint16, nodeID uint32, attrs ...any) *AuditEntry {
	// Extract node_id and network_id from attrs if not explicitly provided
	for i := 0; i+1 < len(attrs); i += 2 {
		k, ok := attrs[i].(string)
		if !ok {
			continue
		}
		if k == "node_id" && nodeID == 0 {
			switch v := attrs[i+1].(type) {
			case uint32:
				nodeID = v
			case int:
				nodeID = uint32(v)
			case float64:
				nodeID = uint32(v)
			}
		}
		if k == "network_id" && netID == 0 {
			switch v := attrs[i+1].(type) {
			case uint16:
				netID = v
			case int:
				netID = uint16(v)
			case float64:
				netID = uint16(v)
			}
		}
	}
	// Build details string from remaining attrs
	var details string
	for i := 0; i+1 < len(attrs); i += 2 {
		if k, ok := attrs[i].(string); ok && k != "node_id" && k != "network_id" {
			if details != "" {
				details += ", "
			}
			details += fmt.Sprintf("%s=%v", k, attrs[i+1])
		}
	}

	entry := AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Action:    action,
		NetworkID: netID,
		NodeID:    nodeID,
		Details:   details,
	}

	s.auditMu.Lock()
	if len(s.auditLog) >= maxAuditEntries {
		s.auditLog = s.auditLog[1:]
	}
	s.auditLog = append(s.auditLog, entry)
	s.auditMu.Unlock()
	return &entry
}

type Server struct {
	mu           sync.RWMutex
	nodes        map[uint32]*NodeInfo
	startTime    time.Time
	requestCount atomic.Int64
	networks     map[uint16]*NetworkInfo
	pubKeyIdx    map[string]uint32 // base64(pubkey) -> nodeID for re-registration
	ownerIdx     map[string]uint32 // owner -> nodeID for key rotation
	hostnameIdx  map[string]uint32 // hostname -> nodeID (unique index)
	nextNode     uint32
	nextNet      uint16
	listener     net.Listener
	readyCh      chan struct{}

	// Beacon coordination
	beaconAddr string

	// Persistence
	storePath string        // empty = no persistence
	saveCh    chan struct{} // debounced save signal
	saveDone  chan struct{} // closed when saveLoop exits

	// TLS
	tlsConfig *tls.Config

	// Trust pairs: "min:max" -> true (bidirectional trust)
	trustPairs map[string]bool

	// Handshake relay inbox: target nodeID -> pending requests
	handshakeInbox map[uint32][]*HandshakeRelayMsg
	// Handshake response inbox: requester nodeID -> approval/rejection responses
	handshakeResponses map[uint32][]*HandshakeResponseMsg

	// Network invite inbox: target nodeID -> pending invites
	inviteInbox map[uint32][]*NetworkInvite

	// Rate limiting
	rateLimiter   *RateLimiter
	opRateLimiter *OperationRateLimiter

	// Connection tracking
	connCount      atomic.Int64
	maxConnections int64

	// Replication
	replMgr    *replicationManager
	replToken  string // H4 fix: required for subscribe_replication; empty = replication disabled
	standby    bool   // if true, reject writes and receive snapshots from primary
	adminToken string // required for create_network; empty = creation disabled

	// Beacon cluster: beacon instances register themselves for peer discovery
	beacons map[uint32]*beaconEntry

	// Prometheus metrics
	metrics *registryMetrics

	// Webhook dispatcher (nil = disabled)
	webhook *registryWebhook

	// Identity verification webhook URL (POST id_token → get verified identity)
	identityWebhookURL string

	// Identity provider configuration (set via blueprint or protocol)
	idpConfig *BlueprintIdentityProvider

	// Audit export adapter (Splunk HEC, syslog/CEF, JSON)
	auditExporter     *AuditExporter
	auditExportConfig *BlueprintAuditExport

	// RBAC pre-assignments: networkID -> roles that auto-apply when matching nodes join
	rbacPreAssign map[uint16][]BlueprintRole

	// Clock (overridable for testing)
	now func() time.Time

	// Shutdown
	done chan struct{}

	// Audit ring buffer (separate mutex — audit() is called while holding s.mu)
	auditMu  sync.Mutex
	auditLog []AuditEntry
}

// AuditEntry records a single audit event.
type AuditEntry struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	NetworkID uint16 `json:"network_id,omitempty"`
	NodeID    uint32 `json:"node_id,omitempty"`
	Details   string `json:"details,omitempty"`
}

// beaconEntry tracks a registered beacon instance.
type beaconEntry struct {
	ID       uint32
	Addr     string
	LastSeen time.Time
}

// beaconTTL is how long a beacon registration is valid without re-register.
const beaconTTL = 60 * time.Second

// staleNodeThreshold is how long since last heartbeat before a node is stale/offline.
const staleNodeThreshold = 3 * time.Minute // 3 missed heartbeats (60s heartbeat interval)

// defaultMaxConnections is the maximum concurrent connections the server will accept.
const defaultMaxConnections int64 = 100000

// maxMessageSize is the maximum allowed wire message size (64KB).
// Messages exceeding this limit cause the connection to be closed.
const maxMessageSize = 64 * 1024

// RateLimiter tracks per-IP registration attempts using a token bucket.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    int           // registrations per window
	window  time.Duration // window size
	now     func() time.Time
}

type bucket struct {
	tokens   float64
	lastFill time.Time
}

// NewRateLimiter creates a rate limiter allowing rate requests per window per IP.
func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		window:  window,
		now:     time.Now,
	}
}

// SetClock overrides the time source (for testing).
func (rl *RateLimiter) SetClock(fn func() time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.now = fn
}

// Allow checks if a request from the given IP is allowed.
// Uses a sliding window: tokens refill proportionally to elapsed time.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	b, ok := rl.buckets[ip]
	if !ok {
		rl.buckets[ip] = &bucket{tokens: float64(rl.rate) - 1, lastFill: now}
		return true
	}

	// Refill tokens proportional to elapsed time
	elapsed := now.Sub(b.lastFill)
	refill := float64(rl.rate) * (float64(elapsed) / float64(rl.window))
	b.tokens += refill
	if b.tokens > float64(rl.rate) {
		b.tokens = float64(rl.rate)
	}
	b.lastFill = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Cleanup removes stale buckets. Called periodically.
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	threshold := rl.now().Add(-2 * rl.window)
	for ip, b := range rl.buckets {
		if b.lastFill.Before(threshold) {
			delete(rl.buckets, ip)
		}
	}
}

// BucketCount returns the number of tracked IPs (for testing).
func (rl *RateLimiter) BucketCount() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.buckets)
}

// HasBucket returns whether a given IP has an active bucket (for testing).
func (rl *RateLimiter) HasBucket(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	_, ok := rl.buckets[ip]
	return ok
}

// OperationRateLimiter provides per-operation rate limiting using separate
// token buckets for each operation category. Each category has its own rate.
type OperationRateLimiter struct {
	mu         sync.Mutex
	categories map[string]*RateLimiter
}

// NewOperationRateLimiter creates a rate limiter with per-operation categories.
func NewOperationRateLimiter() *OperationRateLimiter {
	return &OperationRateLimiter{
		categories: make(map[string]*RateLimiter),
	}
}

// AddCategory registers a rate limit for an operation category.
func (orl *OperationRateLimiter) AddCategory(name string, rate int, window time.Duration) {
	orl.mu.Lock()
	defer orl.mu.Unlock()
	orl.categories[name] = NewRateLimiter(rate, window)
}

// Allow checks if a request from the given IP is allowed for the given category.
// Returns true if the category is not registered (no limit configured).
func (orl *OperationRateLimiter) Allow(category, ip string) bool {
	orl.mu.Lock()
	rl, ok := orl.categories[category]
	orl.mu.Unlock()
	if !ok {
		return true // no rate limit for this category
	}
	return rl.Allow(ip)
}

// SetClock overrides the time source for all categories (for testing).
func (orl *OperationRateLimiter) SetClock(fn func() time.Time) {
	orl.mu.Lock()
	defer orl.mu.Unlock()
	for _, rl := range orl.categories {
		rl.SetClock(fn)
	}
}

// Cleanup removes stale buckets from all categories.
func (orl *OperationRateLimiter) Cleanup() {
	orl.mu.Lock()
	defer orl.mu.Unlock()
	for _, rl := range orl.categories {
		rl.Cleanup()
	}
}

// KeyInfo tracks key lifecycle metadata for compliance and trust decisions.
type KeyInfo struct {
	CreatedAt   time.Time `json:"created_at"`
	RotatedAt   time.Time `json:"rotated_at,omitempty"`  // zero if never rotated
	RotateCount int       `json:"rotate_count"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`  // zero = no expiry
}

type NodeInfo struct {
	ID         uint32
	Owner      string // email or identifier (for key rotation)
	PublicKey  []byte
	RealAddr   string
	Networks   []uint16
	LastSeen   time.Time
	Public     bool     // if true, endpoint is visible in lookup/list_nodes
	Hostname   string   // unique hostname for discovery (empty = none)
	Tags       []string // capability tags (e.g., "webserver", "assistant")
	PoloScore  int      // polo score for reputation system (default: 0)
	TaskExec   bool     // if true, node advertises task execution capability
	LANAddrs   []string // LAN addresses for same-network peer detection
	KeyMeta    KeyInfo  // key lifecycle metadata
	ExternalID string   // verified external identity (e.g., OIDC sub, email from IdP)
}

// Role represents a member's permission level within a network.
type Role string

const (
	RoleOwner  Role = "owner"  // created the network, full control
	RoleAdmin  Role = "admin"  // can invite, remove members, change settings
	RoleMember Role = "member" // can communicate, cannot manage
)

// NetworkPolicy defines constraints and metadata for a network.
type NetworkPolicy struct {
	MaxMembers   int      `json:"max_members"`    // 0 = unlimited
	AllowedPorts []uint16 `json:"allowed_ports"`  // empty = all ports allowed
	Description  string   `json:"description"`    // human-readable network description
}

type NetworkInfo struct {
	ID          uint16
	Name        string
	JoinRule    string
	Token       string            // for token-gated networks
	Members     []uint32
	MemberRoles map[uint32]Role   // per-member RBAC roles
	AdminToken  string            // per-network admin token (optional)
	Policy      NetworkPolicy     // network policy (membership limits, port restrictions)
	Enterprise  bool              // enterprise network (gates Phase 2-5 features)
	Created     time.Time
}

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

// maxHandshakeInbox limits the number of pending handshake requests per node.
const maxHandshakeInbox = 100

// NetworkInvite is a pending network invitation stored in the registry's invite inbox.
type NetworkInvite struct {
	NetworkID uint16    `json:"network_id"`
	InviterID uint32    `json:"inviter_id"`
	Timestamp time.Time `json:"timestamp"`
}

// maxInviteInbox limits the number of pending invites per node.
const maxInviteInbox = 100

// inviteTTL is the maximum age of a pending invite before it expires.
const inviteTTL = 30 * 24 * time.Hour // 30 days

// hostnameRegex validates hostname format: lowercase alphanumeric + hyphens, 1-63 chars.
var hostnameRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// tagRegex validates tag format: lowercase alphanumeric + hyphens, 1-32 chars.
var tagRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// networkNameRegex validates network name format: lowercase alphanumeric + hyphens, 1-63 chars.
var networkNameRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// reservedHostnames are not allowed as node hostnames.
var reservedHostnames = map[string]bool{
	"localhost": true,
	"backbone":  true,
	"broadcast": true,
}

// reservedNetworkNames are not allowed as network names.
var reservedNetworkNames = map[string]bool{
	"backbone": true,
}

// validateHostname checks that a hostname is valid for registration.
func validateHostname(name string) error {
	if len(name) == 0 {
		return nil // empty clears hostname
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

// validateNetworkName checks that a network name is valid.
func validateNetworkName(name string) error {
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

func New(beaconAddr string) *Server {
	return NewWithStore(beaconAddr, "")
}

func NewWithStore(beaconAddr, storePath string) *Server {
	s := &Server{
		nodes:              make(map[uint32]*NodeInfo),
		networks:           make(map[uint16]*NetworkInfo),
		pubKeyIdx:          make(map[string]uint32),
		ownerIdx:           make(map[string]uint32),
		hostnameIdx:        make(map[string]uint32),
		nextNode:           1, // 0 is reserved
		nextNet:            1, // 0 is backbone
		beaconAddr:         beaconAddr,
		storePath:          storePath,
		startTime:          time.Now(),
		trustPairs:         make(map[string]bool),
		handshakeInbox:     make(map[uint32][]*HandshakeRelayMsg),
		handshakeResponses: make(map[uint32][]*HandshakeResponseMsg),
		inviteInbox:        make(map[uint32][]*NetworkInvite),
		rateLimiter:    NewRateLimiter(10, time.Minute), // 10 registrations per IP per minute
		maxConnections: defaultMaxConnections,
		beacons:        make(map[uint32]*beaconEntry),
		replMgr:            newReplicationManager(),
		metrics:            newRegistryMetrics(),
		readyCh:            make(chan struct{}),
		done:               make(chan struct{}),
		saveCh:             make(chan struct{}, 1),
		saveDone:           make(chan struct{}),
		now:                time.Now,
	}

	// Per-operation rate limits
	s.opRateLimiter = NewOperationRateLimiter()
	s.opRateLimiter.AddCategory("resolve", 100, time.Minute)
	s.opRateLimiter.AddCategory("query", 500, time.Minute) // lookup, resolve_hostname, list_nodes
	s.opRateLimiter.AddCategory("heartbeat", 50, time.Minute)

	go s.saveLoop()

	// Try loading from disk
	if storePath != "" {
		if err := s.load(); err != nil {
			slog.Info("registry starting fresh", "reason", err)
		} else {
			slog.Info("registry loaded state from disk",
				"nodes", len(s.nodes),
				"networks", len(s.networks),
				"next_node", s.nextNode,
				"next_net", s.nextNet,
			)
			return s
		}
	}

	// Create the backbone network (ID 0)
	s.networks[0] = &NetworkInfo{
		ID:       0,
		Name:     "backbone",
		JoinRule: "open",
		Members:  []uint32{},
		Created:  time.Now(),
	}

	return s
}

// SetStandby configures this server as a standby that receives replicated
// state from a primary. In standby mode, write operations are rejected.
func (s *Server) SetStandby(primary string) {
	s.mu.Lock()
	s.standby = true
	s.mu.Unlock()
	go s.RunStandby(primary)
}

// IsStandby returns true if this server is running in standby mode.
func (s *Server) IsStandby() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.standby
}

// SetAdminToken sets the admin token required for network creation.
// If empty, network creation is disabled entirely (secure by default).
func (s *Server) SetAdminToken(token string) {
	s.mu.Lock()
	s.adminToken = token
	s.mu.Unlock()
}

// SetClock overrides the time source for testing.
func (s *Server) SetClock(fn func() time.Time) {
	s.mu.Lock()
	s.now = fn
	s.mu.Unlock()
}

// SetMaxConnections overrides the default connection limit (for testing).
func (s *Server) SetMaxConnections(max int64) {
	s.mu.Lock()
	s.maxConnections = max
	s.mu.Unlock()
}

// ConnCount returns the current number of active connections (for testing).
func (s *Server) ConnCount() int64 {
	return s.connCount.Load()
}

// SetOperationRateLimiterClock overrides the time source for per-operation rate limits (for testing).
func (s *Server) SetOperationRateLimiterClock(fn func() time.Time) {
	s.opRateLimiter.SetClock(fn)
}

// Reap triggers stale node and beacon cleanup (for testing).
func (s *Server) Reap() {
	s.reapStaleNodes()
	s.reapStaleBeacons()
}

// SetReplicationToken sets the token required for subscribe_replication (H4 fix).
// If empty, replication subscription is disabled.
func (s *Server) SetReplicationToken(token string) {
	s.mu.Lock()
	s.replToken = token
	s.mu.Unlock()
}

// SetWebhookURL configures the registry to POST audit events to the given URL.
// If url is empty, webhook dispatching is disabled.
func (s *Server) SetWebhookURL(url string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.webhook != nil {
		s.webhook.Close()
		s.webhook = nil
	}
	if url != "" {
		s.webhook = newRegistryWebhook(url)
		slog.Info("registry webhook configured", "url", url)
	}
}

// SetIdentityWebhookURL configures a verification webhook for identity tokens.
// When a node registers with an identity_token, the registry POSTs it to this
// URL for verification. The webhook should return {"verified": true, "external_id": "..."}
// or {"verified": false, "error": "..."}. Empty URL disables identity verification.
func (s *Server) SetIdentityWebhookURL(url string) {
	s.mu.Lock()
	s.identityWebhookURL = url
	s.mu.Unlock()
	if url != "" {
		slog.Info("identity webhook configured", "url", url)
	}
}

// SetTLS configures the registry to use TLS with the given cert and key files.
// If certFile is empty, a self-signed certificate is generated automatically.
func (s *Server) SetTLS(certFile, keyFile string) error {
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("load TLS keypair: %w", err)
		}
		s.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		slog.Info("registry TLS configured", "cert", certFile)
		return nil
	}

	// Generate self-signed certificate
	cert, err := generateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("generate self-signed cert: %w", err)
	}
	s.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	slog.Info("registry TLS configured with auto-generated self-signed certificate")
	return nil
}

func (s *Server) ListenAndServe(addr string) error {
	var ln net.Listener
	var err error

	if s.tlsConfig != nil {
		ln, err = tls.Listen("tcp", addr, s.tlsConfig)
	} else {
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.listener = ln

	tlsStr := "plaintext"
	if s.tlsConfig != nil {
		tlsStr = "TLS"
	}
	slog.Info("registry listening", "addr", ln.Addr(), "transport", tlsStr)
	close(s.readyCh)

	go s.reapLoop()
	go s.replMgr.startHeartbeat(s.done)

	consecutiveErrors := 0
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return nil
			default:
			}
			consecutiveErrors++
			slog.Error("registry accept error", "err", err, "consecutive", consecutiveErrors)
			if consecutiveErrors >= 10 {
				return fmt.Errorf("accept: %d consecutive errors, last: %w", consecutiveErrors, err)
			}
			// Backoff: 100ms * consecutive error count, max 2s
			backoff := time.Duration(consecutiveErrors) * 100 * time.Millisecond
			if backoff > 2*time.Second {
				backoff = 2 * time.Second
			}
			time.Sleep(backoff)
			continue
		}
		consecutiveErrors = 0

		// Connection count limit
		if s.connCount.Load() >= s.maxConnections {
			slog.Warn("connection limit reached, rejecting", "remote", conn.RemoteAddr(), "limit", s.maxConnections)
			conn.Close()
			continue
		}
		s.connCount.Add(1)
		go s.handleConn(conn)
	}
}

// generateSelfSignedCert creates an in-memory self-signed TLS certificate.
func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"Pilot Protocol"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// reapLoop removes nodes that have not sent a heartbeat recently.
func (s *Server) reapLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.reapStaleNodes()
			s.reapStaleBeacons()
			s.rateLimiter.Cleanup()
			s.opRateLimiter.Cleanup()
		case <-s.done:
			return
		}
	}
}

func (s *Server) reapStaleNodes() {
	threshold := s.now().Add(-staleNodeThreshold)
	s.mu.Lock()
	defer s.mu.Unlock()

	reaped := false
	for id, node := range s.nodes {
		if node.LastSeen.Before(threshold) {
			staleDuration := time.Since(node.LastSeen).Round(time.Second)
			slog.Info("registry reaping stale node", "node_id", id, "last_seen_ago", staleDuration)
			s.audit("node.reaped", "node_id", id, "reason", "stale_heartbeat",
				"last_seen_ago", staleDuration.String(), "networks", len(node.Networks))
			// Remove from backbone (network 0) only. Keep non-backbone network
			// memberships in the member lists so re-registration can restore them.
			if net, ok := s.networks[0]; ok {
				for i, m := range net.Members {
					if m == id {
						net.Members = append(net.Members[:i], net.Members[i+1:]...)
						break
					}
				}
			}
			// Keep pubKeyIdx and ownerIdx entries so re-registration can reclaim the node_id
			if node.Hostname != "" {
				delete(s.hostnameIdx, node.Hostname)
			}
			s.cleanupNode(id)
			delete(s.nodes, id)
			reaped = true
		}
	}
	if reaped {
		s.save()
	}
}

func (s *Server) reapStaleBeacons() {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, b := range s.beacons {
		if now.Sub(b.LastSeen) > beaconTTL {
			slog.Info("reaping stale beacon", "beacon_id", id, "last_seen_ago", now.Sub(b.LastSeen).Round(time.Second))
			delete(s.beacons, id)
		}
	}
}

// Ready returns a channel that is closed when the server has bound its port.
func (s *Server) Ready() <-chan struct{} {
	return s.readyCh
}

// Addr returns the server's bound address. Only valid after Ready() fires.
func (s *Server) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

func (s *Server) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	<-s.saveDone // wait for saveLoop to finish its final flush
	if s.webhook != nil {
		s.webhook.Close()
	}
	if s.auditExporter != nil {
		s.auditExporter.Close()
	}
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) handleConn(conn net.Conn) {
	defer func() {
		conn.Close()
		s.connCount.Add(-1)
	}()

	// Shrink socket buffers for agent connections — heartbeat/lookup messages
	// are tiny (~100-200 bytes). Default kernel buffers (~128KB) are 600x oversized.
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetReadBuffer(4096)
		tc.SetWriteBuffer(4096)
	}

	for {
		// S27 fix: read deadline prevents idle connections from holding goroutines forever
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		msg, err := readMessage(conn)
		if err != nil {
			if err != io.EOF {
				slog.Debug("registry read error", "remote", conn.RemoteAddr(), "err", err)
			}
			return
		}

		// Replication subscription takes over the connection
		if msgType, _ := msg["type"].(string); msgType == "subscribe_replication" {
			// H4 fix: require replication token
			s.mu.RLock()
			token := s.replToken
			s.mu.RUnlock()
			if token == "" {
				writeMessage(conn, map[string]interface{}{
					"type":  "error",
					"error": "replication not configured",
				})
				return
			}
			providedToken, _ := msg["token"].(string)
			if subtle.ConstantTimeCompare([]byte(providedToken), []byte(token)) != 1 {
				writeMessage(conn, map[string]interface{}{
					"type":  "error",
					"error": "invalid replication token",
				})
				return
			}
			s.handleSubscribeReplication(conn)
			return // connection is managed by replication handler
		}

		resp, err := s.handleMessage(msg, conn.RemoteAddr().String())
		if err != nil {
			errMsg := "request failed"
			if strings.Contains(err.Error(), "rate limited") ||
				strings.Contains(err.Error(), "enterprise feature") ||
				strings.Contains(err.Error(), "expired") ||
				strings.Contains(err.Error(), "already") ||
				strings.Contains(err.Error(), "not a member") ||
				strings.Contains(err.Error(), "cannot") ||
				strings.Contains(err.Error(), "too many") ||
				strings.Contains(err.Error(), "too long") ||
				strings.Contains(err.Error(), "not found") ||
				strings.Contains(err.Error(), "invalid") ||
				strings.Contains(err.Error(), "required") {
				errMsg = err.Error()
			}
			slog.Error("registry handle error", "remote", conn.RemoteAddr(), "err", err)
			resp = map[string]interface{}{
				"type":  "error",
				"error": errMsg,
			}
		}

		if err := writeMessage(conn, resp); err != nil {
			slog.Error("registry write error", "remote", conn.RemoteAddr(), "err", err)
			return
		}
	}
}

func (s *Server) handleMessage(msg map[string]interface{}, remoteAddr string) (resp map[string]interface{}, err error) {
	s.requestCount.Add(1)
	msgType, _ := msg["type"].(string)

	// Prometheus instrumentation
	s.metrics.requestsTotal.WithLabel(msgType).Inc()
	start := time.Now()
	defer func() {
		s.metrics.requestDuration.WithLabel(msgType).Observe(time.Since(start).Seconds())
		if err != nil {
			s.metrics.errorsTotal.WithLabel(msgType).Inc()
		}
	}()

	// Standby mode: reject write operations, allow reads
	s.mu.RLock()
	isStandby := s.standby
	s.mu.RUnlock()
	if isStandby {
		switch msgType {
		case "lookup", "resolve", "list_networks", "list_nodes", "heartbeat", "poll_handshakes", "poll_invites", "resolve_hostname", "beacon_list",
			"get_polo_score", "get_key_info", "get_network_policy", "get_audit_log", "get_member_role", "check_trust":
			// reads are allowed on standby
		default:
			return nil, fmt.Errorf("standby mode: write operations not accepted (use primary)")
		}
	}

	// Per-operation rate limiting by source IP
	host, _, _ := net.SplitHostPort(remoteAddr)

	switch msgType {
	case "register":
		// Rate limit registrations by source IP (exempt known-key re-registrations)
		if !s.rateLimiter.Allow(host) {
			pubKeyB64, _ := msg["public_key"].(string)
			s.mu.RLock()
			_, knownKey := s.pubKeyIdx[pubKeyB64]
			s.mu.RUnlock()
			if !knownKey {
				slog.Warn("registration rate limited", "remote_ip", host)
				return nil, fmt.Errorf("rate limited: too many registrations from %s", host)
			}
		}
		return s.handleRegister(msg, remoteAddr)
	case "create_network":
		return s.handleCreateNetwork(msg)
	case "join_network":
		return s.handleJoinNetwork(msg)
	case "leave_network":
		return s.handleLeaveNetwork(msg)
	case "delete_network":
		return s.handleDeleteNetwork(msg)
	case "rename_network":
		return s.handleRenameNetwork(msg)
	case "set_network_enterprise":
		return s.handleSetNetworkEnterprise(msg)
	case "lookup":
		if !s.opRateLimiter.Allow("query", host) {
			return nil, fmt.Errorf("rate limited: too many queries from %s", host)
		}
		return s.handleLookup(msg)
	case "resolve":
		if !s.opRateLimiter.Allow("resolve", host) {
			return nil, fmt.Errorf("rate limited: too many resolves from %s", host)
		}
		return s.handleResolve(msg)
	case "list_networks":
		return s.handleListNetworks()
	case "list_nodes":
		if !s.opRateLimiter.Allow("query", host) {
			return nil, fmt.Errorf("rate limited: too many queries from %s", host)
		}
		return s.handleListNodes(msg)
	case "rotate_key":
		return s.handleRotateKey(msg)
	case "update_polo_score":
		return s.handleUpdatePoloScore(msg)
	case "set_polo_score":
		return s.handleSetPoloScore(msg)
	case "get_polo_score":
		return s.handleGetPoloScore(msg)
	case "deregister":
		return s.handleDeregister(msg)
	case "set_visibility":
		return s.handleSetVisibility(msg)
	case "report_trust":
		return s.handleReportTrust(msg)
	case "revoke_trust":
		return s.handleRevokeTrust(msg)
	case "check_trust":
		return s.handleCheckTrust(msg)
	case "request_handshake":
		return s.handleRequestHandshake(msg)
	case "poll_handshakes":
		return s.handlePollHandshakes(msg)
	case "respond_handshake":
		return s.handleRespondHandshake(msg)
	case "heartbeat":
		if !s.opRateLimiter.Allow("heartbeat", host) {
			return nil, fmt.Errorf("rate limited: too many heartbeats from %s", host)
		}
		return s.handleHeartbeat(msg)
	case "punch":
		return s.handlePunch(msg)
	case "set_hostname":
		return s.handleSetHostname(msg)
	case "set_tags":
		return s.handleSetTags(msg)
	case "set_task_exec":
		return s.handleSetTaskExec(msg)
	case "resolve_hostname":
		if !s.opRateLimiter.Allow("query", host) {
			return nil, fmt.Errorf("rate limited: too many queries from %s", host)
		}
		return s.handleResolveHostname(msg)
	case "beacon_register":
		return s.handleBeaconRegister(msg)
	case "beacon_list":
		return s.handleBeaconList()
	case "invite_to_network":
		return s.handleInviteToNetwork(msg)
	case "poll_invites":
		return s.handlePollInvites(msg)
	case "respond_invite":
		return s.handleRespondInvite(msg)
	case "kick_member":
		return s.handleKickMember(msg)
	case "promote_member":
		return s.handlePromoteMember(msg)
	case "demote_member":
		return s.handleDemoteMember(msg)
	case "transfer_ownership":
		return s.handleTransferOwnership(msg)
	case "get_member_role":
		return s.handleGetMemberRole(msg)
	case "set_network_policy":
		return s.handleSetNetworkPolicy(msg)
	case "get_network_policy":
		return s.handleGetNetworkPolicy(msg)
	case "set_key_expiry":
		return s.handleSetKeyExpiry(msg)
	case "get_key_info":
		return s.handleGetKeyInfo(msg)
	case "get_audit_log":
		return s.handleGetAuditLog(msg)
	case "set_webhook":
		return s.handleSetWebhook(msg)
	case "get_webhook":
		return s.handleGetWebhook(msg)
	case "set_identity_webhook":
		return s.handleSetIdentityWebhook(msg)
	case "set_external_id":
		return s.handleSetExternalID(msg)
	case "get_identity":
		return s.handleGetIdentity(msg)
	case "get_webhook_dlq":
		return s.handleGetWebhookDLQ(msg)
	case "provision_network":
		return s.handleProvisionNetwork(msg)
	case "set_audit_export":
		return s.handleSetAuditExport(msg)
	case "get_audit_export":
		return s.handleGetAuditExport(msg)
	case "get_idp_config":
		return s.handleGetIDPConfig(msg)
	case "set_idp_config":
		return s.handleSetIDPConfig(msg)
	case "get_provision_status":
		return s.handleGetProvisionStatus(msg)
	case "directory_sync":
		return s.handleDirectorySync(msg)
	case "directory_status":
		return s.handleGetDirectoryStatus(msg)
	case "validate_token":
		return s.handleValidateToken(msg)
	default:
		return nil, fmt.Errorf("unknown message type: %q", msgType)
	}
}

// sanitizeListenAddr uses the TCP source IP from remoteAddr but accepts
// the port from the client-provided address. This prevents clients from
// registering arbitrary IP addresses while allowing them to specify their
// actual listening port (which may differ from the TCP source port).
func sanitizeListenAddr(remoteAddr, clientAddr string) string {
	remoteHost, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	if clientAddr == "" {
		return remoteAddr
	}
	_, clientPort, err := net.SplitHostPort(clientAddr)
	if err != nil {
		return remoteAddr
	}
	return net.JoinHostPort(remoteHost, clientPort)
}

func (s *Server) handleRegister(msg map[string]interface{}, remoteAddr string) (map[string]interface{}, error) {
	clientAddr, _ := msg["listen_addr"].(string)
	listenAddr := sanitizeListenAddr(remoteAddr, clientAddr)
	owner, _ := msg["owner"].(string)
	hostname, _ := msg["hostname"].(string)
	identityToken, _ := msg["identity_token"].(string)

	// Verify identity token before registration (calls external webhook)
	var externalID string
	if identityToken != "" {
		var err error
		externalID, err = s.verifyIdentityToken(identityToken)
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

	// Extract LAN addresses for same-network peer detection
	var lanAddrs []string
	if rawAddrs, ok := msg["lan_addrs"].([]interface{}); ok {
		for _, raw := range rawAddrs {
			if addr, ok := raw.(string); ok && addr != "" {
				lanAddrs = append(lanAddrs, addr)
			}
		}
	}

	// Registration requires a client-generated public key
	pubKeyB64, ok := msg["public_key"].(string)
	if !ok || pubKeyB64 == "" {
		return nil, fmt.Errorf("registration requires public_key")
	}

	// Validate hostname before acquiring lock (avoids holding lock for validation)
	if hostname != "" {
		if err := validateHostname(hostname); err != nil {
			// Register without hostname, return warning
			resp, regErr := s.handleReRegister(pubKeyB64, listenAddr, owner, "", lanAddrs)
			if regErr != nil {
				return resp, regErr
			}
			s.metrics.registrations.Inc()
			resp["hostname_error"] = err.Error()
			resp["observed_addr"] = listenAddr
			resp["protocol_version"] = int(protocol.Version)
			return resp, nil
		}
	}

	// M3 fix: pass hostname into handleReRegister so registration + hostname
	// are set atomically under a single lock acquisition.
	resp, err := s.handleReRegister(pubKeyB64, listenAddr, owner, hostname, lanAddrs)
	if err == nil {
		s.metrics.registrations.Inc()
		resp["observed_addr"] = listenAddr
		resp["protocol_version"] = int(protocol.Version)
		// Set verified external identity if provided
		if externalID != "" {
			var nid uint32
			switch v := resp["node_id"].(type) {
			case uint32:
				nid = v
			case float64:
				nid = uint32(v)
			}
			if nid != 0 {
				s.mu.Lock()
				if node, exists := s.nodes[nid]; exists {
					node.ExternalID = externalID
					s.save()
				}
				s.mu.Unlock()
				resp["external_id"] = externalID
			}
		}
	}
	return resp, err
}

// handleRotateKey rotates the Ed25519 keypair for a node.
// The caller must prove ownership by signing "rotate:<node_id>" with the current private key
// and provide the new_public_key to replace the old one.
func (s *Server) handleRotateKey(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	sigB64, _ := msg["signature"].(string)
	newPubKeyB64, _ := msg["new_public_key"].(string)

	if sigB64 == "" {
		return nil, fmt.Errorf("rotate_key requires a valid signature")
	}
	if newPubKeyB64 == "" {
		return nil, fmt.Errorf("rotate_key requires new_public_key")
	}

	newPubKey, err := crypto.DecodePublicKey(newPubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("invalid new_public_key: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	// Verify signature: message = "rotate:<node_id>"
	challenge := fmt.Sprintf("rotate:%d", nodeID)
	sig, err := base64Decode(sigB64)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}
	if !crypto.Verify(node.PublicKey, []byte(challenge), sig) {
		return nil, fmt.Errorf("signature verification failed")
	}

	// Swap pubkey index
	oldPubKeyB64 := crypto.EncodePublicKey(node.PublicKey)
	delete(s.pubKeyIdx, oldPubKeyB64)

	node.PublicKey = newPubKey
	node.LastSeen = time.Now()
	node.KeyMeta.RotatedAt = time.Now()
	node.KeyMeta.RotateCount++
	s.pubKeyIdx[newPubKeyB64] = nodeID
	s.save()

	addr := protocol.Addr{Network: 0, Node: nodeID}
	slog.Debug("rotated key", "node_id", nodeID, "addr", addr)
	s.audit("key.rotated", "node_id", nodeID)
	s.metrics.keyRotations.Inc()

	return map[string]interface{}{
		"type":       "rotate_key_ok",
		"node_id":    nodeID,
		"address":    addr.String(),
		"public_key": newPubKeyB64,
	}, nil
}

// handleSetKeyExpiry sets the key expiry time for a node.
// Only the node itself can set its own key expiry (signature-verified).
func (s *Server) handleSetKeyExpiry(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")

	// Parse expires_at — empty string or "never" clears the expiry
	expiresAtStr, _ := msg["expires_at"].(string)
	var expiresAt time.Time
	clearExpiry := expiresAtStr == "" || expiresAtStr == "never"
	if !clearExpiry {
		var err error
		expiresAt, err = time.Parse(time.RFC3339, expiresAtStr)
		if err != nil {
			return nil, fmt.Errorf("invalid expires_at: %w", err)
		}
		// Reject if expiry is in the past
		if expiresAt.Before(s.now()) {
			return nil, fmt.Errorf("expires_at must be in the future")
		}
		// Reject unreasonably far expiry (max 10 years)
		if expiresAt.After(s.now().Add(10 * 365 * 24 * time.Hour)) {
			return nil, fmt.Errorf("invalid expires_at: cannot exceed 10 years")
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	// Verify signature (admin token bypass for console control plane)
	if sigErr := s.verifyNodeSignature(node, msg, fmt.Sprintf("set_key_expiry:%d", nodeID)); sigErr != nil {
		if err := s.requireAdminTokenLocked(msg); err != nil {
			return nil, sigErr
		}
	}

	// Enterprise gate: key expiry is a Phase 4 feature
	// (inline check — lock already held, cannot call isEnterpriseNode)
	isEnterprise := false
	for _, nid := range node.Networks {
		if net, ok := s.networks[nid]; ok && net.Enterprise {
			isEnterprise = true
			break
		}
	}
	if !isEnterprise {
		return nil, fmt.Errorf("enterprise feature: key expiry requires enterprise network membership")
	}

	oldExpiresAt := node.KeyMeta.ExpiresAt
	node.KeyMeta.ExpiresAt = expiresAt // zero value clears it
	s.save()

	if clearExpiry {
		slog.Debug("cleared key expiry", "node_id", nodeID)
		if !oldExpiresAt.IsZero() {
			s.audit("key.expiry_cleared", "node_id", nodeID, "old_expires_at", oldExpiresAt.Format(time.RFC3339))
		} else {
			s.audit("key.expiry_cleared", "node_id", nodeID)
		}
		return map[string]interface{}{
			"type":    "set_key_expiry_ok",
			"node_id": nodeID,
		}, nil
	}

	slog.Debug("set key expiry", "node_id", nodeID, "expires_at", expiresAt)
	if !oldExpiresAt.IsZero() {
		s.audit("key.expiry_set", "node_id", nodeID, "expires_at", expiresAt.Format(time.RFC3339), "old_expires_at", oldExpiresAt.Format(time.RFC3339))
	} else {
		s.audit("key.expiry_set", "node_id", nodeID, "expires_at", expiresAt.Format(time.RFC3339))
	}

	return map[string]interface{}{
		"type":       "set_key_expiry_ok",
		"node_id":    nodeID,
		"expires_at": expiresAt.Format(time.RFC3339),
	}, nil
}

// handleGetKeyInfo returns key lifecycle metadata for a node.
// Any authenticated caller can query (public information for trust decisions).
func (s *Server) handleGetKeyInfo(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")

	s.mu.RLock()
	defer s.mu.RUnlock()

	node, ok := s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	resp := map[string]interface{}{
		"type":         "get_key_info_ok",
		"node_id":      nodeID,
		"created_at":   node.KeyMeta.CreatedAt.Format(time.RFC3339),
		"rotate_count": node.KeyMeta.RotateCount,
	}
	if !node.KeyMeta.RotatedAt.IsZero() {
		resp["rotated_at"] = node.KeyMeta.RotatedAt.Format(time.RFC3339)
	}
	if !node.KeyMeta.ExpiresAt.IsZero() {
		resp["expires_at"] = node.KeyMeta.ExpiresAt.Format(time.RFC3339)
	}

	// Calculate key_age_days: if rotated, use RotatedAt; otherwise use CreatedAt
	keyStart := node.KeyMeta.CreatedAt
	if !node.KeyMeta.RotatedAt.IsZero() {
		keyStart = node.KeyMeta.RotatedAt
	}
	if !keyStart.IsZero() {
		resp["key_age_days"] = int(time.Since(keyStart).Hours() / 24)
	}

	return resp, nil
}

// handleGetAuditLog returns recent audit entries, optionally filtered by network_id.
func (s *Server) handleGetAuditLog(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}

	filterNetID := jsonUint16(msg, "network_id")
	limit := 100
	if l, ok := msg["limit"].(float64); ok && l > 0 && l <= 1000 {
		limit = int(l)
	}

	s.auditMu.Lock()
	all := make([]AuditEntry, len(s.auditLog))
	copy(all, s.auditLog)
	s.auditMu.Unlock()

	// Filter and reverse (newest first)
	var entries []map[string]interface{}
	for i := len(all) - 1; i >= 0 && len(entries) < limit; i-- {
		e := all[i]
		if filterNetID != 0 && e.NetworkID != filterNetID {
			continue
		}
		entry := map[string]interface{}{
			"timestamp": e.Timestamp,
			"action":    e.Action,
		}
		if e.NetworkID != 0 {
			entry["network_id"] = e.NetworkID
		}
		if e.NodeID != 0 {
			entry["node_id"] = e.NodeID
		}
		if e.Details != "" {
			entry["details"] = e.Details
		}
		entries = append(entries, entry)
	}
	if entries == nil {
		entries = []map[string]interface{}{}
	}

	return map[string]interface{}{
		"type":    "get_audit_log_ok",
		"entries": entries,
	}, nil
}

// handleSetWebhook configures the registry webhook URL. Requires admin token.
func (s *Server) handleSetWebhook(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}
	url, _ := msg["url"].(string)
	s.SetWebhookURL(url)
	status := "disabled"
	if url != "" {
		status = "enabled"
	}
	return map[string]interface{}{
		"type":   "set_webhook_ok",
		"status": status,
		"url":    url,
	}, nil
}

// handleGetWebhook returns the current webhook configuration. Requires admin token.
func (s *Server) handleGetWebhook(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}
	s.mu.RLock()
	wh := s.webhook
	s.mu.RUnlock()

	url := ""
	var delivered, failed, dropped uint64
	dlqLen := 0
	if wh != nil {
		url = wh.url
		delivered, failed, dropped = wh.Stats()
		dlqLen = len(wh.DLQ())
	}
	return map[string]interface{}{
		"type":      "get_webhook_ok",
		"enabled":   wh != nil,
		"url":       url,
		"delivered": delivered,
		"failed":    failed,
		"dropped":   dropped,
		"dlq_size":  dlqLen,
	}, nil
}

// handleGetWebhookDLQ returns the dead letter queue (failed webhook events).
func (s *Server) handleGetWebhookDLQ(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}
	s.mu.RLock()
	wh := s.webhook
	s.mu.RUnlock()

	var events []map[string]interface{}
	if wh != nil {
		for _, ev := range wh.DLQ() {
			entry := map[string]interface{}{
				"event_id":  ev.EventID,
				"action":    ev.Action,
				"timestamp": ev.Timestamp.Format("2006-01-02T15:04:05Z"),
			}
			if len(ev.Details) > 0 {
				entry["details"] = ev.Details
			}
			events = append(events, entry)
		}
	}

	return map[string]interface{}{
		"type":   "get_webhook_dlq_ok",
		"events": events,
		"count":  len(events),
	}, nil
}

// handleSetIdentityWebhook configures the identity verification webhook URL.
func (s *Server) handleSetIdentityWebhook(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}
	url, _ := msg["url"].(string)
	s.SetIdentityWebhookURL(url)
	status := "disabled"
	if url != "" {
		status = "enabled"
	}
	return map[string]interface{}{
		"type":   "set_identity_webhook_ok",
		"status": status,
	}, nil
}

// handleSetExternalID sets the external identity on a node. Requires admin token.
func (s *Server) handleSetExternalID(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}
	nodeID := jsonUint32(msg, "node_id")
	externalID, _ := msg["external_id"].(string)

	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node not found")
	}

	oldID := node.ExternalID
	node.ExternalID = externalID
	s.save()
	s.audit("identity.external_id_set", "node_id", nodeID, "old_external_id", oldID, "new_external_id", externalID)

	return map[string]interface{}{
		"type":        "set_external_id_ok",
		"node_id":     nodeID,
		"external_id": externalID,
	}, nil
}

// handleGetIdentity returns the external identity of a node. Requires admin token.
func (s *Server) handleGetIdentity(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}
	nodeID := jsonUint32(msg, "node_id")

	s.mu.RLock()
	defer s.mu.RUnlock()

	node, ok := s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node not found")
	}

	return map[string]interface{}{
		"type":        "get_identity_ok",
		"node_id":     nodeID,
		"external_id": node.ExternalID,
		"owner":       node.Owner,
	}, nil
}

// handleSetAuditExport configures the audit export adapter. Requires admin token.
func (s *Server) handleSetAuditExport(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}
	format, _ := msg["format"].(string)
	endpoint, _ := msg["endpoint"].(string)
	token, _ := msg["token"].(string)
	index, _ := msg["index"].(string)
	source, _ := msg["source"].(string)

	if format == "" || endpoint == "" {
		// Disable export
		s.mu.Lock()
		if s.auditExporter != nil {
			s.auditExporter.Close()
			s.auditExporter = nil
		}
		s.auditExportConfig = nil
		s.mu.Unlock()
		return map[string]interface{}{
			"type":   "set_audit_export_ok",
			"status": "disabled",
		}, nil
	}

	cfg := &BlueprintAuditExport{
		Format:   format,
		Endpoint: endpoint,
		Token:    token,
		Index:    index,
		Source:   source,
	}

	s.mu.Lock()
	if s.auditExporter != nil {
		s.auditExporter.Close()
	}
	s.auditExporter = newAuditExporter(cfg)
	s.auditExportConfig = cfg
	s.mu.Unlock()

	s.audit("audit_export.configured", "format", format, "endpoint", endpoint)
	return map[string]interface{}{
		"type":     "set_audit_export_ok",
		"status":   "enabled",
		"format":   format,
		"endpoint": endpoint,
	}, nil
}

// handleGetAuditExport returns the current audit export configuration.
func (s *Server) handleGetAuditExport(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}
	s.mu.RLock()
	cfg := s.auditExportConfig
	exp := s.auditExporter
	s.mu.RUnlock()

	resp := map[string]interface{}{
		"type":    "get_audit_export_ok",
		"enabled": cfg != nil,
	}
	if cfg != nil {
		resp["format"] = cfg.Format
		resp["endpoint"] = cfg.Endpoint
		if exp != nil {
			exported, dropped := exp.Stats()
			resp["exported"] = exported
			resp["dropped"] = dropped
		}
	}
	return resp, nil
}

// handleSetIDPConfig configures the identity provider. Requires admin token.
func (s *Server) handleSetIDPConfig(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}

	idpType, _ := msg["idp_type"].(string)
	url, _ := msg["url"].(string)

	if idpType == "" || url == "" {
		// Clear IDP config
		s.mu.Lock()
		s.idpConfig = nil
		s.identityWebhookURL = ""
		s.mu.Unlock()
		return map[string]interface{}{
			"type":   "set_idp_config_ok",
			"status": "disabled",
		}, nil
	}

	cfg := &BlueprintIdentityProvider{
		Type: idpType,
		URL:  url,
	}
	if v, ok := msg["issuer"].(string); ok {
		cfg.Issuer = v
	}
	if v, ok := msg["client_id"].(string); ok {
		cfg.ClientID = v
	}
	if v, ok := msg["tenant_id"].(string); ok {
		cfg.TenantID = v
	}
	if v, ok := msg["domain"].(string); ok {
		cfg.Domain = v
	}

	s.mu.Lock()
	s.idpConfig = cfg
	s.identityWebhookURL = url
	s.mu.Unlock()

	s.audit("idp.configured", "type", idpType, "url", url)
	return map[string]interface{}{
		"type":     "set_idp_config_ok",
		"status":   "enabled",
		"idp_type": idpType,
	}, nil
}

// handleGetIDPConfig returns the current identity provider configuration.
func (s *Server) handleGetIDPConfig(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}
	cfg := s.GetIdentityProviderConfig()
	resp := map[string]interface{}{
		"type":       "get_idp_config_ok",
		"configured": cfg != nil,
	}
	if cfg != nil {
		resp["idp_type"] = cfg.Type
		resp["url"] = cfg.URL
		if cfg.Issuer != "" {
			resp["issuer"] = cfg.Issuer
		}
		if cfg.ClientID != "" {
			resp["client_id"] = cfg.ClientID
		}
		if cfg.TenantID != "" {
			resp["tenant_id"] = cfg.TenantID
		}
		if cfg.Domain != "" {
			resp["domain"] = cfg.Domain
		}
	}
	return resp, nil
}

// handleGetProvisionStatus returns per-network provisioning details.
func (s *Server) handleGetProvisionStatus(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var networks []map[string]interface{}
	for _, net := range s.networks {
		if net.ID == 0 {
			continue // skip backbone
		}
		entry := map[string]interface{}{
			"network_id": net.ID,
			"name":       net.Name,
			"enterprise": net.Enterprise,
			"members":    len(net.Members),
			"join_rule":  net.JoinRule,
		}
		if net.Policy.MaxMembers > 0 {
			entry["max_members"] = net.Policy.MaxMembers
		}
		if len(net.Policy.AllowedPorts) > 0 {
			entry["allowed_ports"] = net.Policy.AllowedPorts
		}
		if roles, ok := s.rbacPreAssign[net.ID]; ok {
			entry["rbac_pre_assignments"] = len(roles)
		}
		networks = append(networks, entry)
	}

	resp := map[string]interface{}{
		"type":     "get_provision_status_ok",
		"networks": networks,
	}
	if s.idpConfig != nil {
		resp["idp_type"] = s.idpConfig.Type
	}
	if s.auditExportConfig != nil {
		resp["audit_export"] = s.auditExportConfig.Format
	}
	if s.webhook != nil {
		resp["webhook_enabled"] = true
	}
	return resp, nil
}

// maxPoloScore defines the valid range for polo scores.
const maxPoloScore = 1_000_000

// handleUpdatePoloScore adjusts the polo score of a node by a delta value.
func (s *Server) handleUpdatePoloScore(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	delta, ok := msg["delta"].(float64)
	if !ok {
		return nil, fmt.Errorf("update_polo_score requires delta field")
	}
	if delta > maxPoloScore || delta < -maxPoloScore {
		return nil, fmt.Errorf("polo score delta out of range (max %d)", maxPoloScore)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	node, exists := s.nodes[nodeID]
	if !exists {
		return nil, fmt.Errorf("node %d not found", nodeID)
	}

	newScore := node.PoloScore + int(delta)
	if newScore > maxPoloScore {
		newScore = maxPoloScore
	} else if newScore < -maxPoloScore {
		newScore = -maxPoloScore
	}
	node.PoloScore = newScore
	node.LastSeen = time.Now()
	s.save()

	addr := protocol.Addr{Network: 0, Node: nodeID}
	slog.Info("polo score updated", "node_id", nodeID, "delta", int(delta), "new_score", node.PoloScore)
	s.audit("polo_score.updated", "node_id", nodeID, "delta", int(delta), "new_score", node.PoloScore)

	return map[string]interface{}{
		"type":       "update_polo_score_ok",
		"node_id":    nodeID,
		"address":    addr.String(),
		"polo_score": node.PoloScore,
	}, nil
}

// handleSetPoloScore sets the polo score of a node to a specific value.
func (s *Server) handleSetPoloScore(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	poloScore, ok := msg["polo_score"].(float64)
	if !ok {
		return nil, fmt.Errorf("set_polo_score requires polo_score field")
	}
	if poloScore > maxPoloScore || poloScore < -maxPoloScore {
		return nil, fmt.Errorf("polo score out of range (max %d)", maxPoloScore)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	node, exists := s.nodes[nodeID]
	if !exists {
		return nil, fmt.Errorf("node %d not found", nodeID)
	}

	node.PoloScore = int(poloScore)
	node.LastSeen = time.Now()
	s.save()

	s.audit("polo_score.set", "node_id", nodeID, "polo_score", node.PoloScore)

	addr := protocol.Addr{Network: 0, Node: nodeID}

	return map[string]interface{}{
		"type":       "set_polo_score_ok",
		"node_id":    nodeID,
		"address":    addr.String(),
		"polo_score": node.PoloScore,
	}, nil
}

// handleGetPoloScore retrieves the polo score for a node.
func (s *Server) handleGetPoloScore(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")

	s.mu.RLock()
	defer s.mu.RUnlock()

	node, exists := s.nodes[nodeID]
	if !exists {
		return nil, fmt.Errorf("node %d not found", nodeID)
	}

	addr := protocol.Addr{Network: 0, Node: nodeID}

	return map[string]interface{}{
		"type":       "get_polo_score_ok",
		"node_id":    nodeID,
		"address":    addr.String(),
		"polo_score": node.PoloScore,
	}, nil
}

// setNodeHostname sets the hostname on a node atomically. Must be called with s.mu held.
func (s *Server) setNodeHostname(node *NodeInfo, hostname string, resp map[string]interface{}) {
	if hostname == "" {
		return
	}
	if existingID, taken := s.hostnameIdx[hostname]; taken && existingID != node.ID {
		return // hostname taken by another node
	}
	if node.Hostname != "" {
		delete(s.hostnameIdx, node.Hostname)
	}
	node.Hostname = hostname
	s.hostnameIdx[hostname] = node.ID
	resp["hostname"] = hostname
	slog.Debug("hostname set during registration", "node_id", node.ID, "hostname", hostname)
}

// handleReRegister handles a node presenting an existing public key.
// Returns the same node_id if the key is known, or assigns a new one.
// M3 fix: hostname is set atomically under the same lock as registration.
func (s *Server) handleReRegister(pubKeyB64, listenAddr, owner, hostname string, lanAddrs []string) (map[string]interface{}, error) {
	pubKey, err := crypto.DecodePublicKey(pubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if this public key was seen before
	if nodeID, ok := s.pubKeyIdx[pubKeyB64]; ok {
		if node, exists := s.nodes[nodeID]; exists {
			// Node is still alive — update endpoint, reset heartbeat
			node.RealAddr = listenAddr
			node.LastSeen = time.Now()
			node.LANAddrs = lanAddrs
			if owner != "" && node.Owner == "" {
				node.Owner = owner
				s.ownerIdx[owner] = nodeID
			}

			addr := protocol.Addr{Network: 0, Node: nodeID}
			resp := map[string]interface{}{
				"type":       "register_ok",
				"node_id":    nodeID,
				"network_id": 0,
				"address":    addr.String(),
				"public_key": pubKeyB64,
			}
			s.setNodeHostname(node, hostname, resp)
			s.save()
			slog.Debug("registered node", "node_id", nodeID, "listen", listenAddr, "addr", addr, "mode", "existing_identity")
			s.audit("node.re_registered", "node_id", nodeID, "mode", "existing_identity")
			return resp, nil
		}

		// Node was deregistered/reaped but key is known — recreate with same ID.
		// Restore network memberships by scanning which networks still list this node.
		networks := []uint16{0}
		for netID, net := range s.networks {
			if netID == 0 {
				continue
			}
			for _, m := range net.Members {
				if m == nodeID {
					networks = append(networks, netID)
					break
				}
			}
		}
		node := &NodeInfo{
			ID:        nodeID,
			Owner:     owner,
			PublicKey: pubKey,
			RealAddr:  listenAddr,
			Networks:  networks,
			LastSeen:  time.Now(),
			LANAddrs:  lanAddrs,
			KeyMeta:   KeyInfo{CreatedAt: time.Now()},
		}
		s.nodes[nodeID] = node
		if owner != "" {
			s.ownerIdx[owner] = nodeID
		}
		// Only add to backbone members if not already present
		inBackbone := false
		for _, m := range s.networks[0].Members {
			if m == nodeID {
				inBackbone = true
				break
			}
		}
		if !inBackbone {
			s.networks[0].Members = append(s.networks[0].Members, nodeID)
		}

		addr := protocol.Addr{Network: 0, Node: nodeID}
		resp := map[string]interface{}{
			"type":       "register_ok",
			"node_id":    nodeID,
			"network_id": 0,
			"address":    addr.String(),
			"public_key": pubKeyB64,
		}
		s.setNodeHostname(node, hostname, resp)
		s.save()
		slog.Debug("registered node", "node_id", nodeID, "listen", listenAddr, "addr", addr, "mode", "reclaimed_identity")
		s.audit("node.re_registered", "node_id", nodeID, "mode", "reclaimed_identity")
		return resp, nil
	}

	// Key not seen before — check if owner can reclaim an existing node
	if owner != "" {
		if existingID, ok := s.ownerIdx[owner]; ok {
			if existingNode, exists := s.nodes[existingID]; exists {
				// Owner's node still alive — update key and endpoint
				oldPubKeyB64 := crypto.EncodePublicKey(existingNode.PublicKey)
				delete(s.pubKeyIdx, oldPubKeyB64)
				existingNode.PublicKey = pubKey
				existingNode.RealAddr = listenAddr
				existingNode.LastSeen = time.Now()
				existingNode.LANAddrs = lanAddrs
				s.pubKeyIdx[pubKeyB64] = existingID

				addr := protocol.Addr{Network: 0, Node: existingID}
				resp := map[string]interface{}{
					"type":       "register_ok",
					"node_id":    existingID,
					"network_id": 0,
					"address":    addr.String(),
					"public_key": pubKeyB64,
				}
				s.setNodeHostname(existingNode, hostname, resp)
				s.save()
				slog.Debug("registered node", "node_id", existingID, "listen", listenAddr, "addr", addr, "mode", "owner_key_update")
				s.audit("node.re_registered", "node_id", existingID, "mode", "owner_key_update")
				return resp, nil
			}

			// Owner's node was deregistered — reclaim with new key
			s.pubKeyIdx[pubKeyB64] = existingID
			node := &NodeInfo{
				ID:        existingID,
				Owner:     owner,
				PublicKey: pubKey,
				RealAddr:  listenAddr,
				Networks:  []uint16{0},
				LastSeen:  time.Now(),
				LANAddrs:  lanAddrs,
				KeyMeta:   KeyInfo{CreatedAt: time.Now()},
			}
			s.nodes[existingID] = node
			s.networks[0].Members = append(s.networks[0].Members, existingID)

			addr := protocol.Addr{Network: 0, Node: existingID}
			resp := map[string]interface{}{
				"type":       "register_ok",
				"node_id":    existingID,
				"network_id": 0,
				"address":    addr.String(),
				"public_key": pubKeyB64,
			}
			s.setNodeHostname(node, hostname, resp)
			s.save()
			slog.Debug("registered node", "node_id", existingID, "listen", listenAddr, "addr", addr, "mode", "owner_reclaim")
			s.audit("node.re_registered", "node_id", existingID, "mode", "owner_reclaim")
			return resp, nil
		}
	}

	// Entirely new key and no owner match — assign new node
	if s.nextNode == 0 {
		return nil, fmt.Errorf("node ID space exhausted")
	}
	nodeID := s.nextNode
	s.nextNode++

	s.pubKeyIdx[pubKeyB64] = nodeID
	if owner != "" {
		s.ownerIdx[owner] = nodeID
	}

	node := &NodeInfo{
		ID:        nodeID,
		Owner:     owner,
		PublicKey: pubKey,
		RealAddr:  listenAddr,
		Networks:  []uint16{0},
		LastSeen:  time.Now(),
		LANAddrs:  lanAddrs,
		KeyMeta:   KeyInfo{CreatedAt: time.Now()},
	}
	s.nodes[nodeID] = node
	s.networks[0].Members = append(s.networks[0].Members, nodeID)

	addr := protocol.Addr{Network: 0, Node: nodeID}
	resp := map[string]interface{}{
		"type":       "register_ok",
		"node_id":    nodeID,
		"network_id": 0,
		"address":    addr.String(),
		"public_key": pubKeyB64,
	}
	s.setNodeHostname(node, hostname, resp)
	s.save()
	slog.Info("registered node", "node_id", nodeID, "listen", listenAddr, "addr", addr, "mode", "new_node", "owner_hash", hashOwner(owner))
	s.audit("node.registered", "node_id", nodeID, "mode", "new_node")
	return resp, nil
}

func (s *Server) handleCreateNetwork(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}

	nodeID := jsonUint32(msg, "node_id")
	name, _ := msg["name"].(string)
	joinRule, _ := msg["join_rule"].(string)
	token, _ := msg["token"].(string)
	networkAdminToken, _ := msg["network_admin_token"].(string)
	enterprise, _ := msg["enterprise"].(bool)

	if err := validateNetworkName(name); err != nil {
		return nil, err
	}
	if joinRule == "" {
		joinRule = "open"
	}

	// Invite-only join rule requires enterprise network
	if joinRule == "invite" && !enterprise {
		return nil, fmt.Errorf("enterprise feature: invite-only networks require the enterprise flag")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.nodes[nodeID]; !ok {
		return nil, fmt.Errorf("node %d not registered", nodeID)
	}

	// Guard against network ID overflow (uint16 max = 65535, 0 = backbone)
	if s.nextNet == 0 {
		return nil, fmt.Errorf("network ID space exhausted (max 65535 networks)")
	}

	// Check for duplicate name
	for _, n := range s.networks {
		if n.Name == name {
			return nil, fmt.Errorf("network %q already exists", name)
		}
	}

	netID := s.nextNet
	s.nextNet++

	net := &NetworkInfo{
		ID:          netID,
		Name:        name,
		JoinRule:    joinRule,
		Token:       token,
		Members:     []uint32{nodeID},
		MemberRoles: map[uint32]Role{nodeID: RoleOwner},
		AdminToken:  networkAdminToken,
		Enterprise:  enterprise,
		Created:     time.Now(),
	}
	s.networks[netID] = net

	// Add network to node's list
	s.nodes[nodeID].Networks = append(s.nodes[nodeID].Networks, netID)
	s.save()

	slog.Info("created network", "network_id", netID, "name", name, "creator", nodeID, "rule", joinRule, "enterprise", enterprise)
	s.audit("network.created", "network_id", netID, "name", name, "join_rule", joinRule, "creator_node_id", nodeID, "enterprise", enterprise)

	return map[string]interface{}{
		"type":       "create_network_ok",
		"network_id": netID,
		"name":       name,
		"enterprise": enterprise,
	}, nil
}

func (s *Server) handleJoinNetwork(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	netID := jsonUint16(msg, "network_id")
	token, _ := msg["token"].(string)

	if netID == 0 {
		return nil, fmt.Errorf("cannot join the backbone network")
	}

	// Auth: signature (daemon) or admin token (console)
	s.mu.RLock()
	node, ok := s.nodes[nodeID]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("node %d not registered", nodeID)
	}
	sigErr := s.verifyNodeSignature(node, msg, fmt.Sprintf("join_network:%d:%d", nodeID, netID))
	if sigErr != nil {
		if err := s.requireAdminToken(msg); err != nil {
			return nil, sigErr
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Re-check node under write lock
	node, ok = s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node %d not registered", nodeID)
	}

	network, ok := s.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	// Check join rules
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

	// Check membership limit
	if network.Policy.MaxMembers > 0 && len(network.Members) >= network.Policy.MaxMembers {
		return nil, fmt.Errorf("network membership limit reached")
	}

	// Check if already a member
	for _, n := range node.Networks {
		if n == netID {
			return nil, fmt.Errorf("node %d already in network %d", nodeID, netID)
		}
	}

	network.Members = append(network.Members, nodeID)
	if network.MemberRoles == nil {
		network.MemberRoles = make(map[uint32]Role)
	}
	network.MemberRoles[nodeID] = RoleMember
	node.Networks = append(node.Networks, netID)
	s.save()

	// Check RBAC pre-assignments (upgrade role if external_id matches)
	s.applyRBACPreAssignmentLocked(netID, nodeID)

	addr := protocol.Addr{Network: netID, Node: nodeID}

	slog.Info("node joined network", "node_id", nodeID, "network_id", netID, "name", network.Name)
	s.audit("network.joined", "node_id", nodeID, "network_id", netID)

	return map[string]interface{}{
		"type":       "join_network_ok",
		"network_id": netID,
		"address":    addr.String(),
	}, nil
}

func (s *Server) handleLeaveNetwork(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	netID := jsonUint16(msg, "network_id")

	// Cannot leave backbone
	if netID == 0 {
		return nil, fmt.Errorf("cannot leave the backbone network")
	}

	// Auth: signature (daemon) or admin token (console)
	s.mu.RLock()
	node, ok := s.nodes[nodeID]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("node %d not registered", nodeID)
	}
	sigErr := s.verifyNodeSignature(node, msg, fmt.Sprintf("leave_network:%d:%d", nodeID, netID))
	if sigErr != nil {
		if err := s.requireAdminToken(msg); err != nil {
			return nil, sigErr
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Re-check node under write lock
	node, ok = s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node %d not registered", nodeID)
	}

	network, ok := s.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	// Owner cannot leave — must transfer ownership first (check before modifying state)
	if network.Enterprise && network.MemberRoles[nodeID] == RoleOwner {
		return nil, fmt.Errorf("cannot leave network: owner must transfer ownership first")
	}

	// Remove network from node's list
	found := false
	for i, n := range node.Networks {
		if n == netID {
			node.Networks = append(node.Networks[:i], node.Networks[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("node %d is not a member of network %d", nodeID, netID)
	}

	// Remove node from network's member list and RBAC role
	for i, m := range network.Members {
		if m == nodeID {
			network.Members = append(network.Members[:i], network.Members[i+1:]...)
			break
		}
	}
	delete(network.MemberRoles, nodeID)

	// Clean up any pending invites for this node+network (inbound)
	if invites, ok := s.inviteInbox[nodeID]; ok {
		remaining := make([]*NetworkInvite, 0, len(invites))
		for _, inv := range invites {
			if inv.NetworkID != netID {
				remaining = append(remaining, inv)
			}
		}
		if len(remaining) == 0 {
			delete(s.inviteInbox, nodeID)
		} else {
			s.inviteInbox[nodeID] = remaining
		}
	}

	// Revoke outgoing invites sent by this node for this network
	for targetID, invites := range s.inviteInbox {
		remaining := make([]*NetworkInvite, 0, len(invites))
		for _, inv := range invites {
			if !(inv.NetworkID == netID && inv.InviterID == nodeID) {
				remaining = append(remaining, inv)
			}
		}
		if len(remaining) == 0 {
			delete(s.inviteInbox, targetID)
		} else if len(remaining) < len(invites) {
			s.inviteInbox[targetID] = remaining
		}
	}

	s.save()

	slog.Info("node left network", "node_id", nodeID, "network_id", netID, "name", network.Name)
	s.audit("network.left", "node_id", nodeID, "network_id", netID)

	return map[string]interface{}{
		"type":       "leave_network_ok",
		"network_id": netID,
	}, nil
}

func (s *Server) handleDeleteNetwork(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")

	// Cannot delete backbone (check first, before RBAC)
	if netID == 0 {
		return nil, fmt.Errorf("cannot delete the backbone network")
	}

	// RBAC: only owner or global/per-network admin token
	if err := s.requireNetworkRole(msg, netID, RoleOwner); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	network, ok := s.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	// Remove network from all member nodes
	for _, memberID := range network.Members {
		if node, ok := s.nodes[memberID]; ok {
			for i, n := range node.Networks {
				if n == netID {
					node.Networks = append(node.Networks[:i], node.Networks[i+1:]...)
					break
				}
			}
		}
	}

	// Clean up pending invites for this network
	for nodeID, invites := range s.inviteInbox {
		remaining := make([]*NetworkInvite, 0, len(invites))
		for _, inv := range invites {
			if inv.NetworkID != netID {
				remaining = append(remaining, inv)
			}
		}
		if len(remaining) == 0 {
			delete(s.inviteInbox, nodeID)
		} else {
			s.inviteInbox[nodeID] = remaining
		}
	}

	name := network.Name
	delete(s.networks, netID)
	s.save()

	slog.Info("deleted network", "network_id", netID, "name", name, "members", len(network.Members))
	s.audit("network.deleted", "network_id", netID, "name", network.Name,
		"members", len(network.Members), "enterprise", network.Enterprise)

	return map[string]interface{}{
		"type":       "delete_network_ok",
		"network_id": netID,
	}, nil
}

func (s *Server) handleRenameNetwork(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")

	if netID == 0 {
		return nil, fmt.Errorf("cannot rename the backbone network")
	}

	// RBAC: owner or admin role, or global/per-network admin token
	if err := s.requireNetworkRole(msg, netID, RoleOwner, RoleAdmin); err != nil {
		return nil, err
	}
	name, _ := msg["name"].(string)

	if err := validateNetworkName(name); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	network, ok := s.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	// Check for duplicate name
	for _, n := range s.networks {
		if n.ID != netID && n.Name == name {
			return nil, fmt.Errorf("network %q already exists", name)
		}
	}

	oldName := network.Name
	network.Name = name
	s.save()

	slog.Info("renamed network", "network_id", netID, "name", name)
	s.audit("network.renamed", "network_id", netID, "old_name", oldName, "new_name", name)

	return map[string]interface{}{
		"type":       "rename_network_ok",
		"network_id": netID,
		"name":       name,
	}, nil
}

func (s *Server) handleSetNetworkEnterprise(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")
	enterprise, _ := msg["enterprise"].(bool)

	if netID == 0 {
		return nil, fmt.Errorf("cannot set enterprise on the backbone network")
	}

	// Require global admin token
	if err := s.requireAdminToken(msg); err != nil {
		return nil, fmt.Errorf("set_network_enterprise requires admin token")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	network, ok := s.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	network.Enterprise = enterprise

	// Clean up RBAC roles when disabling enterprise
	if !enterprise && network.MemberRoles != nil {
		network.MemberRoles = nil
	}

	// When enabling enterprise, ensure all existing members have RBAC roles.
	// The first member (creator) gets owner if no owner exists; others get member.
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

	s.save()

	slog.Info("set network enterprise", "network_id", netID, "enterprise", enterprise)
	s.audit("network.enterprise_changed", "network_id", netID, "enterprise", enterprise,
		"members", len(network.Members))

	return map[string]interface{}{
		"type":       "set_network_enterprise_ok",
		"network_id": netID,
		"enterprise": enterprise,
	}, nil
}

func (s *Server) handleLookup(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")

	s.mu.RLock()
	defer s.mu.RUnlock()

	node, ok := s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	resp := map[string]interface{}{
		"type":       "lookup_ok",
		"node_id":    node.ID,
		"address":    protocol.Addr{Network: 0, Node: node.ID}.String(),
		"networks":   node.Networks,
		"public_key": crypto.EncodePublicKey(node.PublicKey),
		"public":     node.Public,
		"polo_score": node.PoloScore,
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
		resp["real_addr"] = node.RealAddr
	}
	if node.ExternalID != "" {
		resp["external_id"] = node.ExternalID
	}
	return resp, nil
}

// trustPairKey returns a canonical key for a trust pair (always sorted).
func trustPairKey(a, b uint32) string {
	if a > b {
		a, b = b, a
	}
	return fmt.Sprintf("%d:%d", a, b)
}

// cleanupNode removes transient state for a departed node. Caller must hold s.mu.
// Trust pairs and handshake inboxes are preserved — trust is identity-to-identity
// and must survive disconnections. Only explicit revoke_trust removes trust pairs.
func (s *Server) cleanupNode(nodeID uint32) {
	// Trust pairs: intentionally preserved (identity-level, survive disconnect)
	// Handshake inboxes/responses: intentionally preserved (node may reconnect)
}

func (s *Server) handleResolve(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	requesterID := jsonUint32(msg, "requester_id")

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Requester must be a registered node
	requester, ok := s.nodes[requesterID]
	if !ok {
		return nil, fmt.Errorf("resolve denied: requester node %d is not registered", requesterID)
	}

	// S2 fix: verify requester signature to prevent impersonation
	if err := s.verifyNodeSignature(requester, msg, fmt.Sprintf("resolve:%d:%d", requesterID, nodeID)); err != nil {
		return nil, err
	}

	node, ok := s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	// Public nodes: endpoint always available
	// Private nodes: require mutual trust OR shared non-backbone network
	if !node.Public {
		allowed := false

		// Check mutual trust
		if s.trustPairs[trustPairKey(requesterID, nodeID)] {
			allowed = true
		}

		// Check shared non-backbone network
		if !allowed {
			requester := s.nodes[requesterID]
			for _, rNet := range requester.Networks {
				if rNet == 0 {
					continue // skip backbone
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
			return nil, fmt.Errorf("resolve denied: node %d is private (establish mutual trust first)", nodeID)
		}
	}

	resp := map[string]interface{}{
		"type":      "resolve_ok",
		"node_id":   node.ID,
		"real_addr": node.RealAddr,
	}
	if len(node.LANAddrs) > 0 {
		resp["lan_addrs"] = node.LANAddrs
	}

	// Key freshness for trust decisions: days since key was created/rotated
	keyStart := node.KeyMeta.CreatedAt
	if !node.KeyMeta.RotatedAt.IsZero() {
		keyStart = node.KeyMeta.RotatedAt
	}
	if !keyStart.IsZero() {
		resp["key_age_days"] = int(time.Since(keyStart).Hours() / 24)
	}

	return resp, nil
}

func (s *Server) handleReportTrust(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeA := jsonUint32(msg, "node_id")
	nodeB := jsonUint32(msg, "peer_id")

	s.mu.Lock()
	defer s.mu.Unlock()

	// Both nodes must exist
	nodeAInfo, ok := s.nodes[nodeA]
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeA, protocol.ErrNodeNotFound)
	}
	if _, ok := s.nodes[nodeB]; !ok {
		return nil, fmt.Errorf("node %d: %w", nodeB, protocol.ErrNodeNotFound)
	}

	// H3 fix: verify signature
	if err := s.verifyNodeSignature(nodeAInfo, msg, fmt.Sprintf("report_trust:%d:%d", nodeA, nodeB)); err != nil {
		return nil, err
	}

	key := trustPairKey(nodeA, nodeB)
	s.trustPairs[key] = true
	s.save()
	s.metrics.trustReports.Inc()

	slog.Info("trust pair registered", "node_a", nodeA, "node_b", nodeB)
	s.audit("trust.created", "node_a", nodeA, "node_b", nodeB)

	return map[string]interface{}{
		"type": "report_trust_ok",
	}, nil
}

func (s *Server) handleRevokeTrust(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeA := jsonUint32(msg, "node_id")
	nodeB := jsonUint32(msg, "peer_id")

	s.mu.Lock()
	defer s.mu.Unlock()

	// H3 fix: verify signature — node must exist (prevents auth bypass on missing node)
	nodeAInfo, ok := s.nodes[nodeA]
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeA, protocol.ErrNodeNotFound)
	}
	if err := s.verifyNodeSignature(nodeAInfo, msg, fmt.Sprintf("revoke_trust:%d:%d", nodeA, nodeB)); err != nil {
		return nil, err
	}

	key := trustPairKey(nodeA, nodeB)
	if !s.trustPairs[key] {
		return nil, fmt.Errorf("no trust pair between %d and %d", nodeA, nodeB)
	}

	delete(s.trustPairs, key)
	s.save()
	s.metrics.trustRevocations.Inc()

	slog.Info("trust pair revoked", "node_a", nodeA, "node_b", nodeB)
	s.audit("trust.revoked", "node_a", nodeA, "node_b", nodeB)

	return map[string]interface{}{
		"type": "revoke_trust_ok",
	}, nil
}

// handleCheckTrust checks if a trust pair exists between two nodes OR if they share a non-backbone network.
func (s *Server) handleCheckTrust(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeA := jsonUint32(msg, "node_id")
	nodeB := jsonUint32(msg, "peer_id")

	s.mu.RLock()
	defer s.mu.RUnlock()

	trusted := s.trustPairs[trustPairKey(nodeA, nodeB)]

	// Also check shared non-backbone network
	if !trusted {
		nA, okA := s.nodes[nodeA]
		nB, okB := s.nodes[nodeB]
		if okA && okB {
			for _, aNet := range nA.Networks {
				if aNet == 0 {
					continue
				}
				for _, bNet := range nB.Networks {
					if aNet == bNet {
						trusted = true
						break
					}
				}
				if trusted {
					break
				}
			}
		}
	}

	return map[string]interface{}{
		"type":    "check_trust_ok",
		"trusted": trusted,
	}, nil
}

func (s *Server) handleSetVisibility(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	public, _ := msg["public"].(bool)

	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	// H3 fix: verify signature (admin token bypass for console control plane)
	if sigErr := s.verifyNodeSignature(node, msg, fmt.Sprintf("set_visibility:%d", nodeID)); sigErr != nil {
		if err := s.requireAdminTokenLocked(msg); err != nil {
			return nil, sigErr
		}
	}

	oldPublic := node.Public
	node.Public = public
	s.save()

	visibility := "private"
	if public {
		visibility = "public"
	}
	slog.Info("node visibility changed", "node_id", nodeID, "visibility", visibility)
	s.audit("visibility.changed", "node_id", nodeID, "old_public", oldPublic, "new_public", public)

	return map[string]interface{}{
		"type":       "set_visibility_ok",
		"node_id":    nodeID,
		"visibility": visibility,
	}, nil
}

func (s *Server) handleSetTaskExec(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	enabled, _ := msg["enabled"].(bool)

	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	// H3 fix: verify signature (admin token bypass for console control plane)
	if sigErr := s.verifyNodeSignature(node, msg, fmt.Sprintf("set_task_exec:%d", nodeID)); sigErr != nil {
		if err := s.requireAdminTokenLocked(msg); err != nil {
			return nil, sigErr
		}
	}

	oldEnabled := node.TaskExec
	node.TaskExec = enabled
	s.save()

	slog.Info("node task_exec changed", "node_id", nodeID, "task_exec", enabled)
	s.audit("task_exec.changed", "node_id", nodeID, "old_enabled", oldEnabled, "new_enabled", enabled)

	return map[string]interface{}{
		"type":      "set_task_exec_ok",
		"node_id":   nodeID,
		"task_exec": enabled,
	}, nil
}

// handleRequestHandshake relays a handshake request to a target node's inbox.
// This allows private nodes to receive handshake requests without exposing their IP.
// M12 fix: verifies sender signature to prevent spoofed handshake requests.
func (s *Server) handleRequestHandshake(msg map[string]interface{}) (map[string]interface{}, error) {
	fromNodeID := jsonUint32(msg, "from_node_id")
	toNodeID := jsonUint32(msg, "to_node_id")
	justification, _ := msg["justification"].(string)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Both nodes must exist
	fromNode, ok := s.nodes[fromNodeID]
	if !ok {
		return nil, fmt.Errorf("node %d: %w", fromNodeID, protocol.ErrNodeNotFound)
	}
	if _, ok := s.nodes[toNodeID]; !ok {
		return nil, fmt.Errorf("node %d: %w", toNodeID, protocol.ErrNodeNotFound)
	}

	// M12 fix: verify sender signature if node has a public key
	if fromNode.PublicKey != nil {
		sigB64, _ := msg["signature"].(string)
		if sigB64 == "" {
			return nil, fmt.Errorf("handshake request requires signature")
		}
		sig, err := base64Decode(sigB64)
		if err != nil {
			return nil, fmt.Errorf("invalid signature encoding: %w", err)
		}
		challenge := fmt.Sprintf("handshake:%d:%d", fromNodeID, toNodeID)
		if !crypto.Verify(fromNode.PublicKey, []byte(challenge), sig) {
			return nil, fmt.Errorf("handshake request signature verification failed")
		}
	}

	// Limit inbox size to prevent abuse
	if len(s.handshakeInbox[toNodeID]) >= maxHandshakeInbox {
		return nil, fmt.Errorf("handshake inbox full for node %d", toNodeID)
	}

	// Check for duplicate from same sender
	for _, existing := range s.handshakeInbox[toNodeID] {
		if existing.FromNodeID == fromNodeID {
			return nil, fmt.Errorf("handshake request already pending from node %d", fromNodeID)
		}
	}

	s.handshakeInbox[toNodeID] = append(s.handshakeInbox[toNodeID], &HandshakeRelayMsg{
		FromNodeID:    fromNodeID,
		Justification: justification,
		Timestamp:     time.Now(),
	})

	s.metrics.handshakeRequests.Inc()

	slog.Info("handshake request relayed", "from", fromNodeID, "to", toNodeID)
	s.audit("handshake.relayed", "from_node_id", fromNodeID, "to_node_id", toNodeID)

	return map[string]interface{}{
		"type":   "request_handshake_ok",
		"status": "delivered",
	}, nil
}

// handlePollHandshakes returns and clears a node's handshake inbox.
func (s *Server) handlePollHandshakes(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")

	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	// H3 fix: verify signature to prevent unauthorized inbox access
	if err := s.verifyNodeSignature(node, msg, fmt.Sprintf("poll_handshakes:%d", nodeID)); err != nil {
		return nil, err
	}

	inbox := s.handshakeInbox[nodeID]
	delete(s.handshakeInbox, nodeID)

	respInbox := s.handshakeResponses[nodeID]
	delete(s.handshakeResponses, nodeID)

	requests := make([]map[string]interface{}, len(inbox))
	for i, req := range inbox {
		requests[i] = map[string]interface{}{
			"from_node_id":  req.FromNodeID,
			"justification": req.Justification,
			"timestamp":     req.Timestamp.Unix(),
		}
	}

	responses := make([]map[string]interface{}, len(respInbox))
	for i, resp := range respInbox {
		responses[i] = map[string]interface{}{
			"from_node_id": resp.FromNodeID,
			"accept":       resp.Accept,
			"timestamp":    resp.Timestamp.Unix(),
		}
	}

	return map[string]interface{}{
		"type":      "poll_handshakes_ok",
		"requests":  requests,
		"responses": responses,
	}, nil
}

// handleRespondHandshake processes a handshake response (approve/reject).
// If approved, creates a mutual trust pair.
// M12 fix: verifies responder signature to prevent spoofed trust approvals.
func (s *Server) handleRespondHandshake(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id") // responder
	peerID := jsonUint32(msg, "peer_id") // original requester
	accept, _ := msg["accept"].(bool)

	s.mu.Lock()
	defer s.mu.Unlock()

	respNode, ok := s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}
	if _, ok := s.nodes[peerID]; !ok {
		return nil, fmt.Errorf("node %d: %w", peerID, protocol.ErrNodeNotFound)
	}

	// M12 fix: verify responder signature if node has a public key
	if respNode.PublicKey != nil {
		sigB64, _ := msg["signature"].(string)
		if sigB64 == "" {
			return nil, fmt.Errorf("handshake response requires signature")
		}
		sig, err := base64Decode(sigB64)
		if err != nil {
			return nil, fmt.Errorf("invalid signature encoding: %w", err)
		}
		challenge := fmt.Sprintf("respond:%d:%d", nodeID, peerID)
		if !crypto.Verify(respNode.PublicKey, []byte(challenge), sig) {
			return nil, fmt.Errorf("handshake response signature verification failed")
		}
	}

	if accept {
		key := trustPairKey(nodeID, peerID)
		s.trustPairs[key] = true
		s.save()
		slog.Info("handshake approved via relay, trust pair created", "node", nodeID, "peer", peerID)
	} else {
		slog.Info("handshake rejected via relay", "node", nodeID, "peer", peerID)
	}
	s.audit("handshake.responded", "node_id", nodeID, "peer_id", peerID, "accept", accept)

	// Store response in requester's response inbox so they learn about the approval
	s.handshakeResponses[peerID] = append(s.handshakeResponses[peerID], &HandshakeResponseMsg{
		FromNodeID: nodeID,
		Accept:     accept,
		Timestamp:  time.Now(),
	})

	return map[string]interface{}{
		"type":    "respond_handshake_ok",
		"accept":  accept,
		"peer_id": peerID,
	}, nil
}

// handleInviteToNetwork stores an invite for a target node to join an invite-only network.
// Does NOT add the node to the network — the target must accept via respond_invite.
func (s *Server) handleInviteToNetwork(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")
	inviterID := jsonUint32(msg, "inviter_id")
	targetNodeID := jsonUint32(msg, "target_node_id")

	if inviterID == targetNodeID {
		return nil, fmt.Errorf("cannot invite yourself")
	}

	// Auth check BEFORE write lock (requireAdminToken takes its own RLock)
	s.mu.RLock()
	inviterNode, ok := s.nodes[inviterID]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("inviter node %d: %w", inviterID, protocol.ErrNodeNotFound)
	}
	sigErr := s.verifyNodeSignature(inviterNode, msg, fmt.Sprintf("invite:%d:%d:%d", inviterID, netID, targetNodeID))
	if sigErr != nil {
		// Fall back to admin token (console server uses admin token)
		if err := s.requireAdminToken(msg); err != nil {
			return nil, sigErr // return the signature error, more informative
		}
	}
	// Admin token holders can bootstrap invite-only networks (invite without being a member)
	isAdmin := s.requireAdminToken(msg) == nil

	// Per-network admin token check
	if !isAdmin {
		token, _ := msg["admin_token"].(string)
		s.mu.RLock()
		net, netOK := s.networks[netID]
		s.mu.RUnlock()
		if netOK && net.AdminToken != "" && token != "" {
			if subtle.ConstantTimeCompare([]byte(token), []byte(net.AdminToken)) == 1 {
				isAdmin = true
			}
		}
	}

	// Enterprise gate: invites are a Phase 3 feature
	if err := s.requireEnterprise(netID); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	network, ok := s.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}
	// Re-check enterprise flag under write lock (TOCTOU defense)
	if !network.Enterprise {
		return nil, fmt.Errorf("enterprise feature: requires enterprise network")
	}
	if network.JoinRule != "invite" {
		return nil, fmt.Errorf("network %d is not invite-only (rule: %s)", netID, network.JoinRule)
	}

	// RBAC: admin token holders bypass membership check; otherwise require owner/admin role
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
		// RBAC: members with "member" role cannot invite — only owner/admin
		inviterRole := network.MemberRoles[inviterID]
		if inviterRole != RoleOwner && inviterRole != RoleAdmin {
			return nil, fmt.Errorf("rbac: inviter %d has role %q, requires owner or admin", inviterID, inviterRole)
		}
	}

	// Verify target node exists
	if _, ok := s.nodes[targetNodeID]; !ok {
		return nil, fmt.Errorf("target node %d: %w", targetNodeID, protocol.ErrNodeNotFound)
	}

	// Check target is not already a member
	targetNode := s.nodes[targetNodeID]
	for _, n := range targetNode.Networks {
		if n == netID {
			return nil, fmt.Errorf("node %d is already a member of network %d", targetNodeID, netID)
		}
	}

	// Deduplicate: only one invite per network per target
	for _, inv := range s.inviteInbox[targetNodeID] {
		if inv.NetworkID == netID {
			return map[string]interface{}{
				"type":           "invite_to_network_ok",
				"network_id":     netID,
				"target_node_id": targetNodeID,
				"status":         "already_invited",
			}, nil
		}
	}

	// Inbox size cap
	if len(s.inviteInbox[targetNodeID]) >= maxInviteInbox {
		return nil, fmt.Errorf("invite inbox full for node %d", targetNodeID)
	}

	s.inviteInbox[targetNodeID] = append(s.inviteInbox[targetNodeID], &NetworkInvite{
		NetworkID: netID,
		InviterID: inviterID,
		Timestamp: s.now(),
	})
	s.save()

	slog.Info("network invite stored", "network_id", netID, "inviter_id", inviterID, "target_node_id", targetNodeID)
	s.audit("invite.created", "network_id", netID, "inviter_id", inviterID, "target_node_id", targetNodeID)
	s.metrics.invitesSent.Inc()

	return map[string]interface{}{
		"type":           "invite_to_network_ok",
		"network_id":     netID,
		"target_node_id": targetNodeID,
	}, nil
}

// handlePollInvites returns a node's pending invites (without consuming them).
// Invites are consumed by handleRespondInvite when the node accepts or rejects.
func (s *Server) handlePollInvites(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")

	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	// Verify signature (same pattern as poll_handshakes)
	if err := s.verifyNodeSignature(node, msg, fmt.Sprintf("poll_invites:%d", nodeID)); err != nil {
		return nil, err
	}

	inbox := s.inviteInbox[nodeID]
	now := s.now()

	// Filter out expired invites (TTL-based cleanup on read)
	var active []*NetworkInvite
	var expired int
	for _, inv := range inbox {
		if now.Sub(inv.Timestamp) > inviteTTL {
			expired++
			continue
		}
		active = append(active, inv)
	}
	if expired > 0 {
		s.inviteInbox[nodeID] = active
		s.save()
		s.audit("invite.expired_cleanup", "node_id", nodeID, "expired_count", expired)
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

// handleRespondInvite processes an invite response (accept/reject).
// If accepted, adds the node to the network.
func (s *Server) handleRespondInvite(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	netID := jsonUint16(msg, "network_id")
	accept, _ := msg["accept"].(bool)

	// Enterprise gate: invites are a Phase 3 feature
	if err := s.requireEnterprise(netID); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	// Verify signature
	if err := s.verifyNodeSignature(node, msg, fmt.Sprintf("respond_invite:%d:%d", nodeID, netID)); err != nil {
		return nil, err
	}

	// Verify a pending, non-expired invite exists for this node+network
	inviteFound := false
	now := s.now()
	for _, inv := range s.inviteInbox[nodeID] {
		if inv.NetworkID == netID {
			if now.Sub(inv.Timestamp) > inviteTTL {
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
		network, ok := s.networks[netID]
		if !ok {
			return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
		}
		// Re-check enterprise flag under write lock (TOCTOU defense)
		if !network.Enterprise {
			return nil, fmt.Errorf("enterprise feature: requires enterprise network")
		}

		// Check membership limit (don't consume invite if full — user can retry later)
		if network.Policy.MaxMembers > 0 && len(network.Members) >= network.Policy.MaxMembers {
			return nil, fmt.Errorf("network membership limit reached")
		}

		// Check not already a member
		for _, n := range node.Networks {
			if n == netID {
				return nil, fmt.Errorf("node %d is already a member of network %d", nodeID, netID)
			}
		}

		network.Members = append(network.Members, nodeID)
		if network.MemberRoles == nil {
			network.MemberRoles = make(map[uint32]Role)
		}
		network.MemberRoles[nodeID] = RoleMember
		node.Networks = append(node.Networks, netID)

		slog.Info("invite accepted, node joined network", "node_id", nodeID, "network_id", netID, "name", network.Name)
	} else {
		slog.Info("invite rejected", "node_id", nodeID, "network_id", netID)
	}

	// Consume the invite only after successful accept or explicit reject
	remaining := make([]*NetworkInvite, 0, len(s.inviteInbox[nodeID]))
	for _, inv := range s.inviteInbox[nodeID] {
		if inv.NetworkID != netID {
			remaining = append(remaining, inv)
		}
	}
	if len(remaining) == 0 {
		delete(s.inviteInbox, nodeID)
	} else {
		s.inviteInbox[nodeID] = remaining
	}

	s.save()
	s.audit("invite.responded", "node_id", nodeID, "network_id", netID, "accepted", accept)
	if accept {
		s.metrics.invitesAccepted.Inc()
	} else {
		s.metrics.invitesRejected.Inc()
	}

	return map[string]interface{}{
		"type":       "respond_invite_ok",
		"accepted":   accept,
		"network_id": netID,
	}, nil
}

// handleKickMember removes a member from a network. Requires owner or admin role
// (or global/per-network admin token). Cannot kick the owner.
func (s *Server) handleKickMember(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")
	targetNodeID := jsonUint32(msg, "target_node_id")

	// Cannot kick from backbone
	if netID == 0 {
		return nil, fmt.Errorf("cannot kick from the backbone network")
	}

	// RBAC: owner or admin role required
	if err := s.requireNetworkRole(msg, netID, RoleOwner, RoleAdmin); err != nil {
		return nil, err
	}

	// Enterprise gate: kick is a Phase 2 RBAC feature
	if err := s.requireEnterprise(netID); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	network, ok := s.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	// Cannot kick the owner
	if network.MemberRoles[targetNodeID] == RoleOwner {
		return nil, fmt.Errorf("cannot kick the network owner")
	}

	// Verify target is a member
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

	kickedRole := network.MemberRoles[targetNodeID]
	delete(network.MemberRoles, targetNodeID)

	// Remove network from target node's list
	if node, ok := s.nodes[targetNodeID]; ok {
		for i, n := range node.Networks {
			if n == netID {
				node.Networks = append(node.Networks[:i], node.Networks[i+1:]...)
				break
			}
		}
	}

	// Clean up any pending invites for the kicked node+network
	if invites, ok := s.inviteInbox[targetNodeID]; ok {
		remaining := make([]*NetworkInvite, 0, len(invites))
		for _, inv := range invites {
			if inv.NetworkID != netID {
				remaining = append(remaining, inv)
			}
		}
		if len(remaining) == 0 {
			delete(s.inviteInbox, targetNodeID)
		} else {
			s.inviteInbox[targetNodeID] = remaining
		}
	}

	// Also revoke any outgoing invites sent by the kicked member for this network
	for nodeID, invites := range s.inviteInbox {
		remaining := make([]*NetworkInvite, 0, len(invites))
		for _, inv := range invites {
			if !(inv.NetworkID == netID && inv.InviterID == targetNodeID) {
				remaining = append(remaining, inv)
			}
		}
		if len(remaining) == 0 {
			delete(s.inviteInbox, nodeID)
		} else if len(remaining) < len(invites) {
			s.inviteInbox[nodeID] = remaining
		}
	}

	s.save()

	slog.Info("member kicked from network", "target_node_id", targetNodeID, "network_id", netID, "role", string(kickedRole))
	s.audit("member.kicked", "target_node_id", targetNodeID, "network_id", netID, "role", string(kickedRole))
	s.metrics.rbacOps.WithLabel("kick").Inc()

	return map[string]interface{}{
		"type":           "kick_member_ok",
		"network_id":     netID,
		"target_node_id": targetNodeID,
	}, nil
}

// handlePromoteMember promotes a member to admin. Only the owner can promote.
func (s *Server) handlePromoteMember(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")
	targetNodeID := jsonUint32(msg, "target_node_id")

	// RBAC: only owner can promote
	if err := s.requireNetworkRole(msg, netID, RoleOwner); err != nil {
		return nil, err
	}

	// Enterprise gate: promote is a Phase 2 RBAC feature
	if err := s.requireEnterprise(netID); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	network, ok := s.networks[netID]
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
	s.save()

	slog.Info("member promoted to admin", "target_node_id", targetNodeID, "network_id", netID)
	s.audit("member.promoted", "target_node_id", targetNodeID, "network_id", netID,
		"old_role", string(currentRole), "new_role", "admin")
	s.metrics.rbacOps.WithLabel("promote").Inc()

	return map[string]interface{}{
		"type":           "promote_member_ok",
		"network_id":     netID,
		"target_node_id": targetNodeID,
		"role":           string(RoleAdmin),
	}, nil
}

// handleDemoteMember demotes an admin to member. Only the owner can demote.
func (s *Server) handleDemoteMember(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")
	targetNodeID := jsonUint32(msg, "target_node_id")

	// RBAC: only owner can demote
	if err := s.requireNetworkRole(msg, netID, RoleOwner); err != nil {
		return nil, err
	}

	// Enterprise gate: demote is a Phase 2 RBAC feature
	if err := s.requireEnterprise(netID); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	network, ok := s.networks[netID]
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
	s.save()

	slog.Info("admin demoted to member", "target_node_id", targetNodeID, "network_id", netID)
	s.audit("member.demoted", "target_node_id", targetNodeID, "network_id", netID,
		"old_role", string(currentRole), "new_role", "member")
	s.metrics.rbacOps.WithLabel("demote").Inc()

	return map[string]interface{}{
		"type":           "demote_member_ok",
		"network_id":     netID,
		"target_node_id": targetNodeID,
		"role":           string(RoleMember),
	}, nil
}

// handleTransferOwnership transfers network ownership from the current owner
// to another member. Only the current owner can transfer ownership.
func (s *Server) handleTransferOwnership(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")
	newOwnerID := jsonUint32(msg, "new_owner_id")
	if newOwnerID == 0 {
		return nil, fmt.Errorf("new_owner_id is required")
	}

	// RBAC: only the current owner can transfer
	if err := s.requireNetworkRole(msg, netID, RoleOwner); err != nil {
		return nil, err
	}

	// Enterprise gate
	if err := s.requireEnterprise(netID); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	network, ok := s.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	// Find current owner
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

	// Cannot transfer to self
	if newOwnerID == currentOwnerID {
		return nil, fmt.Errorf("node %d is already the owner", newOwnerID)
	}

	// Verify new owner is a member
	newOwnerRole, isMember := network.MemberRoles[newOwnerID]
	if !isMember {
		return nil, fmt.Errorf("node %d is not a member of network %d", newOwnerID, netID)
	}

	// Transfer: demote current owner to admin, promote new owner to owner
	network.MemberRoles[currentOwnerID] = RoleAdmin
	network.MemberRoles[newOwnerID] = RoleOwner
	s.save()

	slog.Info("ownership transferred", "network_id", netID,
		"old_owner", currentOwnerID, "new_owner", newOwnerID)
	s.audit("network.ownership_transferred", "network_id", netID,
		"old_owner", currentOwnerID, "new_owner", newOwnerID,
		"new_owner_old_role", string(newOwnerRole))
	s.metrics.rbacOps.WithLabel("transfer_ownership").Inc()

	return map[string]interface{}{
		"type":       "transfer_ownership_ok",
		"network_id": netID,
		"old_owner":  currentOwnerID,
		"new_owner":  newOwnerID,
	}, nil
}

// handleGetMemberRole returns the RBAC role of a node in a network.
func (s *Server) handleGetMemberRole(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")
	targetNodeID := jsonUint32(msg, "target_node_id")

	s.mu.RLock()
	defer s.mu.RUnlock()

	network, ok := s.networks[netID]
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

// handleSetNetworkPolicy sets or updates a network's policy.
// Requires owner or admin role (or global/per-network admin token).
func (s *Server) handleSetNetworkPolicy(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")

	if err := s.requireNetworkRole(msg, netID, RoleOwner, RoleAdmin); err != nil {
		return nil, err
	}

	// Enterprise gate: network policies are a Phase 3 feature
	if err := s.requireEnterprise(netID); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	network, ok := s.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	// Merge policy fields: only update fields present in the message (preserve unset fields)
	oldPolicy := network.Policy
	policy := network.Policy

	if v, ok := msg["max_members"].(float64); ok {
		if v < 0 || v > 10000 || v != float64(int(v)) {
			return nil, fmt.Errorf("invalid max_members (must be integer 0-10000)")
		}
		newMax := int(v)
		if newMax > 0 && len(network.Members) > newMax {
			return nil, fmt.Errorf("cannot set max_members to %d: network already has %d members", newMax, len(network.Members))
		}
		policy.MaxMembers = newMax
	}

	if v, ok := msg["allowed_ports"].([]interface{}); ok {
		if len(v) > 100 {
			return nil, fmt.Errorf("too many allowed_ports (max 100)")
		}
		policy.AllowedPorts = nil
		seen := make(map[uint16]bool, len(v))
		for _, p := range v {
			port, ok := p.(float64)
			if !ok || port < 1 || port > 65535 || port != float64(int(port)) {
				return nil, fmt.Errorf("invalid port number in allowed_ports (must be integer 1-65535)")
			}
			p16 := uint16(port)
			if !seen[p16] {
				seen[p16] = true
				policy.AllowedPorts = append(policy.AllowedPorts, p16)
			}
		}
	}

	if v, ok := msg["description"].(string); ok {
		if len(v) > 256 {
			return nil, fmt.Errorf("policy description too long (max 256 chars)")
		}
		policy.Description = v
	}

	network.Policy = policy
	s.save()

	slog.Info("network policy updated", "network_id", netID, "max_members", policy.MaxMembers,
		"allowed_ports", policy.AllowedPorts, "description", policy.Description)
	s.audit("network.policy_changed", "network_id", netID,
		"old_max_members", oldPolicy.MaxMembers, "new_max_members", policy.MaxMembers,
		"old_allowed_ports_count", len(oldPolicy.AllowedPorts), "new_allowed_ports_count", len(policy.AllowedPorts))
	s.metrics.policyChanges.Inc()

	return map[string]interface{}{
		"type":          "set_network_policy_ok",
		"network_id":    netID,
		"max_members":   policy.MaxMembers,
		"allowed_ports": policy.AllowedPorts,
		"description":   policy.Description,
	}, nil
}

// handleGetNetworkPolicy returns the policy for a given network.
// Any member of the network can query the policy.
func (s *Server) handleGetNetworkPolicy(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")

	s.mu.RLock()
	defer s.mu.RUnlock()

	network, ok := s.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	// Convert AllowedPorts to []interface{} for JSON
	var ports []interface{}
	for _, p := range network.Policy.AllowedPorts {
		ports = append(ports, float64(p))
	}
	if ports == nil {
		ports = []interface{}{}
	}

	return map[string]interface{}{
		"type":          "get_network_policy_ok",
		"network_id":    netID,
		"max_members":   network.Policy.MaxMembers,
		"allowed_ports": ports,
		"description":   network.Policy.Description,
	}, nil
}

func (s *Server) handleSetHostname(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	hostname, _ := msg["hostname"].(string)

	if err := validateHostname(hostname); err != nil {
		return nil, fmt.Errorf("invalid hostname: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	// H3 fix: verify signature (admin token bypass for console control plane)
	if sigErr := s.verifyNodeSignature(node, msg, fmt.Sprintf("set_hostname:%d", nodeID)); sigErr != nil {
		if err := s.requireAdminTokenLocked(msg); err != nil {
			return nil, sigErr
		}
	}

	// Check uniqueness: if hostname is non-empty, must not be taken by another node
	if hostname != "" {
		if existingID, taken := s.hostnameIdx[hostname]; taken && existingID != nodeID {
			return nil, fmt.Errorf("hostname %q already in use by node %d", hostname, existingID)
		}
	}

	// Remove old hostname index entry
	oldHostname := node.Hostname
	if node.Hostname != "" {
		delete(s.hostnameIdx, node.Hostname)
	}

	// Set new hostname
	node.Hostname = hostname
	if hostname != "" {
		s.hostnameIdx[hostname] = nodeID
	}
	s.save()

	slog.Debug("hostname set", "node_id", nodeID, "hostname", hostname)
	s.audit("hostname.changed", "node_id", nodeID, "old_hostname", oldHostname, "new_hostname", hostname)

	return map[string]interface{}{
		"type":     "set_hostname_ok",
		"node_id":  nodeID,
		"hostname": hostname,
	}, nil
}

func (s *Server) handleSetTags(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")

	// Extract tags array from message
	var tags []string
	if rawTags, ok := msg["tags"].([]interface{}); ok {
		for _, rt := range rawTags {
			if t, ok := rt.(string); ok {
				tags = append(tags, t)
			}
		}
	}

	// Normalize: strip leading '#'
	for i, t := range tags {
		if len(t) > 0 && t[0] == '#' {
			tags[i] = t[1:]
		}
	}

	// Deduplicate tags (preserve order)
	seen := make(map[string]bool, len(tags))
	deduped := tags[:0]
	for _, t := range tags {
		if !seen[t] {
			seen[t] = true
			deduped = append(deduped, t)
		}
	}
	tags = deduped

	// Validate tags
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

	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	if sigErr := s.verifyNodeSignature(node, msg, fmt.Sprintf("set_tags:%d", nodeID)); sigErr != nil {
		if err := s.requireAdminTokenLocked(msg); err != nil {
			return nil, sigErr
		}
	}

	oldTags := node.Tags
	node.Tags = tags
	s.save()

	slog.Debug("tags set", "node_id", nodeID, "tags", tags)
	s.audit("tags.changed", "node_id", nodeID, "old_tags_count", len(oldTags), "new_tags_count", len(tags))

	return map[string]interface{}{
		"type":    "set_tags_ok",
		"node_id": nodeID,
		"tags":    tags,
	}, nil
}

func (s *Server) handleResolveHostname(msg map[string]interface{}) (map[string]interface{}, error) {
	hostname, _ := msg["hostname"].(string)
	if hostname == "" {
		return nil, fmt.Errorf("hostname required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	nodeID, ok := s.hostnameIdx[hostname]
	if !ok {
		return nil, fmt.Errorf("hostname %q not found", hostname)
	}

	node, ok := s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("hostname %q maps to missing node %d", hostname, nodeID)
	}

	// Privacy check: private nodes require trust or shared network
	if !node.Public {
		requesterID := jsonUint32(msg, "requester_id")
		allowed := false

		// Self-resolve always allowed
		if requesterID == nodeID {
			allowed = true
		}

		// Check trust pair
		if !allowed && s.trustPairs[trustPairKey(requesterID, nodeID)] {
			allowed = true
		}

		// Check shared non-backbone network
		if !allowed {
			if requester, rOk := s.nodes[requesterID]; rOk {
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
			return nil, fmt.Errorf("hostname %q not found", hostname) // same error as non-existent to prevent enumeration
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

// handleBeaconRegister registers or refreshes a beacon instance for peer discovery.
func (s *Server) handleBeaconRegister(msg map[string]interface{}) (map[string]interface{}, error) {
	beaconID := jsonUint32(msg, "beacon_id")
	addr, _ := msg["addr"].(string)

	if beaconID == 0 {
		return nil, fmt.Errorf("beacon_id required")
	}
	if addr == "" {
		return nil, fmt.Errorf("addr required")
	}

	s.mu.Lock()
	s.beacons[beaconID] = &beaconEntry{
		ID:       beaconID,
		Addr:     addr,
		LastSeen: s.now(),
	}
	s.mu.Unlock()

	slog.Debug("beacon registered", "beacon_id", beaconID, "addr", addr)
	s.audit("beacon.registered", "beacon_id", beaconID, "addr", addr)

	return map[string]interface{}{
		"type":      "beacon_register_ok",
		"beacon_id": beaconID,
	}, nil
}

// handleBeaconList returns all known beacon instances (for peer discovery).
func (s *Server) handleBeaconList() (map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := s.now()
	beacons := make([]map[string]interface{}, 0, len(s.beacons))
	for _, b := range s.beacons {
		if now.Sub(b.LastSeen) > beaconTTL {
			continue // skip expired
		}
		beacons = append(beacons, map[string]interface{}{
			"id":   b.ID,
			"addr": b.Addr,
		})
	}

	return map[string]interface{}{
		"type":    "beacon_list_ok",
		"beacons": beacons,
	}, nil
}

func (s *Server) handleListNetworks() (map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nets := make([]map[string]interface{}, 0, len(s.networks))
	for _, n := range s.networks {
		entry := map[string]interface{}{
			"id":         n.ID,
			"name":       n.Name,
			"members":    len(n.Members),
			"join_rule":  n.JoinRule,
			"enterprise": n.Enterprise,
			"created":    n.Created.Unix(),
		}
		if n.Enterprise {
			if n.Policy.MaxMembers > 0 {
				entry["max_members"] = n.Policy.MaxMembers
			}
			if n.Policy.Description != "" {
				entry["description"] = n.Policy.Description
			}
		}
		nets = append(nets, entry)
	}

	return map[string]interface{}{
		"type":     "list_networks_ok",
		"networks": nets,
	}, nil
}

func (s *Server) handleListNodes(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")

	// Backbone (network 0) node listing is restricted to prevent enumeration.
	// Admin token bypasses this restriction.
	if netID == 0 {
		if err := s.requireAdminToken(msg); err != nil {
			return nil, fmt.Errorf("listing backbone nodes is not permitted (use lookup with a specific node_id)")
		}
		// Admin-authenticated: list all registered nodes
		s.mu.RLock()
		defer s.mu.RUnlock()
		nodes := make([]map[string]interface{}, 0, len(s.nodes))
		for _, node := range s.nodes {
			entry := map[string]interface{}{
				"node_id":    node.ID,
				"address":    protocol.Addr{Network: 0, Node: node.ID}.String(),
				"public":     node.Public,
				"polo_score": node.PoloScore,
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
			entry["last_seen"] = node.LastSeen.Format(time.RFC3339)
			nodes = append(nodes, entry)
		}
		return map[string]interface{}{
			"type":  "list_nodes_ok",
			"nodes": nodes,
		}, nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	network, ok := s.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}

	nodes := make([]map[string]interface{}, 0)
	for _, nid := range network.Members {
		if node, ok := s.nodes[nid]; ok {
			entry := map[string]interface{}{
				"node_id":    node.ID,
				"address":    protocol.Addr{Network: netID, Node: node.ID}.String(),
				"public":     node.Public,
				"polo_score": node.PoloScore,
			}
			if role, ok := network.MemberRoles[nid]; ok {
				entry["role"] = string(role)
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
			entry["last_seen"] = node.LastSeen.Format(time.RFC3339)
			nodes = append(nodes, entry)
		} else {
			// Offline member — still include with minimal info
			entry := map[string]interface{}{
				"node_id": nid,
				"address": protocol.Addr{Network: netID, Node: nid}.String(),
				"offline": true,
			}
			if role, ok := network.MemberRoles[nid]; ok {
				entry["role"] = string(role)
			}
			nodes = append(nodes, entry)
		}
	}

	return map[string]interface{}{
		"type":  "list_nodes_ok",
		"nodes": nodes,
	}, nil
}

func (s *Server) handleDeregister(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")

	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[nodeID]
	if !ok {
		return map[string]interface{}{"type": "deregister_ok"}, nil
	}

	// H3 fix: verify signature (admin token bypass for console control plane)
	if sigErr := s.verifyNodeSignature(node, msg, fmt.Sprintf("deregister:%d", nodeID)); sigErr != nil {
		if err := s.requireAdminTokenLocked(msg); err != nil {
			return nil, sigErr
		}
	}

	// Remove from all networks and clean up RBAC roles
	var lostOwnerNets []uint16
	for _, netID := range node.Networks {
		if net, ok := s.networks[netID]; ok {
			if net.MemberRoles[nodeID] == RoleOwner && len(net.Members) > 1 {
				lostOwnerNets = append(lostOwnerNets, netID)
			}
			for i, m := range net.Members {
				if m == nodeID {
					net.Members = append(net.Members[:i], net.Members[i+1:]...)
					break
				}
			}
			delete(net.MemberRoles, nodeID)
		}
	}

	// Clean up pending invites for this node (inbound)
	delete(s.inviteInbox, nodeID)

	// Clean up outgoing invites sent by this node
	for targetID, invites := range s.inviteInbox {
		remaining := make([]*NetworkInvite, 0, len(invites))
		for _, inv := range invites {
			if inv.InviterID != nodeID {
				remaining = append(remaining, inv)
			}
		}
		if len(remaining) == 0 {
			delete(s.inviteInbox, targetID)
		} else if len(remaining) < len(invites) {
			s.inviteInbox[targetID] = remaining
		}
	}

	// Keep ownerIdx entry so owner-based key recovery can reclaim the node_id
	if node.Hostname != "" {
		delete(s.hostnameIdx, node.Hostname)
	}
	s.cleanupNode(nodeID)
	delete(s.nodes, nodeID)
	s.save()
	s.metrics.deregistrations.Inc()

	slog.Info("deregistered node", "node_id", nodeID, "networks", len(node.Networks))
	s.audit("node.deregistered", "node_id", nodeID, "networks", len(node.Networks))

	// Audit any networks that lost their owner
	for _, netID := range lostOwnerNets {
		s.audit("network.owner_lost", "network_id", netID, "former_owner", nodeID)
	}

	return map[string]interface{}{
		"type": "deregister_ok",
	}, nil
}

func (s *Server) handleHeartbeat(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")

	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	// H3 fix: verify signature
	if err := s.verifyNodeSignature(node, msg, fmt.Sprintf("heartbeat:%d", nodeID)); err != nil {
		return nil, err
	}

	// Reject heartbeat if key has expired
	if !node.KeyMeta.ExpiresAt.IsZero() && node.KeyMeta.ExpiresAt.Before(s.now()) {
		s.audit("key.expired_heartbeat_blocked", "node_id", nodeID)
		return nil, fmt.Errorf("node %d: key expired at %s", nodeID, node.KeyMeta.ExpiresAt.Format(time.RFC3339))
	}

	node.LastSeen = s.now()

	resp := map[string]interface{}{
		"type": "heartbeat_ok",
		"time": time.Now().Unix(),
	}

	// Key expiry warning: if key expires within 24 hours, warn the daemon
	if !node.KeyMeta.ExpiresAt.IsZero() && node.KeyMeta.ExpiresAt.Before(s.now().Add(24*time.Hour)) {
		resp["key_expiry_warning"] = true
	}

	return resp, nil
}

func (s *Server) handlePunch(msg map[string]interface{}) (map[string]interface{}, error) {
	requesterID := jsonUint32(msg, "requester_id")
	nodeA := jsonUint32(msg, "node_a")
	nodeB := jsonUint32(msg, "node_b")

	s.mu.RLock()
	defer s.mu.RUnlock()

	requester, ok := s.nodes[requesterID]
	if !ok {
		return nil, fmt.Errorf("node %d: %w", requesterID, protocol.ErrNodeNotFound)
	}

	// H3 fix: verify requester signature and ensure requester is a participant
	if requesterID != nodeA && requesterID != nodeB {
		return nil, fmt.Errorf("punch denied: requester must be participant")
	}
	if err := s.verifyNodeSignature(requester, msg, fmt.Sprintf("punch:%d:%d", nodeA, nodeB)); err != nil {
		return nil, err
	}

	a, okA := s.nodes[nodeA]
	b, okB := s.nodes[nodeB]
	if !okA {
		return nil, fmt.Errorf("node %d: %w", nodeA, protocol.ErrNodeNotFound)
	}
	if !okB {
		return nil, fmt.Errorf("node %d: %w", nodeB, protocol.ErrNodeNotFound)
	}

	// Return both endpoints so the caller (daemon) can attempt direct connection
	return map[string]interface{}{
		"type":        "punch_ok",
		"node_a":      nodeA,
		"node_a_addr": a.RealAddr,
		"node_b":      nodeB,
		"node_b_addr": b.RealAddr,
	}, nil
}

// --- Persistence ---

// TriggerSnapshot manually triggers a snapshot save. This is useful for testing
// and for ensuring data is persisted before shutdown. Returns an error if the
// save fails, or nil if there's no storePath configured.
func (s *Server) TriggerSnapshot() error {
	if s.storePath == "" {
		return nil // no persistence configured
	}
	return s.flushSave()
}

// snapshot is the JSON-serializable registry state.
type snapshot struct {
	Version            int                                `json:"version"`
	NextNode           uint32                             `json:"next_node"`
	NextNet            uint16                             `json:"next_net"`
	Nodes              map[string]*snapshotNode           `json:"nodes"`
	Networks           map[string]*snapshotNet            `json:"networks"`
	TrustPairs         []string                           `json:"trust_pairs,omitempty"`
	PubKeyIdx          map[string]uint32                  `json:"pub_key_idx,omitempty"`
	HandshakeInbox     map[string][]*HandshakeRelayMsg    `json:"handshake_inbox,omitempty"`
	HandshakeResponses map[string][]*HandshakeResponseMsg `json:"handshake_responses,omitempty"`
	InviteInbox        map[string][]*NetworkInvite        `json:"invite_inbox,omitempty"`
	// Dashboard stats persistence (explicit counters for validation)
	TotalRequests int64  `json:"total_requests,omitempty"`
	TotalNodes    int    `json:"total_nodes,omitempty"`
	OnlineNodes   int    `json:"online_nodes,omitempty"`
	TrustLinks    int    `json:"trust_links,omitempty"`
	UniqueTags    int    `json:"unique_tags,omitempty"`
	TaskExecutors int    `json:"task_executors,omitempty"`
	StartTime     string `json:"start_time,omitempty"` // RFC3339 format
	// Audit log persistence (most recent entries, capped at maxAuditEntries)
	AuditLog []AuditEntry `json:"audit_log,omitempty"`
	// Enterprise config persistence
	IDPConfig       *BlueprintIdentityProvider  `json:"idp_config,omitempty"`
	AuditExportCfg  *BlueprintAuditExport       `json:"audit_export_config,omitempty"`
	RBACPreAssign   map[string][]BlueprintRole  `json:"rbac_pre_assign,omitempty"` // networkID -> roles
	// Integrity: SHA256 hex digest of all fields except Checksum
	Checksum string `json:"checksum,omitempty"`
}

type snapshotNode struct {
	ID          uint32   `json:"id"`
	Owner       string   `json:"owner,omitempty"`
	PublicKey   string   `json:"public_key"`
	RealAddr    string   `json:"real_addr,omitempty"`
	Networks    []uint16 `json:"networks"`
	Public      bool     `json:"public,omitempty"`
	LastSeen    string   `json:"last_seen,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	PoloScore   int      `json:"polo_score,omitempty"`
	TaskExec    bool     `json:"task_exec,omitempty"`
	LANAddrs    []string `json:"lan_addrs,omitempty"`
	KeyCreated  string   `json:"key_created,omitempty"`
	KeyRotated  string   `json:"key_rotated,omitempty"`
	KeyRotCount int      `json:"key_rot_count,omitempty"`
	KeyExpires  string   `json:"key_expires,omitempty"`
	ExternalID  string   `json:"external_id,omitempty"`
}

type snapshotNet struct {
	ID          uint16            `json:"id"`
	Name        string            `json:"name"`
	JoinRule    string            `json:"join_rule"`
	Token       string            `json:"token,omitempty"`
	Members     []uint32          `json:"members"`
	MemberRoles map[string]string `json:"member_roles,omitempty"` // nodeID -> role
	AdminToken  string            `json:"admin_token,omitempty"`  // per-network admin token
	Policy      *NetworkPolicy    `json:"policy,omitempty"`       // network policy
	Enterprise  bool              `json:"enterprise,omitempty"`   // enterprise network flag
	Created     string            `json:"created"`
}

// save signals that state has changed and should be persisted.
// Non-blocking: actual serialization and disk I/O happen in saveLoop.
// Caller must hold s.mu (read or write lock).
func (s *Server) save() {
	select {
	case s.saveCh <- struct{}{}:
	default: // already signaled, will be picked up
	}
}

// saveLoop runs in the background and coalesces save signals. It flushes
// state to disk at most once per second, preventing serialization storms
// when many mutations happen in quick succession (trust pairs, registrations).
func (s *Server) saveLoop() {
	defer close(s.saveDone)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	dirty := false
	for {
		select {
		case <-s.saveCh:
			dirty = true
		case <-ticker.C:
			if dirty {
				if err := s.flushSave(); err != nil {
					slog.Error("periodic save failed", "err", err)
				}
				dirty = false
			}
		case <-s.done:
			// Drain pending save signal
			select {
			case <-s.saveCh:
				dirty = true
			default:
			}
			if dirty {
				if err := s.flushSave(); err != nil {
					slog.Error("final save failed", "err", err)
				}
			}
			return
		}
	}
}

// flushSave serializes the full registry state and writes it to disk.
func (s *Server) flushSave() error {
	s.mu.RLock()
	snap := snapshot{
		Version:  1,
		NextNode: s.nextNode,
		NextNet:  s.nextNet,
		Nodes:    make(map[string]*snapshotNode, len(s.nodes)),
		Networks: make(map[string]*snapshotNet, len(s.networks)),
	}

	for id, n := range s.nodes {
		sn := &snapshotNode{
			ID:        n.ID,
			Owner:     n.Owner,
			PublicKey: base64.StdEncoding.EncodeToString(n.PublicKey),
			RealAddr:  n.RealAddr,
			Networks:  n.Networks,
			Public:    n.Public,
			LastSeen:  n.LastSeen.Format(time.RFC3339),
			Hostname:  n.Hostname,
			Tags:      n.Tags,
			PoloScore: n.PoloScore,
			TaskExec:  n.TaskExec,
			LANAddrs:  n.LANAddrs,
		}
		if !n.KeyMeta.CreatedAt.IsZero() {
			sn.KeyCreated = n.KeyMeta.CreatedAt.Format(time.RFC3339)
		}
		if !n.KeyMeta.RotatedAt.IsZero() {
			sn.KeyRotated = n.KeyMeta.RotatedAt.Format(time.RFC3339)
		}
		if n.KeyMeta.RotateCount > 0 {
			sn.KeyRotCount = n.KeyMeta.RotateCount
		}
		if !n.KeyMeta.ExpiresAt.IsZero() {
			sn.KeyExpires = n.KeyMeta.ExpiresAt.Format(time.RFC3339)
		}
		sn.ExternalID = n.ExternalID
		snap.Nodes[fmt.Sprintf("%d", id)] = sn
	}

	for id, n := range s.networks {
		sn := &snapshotNet{
			ID:         n.ID,
			Name:       n.Name,
			JoinRule:   n.JoinRule,
			Token:      n.Token,
			Members:    n.Members,
			AdminToken: n.AdminToken,
			Enterprise: n.Enterprise,
			Created:    n.Created.Format(time.RFC3339),
		}
		if len(n.MemberRoles) > 0 {
			sn.MemberRoles = make(map[string]string, len(n.MemberRoles))
			for nodeID, role := range n.MemberRoles {
				sn.MemberRoles[fmt.Sprintf("%d", nodeID)] = string(role)
			}
		}
		// Persist policy if any field is set
		if n.Policy.MaxMembers != 0 || len(n.Policy.AllowedPorts) > 0 || n.Policy.Description != "" {
			pol := n.Policy // copy
			sn.Policy = &pol
		}
		snap.Networks[fmt.Sprintf("%d", id)] = sn
	}

	// Persist pubKeyIdx (survives reap cycles so re-registering nodes reclaim their ID)
	if len(s.pubKeyIdx) > 0 {
		snap.PubKeyIdx = make(map[string]uint32, len(s.pubKeyIdx))
		for key, id := range s.pubKeyIdx {
			snap.PubKeyIdx[key] = id
		}
	}

	// Persist trust pairs
	for key := range s.trustPairs {
		snap.TrustPairs = append(snap.TrustPairs, key)
	}

	// Persist handshake inboxes
	if len(s.handshakeInbox) > 0 {
		snap.HandshakeInbox = make(map[string][]*HandshakeRelayMsg, len(s.handshakeInbox))
		for nodeID, msgs := range s.handshakeInbox {
			snap.HandshakeInbox[fmt.Sprintf("%d", nodeID)] = msgs
		}
	}
	if len(s.handshakeResponses) > 0 {
		snap.HandshakeResponses = make(map[string][]*HandshakeResponseMsg, len(s.handshakeResponses))
		for nodeID, msgs := range s.handshakeResponses {
			snap.HandshakeResponses[fmt.Sprintf("%d", nodeID)] = msgs
		}
	}
	if len(s.inviteInbox) > 0 {
		snap.InviteInbox = make(map[string][]*NetworkInvite, len(s.inviteInbox))
		for nodeID, invites := range s.inviteInbox {
			snap.InviteInbox[fmt.Sprintf("%d", nodeID)] = invites
		}
	}
	// Persist dashboard stats with current calculations
	snap.TotalRequests = s.requestCount.Load()
	snap.StartTime = s.startTime.Format(time.RFC3339)

	// Calculate and persist all dashboard metrics
	onlineThreshold := time.Now().Add(-staleNodeThreshold)
	onlineCount := 0
	taskExecCount := 0
	tagSet := make(map[string]bool)
	for _, node := range s.nodes {
		if node.LastSeen.After(onlineThreshold) {
			onlineCount++
		}
		if node.TaskExec {
			taskExecCount++
		}
		for _, tag := range node.Tags {
			tagSet[tag] = true
		}
	}

	snap.TotalNodes = len(s.nodes)
	snap.OnlineNodes = onlineCount
	snap.TrustLinks = len(s.trustPairs)
	snap.UniqueTags = len(tagSet)
	snap.TaskExecutors = taskExecCount

	// Enterprise config persistence
	if s.idpConfig != nil {
		snap.IDPConfig = s.idpConfig
	}
	if s.auditExportConfig != nil {
		snap.AuditExportCfg = s.auditExportConfig
	}
	if len(s.rbacPreAssign) > 0 {
		snap.RBACPreAssign = make(map[string][]BlueprintRole, len(s.rbacPreAssign))
		for netID, roles := range s.rbacPreAssign {
			snap.RBACPreAssign[fmt.Sprintf("%d", netID)] = roles
		}
	}

	nodeCount := len(s.nodes)
	netCount := len(s.networks)
	s.mu.RUnlock()

	// Persist audit log (separate mutex from s.mu)
	s.auditMu.Lock()
	if len(s.auditLog) > 0 {
		snap.AuditLog = make([]AuditEntry, len(s.auditLog))
		copy(snap.AuditLog, s.auditLog)
	}
	s.auditMu.Unlock()

	// Compute checksum: marshal without Checksum, hash, then set Checksum and remarshal
	snap.Checksum = ""
	preData, err := json.Marshal(snap)
	if err != nil {
		slog.Error("registry save marshal error", "err", err)
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	hash := sha256.Sum256(preData)
	snap.Checksum = hex.EncodeToString(hash[:])

	data, err := json.Marshal(snap)
	if err != nil {
		slog.Error("registry save marshal error", "err", err)
		return fmt.Errorf("marshal snapshot with checksum: %w", err)
	}

	// Persist to disk atomically
	if s.storePath != "" {
		if err := fsutil.AtomicWrite(s.storePath, data); err != nil {
			slog.Error("registry save error", "err", err)
			return fmt.Errorf("write snapshot: %w", err)
		}
	}

	// Push to replication subscribers
	s.replMgr.push(data)

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
			PoloScore: n.PoloScore,
			TaskExec:  n.TaskExec,
			LANAddrs:  n.LANAddrs,
		}
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
			AdminToken:  n.AdminToken,
			Enterprise:  n.Enterprise,
			Created:     created,
		}
		if n.Policy != nil {
			net.Policy = *n.Policy
		}
		for nodeIDStr, roleStr := range n.MemberRoles {
			var nodeID uint32
			if _, err := fmt.Sscanf(nodeIDStr, "%d", &nodeID); err == nil {
				net.MemberRoles[nodeID] = Role(roleStr)
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

	// Restore trust pairs
	for _, key := range snap.TrustPairs {
		s.trustPairs[key] = true
	}
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

	// Restore handshake inboxes
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
	inboxCount := len(s.handshakeInbox) + len(s.handshakeResponses)
	if inboxCount > 0 {
		slog.Info("loaded handshake inboxes", "request_queues", len(s.handshakeInbox), "response_queues", len(s.handshakeResponses))
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

	// Restore audit log
	if len(snap.AuditLog) > 0 {
		s.auditMu.Lock()
		s.auditLog = snap.AuditLog
		s.auditMu.Unlock()
		slog.Info("loaded audit log", "entries", len(snap.AuditLog))
	}

	// Restore enterprise config (IDP, audit export, RBAC pre-assignments)
	if snap.IDPConfig != nil {
		s.idpConfig = snap.IDPConfig
		s.identityWebhookURL = snap.IDPConfig.URL
		slog.Info("loaded identity provider config", "type", snap.IDPConfig.Type)
	}
	if snap.AuditExportCfg != nil {
		s.auditExportConfig = snap.AuditExportCfg
		if s.auditExporter != nil {
			s.auditExporter.Close()
		}
		s.auditExporter = newAuditExporter(snap.AuditExportCfg)
		slog.Info("loaded audit export config", "format", snap.AuditExportCfg.Format,
			"endpoint", snap.AuditExportCfg.Endpoint)
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

// Wire helpers: 4-byte big-endian length prefix + JSON body

func readMessage(r io.Reader) (map[string]interface{}, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > maxMessageSize { // 64KB max
		return nil, fmt.Errorf("message too large: %d bytes (max %d)", length, maxMessageSize)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}

	var msg map[string]interface{}
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	return msg, nil
}

func writeMessage(w io.Writer, msg map[string]interface{}) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("json encode: %w", err)
	}

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))

	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	return nil
}

// JSON number helpers (json.Unmarshal uses float64 for numbers)

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

func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// --- Dashboard ---

// DashboardNode is a public-safe view of a node for the dashboard.
type DashboardNode struct {
	Address    string   `json:"address"`
	Tags       []string `json:"tags"`
	Online     bool     `json:"online"`
	TrustLinks int      `json:"trust_links"`
	TaskExec   bool     `json:"task_exec"`
	PoloScore  int      `json:"polo_score"`
}

// DashboardNetwork is a public-safe view of a network for the dashboard.
type DashboardNetwork struct {
	ID            uint16 `json:"id"`
	Members       int    `json:"members"`
	OnlineMembers int    `json:"online_members"`
}

// DashboardEdge represents a trust relationship between two nodes.
type DashboardEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// DashboardStats is the public-safe data returned by the dashboard API.
type DashboardStats struct {
	TotalNodes      int                `json:"total_nodes"`
	ActiveNodes     int                `json:"active_nodes"`
	TotalTrustLinks int                `json:"total_trust_links"`
	TotalRequests   int64              `json:"total_requests"`
	UniqueTags      int                `json:"unique_tags"`
	TaskExecutors   int                `json:"task_executors"`
	Networks        []DashboardNetwork `json:"networks"`
	Nodes           []DashboardNode    `json:"nodes"`
	Edges           []DashboardEdge    `json:"edges"`
	UptimeSecs      int64              `json:"uptime_secs"`
}

// GetDashboardStats returns public-safe statistics for the dashboard.
// No IPs, keys, or endpoints are exposed.
func (s *Server) GetDashboardStats() DashboardStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	onlineThreshold := now.Add(-staleNodeThreshold)

	// Count trust links per node and build edge list
	trustCount := make(map[uint32]int)
	// Build nodeID→address map for edges
	nodeAddr := make(map[uint32]string, len(s.nodes))
	for _, node := range s.nodes {
		addr := protocol.Addr{Network: 0, Node: node.ID}
		if len(node.Networks) > 0 {
			addr.Network = node.Networks[0]
		}
		nodeAddr[node.ID] = addr.String()
	}
	edges := make([]DashboardEdge, 0, len(s.trustPairs))
	for key := range s.trustPairs {
		var a, b uint32
		fmt.Sscanf(key, "%d:%d", &a, &b)
		trustCount[a]++
		trustCount[b]++
		if addrA, okA := nodeAddr[a]; okA {
			if addrB, okB := nodeAddr[b]; okB {
				edges = append(edges, DashboardEdge{Source: addrA, Target: addrB})
			}
		}
	}

	nodes := make([]DashboardNode, 0, len(s.nodes))
	activeCount := 0
	taskExecCount := 0
	tagSet := make(map[string]bool)
	for _, node := range s.nodes {
		online := node.LastSeen.After(onlineThreshold)
		if online {
			activeCount++
		}
		if node.TaskExec {
			taskExecCount++
		}
		addr := protocol.Addr{Network: 0, Node: node.ID}
		if len(node.Networks) > 0 {
			addr.Network = node.Networks[0]
		}
		for _, t := range node.Tags {
			tagSet[t] = true
		}
		tags := node.Tags
		if tags == nil {
			tags = []string{}
		}
		nodes = append(nodes, DashboardNode{
			Address:    addr.String(),
			Tags:       tags,
			Online:     online,
			TrustLinks: trustCount[node.ID],
			TaskExec:   node.TaskExec,
			PoloScore:  node.PoloScore,
		})
	}

	// Sort nodes by address (ascending)
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Address < nodes[j].Address
	})

	networks := make([]DashboardNetwork, 0, len(s.networks))
	for _, net := range s.networks {
		onlineCount := 0
		for _, memberID := range net.Members {
			if node, exists := s.nodes[memberID]; exists {
				if node.LastSeen.After(onlineThreshold) {
					onlineCount++
				}
			}
		}
		networks = append(networks, DashboardNetwork{
			ID:            net.ID,
			Members:       len(net.Members),
			OnlineMembers: onlineCount,
		})
	}

	return DashboardStats{
		TotalNodes:      len(s.nodes),
		ActiveNodes:     activeCount,
		TotalTrustLinks: len(s.trustPairs),
		TotalRequests:   s.requestCount.Load(),
		UniqueTags:      len(tagSet),
		TaskExecutors:   taskExecCount,
		Networks:        networks,
		Nodes:           nodes,
		Edges:           edges,
		UptimeSecs:      int64(now.Sub(s.startTime).Seconds()),
	}
}

// verifyNodeSignature checks a signature for a registry write operation (H3 fix).
// If the node has a public key, the signature is required and verified.
// If the node has no public key (old registration), unsigned requests are allowed.
func (s *Server) verifyNodeSignature(node *NodeInfo, msg map[string]interface{}, challenge string) error {
	if node.PublicKey == nil {
		// M4 fix: no key on file — require admin token as fallback auth
		if err := s.checkAdminToken(msg, s.adminToken); err != nil {
			return fmt.Errorf("node has no public key: signature or admin token required")
		}
		return nil
	}
	sigB64, _ := msg["signature"].(string)
	if sigB64 == "" {
		return fmt.Errorf("signature required for authenticated node")
	}
	sig, err := base64Decode(sigB64)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	if !crypto.Verify(node.PublicKey, []byte(challenge), sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

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
	"sync"
	"sync/atomic"
	"time"

	"web4/internal/crypto"
	"web4/internal/fsutil"
	"web4/pkg/protocol"
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
	if adminToken == "" {
		return fmt.Errorf("network creation is disabled")
	}
	token, _ := msg["admin_token"].(string)
	if subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) != 1 {
		return fmt.Errorf("invalid admin token")
	}
	return nil
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

	// Rate limiting
	rateLimiter *RateLimiter

	// Replication
	replMgr    *replicationManager
	replToken  string // H4 fix: required for subscribe_replication; empty = replication disabled
	standby    bool   // if true, reject writes and receive snapshots from primary
	adminToken string // required for create_network; empty = creation disabled

	// Beacon cluster: beacon instances register themselves for peer discovery
	beacons map[uint32]*beaconEntry

	// Shutdown
	done chan struct{}
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

type NodeInfo struct {
	ID        uint32
	Owner     string // email or identifier (for key rotation)
	PublicKey []byte
	RealAddr  string
	Networks  []uint16
	LastSeen  time.Time
	Public    bool     // if true, endpoint is visible in lookup/list_nodes
	Hostname  string   // unique hostname for discovery (empty = none)
	Tags      []string // capability tags (e.g., "webserver", "assistant")
}

type NetworkInfo struct {
	ID       uint16
	Name     string
	JoinRule string
	Token    string // for token-gated networks
	Members  []uint32
	Created  time.Time
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
		rateLimiter:        NewRateLimiter(10, time.Minute), // 10 registrations per IP per minute
		beacons:            make(map[uint32]*beaconEntry),
		replMgr:            newReplicationManager(),
		readyCh:            make(chan struct{}),
		done:               make(chan struct{}),
		saveCh:             make(chan struct{}, 1),
		saveDone:           make(chan struct{}),
	}

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

// SetReplicationToken sets the token required for subscribe_replication (H4 fix).
// If empty, replication subscription is disabled.
func (s *Server) SetReplicationToken(token string) {
	s.mu.Lock()
	s.replToken = token
	s.mu.Unlock()
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
		case <-s.done:
			return
		}
	}
}

func (s *Server) reapStaleNodes() {
	threshold := time.Now().Add(-staleNodeThreshold)
	s.mu.Lock()
	defer s.mu.Unlock()

	reaped := false
	for id, node := range s.nodes {
		if node.LastSeen.Before(threshold) {
			slog.Info("registry reaping stale node", "node_id", id, "last_seen_ago", time.Since(node.LastSeen).Round(time.Second))
			// Remove from all networks
			for _, netID := range node.Networks {
				if net, ok := s.networks[netID]; ok {
					for i, m := range net.Members {
						if m == id {
							net.Members = append(net.Members[:i], net.Members[i+1:]...)
							break
						}
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
	now := time.Now()
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
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

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
			slog.Error("registry handle error", "remote", conn.RemoteAddr(), "err", err)
			resp = map[string]interface{}{
				"type":  "error",
				"error": "request failed",
			}
		}

		if err := writeMessage(conn, resp); err != nil {
			slog.Error("registry write error", "remote", conn.RemoteAddr(), "err", err)
			return
		}
	}
}

func (s *Server) handleMessage(msg map[string]interface{}, remoteAddr string) (map[string]interface{}, error) {
	s.requestCount.Add(1)
	msgType, _ := msg["type"].(string)

	// Standby mode: reject write operations, allow reads
	s.mu.RLock()
	isStandby := s.standby
	s.mu.RUnlock()
	if isStandby {
		switch msgType {
		case "lookup", "resolve", "list_networks", "list_nodes", "heartbeat", "poll_handshakes", "resolve_hostname", "beacon_list":
			// reads are allowed on standby
		default:
			return nil, fmt.Errorf("standby mode: write operations not accepted (use primary)")
		}
	}

	switch msgType {
	case "register":
		// Rate limit registrations by source IP (exempt known-key re-registrations)
		host, _, _ := net.SplitHostPort(remoteAddr)
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
		return nil, fmt.Errorf("custom networks are WIP — only backbone (network 0) is available")
	case "join_network":
		return nil, fmt.Errorf("custom networks are WIP — only backbone (network 0) is available")
	case "leave_network":
		return nil, fmt.Errorf("custom networks are WIP — only backbone (network 0) is available")
	case "lookup":
		return s.handleLookup(msg)
	case "resolve":
		return s.handleResolve(msg)
	case "list_networks":
		return s.handleListNetworks()
	case "list_nodes":
		return s.handleListNodes(msg)
	case "rotate_key":
		return s.handleRotateKey(msg)
	case "deregister":
		return s.handleDeregister(msg)
	case "set_visibility":
		return s.handleSetVisibility(msg)
	case "report_trust":
		return s.handleReportTrust(msg)
	case "revoke_trust":
		return s.handleRevokeTrust(msg)
	case "request_handshake":
		return s.handleRequestHandshake(msg)
	case "poll_handshakes":
		return s.handlePollHandshakes(msg)
	case "respond_handshake":
		return s.handleRespondHandshake(msg)
	case "heartbeat":
		return s.handleHeartbeat(msg)
	case "punch":
		return s.handlePunch(msg)
	case "set_hostname":
		return s.handleSetHostname(msg)
	case "set_tags":
		return s.handleSetTags(msg)
	case "resolve_hostname":
		return s.handleResolveHostname(msg)
	case "beacon_register":
		return s.handleBeaconRegister(msg)
	case "beacon_list":
		return s.handleBeaconList()
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

	// Registration requires a client-generated public key
	pubKeyB64, ok := msg["public_key"].(string)
	if !ok || pubKeyB64 == "" {
		return nil, fmt.Errorf("registration requires public_key")
	}

	// Validate hostname before acquiring lock (avoids holding lock for validation)
	if hostname != "" {
		if err := validateHostname(hostname); err != nil {
			// Register without hostname, return warning
			resp, regErr := s.handleReRegister(pubKeyB64, listenAddr, owner, "")
			if regErr != nil {
				return resp, regErr
			}
			resp["hostname_error"] = err.Error()
			return resp, nil
		}
	}

	// M3 fix: pass hostname into handleReRegister so registration + hostname
	// are set atomically under a single lock acquisition.
	return s.handleReRegister(pubKeyB64, listenAddr, owner, hostname)
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
	s.pubKeyIdx[newPubKeyB64] = nodeID
	s.save()

	addr := protocol.Addr{Network: 0, Node: nodeID}
	slog.Debug("rotated key", "node_id", nodeID, "addr", addr)

	return map[string]interface{}{
		"type":       "rotate_key_ok",
		"node_id":    nodeID,
		"address":    addr.String(),
		"public_key": newPubKeyB64,
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
func (s *Server) handleReRegister(pubKeyB64, listenAddr, owner, hostname string) (map[string]interface{}, error) {
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
			return resp, nil
		}

		// Node was deregistered/reaped but key is known — recreate with same ID
		node := &NodeInfo{
			ID:        nodeID,
			Owner:     owner,
			PublicKey: pubKey,
			RealAddr:  listenAddr,
			Networks:  []uint16{0},
			LastSeen:  time.Now(),
		}
		s.nodes[nodeID] = node
		if owner != "" {
			s.ownerIdx[owner] = nodeID
		}
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
		slog.Debug("registered node", "node_id", nodeID, "listen", listenAddr, "addr", addr, "mode", "reclaimed_identity")
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
			return resp, nil
		}
	}

	// Entirely new key and no owner match — assign new node
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

	if err := validateNetworkName(name); err != nil {
		return nil, err
	}
	if joinRule == "" {
		joinRule = "open"
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
		ID:       netID,
		Name:     name,
		JoinRule: joinRule,
		Token:    token,
		Members:  []uint32{nodeID},
		Created:  time.Now(),
	}
	s.networks[netID] = net

	// Add network to node's list
	s.nodes[nodeID].Networks = append(s.nodes[nodeID].Networks, netID)
	s.save()

	slog.Info("created network", "network_id", netID, "name", name, "creator", nodeID, "rule", joinRule)

	return map[string]interface{}{
		"type":       "create_network_ok",
		"network_id": netID,
		"name":       name,
	}, nil
}

func (s *Server) handleJoinNetwork(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}

	nodeID := jsonUint32(msg, "node_id")
	netID := jsonUint16(msg, "network_id")
	token, _ := msg["token"].(string)
	inviterID := jsonUint32(msg, "inviter_id")

	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[nodeID]
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
		if token != network.Token {
			return nil, fmt.Errorf("invalid token for network %d", netID)
		}
	case "invite":
		if inviterID == 0 {
			return nil, fmt.Errorf("invite required for network %d", netID)
		}
		found := false
		for _, m := range network.Members {
			if m == inviterID {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("inviter %d is not a member of network %d", inviterID, netID)
		}
	default:
		return nil, fmt.Errorf("unknown join rule: %s", network.JoinRule)
	}

	// Check if already a member
	for _, n := range node.Networks {
		if n == netID {
			return nil, fmt.Errorf("node %d already in network %d", nodeID, netID)
		}
	}

	network.Members = append(network.Members, nodeID)
	node.Networks = append(node.Networks, netID)
	s.save()

	addr := protocol.Addr{Network: netID, Node: nodeID}

	slog.Info("node joined network", "node_id", nodeID, "network_id", netID, "name", network.Name)

	return map[string]interface{}{
		"type":       "join_network_ok",
		"network_id": netID,
		"address":    addr.String(),
	}, nil
}

func (s *Server) handleLeaveNetwork(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}

	nodeID := jsonUint32(msg, "node_id")
	netID := jsonUint16(msg, "network_id")

	// Cannot leave backbone
	if netID == 0 {
		return nil, fmt.Errorf("cannot leave the backbone network")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("node %d not registered", nodeID)
	}

	network, ok := s.networks[netID]
	if !ok {
		return nil, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
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

	// Remove node from network's member list
	for i, m := range network.Members {
		if m == nodeID {
			network.Members = append(network.Members[:i], network.Members[i+1:]...)
			break
		}
	}
	s.save()

	slog.Info("node left network", "node_id", nodeID, "network_id", netID, "name", network.Name)

	return map[string]interface{}{
		"type":       "leave_network_ok",
		"network_id": netID,
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
	}
	if node.Hostname != "" {
		resp["hostname"] = node.Hostname
	}
	if len(node.Tags) > 0 {
		resp["tags"] = node.Tags
	}
	if node.Public {
		resp["real_addr"] = node.RealAddr
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

	return map[string]interface{}{
		"type":      "resolve_ok",
		"node_id":   node.ID,
		"real_addr": node.RealAddr,
	}, nil
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

	slog.Info("trust pair registered", "node_a", nodeA, "node_b", nodeB)

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

	slog.Info("trust pair revoked", "node_a", nodeA, "node_b", nodeB)

	return map[string]interface{}{
		"type": "revoke_trust_ok",
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

	// H3 fix: verify signature
	if err := s.verifyNodeSignature(node, msg, fmt.Sprintf("set_visibility:%d", nodeID)); err != nil {
		return nil, err
	}

	node.Public = public
	s.save()

	visibility := "private"
	if public {
		visibility = "public"
	}
	slog.Info("node visibility changed", "node_id", nodeID, "visibility", visibility)

	return map[string]interface{}{
		"type":       "set_visibility_ok",
		"node_id":    nodeID,
		"visibility": visibility,
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

	slog.Info("handshake request relayed", "from", fromNodeID, "to", toNodeID)

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

	// H3 fix: verify signature
	if err := s.verifyNodeSignature(node, msg, fmt.Sprintf("set_hostname:%d", nodeID)); err != nil {
		return nil, err
	}

	// Check uniqueness: if hostname is non-empty, must not be taken by another node
	if hostname != "" {
		if existingID, taken := s.hostnameIdx[hostname]; taken && existingID != nodeID {
			return nil, fmt.Errorf("hostname %q already in use by node %d", hostname, existingID)
		}
	}

	// Remove old hostname index entry
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

	if err := s.verifyNodeSignature(node, msg, fmt.Sprintf("set_tags:%d", nodeID)); err != nil {
		return nil, err
	}

	node.Tags = tags
	s.save()

	slog.Debug("tags set", "node_id", nodeID, "tags", tags)

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
		LastSeen: time.Now(),
	}
	s.mu.Unlock()

	slog.Debug("beacon registered", "beacon_id", beaconID, "addr", addr)

	return map[string]interface{}{
		"type":      "beacon_register_ok",
		"beacon_id": beaconID,
	}, nil
}

// handleBeaconList returns all known beacon instances (for peer discovery).
func (s *Server) handleBeaconList() (map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
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
		nets = append(nets, map[string]interface{}{
			"id":        n.ID,
			"name":      n.Name,
			"members":   len(n.Members),
			"join_rule": n.JoinRule,
		})
	}

	return map[string]interface{}{
		"type":     "list_networks_ok",
		"networks": nets,
	}, nil
}

func (s *Server) handleListNodes(msg map[string]interface{}) (map[string]interface{}, error) {
	netID := jsonUint16(msg, "network_id")

	// Backbone (network 0) node listing is restricted to prevent enumeration
	if netID == 0 {
		return nil, fmt.Errorf("listing backbone nodes is not permitted (use lookup with a specific node_id)")
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
				"node_id": node.ID,
				"address": protocol.Addr{Network: netID, Node: node.ID}.String(),
			}
			if node.Hostname != "" {
				entry["hostname"] = node.Hostname
			}
			if node.Public {
				entry["real_addr"] = node.RealAddr
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

	// H3 fix: verify signature
	if err := s.verifyNodeSignature(node, msg, fmt.Sprintf("deregister:%d", nodeID)); err != nil {
		return nil, err
	}

	// Remove from all networks
	for _, netID := range node.Networks {
		if net, ok := s.networks[netID]; ok {
			for i, m := range net.Members {
				if m == nodeID {
					net.Members = append(net.Members[:i], net.Members[i+1:]...)
					break
				}
			}
		}
	}
	// Keep ownerIdx entry so owner-based key recovery can reclaim the node_id
	if node.Hostname != "" {
		delete(s.hostnameIdx, node.Hostname)
	}
	s.cleanupNode(nodeID)
	delete(s.nodes, nodeID)
	s.save()

	slog.Info("deregistered node", "node_id", nodeID)

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

	node.LastSeen = time.Now()

	return map[string]interface{}{
		"type": "heartbeat_ok",
		"time": time.Now().Unix(),
	}, nil
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

// snapshot is the JSON-serializable registry state.
type snapshot struct {
	NextNode           uint32                             `json:"next_node"`
	NextNet            uint16                             `json:"next_net"`
	Nodes              map[string]*snapshotNode           `json:"nodes"`
	Networks           map[string]*snapshotNet            `json:"networks"`
	TrustPairs         []string                           `json:"trust_pairs,omitempty"`
	PubKeyIdx          map[string]uint32                  `json:"pub_key_idx,omitempty"`
	HandshakeInbox     map[string][]*HandshakeRelayMsg    `json:"handshake_inbox,omitempty"`
	HandshakeResponses map[string][]*HandshakeResponseMsg `json:"handshake_responses,omitempty"`
}

type snapshotNode struct {
	ID        uint32   `json:"id"`
	Owner     string   `json:"owner,omitempty"`
	PublicKey string   `json:"public_key"`
	RealAddr  string   `json:"real_addr,omitempty"`
	Networks  []uint16 `json:"networks"`
	Public    bool     `json:"public,omitempty"`
	LastSeen  string   `json:"last_seen,omitempty"`
	Hostname  string   `json:"hostname,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

type snapshotNet struct {
	ID       uint16   `json:"id"`
	Name     string   `json:"name"`
	JoinRule string   `json:"join_rule"`
	Token    string   `json:"token,omitempty"`
	Members  []uint32 `json:"members"`
	Created  string   `json:"created"`
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
				s.flushSave()
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
				s.flushSave()
			}
			return
		}
	}
}

// flushSave serializes the full registry state and writes it to disk.
func (s *Server) flushSave() {
	s.mu.RLock()
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
			Tags:      n.Tags,
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
	nodeCount := len(s.nodes)
	netCount := len(s.networks)
	s.mu.RUnlock()

	data, err := json.Marshal(snap)
	if err != nil {
		slog.Error("registry save marshal error", "err", err)
		return
	}

	// Persist to disk atomically
	if s.storePath != "" {
		if err := fsutil.AtomicWrite(s.storePath, data); err != nil {
			slog.Error("registry save error", "err", err)
		}
	}

	// Push to replication subscribers
	s.replMgr.push(data)

	slog.Debug("registry state saved", "nodes", nodeCount, "networks", netCount)
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

	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextNode = snap.NextNode
	s.nextNet = snap.NextNet

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
	if length > 1<<20 { // 1MB max
		return nil, fmt.Errorf("message too large: %d bytes", length)
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
}

// DashboardNetwork is a public-safe view of a network for the dashboard.
type DashboardNetwork struct {
	ID      uint16 `json:"id"`
	Name    string `json:"name"`
	Members int    `json:"members"`
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
	tagSet := make(map[string]bool)
	for _, node := range s.nodes {
		online := node.LastSeen.After(onlineThreshold)
		if online {
			activeCount++
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
		})
	}

	// Sort nodes by address (ascending)
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Address < nodes[j].Address
	})

	networks := make([]DashboardNetwork, 0, len(s.networks))
	for _, net := range s.networks {
		networks = append(networks, DashboardNetwork{
			ID:      net.ID,
			Name:    net.Name,
			Members: len(net.Members),
		})
	}

	return DashboardStats{
		TotalNodes:      len(s.nodes),
		ActiveNodes:     activeCount,
		TotalTrustLinks: len(s.trustPairs),
		TotalRequests:   s.requestCount.Load(),
		UniqueTags:      len(tagSet),
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
		return nil // no key on file, allow unsigned
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

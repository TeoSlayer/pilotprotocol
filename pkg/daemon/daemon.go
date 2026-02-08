package daemon

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"web4/internal/crypto"
	"web4/pkg/protocol"
	"web4/pkg/registry"
)

var (
	zeroTime     = func() time.Time { return time.Time{} }
	fixedTimeout = func() time.Time { return time.Now().Add(5 * time.Second) }
)

type Config struct {
	RegistryAddr        string
	BeaconAddr          string
	ListenAddr          string // UDP listen address for tunnel traffic
	SocketPath          string // Unix socket path for IPC
	Encrypt             bool   // enable tunnel-layer encryption (X25519 + AES-256-GCM)
	RegistryTLS         bool   // use TLS for registry connection
	RegistryFingerprint string // hex SHA-256 fingerprint for TLS cert pinning
	IdentityPath        string // path to persist Ed25519 identity (empty = no persistence)
	Owner               string // owner identifier (email) for key rotation recovery

	Endpoint string // fixed public endpoint (host:port) — skips STUN discovery (for cloud VMs)
	Public   bool   // make this node's endpoint publicly discoverable
	Hostname string // hostname for discovery (empty = none)

	// Built-in services
	DisableEcho         bool // disable built-in echo service (port 7)
	DisableDataExchange bool // disable built-in data exchange service (port 1001)
	DisableEventStream  bool // disable built-in event stream service (port 1002)

	// Webhook
	WebhookURL string // HTTP(S) endpoint for event notifications (empty = disabled)

	// Tuning (zero = use defaults)
	KeepaliveInterval     time.Duration // default 30s
	IdleTimeout           time.Duration // default 120s
	SYNRateLimit          int           // default 100
	MaxConnectionsPerPort int           // default 1024
	MaxTotalConnections   int           // default 4096
	TimeWaitDuration      time.Duration // default 10s
}

// Default tuning constants (used when Config fields are zero).
const (
	DefaultKeepaliveInterval     = 30 * time.Second
	DefaultIdleTimeout           = 120 * time.Second
	DefaultIdleSweepInterval     = 15 * time.Second
	DefaultSYNRateLimit          = 100
	DefaultMaxConnectionsPerPort = 1024
	DefaultMaxTotalConnections   = 4096
	DefaultTimeWaitDuration      = 10 * time.Second
)

// Dial and retransmission constants.
const (
	DialDirectRetries    = 3                      // direct connection attempts before relay
	DialMaxRetries       = 6                      // total attempts (direct + relay)
	DialInitialRTO       = 1 * time.Second        // initial SYN retransmission timeout
	DialMaxRTO           = 8 * time.Second        // max backoff for SYN retransmission
	DialCheckInterval    = 10 * time.Millisecond  // poll interval for state changes during dial
	RetxCheckInterval    = 100 * time.Millisecond // retransmission check ticker
	MaxRetxAttempts      = 8                      // abandon connection after this many retransmissions
	HeartbeatReregThresh = 3                      // heartbeat failures before re-registration
	SYNBucketAge         = 10 * time.Second       // stale per-source SYN bucket reap threshold
)

// Zero-window probe constants.
const (
	ZeroWinProbeInitial = 500 * time.Millisecond // initial zero-window probe interval
	ZeroWinProbeMax     = 30 * time.Second       // max zero-window probe backoff
)

type Daemon struct {
	config     Config
	addrMu     sync.RWMutex // protects nodeID and addr (H6 fix)
	nodeID     uint32
	addr       protocol.Addr
	identity   *crypto.Identity
	regConn    *registry.Client
	tunnels    *TunnelManager
	ports      *PortManager
	ipc        *IPCServer
	handshakes *HandshakeManager
	webhook    *WebhookClient
	startTime  time.Time
	stopCh     chan struct{} // closed on Stop() to signal goroutines

	// SYN rate limiter (token bucket)
	synMu       sync.Mutex
	synTokens   int
	synLastFill time.Time

	// Per-source SYN rate limiter
	perSrcSYNMu sync.Mutex
	perSrcSYN   map[uint32]*srcSYNBucket // source nodeID -> bucket
}

const perSourceSYNLimit = 10     // max SYNs per source per second
const maxPerSrcSYNEntries = 4096 // max tracked source entries (M9 fix)

type srcSYNBucket struct {
	tokens   int
	lastFill time.Time
}

func (c *Config) keepaliveInterval() time.Duration {
	if c.KeepaliveInterval > 0 {
		return c.KeepaliveInterval
	}
	return DefaultKeepaliveInterval
}

func (c *Config) idleTimeout() time.Duration {
	if c.IdleTimeout > 0 {
		return c.IdleTimeout
	}
	return DefaultIdleTimeout
}

func (c *Config) synRateLimit() int {
	if c.SYNRateLimit > 0 {
		return c.SYNRateLimit
	}
	return DefaultSYNRateLimit
}

func (c *Config) maxConnectionsPerPort() int {
	if c.MaxConnectionsPerPort > 0 {
		return c.MaxConnectionsPerPort
	}
	return DefaultMaxConnectionsPerPort
}

func (c *Config) maxTotalConnections() int {
	if c.MaxTotalConnections > 0 {
		return c.MaxTotalConnections
	}
	return DefaultMaxTotalConnections
}

func (c *Config) timeWaitDuration() time.Duration {
	if c.TimeWaitDuration > 0 {
		return c.TimeWaitDuration
	}
	return DefaultTimeWaitDuration
}

func New(cfg Config) *Daemon {
	d := &Daemon{
		config:      cfg,
		tunnels:     NewTunnelManager(),
		ports:       NewPortManager(),
		stopCh:      make(chan struct{}),
		synTokens:   cfg.synRateLimit(),
		synLastFill: time.Now(),
		perSrcSYN:   make(map[uint32]*srcSYNBucket),
	}
	d.ipc = NewIPCServer(cfg.SocketPath, d)
	d.handshakes = NewHandshakeManager(d)
	return d
}

// allowSYN returns true if a SYN should be accepted under the rate limit.
// Uses a simple token bucket: refills at SYNRateLimit tokens/second.
func (d *Daemon) allowSYN() bool {
	d.synMu.Lock()
	defer d.synMu.Unlock()

	limit := d.config.synRateLimit()
	now := time.Now()
	elapsed := now.Sub(d.synLastFill)
	if elapsed > 0 {
		refill := int(elapsed.Seconds() * float64(limit))
		if refill > 0 {
			d.synTokens += refill
			if d.synTokens > limit {
				d.synTokens = limit
			}
			d.synLastFill = now
		}
	}

	if d.synTokens > 0 {
		d.synTokens--
		return true
	}
	return false
}

// allowSYNFromSource checks per-source SYN rate limit (10 SYNs/source/second).
func (d *Daemon) allowSYNFromSource(srcNode uint32) bool {
	d.perSrcSYNMu.Lock()
	defer d.perSrcSYNMu.Unlock()

	b, ok := d.perSrcSYN[srcNode]
	now := time.Now()
	if !ok {
		// Cap the map size to prevent unbounded growth (M9 fix)
		if len(d.perSrcSYN) >= maxPerSrcSYNEntries {
			return false // reject when map is full
		}
		d.perSrcSYN[srcNode] = &srcSYNBucket{tokens: perSourceSYNLimit - 1, lastFill: now}
		return true
	}

	elapsed := now.Sub(b.lastFill)
	if elapsed > 0 {
		refill := int(elapsed.Seconds() * float64(perSourceSYNLimit))
		if refill > 0 {
			b.tokens += refill
			if b.tokens > perSourceSYNLimit {
				b.tokens = perSourceSYNLimit
			}
			b.lastFill = now
		}
	}

	if b.tokens > 0 {
		b.tokens--
		return true
	}
	return false
}

// reapPerSrcSYN removes stale per-source SYN buckets.
func (d *Daemon) reapPerSrcSYN() {
	d.perSrcSYNMu.Lock()
	defer d.perSrcSYNMu.Unlock()
	threshold := time.Now().Add(-SYNBucketAge)
	for id, b := range d.perSrcSYN {
		if b.lastFill.Before(threshold) {
			delete(d.perSrcSYN, id)
		}
	}
}

func (d *Daemon) Start() error {
	// 1. Discover our public endpoint via beacon using a temporary UDP socket.
	// If -endpoint is set, skip STUN and use the fixed address (for cloud VMs).
	var registrationAddr string
	if d.config.Endpoint != "" {
		registrationAddr = d.config.Endpoint
		slog.Info("using fixed endpoint", "endpoint", registrationAddr)
	} else {
		registrationAddr = resolveLocalAddr(d.config.ListenAddr)
		if d.config.BeaconAddr != "" {
			pubAddr, err := discoverWithTempSocket(d.config.BeaconAddr, d.config.ListenAddr)
			if err != nil {
				slog.Warn("beacon discover failed, using local addr", "error", err)
			} else {
				registrationAddr = pubAddr
				slog.Debug("discovered public endpoint", "endpoint", pubAddr)
			}
		}
	}

	// 2. Enable tunnel encryption if configured
	if d.config.Encrypt {
		if err := d.tunnels.EnableEncryption(); err != nil {
			return fmt.Errorf("tunnel encryption: %w", err)
		}
	}

	// 3. Start UDP listener for tunnel traffic
	if err := d.tunnels.Listen(d.config.ListenAddr); err != nil {
		return fmt.Errorf("tunnel listen: %w", err)
	}
	actualAddr := d.tunnels.LocalAddr().String()
	slog.Info("tunnel listening", "addr", actualAddr)

	// If STUN discovered a public endpoint, keep it. The temp socket and
	// tunnel socket bind the same local port, so endpoint-independent NAT
	// (like Cloud NAT) maps them to the same external IP:port.
	// Only fall back to the local address if STUN didn't run or failed.
	stunHost, _, splitErr := net.SplitHostPort(registrationAddr)
	isLocalAddr := splitErr != nil || stunHost == "" || stunHost == "127.0.0.1" || stunHost == "::1" || stunHost == "0.0.0.0" || stunHost == "::"
	if isLocalAddr {
		registrationAddr = resolveLocalAddr(actualAddr)
	}

	// 3. Load or generate identity locally
	if d.config.IdentityPath != "" {
		id, err := crypto.LoadIdentity(d.config.IdentityPath)
		if err != nil {
			return fmt.Errorf("load identity: %w", err)
		}
		if id != nil {
			d.identity = id
			slog.Info("loaded identity", "path", d.config.IdentityPath)
		}
	}
	// Always generate identity locally if we don't have one
	if d.identity == nil {
		id, err := crypto.GenerateIdentity()
		if err != nil {
			return fmt.Errorf("generate identity: %w", err)
		}
		d.identity = id
		if d.config.IdentityPath != "" {
			if err := crypto.SaveIdentity(d.config.IdentityPath, d.identity); err != nil {
				slog.Warn("failed to save identity", "error", err)
			} else {
				slog.Info("saved identity", "path", d.config.IdentityPath)
			}
		}
	}

	// 4. Register with the registry (always with client-generated key)
	var rc *registry.Client
	var err error
	if d.config.RegistryTLS {
		if d.config.RegistryFingerprint != "" {
			rc, err = registry.DialTLSPinned(d.config.RegistryAddr, d.config.RegistryFingerprint)
		} else {
			return fmt.Errorf("registry TLS requires RegistryFingerprint for certificate pinning")
		}
	} else {
		rc, err = registry.Dial(d.config.RegistryAddr)
	}
	if err != nil {
		return fmt.Errorf("registry dial: %w", err)
	}
	d.regConn = rc

	// H3 fix: set signer for authenticated registry operations
	if d.identity != nil {
		id := d.identity
		rc.SetSigner(func(challenge string) string {
			sig := id.Sign([]byte(challenge))
			return base64.StdEncoding.EncodeToString(sig)
		})
	}

	pubKeyB64 := crypto.EncodePublicKey(d.identity.PublicKey)
	resp, err := rc.RegisterWithKey(registrationAddr, pubKeyB64, d.config.Owner)
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}

	nodeIDVal, ok := resp["node_id"].(float64)
	if !ok {
		return fmt.Errorf("register: missing node_id in response")
	}
	d.nodeID = uint32(nodeIDVal)
	addrStr, ok := resp["address"].(string)
	if !ok {
		return fmt.Errorf("register: missing address in response")
	}
	parsedAddr, err := protocol.ParseAddr(addrStr)
	if err != nil {
		return fmt.Errorf("register: invalid address %q: %w", addrStr, err)
	}
	d.addr = parsedAddr
	d.tunnels.SetNodeID(d.nodeID)

	// Set identity on tunnel manager for authenticated key exchange
	if d.identity != nil {
		d.tunnels.SetIdentity(d.identity)
		d.tunnels.SetPeerVerifyFunc(d.lookupPeerPubKey)
	}

	slog.Info("daemon registered", "node_id", d.nodeID, "addr", d.addr, "endpoint", registrationAddr)

	// Initialize webhook client (no-op if URL is empty)
	d.webhook = NewWebhookClient(d.config.WebhookURL, d.NodeID)
	d.tunnels.SetWebhook(d.webhook)
	d.handshakes.SetWebhook(d.webhook)
	d.webhook.Emit("node.registered", map[string]interface{}{
		"address":  d.addr.String(),
		"endpoint": registrationAddr,
	})

	// Register with beacon using real nodeID for NAT traversal (punch/relay)
	if d.config.BeaconAddr != "" {
		if err := d.tunnels.SetBeaconAddr(d.config.BeaconAddr); err != nil {
			slog.Warn("failed to set beacon addr", "error", err)
		} else {
			d.tunnels.RegisterWithBeacon()
		}
	}

	// Set node visibility
	if d.config.Public {
		if _, err := d.regConn.SetVisibility(d.nodeID, true); err != nil {
			slog.Warn("failed to set public visibility", "error", err)
		} else {
			slog.Info("node visibility set", "visibility", "public")
		}
	}

	// Set hostname if configured
	if d.config.Hostname != "" {
		if _, err := d.regConn.SetHostname(d.nodeID, d.config.Hostname); err != nil {
			slog.Warn("failed to set hostname", "hostname", d.config.Hostname, "error", err)
		} else {
			slog.Info("hostname set", "hostname", d.config.Hostname)
		}
	}

	// 4. Start IPC server
	if err := d.ipc.Start(); err != nil {
		return fmt.Errorf("ipc start: %w", err)
	}

	// 5. Start handshake service on port 444
	if d.identity != nil {
		if err := d.handshakes.Start(); err != nil {
			slog.Warn("handshake service failed to start", "error", err)
		}
	}

	// 6. Start built-in services (echo, dataexchange, eventstream)
	d.startBuiltinServices()

	// 7. Start packet router
	go d.routeLoop()

	// 8. Start heartbeat
	go d.heartbeatLoop()

	// 9. Start idle connection sweeper
	go d.idleSweepLoop()

	d.startTime = time.Now()
	slog.Info("daemon running", "node_id", d.nodeID, "addr", d.addr)
	return nil
}

// discoverWithTempSocket does STUN discovery on a temporary UDP socket
// bound to the same port, then closes it so the tunnel can bind.
func discoverWithTempSocket(beaconAddr, listenAddr string) (string, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return "", err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return "", fmt.Errorf("temp listen: %w", err)
	}
	defer conn.Close()

	pub, err := DiscoverEndpoint(beaconAddr, 0, conn)
	if err != nil {
		return "", err
	}
	return pub.String(), nil
}

func (d *Daemon) Stop() error {
	// Signal all goroutines to stop
	select {
	case <-d.stopCh:
	default:
		close(d.stopCh)
	}

	// Graceful close: send FIN to all active connections, then force remove
	conns := d.ports.AllConnections()
	for _, conn := range conns {
		conn.Mu.Lock()
		st := conn.State
		seq := conn.SendSeq
		conn.Mu.Unlock()
		if st == StateEstablished {
			// Send FIN
			fin := &protocol.Packet{
				Version:  protocol.Version,
				Flags:    protocol.FlagFIN,
				Protocol: protocol.ProtoStream,
				Src:      d.Addr(),
				Dst:      conn.RemoteAddr,
				SrcPort:  conn.LocalPort,
				DstPort:  conn.RemotePort,
				Seq:      seq,
			}
			d.tunnels.Send(conn.RemoteAddr.Node, fin)
		}
		// On shutdown, skip TIME_WAIT and remove immediately
		conn.Mu.Lock()
		conn.State = StateClosed
		conn.Mu.Unlock()
		conn.CloseRecvBuf()
		d.ports.RemoveConnection(conn.ID)
	}
	if len(conns) > 0 {
		slog.Info("closed active connections", "count", len(conns))
	}

	// Wait for background handshake RPCs to drain
	if d.handshakes != nil {
		d.handshakes.Stop()
	}

	// Deregister from registry
	if d.regConn != nil {
		d.webhook.Emit("node.deregistered", nil)
		d.regConn.Deregister(d.NodeID())
		d.regConn.Close()
	}

	d.ipc.Close()
	d.tunnels.Close()
	d.webhook.Close()
	return nil
}

func (d *Daemon) NodeID() uint32 {
	d.addrMu.RLock()
	defer d.addrMu.RUnlock()
	return d.nodeID
}

// SetWebhookURL hot-swaps the webhook client at runtime.
// An empty URL disables the webhook (all Emit calls become no-ops).
func (d *Daemon) SetWebhookURL(url string) {
	old := d.webhook
	d.webhook = NewWebhookClient(url, d.NodeID)
	d.tunnels.SetWebhook(d.webhook)
	d.handshakes.SetWebhook(d.webhook)
	old.Close()
	if url != "" {
		slog.Info("webhook updated", "url", url)
	} else {
		slog.Info("webhook cleared")
	}
}

// Identity returns the daemon's Ed25519 identity (may be nil if unset).
func (d *Daemon) Identity() *crypto.Identity { return d.identity }

func (d *Daemon) Addr() protocol.Addr {
	d.addrMu.RLock()
	defer d.addrMu.RUnlock()
	return d.addr
}

// DaemonInfo holds status information about the running daemon.
type DaemonInfo struct {
	NodeID             uint32
	Address            string
	Hostname           string
	Uptime             time.Duration
	Connections        int
	Ports              int
	Peers              int
	EncryptedPeers     int
	AuthenticatedPeers int
	Encrypt            bool
	Identity           bool   // true if identity is persisted
	PublicKey          string // base64 Ed25519 public key (empty if no identity)
	Owner              string // owner identifier for key rotation recovery
	BytesSent          uint64
	BytesRecv          uint64
	PktsSent           uint64
	PktsRecv           uint64
	PeerList           []PeerInfo
	ConnList           []ConnectionInfo
}

// Info returns current daemon status.
func (d *Daemon) Info() *DaemonInfo {
	d.ports.mu.RLock()
	numConns := 0
	for _, c := range d.ports.connections {
		c.Mu.Lock()
		st := c.State
		c.Mu.Unlock()
		if st == StateEstablished || st == StateSynSent || st == StateSynReceived {
			numConns++
		}
	}
	numPorts := len(d.ports.listeners)
	d.ports.mu.RUnlock()

	peerList := d.tunnels.PeerList()
	encryptedPeers := 0
	authenticatedPeers := 0
	for _, p := range peerList {
		if p.Encrypted {
			encryptedPeers++
		}
		if p.Authenticated {
			authenticatedPeers++
		}
	}

	hasIdentity := d.config.IdentityPath != ""
	pubKeyStr := ""
	if d.identity != nil {
		pubKeyStr = crypto.EncodePublicKey(d.identity.PublicKey)
	}

	d.addrMu.RLock()
	nid := d.nodeID
	addrStr := d.addr.String()
	hostname := d.config.Hostname
	d.addrMu.RUnlock()

	return &DaemonInfo{
		NodeID:             nid,
		Address:            addrStr,
		Hostname:           hostname,
		Uptime:             time.Since(d.startTime).Round(time.Second),
		Connections:        numConns,
		Ports:              numPorts,
		Peers:              d.tunnels.PeerCount(),
		EncryptedPeers:     encryptedPeers,
		AuthenticatedPeers: authenticatedPeers,
		Encrypt:            d.config.Encrypt,
		Identity:           hasIdentity,
		PublicKey:          pubKeyStr,
		Owner:              d.config.Owner,
		BytesSent:          atomic.LoadUint64(&d.tunnels.BytesSent),
		BytesRecv:          atomic.LoadUint64(&d.tunnels.BytesRecv),
		PktsSent:           atomic.LoadUint64(&d.tunnels.PktsSent),
		PktsRecv:           atomic.LoadUint64(&d.tunnels.PktsRecv),
		PeerList:           peerList,
		ConnList:           d.ports.ConnectionList(),
	}
}

func (d *Daemon) routeLoop() {
	for incoming := range d.tunnels.RecvCh() {
		d.handlePacket(incoming.Packet, incoming.From)
	}
}

func (d *Daemon) handlePacket(pkt *protocol.Packet, from *net.UDPAddr) {
	// D14 mitigation: when encryption is enabled, only auto-add peers that have an
	// established crypto context (proving prior key exchange). This prevents peer table
	// poisoning from spoofed packets. In plaintext mode, auto-add is safe since
	// there's no authentication to bypass.
	if !d.tunnels.HasPeer(pkt.Src.Node) {
		if !d.config.Encrypt || d.tunnels.HasCrypto(pkt.Src.Node) {
			d.tunnels.AddPeer(pkt.Src.Node, from)
			d.webhook.Emit("tunnel.peer_added", map[string]interface{}{
				"peer_node_id": pkt.Src.Node, "endpoint": from.String(),
			})
		}
	}

	switch pkt.Protocol {
	case protocol.ProtoStream:
		d.handleStreamPacket(pkt)
	case protocol.ProtoDatagram:
		d.handleDatagramPacket(pkt)
	case protocol.ProtoControl:
		d.handleControlPacket(pkt)
	}
}

func (d *Daemon) handleStreamPacket(pkt *protocol.Packet) {
	// SYN — incoming connection request
	if pkt.HasFlag(protocol.FlagSYN) && !pkt.HasFlag(protocol.FlagACK) {
		ln := d.ports.GetListener(pkt.DstPort)
		if ln == nil {
			// Nothing listening — send RST
			d.sendRST(pkt)
			return
		}

		// Check for retransmitted SYN (connection already exists for this 4-tuple)
		if existing := d.ports.FindConnection(pkt.DstPort, pkt.Src, pkt.SrcPort); existing != nil {
			// Resend SYN-ACK for the existing connection
			existing.Mu.Lock()
			eSeq := existing.SendSeq
			eAck := existing.RecvAck
			existing.Mu.Unlock()
			synack := &protocol.Packet{
				Version:  protocol.Version,
				Flags:    protocol.FlagSYN | protocol.FlagACK,
				Protocol: protocol.ProtoStream,
				Src:      d.Addr(),
				Dst:      pkt.Src,
				SrcPort:  pkt.DstPort,
				DstPort:  pkt.SrcPort,
				Seq:      eSeq - 1, // original SYN-ACK seq
				Ack:      eAck,
				Window:   existing.RecvWindow(),
			}
			d.tunnels.Send(pkt.Src.Node, synack)
			return
		}

		// SYN rate limiting
		if !d.allowSYN() {
			slog.Warn("SYN rate limit exceeded", "src_addr", pkt.Src, "src_port", pkt.SrcPort)
			d.webhook.Emit("security.syn_rate_limited", map[string]interface{}{
				"src_addr": pkt.Src.String(), "src_port": pkt.SrcPort,
			})
			return // silently drop — don't even RST (avoid amplification)
		}
		if !d.allowSYNFromSource(pkt.Src.Node) {
			slog.Warn("per-source SYN rate limit exceeded", "src_node", pkt.Src.Node, "src_port", pkt.SrcPort)
			return
		}

		// Check per-port connection limit
		if d.ports.ConnectionCountForPort(pkt.DstPort) >= d.config.maxConnectionsPerPort() {
			slog.Warn("max connections per port reached, rejecting SYN", "port", pkt.DstPort, "src_addr", pkt.Src, "src_port", pkt.SrcPort)
			d.sendRST(pkt)
			return
		}

		// Check global connection limit
		if d.ports.TotalActiveConnections() >= d.config.maxTotalConnections() {
			slog.Warn("max total connections reached, rejecting SYN", "src_addr", pkt.Src, "src_port", pkt.SrcPort)
			d.sendRST(pkt)
			return
		}

		conn := d.ports.NewConnection(pkt.DstPort, pkt.Src, pkt.SrcPort)
		conn.Mu.Lock()
		conn.LocalAddr = d.Addr()
		conn.State = StateSynReceived
		conn.RecvAck = pkt.Seq + 1
		conn.ExpectedSeq = pkt.Seq + 1 // first data segment after SYN
		conn.Mu.Unlock()
		d.webhook.Emit("conn.syn_received", map[string]interface{}{
			"src_addr": pkt.Src.String(), "src_port": pkt.SrcPort,
			"dst_port": pkt.DstPort, "conn_id": conn.ID,
		})

		// Process peer's receive window from SYN (H9 fix: always update, including Window==0)
		conn.RetxMu.Lock()
		conn.PeerRecvWin = int(pkt.Window) * MaxSegmentSize
		conn.RetxMu.Unlock()

		// Send SYN-ACK with our receive window
		conn.Mu.Lock()
		synack := &protocol.Packet{
			Version:  protocol.Version,
			Flags:    protocol.FlagSYN | protocol.FlagACK,
			Protocol: protocol.ProtoStream,
			Src:      d.Addr(),
			Dst:      pkt.Src,
			SrcPort:  pkt.DstPort,
			DstPort:  pkt.SrcPort,
			Seq:      conn.SendSeq,
			Ack:      conn.RecvAck,
			Window:   conn.RecvWindow(),
		}
		d.tunnels.Send(pkt.Src.Node, synack)
		conn.SendSeq++
		conn.State = StateEstablished
		conn.Mu.Unlock()
		d.webhook.Emit("conn.established", map[string]interface{}{
			"src_addr": pkt.Src.String(), "src_port": pkt.SrcPort,
			"dst_port": pkt.DstPort, "conn_id": conn.ID,
		})

		d.startRetxLoop(conn)
		// Non-blocking push to accept queue — if full, clean up and RST
		select {
		case ln.AcceptCh <- conn:
		default:
			slog.Warn("accept queue full after SYN-ACK, closing connection", "port", pkt.DstPort, "src_addr", pkt.Src)
			conn.Mu.Lock()
			conn.State = StateClosed
			conn.Mu.Unlock()
			d.ports.RemoveConnection(conn.ID)
			d.sendRST(pkt)
		}
		return
	}

	// SYN-ACK — response to our dial
	if pkt.HasFlag(protocol.FlagSYN) && pkt.HasFlag(protocol.FlagACK) {
		conn := d.ports.FindConnection(pkt.DstPort, pkt.Src, pkt.SrcPort)
		if conn == nil {
			return
		}
		conn.Mu.Lock()
		if conn.State != StateSynSent {
			conn.Mu.Unlock()
			return
		}
		conn.RecvAck = pkt.Seq + 1
		conn.State = StateEstablished
		sendSeq := conn.SendSeq
		recvAck := conn.RecvAck
		conn.Mu.Unlock()

		conn.RecvMu.Lock()
		conn.ExpectedSeq = pkt.Seq + 1 // first data segment after SYN-ACK
		conn.RecvMu.Unlock()

		// Process peer's receive window from SYN-ACK (H9 fix: always update)
		conn.RetxMu.Lock()
		conn.PeerRecvWin = int(pkt.Window) * MaxSegmentSize
		conn.RetxMu.Unlock()

		// Send ACK with our receive window
		ack := &protocol.Packet{
			Version:  protocol.Version,
			Flags:    protocol.FlagACK,
			Protocol: protocol.ProtoStream,
			Src:      d.Addr(),
			Dst:      pkt.Src,
			SrcPort:  pkt.DstPort,
			DstPort:  pkt.SrcPort,
			Seq:      sendSeq,
			Ack:      recvAck,
			Window:   conn.RecvWindow(),
		}
		d.tunnels.Send(pkt.Src.Node, ack)
		return
	}

	// FIN — remote close
	if pkt.HasFlag(protocol.FlagFIN) {
		conn := d.ports.FindConnection(pkt.DstPort, pkt.Src, pkt.SrcPort)
		if conn != nil {
			conn.CloseRecvBuf()
			conn.Mu.Lock()
			wasTimeWait := conn.State == StateTimeWait
			conn.State = StateTimeWait
			conn.LastActivity = time.Now()
			sendSeq := conn.SendSeq
			conn.Mu.Unlock()
			if !wasTimeWait {
				d.webhook.Emit("conn.fin", map[string]interface{}{
					"remote_addr": pkt.Src.String(), "remote_port": pkt.SrcPort,
					"local_port": pkt.DstPort, "conn_id": conn.ID,
				})
			}
			// Connection will be reaped by idleSweepLoop after TimeWaitDuration

			// Send FIN-ACK
			finack := &protocol.Packet{
				Version:  protocol.Version,
				Flags:    protocol.FlagFIN | protocol.FlagACK,
				Protocol: protocol.ProtoStream,
				Src:      d.Addr(),
				Dst:      pkt.Src,
				SrcPort:  pkt.DstPort,
				DstPort:  pkt.SrcPort,
				Seq:      sendSeq,
				Ack:      pkt.Seq + 1,
			}
			d.tunnels.Send(pkt.Src.Node, finack)
		}
		return
	}

	// RST
	if pkt.HasFlag(protocol.FlagRST) {
		conn := d.ports.FindConnection(pkt.DstPort, pkt.Src, pkt.SrcPort)
		if conn != nil {
			conn.Mu.Lock()
			conn.State = StateClosed
			conn.Mu.Unlock()
			conn.CloseRecvBuf()
			d.ports.RemoveConnection(conn.ID)
			d.webhook.Emit("conn.rst", map[string]interface{}{
				"remote_addr": pkt.Src.String(), "remote_port": pkt.SrcPort,
				"local_port": pkt.DstPort, "conn_id": conn.ID,
			})
		}
		return
	}

	// ACK — pure ACK or data packet
	if pkt.HasFlag(protocol.FlagACK) {
		conn := d.ports.FindConnection(pkt.DstPort, pkt.Src, pkt.SrcPort)
		if conn == nil {
			return
		}

		conn.Mu.Lock()
		conn.LastActivity = time.Now()
		conn.Mu.Unlock()

		// Update peer's receive window (H9 fix: always update, honor Window==0)
		conn.RetxMu.Lock()
		conn.PeerRecvWin = int(pkt.Window) * MaxSegmentSize
		conn.RetxMu.Unlock()

		// Process ACK for retransmission tracking
		// Only count as pure ACK for dup detection if no data payload
		if pkt.Ack > 0 {
			isPureACK := len(pkt.Payload) == 0
			conn.ProcessAck(pkt.Ack, isPureACK)
		}

		// Check if payload is SACK info (not user data)
		if sackBlocks, ok := DecodeSACK(pkt.Payload); ok {
			conn.ProcessSACK(sackBlocks)
		} else if len(pkt.Payload) > 0 {
			conn.Mu.Lock()
			established := conn.State == StateEstablished
			if established {
				conn.LastActivity = time.Now()
				conn.Stats.BytesRecv += uint64(len(pkt.Payload))
				conn.Stats.SegsRecv++
			}
			conn.Mu.Unlock()
			if !established {
				return
			}
			// Deliver data using receive window (handles reordering)
			cumAck := conn.DeliverInOrder(pkt.Seq, pkt.Payload)
			conn.Mu.Lock()
			conn.RecvAck = cumAck
			conn.Mu.Unlock()

			// Check if we have out-of-order data — ACK immediately with SACK
			conn.RecvMu.Lock()
			hasOOO := len(conn.OOOBuf) > 0
			conn.RecvMu.Unlock()

			conn.AckMu.Lock()
			if hasOOO {
				// Immediate ACK with SACK blocks (trigger fast retransmit)
				conn.AckMu.Unlock()
				d.sendDelayedACK(conn)
			} else {
				// Delayed ACK: batch up to 2 segments or 40ms
				conn.PendingACKs++
				if conn.PendingACKs >= DelayedACKThreshold {
					conn.AckMu.Unlock()
					d.sendDelayedACK(conn)
				} else if conn.ACKTimer == nil {
					conn.ACKTimer = time.AfterFunc(DelayedACKTimeout, func() {
						d.sendDelayedACK(conn)
					})
					conn.AckMu.Unlock()
				} else {
					conn.AckMu.Unlock()
				}
			}
		}
	}
}

// sendDelayedACK sends a cumulative ACK for a connection, including SACK blocks if needed.
func (d *Daemon) sendDelayedACK(conn *Connection) {
	// Reset delayed ACK state
	conn.AckMu.Lock()
	if conn.ACKTimer != nil {
		conn.ACKTimer.Stop()
		conn.ACKTimer = nil
	}
	conn.PendingACKs = 0
	conn.AckMu.Unlock()

	conn.Mu.Lock()
	sendSeq := conn.SendSeq
	recvAck := conn.RecvAck
	conn.Mu.Unlock()

	ack := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagACK,
		Protocol: protocol.ProtoStream,
		Src:      d.Addr(),
		Dst:      conn.RemoteAddr,
		SrcPort:  conn.LocalPort,
		DstPort:  conn.RemotePort,
		Seq:      sendSeq,
		Ack:      recvAck,
		Window:   conn.RecvWindow(),
	}

	// Include SACK blocks if we have out-of-order segments
	conn.RecvMu.Lock()
	sackBlocks := conn.SACKBlocks()
	conn.RecvMu.Unlock()
	if len(sackBlocks) > 0 {
		ack.Payload = EncodeSACK(sackBlocks)
		conn.Mu.Lock()
		conn.Stats.SACKSent += uint64(len(sackBlocks))
		conn.Mu.Unlock()
	}

	d.tunnels.Send(conn.RemoteAddr.Node, ack)
}

func (d *Daemon) handleDatagramPacket(pkt *protocol.Packet) {
	if len(pkt.Payload) > 0 {
		d.webhook.Emit("data.datagram", map[string]interface{}{
			"src_addr": pkt.Src.String(), "src_port": pkt.SrcPort,
			"dst_port": pkt.DstPort, "size": len(pkt.Payload),
		})
		d.ipc.DeliverDatagram(pkt.Src, pkt.SrcPort, pkt.DstPort, pkt.Payload)
	}
}

func (d *Daemon) handleControlPacket(pkt *protocol.Packet) {
	if pkt.DstPort == protocol.PortPing {
		// Ping request — send pong back
		pong := &protocol.Packet{
			Version:  protocol.Version,
			Flags:    protocol.FlagACK,
			Protocol: protocol.ProtoControl,
			Src:      d.Addr(),
			Dst:      pkt.Src,
			SrcPort:  protocol.PortPing,
			DstPort:  pkt.SrcPort,
			Seq:      pkt.Seq,
			Ack:      pkt.Seq + 1,
			Payload:  pkt.Payload,
		}
		d.tunnels.Send(pkt.Src.Node, pong)
	}
}

func (d *Daemon) sendRST(orig *protocol.Packet) {
	rst := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagRST,
		Protocol: protocol.ProtoStream,
		Src:      d.Addr(),
		Dst:      orig.Src,
		SrcPort:  orig.DstPort,
		DstPort:  orig.SrcPort,
	}
	d.tunnels.Send(orig.Src.Node, rst)
}

// DialConnection initiates a connection to a remote address:port.
func (d *Daemon) DialConnection(dstAddr protocol.Addr, dstPort uint16) (*Connection, error) {
	// Ensure we have a tunnel to the destination
	if err := d.ensureTunnel(dstAddr.Node); err != nil {
		return nil, err
	}

	localPort := d.ports.AllocEphemeralPort()
	conn := d.ports.NewConnection(localPort, dstAddr, dstPort)
	conn.LocalAddr = d.Addr()
	conn.State = StateSynSent

	// Send SYN with our receive window
	syn := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      d.Addr(),
		Dst:      dstAddr,
		SrcPort:  localPort,
		DstPort:  dstPort,
		Seq:      conn.SendSeq,
		Window:   conn.RecvWindow(),
	}

	if err := d.tunnels.Send(dstAddr.Node, syn); err != nil {
		d.ports.RemoveConnection(conn.ID)
		return nil, fmt.Errorf("send SYN: %w", err)
	}
	conn.Mu.Lock()
	conn.SendSeq++
	conn.Mu.Unlock()

	// Wait for ESTABLISHED with SYN retransmission.
	// Phase 1: Direct connection (3 retries).
	// Phase 2: Relay through beacon if direct fails (3 more retries).
	retries := 0
	directRetries := DialDirectRetries
	maxRetries := DialMaxRetries
	relayActive := d.tunnels.IsRelayPeer(dstAddr.Node) // may already be relay from prior attempt
	if relayActive {
		directRetries = 0 // skip direct phase, go straight to relay
	}
	rto := DialInitialRTO
	timer := time.NewTimer(rto)
	defer timer.Stop()

	check := time.NewTicker(DialCheckInterval)
	defer check.Stop()

	for {
		select {
		case <-check.C:
			conn.Mu.Lock()
			st := conn.State
			conn.Mu.Unlock()
			if st == StateEstablished {
				d.startRetxLoop(conn)
				return conn, nil
			}
			if st == StateClosed {
				return nil, protocol.ErrConnRefused
			}
		case <-timer.C:
			retries++

			// Switch to relay mode after direct retries exhaust
			if retries == directRetries && d.config.BeaconAddr != "" && !relayActive {
				slog.Info("direct dial timed out, switching to relay", "node_id", dstAddr.Node)
				d.tunnels.SetRelayPeer(dstAddr.Node, true)
				relayActive = true
				rto = DialInitialRTO // reset backoff for relay phase
			}

			if retries > maxRetries {
				d.ports.RemoveConnection(conn.ID)
				return nil, protocol.ErrDialTimeout
			}
			// Resend SYN (uses relay if relayActive)
			conn.Mu.Lock()
			syn.Seq = conn.SendSeq - 1
			conn.Mu.Unlock()
			d.tunnels.Send(dstAddr.Node, syn)
			rto = rto * 2 // exponential backoff
			if rto > DialMaxRTO {
				rto = DialMaxRTO
			}
			timer.Reset(rto)
		}
	}
}

// NagleTimeout is the maximum time to buffer small writes before flushing.
const NagleTimeout = 40 * time.Millisecond

// DelayedACKTimeout is the max time to delay an ACK (RFC 1122 suggests 500ms max, we use 40ms).
const DelayedACKTimeout = 40 * time.Millisecond

// DelayedACKThreshold is the number of segments to receive before sending an ACK immediately.
const DelayedACKThreshold = 2

// SendData sends data over an established connection.
// Implements Nagle's algorithm: small writes are coalesced into MSS-sized
// segments unless NoDelay is set. Large writes (>= MSS) are sent immediately.
func (d *Daemon) SendData(conn *Connection, data []byte) error {
	conn.Mu.Lock()
	st := conn.State
	conn.Mu.Unlock()
	if st != StateEstablished {
		return fmt.Errorf("connection not established")
	}

	// If Nagle is disabled (NoDelay), send everything immediately in segments
	if conn.NoDelay {
		return d.sendDataImmediate(conn, data)
	}

	conn.NagleMu.Lock()
	conn.NagleBuf = append(conn.NagleBuf, data...)
	conn.NagleMu.Unlock()

	return d.nagleFlush(conn)
}

// nagleFlush sends buffered data according to Nagle's algorithm:
// - Full MSS segments are always sent
// - Sub-MSS data is sent only if no unacknowledged data exists or timeout
func (d *Daemon) nagleFlush(conn *Connection) error {
	for {
		conn.NagleMu.Lock()
		if len(conn.NagleBuf) == 0 {
			conn.NagleMu.Unlock()
			return nil
		}

		// If we have at least MSS bytes, send a full segment
		if len(conn.NagleBuf) >= MaxSegmentSize {
			segment := make([]byte, MaxSegmentSize)
			copy(segment, conn.NagleBuf[:MaxSegmentSize])
			conn.NagleBuf = conn.NagleBuf[MaxSegmentSize:]
			conn.NagleMu.Unlock()

			if err := d.sendSegment(conn, segment); err != nil {
				return err
			}
			continue
		}

		// Sub-MSS data: check if we can send now (check under NagleMu)
		conn.RetxMu.Lock()
		hasUnacked := len(conn.Unacked) > 0
		conn.RetxMu.Unlock()

		if !hasUnacked {
			// No data in flight — send immediately (Nagle allows this)
			segment := make([]byte, len(conn.NagleBuf))
			copy(segment, conn.NagleBuf)
			conn.NagleBuf = conn.NagleBuf[:0]
			conn.NagleMu.Unlock()

			return d.sendSegment(conn, segment)
		}
		conn.NagleMu.Unlock()

		// Data in flight — wait for ACK or timeout
		select {
		case <-conn.NagleCh:
			// All data ACKed — flush now
		case <-time.After(NagleTimeout):
			// Timeout — flush regardless
		case <-conn.RetxStop:
			return protocol.ErrConnClosed
		}

		// Re-check under lock after waking
		conn.NagleMu.Lock()
		if len(conn.NagleBuf) == 0 {
			conn.NagleMu.Unlock()
			return nil
		}

		// Send whatever we have (might have reached MSS now)
		if len(conn.NagleBuf) >= MaxSegmentSize {
			conn.NagleMu.Unlock()
			continue // loop back to send full segments
		}

		segment := make([]byte, len(conn.NagleBuf))
		copy(segment, conn.NagleBuf)
		conn.NagleBuf = conn.NagleBuf[:0]
		conn.NagleMu.Unlock()

		return d.sendSegment(conn, segment)
	}
}

// sendDataImmediate sends data in MSS-sized segments without Nagle coalescing.
func (d *Daemon) sendDataImmediate(conn *Connection, data []byte) error {
	for offset := 0; offset < len(data); {
		end := offset + MaxSegmentSize
		if end > len(data) {
			end = len(data)
		}
		segment := data[offset:end]

		if err := d.sendSegment(conn, segment); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

// sendSegment sends a single segment, waiting for the congestion window.
// Implements zero-window probing when the peer's receive window is 0.
func (d *Daemon) sendSegment(conn *Connection, data []byte) error {
	probeInterval := ZeroWinProbeInitial

	// Wait for effective window to have space
	for {
		conn.RetxMu.Lock()
		avail := conn.WindowAvailable()
		conn.RetxMu.Unlock()
		if avail {
			break
		}

		// Window full — wait for ACK to open it, with zero-window probing
		select {
		case <-conn.WindowCh:
			probeInterval = ZeroWinProbeInitial
		case <-conn.RetxStop:
			return protocol.ErrConnClosed
		case <-time.After(probeInterval):
			// Send zero-window probe (empty ACK) to trigger window update
			conn.Mu.Lock()
			probeSeq := conn.SendSeq
			probeAck := conn.RecvAck
			conn.Mu.Unlock()
			probe := &protocol.Packet{
				Version:  protocol.Version,
				Flags:    protocol.FlagACK,
				Protocol: protocol.ProtoStream,
				Src:      d.Addr(),
				Dst:      conn.RemoteAddr,
				SrcPort:  conn.LocalPort,
				DstPort:  conn.RemotePort,
				Seq:      probeSeq,
				Ack:      probeAck,
				Window:   conn.RecvWindow(),
			}
			d.tunnels.Send(conn.RemoteAddr.Node, probe)
			// Exponential backoff up to 30s
			probeInterval = probeInterval * 2
			if probeInterval > ZeroWinProbeMax {
				probeInterval = ZeroWinProbeMax
			}
		}
	}

	conn.Mu.Lock()
	seq := conn.SendSeq
	ack := conn.RecvAck
	conn.Mu.Unlock()
	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagACK,
		Protocol: protocol.ProtoStream,
		Src:      d.Addr(),
		Dst:      conn.RemoteAddr,
		SrcPort:  conn.LocalPort,
		DstPort:  conn.RemotePort,
		Seq:      seq,
		Ack:      ack,
		Window:   conn.RecvWindow(),
		Payload:  data,
	}

	if err := d.tunnels.Send(conn.RemoteAddr.Node, pkt); err != nil {
		return err
	}
	conn.Mu.Lock()
	conn.SendSeq += uint32(len(data))
	conn.LastActivity = time.Now()
	conn.Stats.BytesSent += uint64(len(data))
	conn.Stats.SegsSent++
	conn.Mu.Unlock()
	conn.TrackSend(seq, data)

	// Cancel delayed ACK — this data packet piggybacks the ACK
	conn.AckMu.Lock()
	if conn.ACKTimer != nil {
		conn.ACKTimer.Stop()
		conn.ACKTimer = nil
	}
	conn.PendingACKs = 0
	conn.AckMu.Unlock()

	return nil
}

// startRetxLoop starts the retransmission goroutine for a connection.
func (d *Daemon) startRetxLoop(conn *Connection) {
	conn.RTO = InitialRTO
	conn.RetxStop = make(chan struct{})
	conn.RetxSend = func(pkt *protocol.Packet) {
		d.tunnels.Send(conn.RemoteAddr.Node, pkt)
	}
	go d.retxLoop(conn)
}

func (d *Daemon) retxLoop(conn *Connection) {
	ticker := time.NewTicker(RetxCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-conn.RetxStop:
			return
		case <-ticker.C:
			conn.Mu.Lock()
			st := conn.State
			conn.Mu.Unlock()
			if st == StateEstablished {
				d.retransmitUnacked(conn)
			} else if st == StateClosed {
				// Connection abandoned (max retransmit) — clean up immediately
				conn.CloseRecvBuf()
				d.ports.RemoveConnection(conn.ID)
				return
			} else {
				// TIME_WAIT or other non-active state — stop retransmitting
				// Cleanup is handled by idleSweepLoop
				return
			}
		}
	}
}

func (d *Daemon) retransmitUnacked(conn *Connection) {
	conn.RetxMu.Lock()
	defer conn.RetxMu.Unlock()

	if len(conn.Unacked) == 0 {
		return
	}

	now := time.Now()

	// Only retransmit one segment per RTO period (like real TCP).
	if !conn.LastRetxTime.IsZero() && now.Sub(conn.LastRetxTime) < conn.RTO {
		return
	}

	// Find the first non-SACKed unacked segment that has timed out
	for _, e := range conn.Unacked {
		if e.sacked {
			continue
		}
		if now.Sub(e.sentAt) > conn.RTO {
			if e.attempts >= MaxRetxAttempts {
				// Too many retransmissions — abandon connection
				slog.Error("max retransmits exceeded, sending RST", "conn_id", conn.ID)
				// Send RST to notify the remote peer
				rst := &protocol.Packet{
					Version:  protocol.Version,
					Flags:    protocol.FlagRST,
					Protocol: protocol.ProtoStream,
					Src:      conn.LocalAddr,
					Dst:      conn.RemoteAddr,
					SrcPort:  conn.LocalPort,
					DstPort:  conn.RemotePort,
				}
				if conn.RetxSend != nil {
					conn.RetxSend(rst)
				}
				conn.Mu.Lock()
				conn.State = StateClosed
				conn.Mu.Unlock()
				return
			}

			conn.Mu.Lock()
			sendSeq := conn.SendSeq
			conn.Mu.Unlock()

			isNewLossEvent := !conn.InRecovery
			if isNewLossEvent {
				// New loss event: reduce window, enter recovery
				conn.SSThresh = conn.CongWin / 2
				if conn.SSThresh < MaxSegmentSize {
					conn.SSThresh = MaxSegmentSize
				}
				conn.CongWin = InitialCongWin
				conn.InRecovery = true
				conn.RecoveryPoint = sendSeq

				// Double RTO for first timeout in this loss event
				conn.RTO = conn.RTO * 2
				if conn.RTO > 10*time.Second {
					conn.RTO = 10 * time.Second
				}
			}
			// During recovery, retransmit without further RTO doubling

			e.attempts++
			e.sentAt = now
			conn.Mu.Lock()
			conn.Stats.Retransmits++
			conn.Mu.Unlock()
			conn.LastRetxTime = now

			conn.Mu.Lock()
			recvAck := conn.RecvAck
			conn.Mu.Unlock()
			pkt := &protocol.Packet{
				Version:  protocol.Version,
				Flags:    protocol.FlagACK,
				Protocol: protocol.ProtoStream,
				Src:      d.Addr(),
				Dst:      conn.RemoteAddr,
				SrcPort:  conn.LocalPort,
				DstPort:  conn.RemotePort,
				Seq:      e.seq,
				Ack:      recvAck,
				Window:   conn.RecvWindow(),
				Payload:  e.data,
			}
			if conn.RetxSend != nil {
				conn.RetxSend(pkt)
			}
			return // only retransmit ONE segment per RTO
		}
		break // segments are ordered by time; if first hasn't timed out, none have
	}
}

// CloseConnection sends FIN and enters TIME_WAIT.
func (d *Daemon) CloseConnection(conn *Connection) {
	conn.Mu.Lock()
	st := conn.State
	sendSeq := conn.SendSeq
	conn.Mu.Unlock()
	if st == StateEstablished {
		fin := &protocol.Packet{
			Version:  protocol.Version,
			Flags:    protocol.FlagFIN,
			Protocol: protocol.ProtoStream,
			Src:      d.Addr(),
			Dst:      conn.RemoteAddr,
			SrcPort:  conn.LocalPort,
			DstPort:  conn.RemotePort,
			Seq:      sendSeq,
		}
		d.tunnels.Send(conn.RemoteAddr.Node, fin)
	}
	conn.CloseRecvBuf()
	conn.Mu.Lock()
	conn.State = StateTimeWait
	conn.LastActivity = time.Now() // start TIME_WAIT timer
	conn.Mu.Unlock()
	// Connection will be reaped by idleSweepLoop after TimeWaitDuration
}

// SendDatagram sends an unreliable packet.
// If the destination is a broadcast address, sends to all members of that network.
func (d *Daemon) SendDatagram(dstAddr protocol.Addr, dstPort uint16, data []byte) error {
	srcPort := d.ports.AllocEphemeralPort()

	if dstAddr.IsBroadcast() {
		return fmt.Errorf("broadcast is not available — custom networks are WIP")
	}

	if err := d.ensureTunnel(dstAddr.Node); err != nil {
		return err
	}

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoDatagram,
		Src:      d.Addr(),
		Dst:      dstAddr,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Payload:  data,
	}

	return d.tunnels.Send(dstAddr.Node, pkt)
}

// broadcastDatagram sends a datagram to all members of a network.
func (d *Daemon) broadcastDatagram(netID uint16, srcPort, dstPort uint16, data []byte) error {
	resp, err := d.regConn.ListNodes(netID)
	if err != nil {
		return fmt.Errorf("list nodes for broadcast: %w", err)
	}

	nodesRaw, ok := resp["nodes"].([]interface{})
	if !ok {
		return nil // no nodes
	}

	for _, n := range nodesRaw {
		nodeMap, ok := n.(map[string]interface{})
		if !ok {
			continue
		}
		nidVal, ok := nodeMap["node_id"].(float64)
		if !ok {
			continue
		}
		nodeID := uint32(nidVal)
		if nodeID == d.NodeID() {
			continue // skip self
		}

		if err := d.ensureTunnel(nodeID); err != nil {
			slog.Warn("broadcast: skip node", "node_id", nodeID, "error", err)
			continue
		}

		pkt := &protocol.Packet{
			Version:  protocol.Version,
			Protocol: protocol.ProtoDatagram,
			Src:      d.Addr(),
			Dst:      protocol.Addr{Network: netID, Node: nodeID},
			SrcPort:  srcPort,
			DstPort:  dstPort,
			Payload:  data,
		}
		d.tunnels.Send(nodeID, pkt)
	}
	return nil
}

// ensureTunnel makes sure we have a route to the given node.
// Requests beacon hole-punching for NAT traversal when beacon is configured.
func (d *Daemon) ensureTunnel(nodeID uint32) error {
	if d.tunnels.HasPeer(nodeID) {
		return nil
	}

	// Resolve the node's real address from registry (requires our node ID)
	resp, err := d.regConn.Resolve(nodeID, d.NodeID())
	if err != nil {
		return fmt.Errorf("resolve node %d: %w", nodeID, err)
	}

	realAddr, ok := resp["real_addr"].(string)
	if !ok || realAddr == "" {
		return fmt.Errorf("node %d has no real address", nodeID)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", realAddr)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", realAddr, err)
	}

	// Request beacon-coordinated NAT hole-punching (cheap, one UDP packet).
	// Works for Full Cone, Restricted Cone, and Port-Restricted Cone NAT.
	// For Symmetric NAT, hole-punching fails but relay fallback kicks in during DialConnection.
	if d.config.BeaconAddr != "" {
		d.tunnels.RequestHolePunch(nodeID)
	}

	d.tunnels.AddPeer(nodeID, udpAddr)
	return nil
}

func (d *Daemon) heartbeatLoop() {
	ticker := time.NewTicker(d.config.keepaliveInterval())
	defer ticker.Stop()
	consecutiveFailures := 0
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			if d.regConn != nil {
				_, err := d.regConn.Heartbeat(d.NodeID())
				if err != nil {
					consecutiveFailures++
					slog.Warn("heartbeat failed", "consecutive_failures", consecutiveFailures, "error", err)

					// After 3 failures, try to re-register (the auto-reconnect in
					// the registry client will re-establish the TCP connection, but
					// after a registry restart we need to re-register our node)
					if consecutiveFailures >= HeartbeatReregThresh {
						slog.Info("attempting re-registration")
						d.reRegister()
						consecutiveFailures = 0
					}
				} else {
					if consecutiveFailures > 0 {
						slog.Info("heartbeat recovered", "previous_failures", consecutiveFailures)
					}
					consecutiveFailures = 0

					// Re-register with beacon (keeps NAT mapping alive)
					if d.config.BeaconAddr != "" {
						d.tunnels.RegisterWithBeacon()
					}

					// Poll for relayed handshake requests
					d.pollRelayedHandshakes()
				}
			}
		}
	}
}

// reRegister re-registers with the registry after a connection loss or registry restart.
func (d *Daemon) reRegister() {
	var registrationAddr string
	if d.config.Endpoint != "" {
		registrationAddr = d.config.Endpoint
	} else {
		registrationAddr = resolveLocalAddr(d.config.ListenAddr)
		if d.tunnels.LocalAddr() != nil {
			registrationAddr = resolveLocalAddr(d.tunnels.LocalAddr().String())
		}
	}

	// Always re-register with client-generated key
	pubKeyB64 := crypto.EncodePublicKey(d.identity.PublicKey)
	resp, err := d.regConn.RegisterWithKey(registrationAddr, pubKeyB64, d.config.Owner)
	if err != nil {
		slog.Error("re-registration failed", "error", err)
		return
	}

	nodeIDVal, ok := resp["node_id"].(float64)
	if !ok {
		slog.Error("re-registration: missing node_id in response")
		return
	}
	newNodeID := uint32(nodeIDVal)
	addrStr, ok := resp["address"].(string)
	if !ok {
		slog.Error("re-registration: missing address in response")
		return
	}
	newAddr, err := protocol.ParseAddr(addrStr)
	if err != nil {
		slog.Error("re-registration: invalid address", "address", addrStr, "error", err)
		return
	}

	d.addrMu.Lock()
	if newNodeID != d.nodeID {
		slog.Warn("re-registered with new node ID", "new_node_id", newNodeID, "old_node_id", d.nodeID)
		d.nodeID = newNodeID
		d.addr = newAddr
		d.tunnels.SetNodeID(d.nodeID)
	}
	nodeID := d.nodeID
	slog.Info("re-registered", "node_id", nodeID, "addr", d.addr)
	d.addrMu.Unlock()
	d.webhook.Emit("node.reregistered", map[string]interface{}{
		"address": d.addr.String(),
	})

	// Restore visibility and hostname after re-registration
	if d.config.Public {
		if _, err := d.regConn.SetVisibility(nodeID, true); err != nil {
			slog.Warn("re-registration: failed to restore visibility", "error", err)
		}
	}
	if d.config.Hostname != "" {
		if _, err := d.regConn.SetHostname(nodeID, d.config.Hostname); err != nil {
			slog.Warn("re-registration: failed to restore hostname", "error", err)
		}
	}

	// Re-sync local trust pairs to registry (trust survives disconnection locally
	// but the registry may have lost and re-loaded state)
	if d.handshakes != nil {
		peers := d.handshakes.TrustedPeers()
		for _, rec := range peers {
			if _, err := d.regConn.ReportTrust(nodeID, rec.NodeID); err != nil {
				slog.Debug("re-registration: failed to re-sync trust pair", "peer", rec.NodeID, "error", err)
			}
		}
		if len(peers) > 0 {
			slog.Info("re-synced trust pairs", "count", len(peers))
		}
	}

	// Re-register with beacon for NAT traversal
	if d.config.BeaconAddr != "" {
		d.tunnels.RegisterWithBeacon()
	}
}

// idleSweepLoop periodically sends keepalive probes and closes dead connections.
func (d *Daemon) idleSweepLoop() {
	ticker := time.NewTicker(DefaultIdleSweepInterval)
	defer ticker.Stop()
	idleTimeout := d.config.idleTimeout()
	keepaliveInterval := d.config.keepaliveInterval()
	timeWaitDur := d.config.timeWaitDuration()
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			// Clean up stale non-established connections (CLOSED, FIN_WAIT, etc.)
			stale := d.ports.StaleConnections(timeWaitDur)
			for _, conn := range stale {
				conn.CloseRecvBuf()
				d.ports.RemoveConnection(conn.ID)
			}

			// Close connections idle beyond timeout
			dead := d.ports.IdleConnections(idleTimeout)
			for _, conn := range dead {
				slog.Debug("closing dead connection", "conn_id", conn.ID, "idle_timeout", idleTimeout, "remote_addr", conn.RemoteAddr, "remote_port", conn.RemotePort)
				d.webhook.Emit("conn.idle_timeout", map[string]interface{}{
					"remote_addr": conn.RemoteAddr.String(), "remote_port": conn.RemotePort,
					"local_port": conn.LocalPort, "conn_id": conn.ID,
				})
				d.CloseConnection(conn)
			}

			// Reap stale per-source SYN rate limit buckets
			d.reapPerSrcSYN()

			// Send keepalive probes to connections idle beyond keepalive interval
			idle := d.ports.IdleConnections(keepaliveInterval)
			for _, conn := range idle {
				conn.Mu.Lock()
				st := conn.State
				sendSeq := conn.SendSeq
				recvAck := conn.RecvAck
				conn.Mu.Unlock()
				if st != StateEstablished {
					continue
				}
				probe := &protocol.Packet{
					Version:  protocol.Version,
					Flags:    protocol.FlagACK,
					Protocol: protocol.ProtoStream,
					Src:      d.Addr(),
					Dst:      conn.RemoteAddr,
					SrcPort:  conn.LocalPort,
					DstPort:  conn.RemotePort,
					Seq:      sendSeq,
					Ack:      recvAck,
				}
				d.tunnels.Send(conn.RemoteAddr.Node, probe)
			}
		}
	}
}

// lookupPeerPubKey fetches a peer's Ed25519 public key from the registry.
func (d *Daemon) lookupPeerPubKey(nodeID uint32) (ed25519.PublicKey, error) {
	resp, err := d.regConn.Lookup(nodeID)
	if err != nil {
		return nil, fmt.Errorf("lookup node %d: %w", nodeID, err)
	}

	pubKeyB64, ok := resp["public_key"].(string)
	if !ok || pubKeyB64 == "" {
		return nil, fmt.Errorf("node %d has no public key", nodeID)
	}

	return crypto.DecodePublicKey(pubKeyB64)
}

// pollRelayedHandshakes checks the registry for handshake requests and
// responses relayed to this node and processes them.
func (d *Daemon) pollRelayedHandshakes() {
	resp, err := d.regConn.PollHandshakes(d.NodeID())
	if err != nil {
		slog.Debug("poll handshakes failed", "error", err)
		return
	}

	// Process incoming handshake requests
	requests, _ := resp["requests"].([]interface{})
	for _, r := range requests {
		req, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		fromIDVal, ok := req["from_node_id"].(float64)
		if !ok {
			continue
		}
		fromNodeID := uint32(fromIDVal)
		justification, _ := req["justification"].(string)

		slog.Info("relayed handshake request received", "from_node_id", fromNodeID, "justification", justification)

		// Process through the handshake manager as if it were a direct request
		d.handshakes.processRelayedRequest(fromNodeID, justification)
	}

	// Process handshake responses (approvals/rejections relayed back to us)
	responses, _ := resp["responses"].([]interface{})
	for _, r := range responses {
		respMsg, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		fromIDVal, ok := respMsg["from_node_id"].(float64)
		if !ok {
			continue
		}
		fromNodeID := uint32(fromIDVal)
		accept, _ := respMsg["accept"].(bool)

		if accept {
			slog.Info("relayed handshake approval received", "from_node_id", fromNodeID)
			d.handshakes.processRelayedApproval(fromNodeID)
		} else {
			slog.Info("relayed handshake rejection received", "from_node_id", fromNodeID)
			d.handshakes.processRelayedRejection(fromNodeID)
		}
	}
}

// resolveLocalAddr replaces wildcard addresses with the appropriate loopback.
func resolveLocalAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "0.0.0.0" {
		return "127.0.0.1:" + port
	}
	if host == "::" {
		return "[::1]:" + port
	}
	return addr
}

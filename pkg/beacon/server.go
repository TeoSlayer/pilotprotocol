package beacon

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// beaconNode tracks a node's observed endpoint and when it was last seen.
type beaconNode struct {
	addr     *net.UDPAddr
	lastSeen time.Time
}

// relayJob is a pre-parsed relay packet dispatched to a worker.
type relayJob struct {
	senderID uint32
	destID   uint32
	payload  []byte // owned by the job, returned to pool after send
}

type Server struct {
	mu      sync.RWMutex
	conn    *net.UDPConn
	nodes   map[uint32]*beaconNode // node_id → observed endpoint + last-seen
	readyCh chan struct{}
	relayCh chan relayJob // buffered channel for relay workers
	pool    sync.Pool     // reusable payload buffers

	// Relay counters (atomic for lock-free worker access)
	relayForwarded atomic.Uint64 // successful relay deliveries
	relayDropped   atomic.Uint64 // queue-full drops
	relayNotFound  atomic.Uint64 // unknown destination drops
	lastDropLog    atomic.Int64  // UnixNano of last drop warning (rate limit)

	// Peer mesh (gossip)
	beaconID  uint32
	peers     []*net.UDPAddr          // peer beacon addresses
	peerNodes map[uint32]*net.UDPAddr // nodeID → peer beacon that owns it
	peerMu    sync.RWMutex
	healthOk  atomic.Bool

	registryAddr string // registry address for dynamic peer discovery

	done chan struct{} // closed on shutdown
}

const relayQueueSize = 131072 // 128K buffered relay jobs before backpressure

// maxRelayPayload caps the relay payload size. UDP itself limits datagrams to ~65KB,
// but this provides defense-in-depth against future transport changes.
const maxRelayPayload = 65535

// maxBeaconNodes caps the number of tracked nodes to prevent memory exhaustion.
const maxBeaconNodes = 100_000

// beaconNodeTTL is how long a node entry lives without a discover refresh.
// Set to 10 minutes (well above the 60s heartbeat-driven re-discover interval)
// so nodes survive brief registry outages without losing beacon registration.
const beaconNodeTTL = 10 * time.Minute

func New() *Server {
	return NewWithPeers(0, nil)
}

// NewWithPeers creates a beacon server with gossip peer support.
// beaconID uniquely identifies this beacon instance (0 = standalone).
// peers is a list of peer beacon addresses for gossip exchange.
func NewWithPeers(beaconID uint32, peers []string) *Server {
	s := &Server{
		nodes:     make(map[uint32]*beaconNode),
		readyCh:   make(chan struct{}),
		relayCh:   make(chan relayJob, relayQueueSize),
		beaconID:  beaconID,
		peerNodes: make(map[uint32]*net.UDPAddr),
		done:      make(chan struct{}),
	}
	s.pool.New = func() interface{} {
		b := make([]byte, 1500)
		return &b
	}
	s.healthOk.Store(true)

	for _, p := range peers {
		addr, err := net.ResolveUDPAddr("udp", p)
		if err != nil {
			slog.Warn("beacon: invalid peer address", "addr", p, "err", err)
			continue
		}
		s.peers = append(s.peers, addr)
	}

	return s
}

func (s *Server) ListenAndServe(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.conn = conn

	// Increase UDP receive buffer to handle bursts
	_ = conn.SetReadBuffer(4 * 1024 * 1024) // 4MB

	slog.Info("beacon listening", "addr", conn.LocalAddr(), "beacon_id", s.beaconID, "peers", len(s.peers))
	close(s.readyCh)

	// Start relay workers — two per CPU core to absorb WriteToUDP
	// syscall latency. Each worker processes relay jobs independently.
	workers := runtime.NumCPU() * 2
	if workers < 4 {
		workers = 4
	}
	for i := 0; i < workers; i++ {
		go s.relayWorker()
	}

	// Start relay stats logger (every 60s)
	go s.relayStatsLoop()

	// Start reap loop to evict stale node entries
	go s.reapLoop()

	// Start gossip loop (always — peers may be added dynamically via registry)
	go s.gossipLoop()

	// Start registry-based peer discovery if configured
	if s.registryAddr != "" {
		go s.registryDiscoveryLoop()
	}

	buf := make([]byte, 65535)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				return nil
			}
			slog.Debug("beacon read error", "err", err)
			continue
		}
		if n < 1 {
			continue
		}

		s.handlePacket(buf[:n], remote)
	}
}

// Ready returns a channel that is closed when the server has bound its port.
func (s *Server) Ready() <-chan struct{} {
	return s.readyCh
}

// Addr returns the server's bound address. Only valid after Ready() fires.
func (s *Server) Addr() net.Addr {
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

func (s *Server) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *Server) handlePacket(data []byte, remote *net.UDPAddr) {
	msgType := data[0]

	switch msgType {
	case protocol.BeaconMsgDiscover:
		s.handleDiscover(data[1:], remote)
	case protocol.BeaconMsgPunchRequest:
		s.handlePunchRequest(data[1:], remote)
	case protocol.BeaconMsgRelay:
		s.dispatchRelay(data[1:])
	case protocol.BeaconMsgSync:
		s.handleSync(data[1:], remote)
	default:
		slog.Debug("unknown beacon message type", "type", fmt.Sprintf("0x%02X", msgType), "from", remote)
	}
}

func (s *Server) handleDiscover(data []byte, remote *net.UDPAddr) {
	if len(data) < 4 {
		return
	}

	nodeID := binary.BigEndian.Uint32(data[0:4])

	// Record this node's observed public endpoint
	now := time.Now()
	s.mu.Lock()
	if existing, ok := s.nodes[nodeID]; ok {
		existing.addr = remote
		existing.lastSeen = now
	} else if len(s.nodes) < maxBeaconNodes {
		s.nodes[nodeID] = &beaconNode{addr: remote, lastSeen: now}
	} else {
		s.mu.Unlock()
		return // at capacity — drop silently
	}
	s.mu.Unlock()

	slog.Debug("beacon discover", "node_id", nodeID, "addr", remote)

	// Reply with observed IP:port using variable-length IP encoding
	ip := remote.IP.To4()
	if ip == nil {
		ip = remote.IP.To16()
	}
	if ip == nil {
		slog.Warn("beacon: cannot encode IP", "node_id", nodeID, "addr", remote)
		return
	}

	// Format: [type(1)][iplen(1)][IP(4 or 16)][port(2)]
	reply := make([]byte, 1+1+len(ip)+2)
	reply[0] = protocol.BeaconMsgDiscoverReply
	reply[1] = byte(len(ip))
	copy(reply[2:2+len(ip)], ip)
	binary.BigEndian.PutUint16(reply[2+len(ip):], uint16(remote.Port))

	if _, err := s.conn.WriteToUDP(reply, remote); err != nil {
		slog.Debug("beacon discover reply failed", "node_id", nodeID, "err", err)
	}
}

func (s *Server) handlePunchRequest(data []byte, remote *net.UDPAddr) {
	if len(data) < 8 {
		return
	}

	requesterID := binary.BigEndian.Uint32(data[0:4])
	targetID := binary.BigEndian.Uint32(data[4:8])

	// Update requester's endpoint (handles symmetric NAT port changes)
	now := time.Now()
	s.mu.Lock()
	if existing, ok := s.nodes[requesterID]; ok {
		existing.addr = remote
		existing.lastSeen = now
	} else if len(s.nodes) < maxBeaconNodes {
		s.nodes[requesterID] = &beaconNode{addr: remote, lastSeen: now}
	}
	s.mu.Unlock()

	s.mu.RLock()
	targetNode := s.nodes[targetID]
	requesterNode := s.nodes[requesterID]
	s.mu.RUnlock()

	if targetNode == nil {
		slog.Warn("punch target not found", "target_id", targetID)
		return
	}
	if requesterNode == nil {
		slog.Warn("punch requester not found", "requester_id", requesterID)
		return
	}

	targetAddr := targetNode.addr
	requesterAddr := requesterNode.addr

	// Send punch commands to both sides
	if err := s.SendPunchCommand(requesterID, targetAddr.IP, uint16(targetAddr.Port)); err != nil {
		slog.Debug("punch command to requester failed", "node_id", requesterID, "err", err)
	}
	if err := s.SendPunchCommand(targetID, requesterAddr.IP, uint16(requesterAddr.Port)); err != nil {
		slog.Debug("punch command to target failed", "node_id", targetID, "err", err)
	}
	slog.Debug("punch coordinated", "requester", requesterID, "target", targetID,
		"requester_addr", requesterAddr, "target_addr", targetAddr)
}

// dispatchRelay parses the relay header and dispatches to a worker goroutine.
// The read loop stays fast — no locks, no syscalls, no allocations on the hot path.
func (s *Server) dispatchRelay(data []byte) {
	if len(data) < 8 {
		return
	}

	senderID := binary.BigEndian.Uint32(data[0:4])
	destID := binary.BigEndian.Uint32(data[4:8])

	// Copy payload into a pooled buffer so we don't hold the read buffer
	payload := data[8:]
	if len(payload) > maxRelayPayload {
		return // oversized relay payload — drop silently
	}
	bp := s.pool.Get().(*[]byte)
	buf := *bp
	if cap(buf) < len(payload) {
		buf = make([]byte, len(payload))
	} else {
		buf = buf[:len(payload)]
	}
	copy(buf, payload)

	select {
	case s.relayCh <- relayJob{senderID: senderID, destID: destID, payload: buf}:
	default:
		// Queue full — drop packet (UDP is best-effort)
		s.relayDropped.Add(1)
		now := time.Now().UnixNano()
		if last := s.lastDropLog.Load(); now-last > int64(time.Second) {
			if s.lastDropLog.CompareAndSwap(last, now) {
				slog.Warn("relay queue full, dropping packet", "sender", senderID, "dest", destID)
			}
		}
		*bp = buf[:cap(buf)]
		s.pool.Put(bp)
	}
}

// relayWorker processes relay jobs: dest lookup and UDP send.
// Multiple workers run in parallel to distribute the WriteToUDP syscalls.
// 3-tier destination lookup:
//  1. Local nodes map → send MsgRelayDeliver directly to agent
//  2. Peer nodes map → forward original MsgRelay to peer beacon
//  3. Neither → drop (unknown dest)
func (s *Server) relayWorker() {
	sendBuf := make([]byte, 1500) // per-worker send buffer, no allocations
	for job := range s.relayCh {
		// Tier 1: local node lookup
		s.mu.RLock()
		destNode, ok := s.nodes[job.destID]
		var destAddr *net.UDPAddr
		if ok {
			destAddr = destNode.addr
		}
		s.mu.RUnlock()

		if ok {
			// Build relay deliver message in pre-allocated send buffer
			msgLen := 1 + 4 + len(job.payload)
			if cap(sendBuf) < msgLen {
				sendBuf = make([]byte, msgLen)
			}
			msg := sendBuf[:msgLen]
			msg[0] = protocol.BeaconMsgRelayDeliver
			binary.BigEndian.PutUint32(msg[1:5], job.senderID)
			copy(msg[5:], job.payload)

			if _, err := s.conn.WriteToUDP(msg, destAddr); err != nil {
				slog.Warn("beacon relay send failed", "dest_node_id", job.destID, "err", err)
			} else {
				s.relayForwarded.Add(1)
			}
			s.returnPayload(job.payload)
			continue
		}

		// Tier 2: peer beacon lookup
		s.peerMu.RLock()
		peerAddr, peerOk := s.peerNodes[job.destID]
		s.peerMu.RUnlock()

		if peerOk {
			// Forward the original MsgRelay to the peer beacon
			fwdLen := 1 + 4 + 4 + len(job.payload)
			if cap(sendBuf) < fwdLen {
				sendBuf = make([]byte, fwdLen)
			}
			fwd := sendBuf[:fwdLen]
			fwd[0] = protocol.BeaconMsgRelay
			binary.BigEndian.PutUint32(fwd[1:5], job.senderID)
			binary.BigEndian.PutUint32(fwd[5:9], job.destID)
			copy(fwd[9:], job.payload)

			if _, err := s.conn.WriteToUDP(fwd, peerAddr); err != nil {
				slog.Warn("beacon relay forward to peer failed", "dest_node_id", job.destID, "peer", peerAddr, "err", err)
			} else {
				s.relayForwarded.Add(1)
			}
			s.returnPayload(job.payload)
			continue
		}

		// Tier 3: unknown destination
		s.relayNotFound.Add(1)
		slog.Warn("relay dest not found", "dest_node_id", job.destID, "sender_node_id", job.senderID)
		s.returnPayload(job.payload)
	}
}

func (s *Server) returnPayload(buf []byte) {
	buf = buf[:cap(buf)]
	s.pool.Put(&buf)
}

// relayStatsLoop logs relay counters every 60 seconds.
func (s *Server) relayStatsLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			fwd := s.relayForwarded.Load()
			drop := s.relayDropped.Load()
			nf := s.relayNotFound.Load()
			if fwd > 0 || drop > 0 || nf > 0 {
				slog.Info("relay stats", "forwarded", fwd, "dropped", drop, "not_found", nf)
			}
		}
	}
}

// SendPunchCommand tells a node to send UDP to a target endpoint.
func (s *Server) SendPunchCommand(nodeID uint32, targetIP net.IP, targetPort uint16) error {
	s.mu.RLock()
	node, ok := s.nodes[nodeID]
	var nodeAddr *net.UDPAddr
	if ok {
		nodeAddr = node.addr
	}
	s.mu.RUnlock()

	if !ok {
		return fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	ip := targetIP.To4()
	if ip == nil {
		ip = targetIP.To16()
	}
	if ip == nil {
		return fmt.Errorf("cannot encode target IP")
	}

	// Format: [type(1)][iplen(1)][IP(4 or 16)][port(2)]
	msg := make([]byte, 1+1+len(ip)+2)
	msg[0] = protocol.BeaconMsgPunchCommand
	msg[1] = byte(len(ip))
	copy(msg[2:2+len(ip)], ip)
	binary.BigEndian.PutUint16(msg[2+len(ip):], targetPort)

	_, err := s.conn.WriteToUDP(msg, nodeAddr)
	return err
}

// --- Reap ---

// reapLoop periodically removes stale node entries that haven't sent a
// discover message within beaconNodeTTL. Prevents dead nodes from
// accumulating indefinitely.
func (s *Server) reapLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.reapStaleNodes()
		case <-s.done:
			return
		}
	}
}

func (s *Server) reapStaleNodes() {
	threshold := time.Now().Add(-beaconNodeTTL)
	s.mu.Lock()
	for id, node := range s.nodes {
		if node.lastSeen.Before(threshold) {
			delete(s.nodes, id)
		}
	}
	s.mu.Unlock()
}

// --- Gossip ---

// gossipLoop periodically sends the local node list to all peer beacons.
// Format: [0x07][beaconID(4)][nodeCount(2)][nodeID(4)]...[nodeID(4)]
func (s *Server) gossipLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.sendGossip()
		case <-s.done:
			return
		}
	}
}

func (s *Server) sendGossip() {
	s.mu.RLock()
	nodeIDs := make([]uint32, 0, len(s.nodes))
	for id := range s.nodes {
		nodeIDs = append(nodeIDs, id)
	}
	s.mu.RUnlock()

	if len(nodeIDs) > 65535 {
		nodeIDs = nodeIDs[:65535] // cap at uint16 max
	}

	// Build sync message: [type(1)][beaconID(4)][nodeCount(2)][nodeID(4)...]
	msgLen := 1 + 4 + 2 + 4*len(nodeIDs)
	msg := make([]byte, msgLen)
	msg[0] = protocol.BeaconMsgSync
	binary.BigEndian.PutUint32(msg[1:5], s.beaconID)
	binary.BigEndian.PutUint16(msg[5:7], uint16(len(nodeIDs)))
	for i, id := range nodeIDs {
		binary.BigEndian.PutUint32(msg[7+4*i:7+4*i+4], id)
	}

	s.peerMu.RLock()
	peers := make([]*net.UDPAddr, len(s.peers))
	copy(peers, s.peers)
	s.peerMu.RUnlock()

	for _, peer := range peers {
		if _, err := s.conn.WriteToUDP(msg, peer); err != nil {
			slog.Debug("gossip send failed", "peer", peer, "err", err)
		}
	}

	slog.Debug("gossip sent", "beacon_id", s.beaconID, "nodes", len(nodeIDs), "peers", len(peers))
}

// handleSync processes an incoming gossip sync message from a peer beacon.
func (s *Server) handleSync(data []byte, remote *net.UDPAddr) {
	// Need at least beaconID(4) + nodeCount(2)
	if len(data) < 6 {
		return
	}

	peerBeaconID := binary.BigEndian.Uint32(data[0:4])
	nodeCount := binary.BigEndian.Uint16(data[4:6])

	// Validate message length
	expected := 6 + 4*int(nodeCount)
	if len(data) < expected {
		slog.Debug("gossip sync message too short", "peer_beacon_id", peerBeaconID, "expected", expected, "got", len(data))
		return
	}

	// Parse node IDs
	nodeIDs := make([]uint32, nodeCount)
	for i := 0; i < int(nodeCount); i++ {
		nodeIDs[i] = binary.BigEndian.Uint32(data[6+4*i : 6+4*i+4])
	}

	// Update peer node map: clear old entries for this peer, add new ones
	s.peerMu.Lock()
	// Remove all entries pointing to this peer
	for id, addr := range s.peerNodes {
		if addr.IP.Equal(remote.IP) && addr.Port == remote.Port {
			delete(s.peerNodes, id)
		}
	}
	// Add new entries (skip nodes we own locally)
	s.mu.RLock()
	for _, id := range nodeIDs {
		if _, local := s.nodes[id]; !local {
			s.peerNodes[id] = remote
		}
	}
	s.mu.RUnlock()
	s.peerMu.Unlock()

	slog.Debug("gossip sync received", "peer_beacon_id", peerBeaconID, "nodes", nodeCount, "from", remote)
}

// --- Registry-based peer discovery ---

// SetRegistry sets the registry address for dynamic peer discovery.
// The beacon will periodically register itself and discover peers via the registry.
func (s *Server) SetRegistry(addr string) {
	s.registryAddr = addr
}

// registryDiscoveryLoop registers this beacon with the registry and discovers
// peers every 30 seconds. Requires the beacon to be listening (conn bound).
func (s *Server) registryDiscoveryLoop() {
	// Wait until we have a bound address
	<-s.readyCh

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Run immediately, then on tick
	s.registryDiscover()
	for {
		select {
		case <-ticker.C:
			s.registryDiscover()
		case <-s.done:
			return
		}
	}
}

func (s *Server) registryDiscover() {
	if s.registryAddr == "" || s.beaconID == 0 {
		return
	}

	conn, err := net.DialTimeout("tcp", s.registryAddr, 5*time.Second)
	if err != nil {
		slog.Debug("beacon registry connect failed", "addr", s.registryAddr, "err", err)
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Registry uses 4-byte big-endian length-prefix framing
	sendMsg := func(msg map[string]interface{}) error {
		body, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
		if _, err := conn.Write(lenBuf[:]); err != nil {
			return err
		}
		_, err = conn.Write(body)
		return err
	}
	recvMsg := func() (map[string]interface{}, error) {
		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return nil, err
		}
		length := binary.BigEndian.Uint32(lenBuf[:])
		if length > 1<<20 {
			return nil, fmt.Errorf("message too large: %d", length)
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, err
		}
		var resp map[string]interface{}
		return resp, json.Unmarshal(body, &resp)
	}

	// Register this beacon with our listen address
	listenAddr := s.conn.LocalAddr().String()
	// Resolve wildcard to actual IP for peers to reach us
	host, port, _ := net.SplitHostPort(listenAddr)
	if host == "::" || host == "0.0.0.0" || host == "" {
		// Use the outbound IP (the IP used to reach the registry)
		if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			host = tcpAddr.IP.String()
		}
	}
	myAddr := net.JoinHostPort(host, port)

	if err := sendMsg(map[string]interface{}{
		"type":      "beacon_register",
		"beacon_id": s.beaconID,
		"addr":      myAddr,
	}); err != nil {
		slog.Debug("beacon register send failed", "err", err)
		return
	}

	if _, err := recvMsg(); err != nil {
		slog.Debug("beacon register response failed", "err", err)
		return
	}

	// List all beacons
	if err := sendMsg(map[string]interface{}{
		"type": "beacon_list",
	}); err != nil {
		slog.Debug("beacon list send failed", "err", err)
		return
	}

	listResp, err := recvMsg()
	if err != nil {
		slog.Debug("beacon list response failed", "err", err)
		return
	}

	beacons, _ := listResp["beacons"].([]interface{})
	var newPeers []*net.UDPAddr
	for _, b := range beacons {
		bm, ok := b.(map[string]interface{})
		if !ok {
			continue
		}
		bid := uint32(0)
		if v, ok := bm["id"].(float64); ok {
			bid = uint32(v)
		}
		baddr, _ := bm["addr"].(string)
		if bid == s.beaconID || baddr == "" {
			continue // skip self
		}
		udpAddr, err := net.ResolveUDPAddr("udp", baddr)
		if err != nil {
			slog.Debug("beacon peer resolve failed", "addr", baddr, "err", err)
			continue
		}
		newPeers = append(newPeers, udpAddr)
	}

	// Update peers atomically
	s.peerMu.Lock()
	s.peers = newPeers
	s.peerMu.Unlock()

	slog.Info("beacon registry discovery", "beacon_id", s.beaconID, "my_addr", myAddr, "peers", len(newPeers))
}

// --- Health ---

// ServeHealth starts a simple HTTP server with a /healthz endpoint for load balancer health checks.
func (s *Server) ServeHealth(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if s.healthOk.Load() {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "ok")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, "unhealthy")
		}
	})
	slog.Info("health endpoint listening", "addr", addr)
	return http.ListenAndServe(addr, mux)
}

// SetHealthy sets the health status (for graceful drain on scale-down).
func (s *Server) SetHealthy(ok bool) {
	s.healthOk.Store(ok)
}

// PeerNodeCount returns the number of nodes known via gossip from peer beacons.
func (s *Server) PeerNodeCount() int {
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	return len(s.peerNodes)
}

// LocalNodeCount returns the number of locally registered nodes.
func (s *Server) LocalNodeCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.nodes)
}

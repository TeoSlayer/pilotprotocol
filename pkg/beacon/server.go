package beacon

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"sync"

	"web4/pkg/protocol"
)

// relayJob is a pre-parsed relay packet dispatched to a worker.
type relayJob struct {
	senderID uint32
	destID   uint32
	payload  []byte // owned by the job, returned to pool after send
}

type Server struct {
	mu      sync.RWMutex
	conn    *net.UDPConn
	nodes   map[uint32]*net.UDPAddr // node_id → observed public endpoint
	readyCh chan struct{}
	relayCh chan relayJob // buffered channel for relay workers
	pool    sync.Pool     // reusable payload buffers
}

const relayQueueSize = 4096 // buffered relay jobs before backpressure

func New() *Server {
	s := &Server{
		nodes:   make(map[uint32]*net.UDPAddr),
		readyCh: make(chan struct{}),
		relayCh: make(chan relayJob, relayQueueSize),
	}
	s.pool.New = func() interface{} {
		b := make([]byte, 1500)
		return &b
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

	slog.Info("beacon listening", "addr", conn.LocalAddr())
	close(s.readyCh)

	// Start relay workers — one per CPU core, each processes relay
	// jobs independently: lookup dest + WriteToUDP in parallel.
	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}
	for i := 0; i < workers; i++ {
		go s.relayWorker()
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
	s.mu.Lock()
	s.nodes[nodeID] = remote
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
	s.mu.Lock()
	s.nodes[requesterID] = remote
	s.mu.Unlock()

	s.mu.RLock()
	targetAddr := s.nodes[targetID]
	requesterAddr := s.nodes[requesterID]
	s.mu.RUnlock()

	if targetAddr == nil {
		slog.Warn("punch target not found", "target_id", targetID)
		return
	}

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
		*bp = buf[:cap(buf)]
		s.pool.Put(bp)
	}
}

// relayWorker processes relay jobs: dest lookup and UDP send.
// Multiple workers run in parallel to distribute the WriteToUDP syscalls.
// Sender endpoint is NOT updated here — discover/punch already handle it.
// This keeps the relay path entirely read-only (no write lock contention).
func (s *Server) relayWorker() {
	sendBuf := make([]byte, 1500) // per-worker send buffer, no allocations
	for job := range s.relayCh {
		// Lookup dest (read lock — all workers can do this concurrently)
		s.mu.RLock()
		destAddr, ok := s.nodes[job.destID]
		s.mu.RUnlock()

		if !ok {
			slog.Debug("relay dest not found", "dest_node_id", job.destID, "sender_node_id", job.senderID)
			s.returnPayload(job.payload)
			continue
		}

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
			slog.Debug("beacon relay send failed", "dest_node_id", job.destID, "err", err)
		}

		s.returnPayload(job.payload)
	}
}

func (s *Server) returnPayload(buf []byte) {
	buf = buf[:cap(buf)]
	s.pool.Put(&buf)
}

// SendPunchCommand tells a node to send UDP to a target endpoint.
func (s *Server) SendPunchCommand(nodeID uint32, targetIP net.IP, targetPort uint16) error {
	s.mu.RLock()
	nodeAddr, ok := s.nodes[nodeID]
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

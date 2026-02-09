package beacon

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"web4/pkg/protocol"
)

type Server struct {
	mu      sync.RWMutex
	conn    *net.UDPConn
	nodes   map[uint32]*net.UDPAddr // node_id → observed public endpoint
	readyCh chan struct{}
}

func New() *Server {
	return &Server{
		nodes:   make(map[uint32]*net.UDPAddr),
		readyCh: make(chan struct{}),
	}
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
	slog.Info("beacon listening", "addr", conn.LocalAddr())
	close(s.readyCh)

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
		s.handleRelay(data[1:], remote)
	default:
		slog.Warn("unknown beacon message type", "type", fmt.Sprintf("0x%02X", msgType), "from", remote)
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

	slog.Info("beacon discover", "node_id", nodeID, "addr", remote)

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
	slog.Info("punch coordinated", "requester", requesterID, "target", targetID,
		"requester_addr", requesterAddr, "target_addr", targetAddr)
}

func (s *Server) handleRelay(data []byte, remote *net.UDPAddr) {
	// Format: [senderNodeID(4)][destNodeID(4)][payload...]
	if len(data) < 8 {
		return
	}

	senderNodeID := binary.BigEndian.Uint32(data[0:4])
	destNodeID := binary.BigEndian.Uint32(data[4:8])
	payload := data[8:]

	// Update sender's endpoint (handles symmetric NAT port changes)
	s.mu.Lock()
	s.nodes[senderNodeID] = remote
	s.mu.Unlock()

	s.mu.RLock()
	destAddr, ok := s.nodes[destNodeID]
	s.mu.RUnlock()

	if !ok {
		slog.Warn("relay dest not found", "dest_node_id", destNodeID, "sender_node_id", senderNodeID)
		return
	}

	slog.Info("relaying", "from", senderNodeID, "to", destNodeID, "dest_addr", destAddr, "payload_len", len(payload))

	// Build relay deliver message
	msg := make([]byte, 1+4+len(payload))
	msg[0] = protocol.BeaconMsgRelayDeliver
	binary.BigEndian.PutUint32(msg[1:5], senderNodeID)
	copy(msg[5:], payload)

	if _, err := s.conn.WriteToUDP(msg, destAddr); err != nil {
		slog.Warn("beacon relay send failed", "dest_node_id", destNodeID, "err", err)
	}
}

// SendPunchCommand tells a node to send UDP to a target endpoint.
func (s *Server) SendPunchCommand(nodeID uint32, targetIP net.IP, targetPort uint16) error {
	s.mu.RLock()
	nodeAddr, ok := s.nodes[nodeID]
	s.mu.RUnlock()

	if !ok {
		return fmt.Errorf("node %d not found", nodeID)
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

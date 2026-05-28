// SPDX-License-Identifier: AGPL-3.0-or-later

package routing

import (
	"encoding/binary"
	"log/slog"
	"net"

	"github.com/pilot-protocol/common/protocol"
)

// RegisterWithBeacon sends a MsgDiscover to the beacon from the tunnel
// socket using our nodeID, so the beacon knows our endpoint for punch
// coordination. Returns nil if no beacon is configured.
func (m *Manager) RegisterWithBeacon() error {
	m.mu.RLock()
	bAddr := m.beaconAddr
	sock := m.sock
	m.mu.RUnlock()
	if bAddr == nil || sock == nil {
		return nil
	}
	msg := make([]byte, 5)
	msg[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(msg[1:5], m.localNodeID())
	_, err := sock.Send(msg, bAddr)
	return err
}

// RequestHolePunch asks the beacon to coordinate NAT hole-punching with
// a target peer. Returns nil if no beacon is configured.
func (m *Manager) RequestHolePunch(targetNodeID uint32) error {
	m.mu.RLock()
	bAddr := m.beaconAddr
	sock := m.sock
	m.mu.RUnlock()
	if bAddr == nil || sock == nil {
		return nil
	}
	// Format: [MsgPunchRequest(1)][ourNodeID(4)][targetNodeID(4)]
	msg := make([]byte, 9)
	msg[0] = protocol.BeaconMsgPunchRequest
	binary.BigEndian.PutUint32(msg[1:5], m.localNodeID())
	binary.BigEndian.PutUint32(msg[5:9], targetNodeID)
	_, err := sock.Send(msg, bAddr)
	return err
}

// HandlePunchCommand processes a beacon punch command, sending punch
// packets to the specified target to create a NAT mapping.
//
// Format: [iplen(1)][IP(4 or 16)][port(2)]
func (m *Manager) HandlePunchCommand(data []byte) {
	if len(data) < 1 {
		return
	}
	ipLen := int(data[0])
	if ipLen != 4 && ipLen != 16 {
		return
	}
	if len(data) < 1+ipLen+2 {
		return
	}
	ip := net.IP(make([]byte, ipLen))
	copy(ip, data[1:1+ipLen])
	port := binary.BigEndian.Uint16(data[1+ipLen:])
	addr := &net.UDPAddr{IP: ip, Port: int(port)}

	m.mu.RLock()
	sock := m.sock
	m.mu.RUnlock()
	if sock == nil {
		return
	}

	// Send punch packets to create NAT mapping (multiple for reliability).
	punch := make([]byte, 4)
	copy(punch, protocol.TunnelMagicPunch[:])
	for i := 0; i < 3; i++ {
		_, _ = sock.Send(punch, addr)
	}
	slog.Info("NAT punch sent", "target", addr)
}

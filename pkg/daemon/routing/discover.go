// SPDX-License-Identifier: AGPL-3.0-or-later

package routing

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// DiscoverEndpoint sends a STUN-style discover to the beacon over the
// supplied UDP socket and returns the public endpoint the beacon
// observed for us. Synchronous: blocks until reply or timeout.
//
// This is the cold-start STUN path; it runs BEFORE the long-lived
// readLoop is wired up so the same conn that will later host tunnel
// traffic is reused without contention. Callers must close the
// returned conn (or hand it off to udpio.WrapConn) once registration
// is complete.
//
// Format on the wire matches the existing pre-extraction shape:
//
//	tx: [BeaconMsgDiscover(1)][nodeID(4)]
//	rx: [BeaconMsgDiscoverReply(1)][iplen(1)][IP(4 or 16)][port(2)]
func DiscoverEndpoint(beaconAddr string, nodeID uint32, conn *net.UDPConn, readDeadline time.Time) (*net.UDPAddr, error) {
	bAddr, err := net.ResolveUDPAddr("udp", beaconAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve beacon: %w", err)
	}

	// Send discover message.
	msg := make([]byte, 5)
	msg[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(msg[1:5], nodeID)

	if _, err := conn.WriteToUDP(msg, bAddr); err != nil {
		return nil, fmt.Errorf("send discover: %w", err)
	}

	// Read reply with the supplied deadline.
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(readDeadline)
	n, _, err := conn.ReadFromUDP(buf)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, fmt.Errorf("discover reply: %w", err)
	}

	if n < 4 || buf[0] != protocol.BeaconMsgDiscoverReply {
		return nil, fmt.Errorf("invalid discover reply")
	}
	ipLen := int(buf[1])
	if ipLen != 4 && ipLen != 16 {
		return nil, fmt.Errorf("invalid discover reply: bad IP length %d", ipLen)
	}
	if n < 2+ipLen+2 {
		return nil, fmt.Errorf("invalid discover reply: too short")
	}

	ip := net.IP(make([]byte, ipLen))
	copy(ip, buf[2:2+ipLen])
	port := binary.BigEndian.Uint16(buf[2+ipLen : 2+ipLen+2])

	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

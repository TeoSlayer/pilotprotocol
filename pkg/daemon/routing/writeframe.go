// SPDX-License-Identifier: AGPL-3.0-or-later

package routing

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// WriteFrame ships a raw UDP frame to a peer. Routes through the beacon
// (relay-wrapped MsgRelay) if the peer is in relay mode; otherwise sends
// direct to addr.
//
// Side effects:
//   - May flip the peer to relay mode if the blackhole heuristic trips.
//   - Updates lastOutboundSend on success.
//   - Bumps the caller's PktsSent / BytesSent atomics via counters.
//   - Records ICMP-unreachable errors and may flip to relay on threshold.
//
// Returns the underlying UDP error (or ErrNoAddress if neither a relay
// path nor a direct addr is available). The caller logs flips and
// records auxiliary errors.
func (m *Manager) WriteFrame(nodeID uint32, addr *net.UDPAddr, frame []byte, counters CounterTarget) (SendOutcome, error) {
	// Direct-blackhole detection with hysteresis.
	shouldRelay, flipped, silentFor, misses := m.MaybeFlipBlackhole(nodeID)
	_ = flipped
	_ = silentFor
	_ = misses

	// Compat-mode daemons have no usable direct UDP path — the only
	// way for an outbound packet to reach a peer is wrapped in
	// BeaconMsgRelay so the beacon's relayWorker can route it (over
	// UDP if the peer is a regular UDP node, over WSS if the peer
	// is itself in compat mode).
	if m.forceRelay.Load() {
		shouldRelay = true
	}

	m.mu.RLock()
	bAddr := m.beaconAddr
	sock := m.sock
	m.mu.RUnlock()

	if shouldRelay && bAddr != nil {
		// MsgRelay: [0x05][senderNodeID(4)][destNodeID(4)][frame...]
		msg := make([]byte, 1+4+4+len(frame))
		msg[0] = protocol.BeaconMsgRelay
		binary.BigEndian.PutUint32(msg[1:5], m.localNodeID())
		binary.BigEndian.PutUint32(msg[5:9], nodeID)
		copy(msg[9:], frame)

		if sock == nil {
			return SendOutcome{}, fmt.Errorf("routing: socket not set")
		}
		n, err := sock.Send(msg, bAddr)
		if err == nil {
			counters.recordSend(n)
			m.RecordOutboundSend(nodeID, time.Now())
			return SendOutcome{BytesSent: n, WasRelay: true}, nil
		}
		// HandleSendError tracks ICMP-unreachable counters.
		_, _ = m.HandleSendError(nodeID, err)
		return SendOutcome{WasRelay: true}, err
	}

	if addr == nil {
		return SendOutcome{}, fmt.Errorf("%w: node %d", ErrNoAddress, nodeID)
	}
	if sock == nil {
		return SendOutcome{}, fmt.Errorf("routing: socket not set")
	}
	n, err := sock.Send(frame, addr)
	if err == nil {
		counters.recordSend(n)
		m.RecordOutboundSend(nodeID, time.Now())
		return SendOutcome{BytesSent: n, WasRelay: false}, nil
	}
	_, _ = m.HandleSendError(nodeID, err)
	return SendOutcome{}, err
}

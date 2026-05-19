// SPDX-License-Identifier: AGPL-3.0-or-later

// Package routing is L4 — peer discovery & routing.
//
// The Manager owns:
//   - relayPeers map[uint32]bool — peers that need relay (symmetric NAT)
//   - relayPinned map[uint32]bool — peers whose relay flag is authoritative
//   - blackholeMissCount map[uint32]int — consecutive miss observations
//   - directClearCount map[uint32]int — consecutive direct receipts
//   - sendErrCount map[uint32]int — consecutive ICMP-unreachable errors
//   - lastDirectRecv map[uint32]time.Time — last direct-path receipt
//   - lastOutboundSend map[uint32]time.Time — last successful send
//   - firstOutboundSend map[uint32]time.Time — first ever send (blackhole baseline)
//   - beaconAddr — the picked beacon for relay/punch
//
// Per docs/architecture/01-LAYERS.md L4:
//
//	Role: given a nodeID, return a reachable UDP endpoint (or relay path);
//	  coordinate NAT traversal.
//	Owns: relayPeers map, relayPinned map, blackholeMissCount map,
//	  lastDirectRecv, beacon list, beacon-cache file.
//	Consumes: L1, L2; reads identity from L3 (FNV-32 hash on Ed25519
//	  pubkey for stable beacon pick).
//	Exposes: Resolve(nodeID) → endpoint, RouteFrame(dst, frame),
//	  PunchTo(peer).
//
// Per docs/architecture/03-INVARIANTS.md §3 (lock graph): the Manager's
// mu is a LEAF lock — never held while taking any TunnelManager mutex.
// All callers obey this by reading state under mu, releasing, then
// mutating tm-side state in a separate critical section.
package routing

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MaxRelayPeers caps the relayPeers map. The beacon relays packets to us
// with a caller-supplied srcNodeID, so without a bound an attacker can
// grow relayPeers indefinitely. Real networks never approach this cap.
const MaxRelayPeers = 4096

// DirectBlackholeThreshold is how long a peer can go without a direct
// recv before WriteFrame auto-flips to relay. Tuned for force_relay_*
// integration tests which sleep 10s after partitioning UDP between peers.
const DirectBlackholeThreshold = 8 * time.Second

// BlackholeMissesRequired is the number of consecutive WriteFrame
// observations of "direct path silent for >threshold" needed before
// the tunnel flips to relay.
const BlackholeMissesRequired = 3

// DirectClearsRequired is the symmetric hysteresis on the relay→direct
// auto-clear path.
const DirectClearsRequired = 3

// SendErrThreshold is the number of consecutive ICMP-unreachable errors
// from a single peer required before HandleSendError flips them to relay.
const SendErrThreshold = 3

// ErrNoAddress is returned by WriteFrame when no UDP address is available
// for a peer (neither a stored direct addr nor a beacon for relay).
var ErrNoAddress = errors.New("routing: no address for peer")

// SendOutcome describes the outcome of a WriteFrame call. The caller
// (TunnelManager) uses this to maintain its own atomics (PktsSent,
// BytesSent) without the Manager owning those counters.
type SendOutcome struct {
	BytesSent int  // bytes written on the wire
	WasRelay  bool // true if frame was wrapped + sent to beacon
}

// SocketSender is the L2 hook the Manager uses to ship a UDP datagram.
// Concrete implementations: udpio.Socket.Send.
type SocketSender interface {
	Send(frame []byte, dst *net.UDPAddr) (int, error)
}

// LocalNodeIDFn returns our own node ID. Plumbed in from the daemon
// (atomic load over tm.nodeID).
type LocalNodeIDFn func() uint32

// Manager owns the L4 routing state.
type Manager struct {
	sock SocketSender

	mu sync.RWMutex

	// beaconAddr is the picked beacon's UDP endpoint. Used for relay
	// wrapping, NAT punch coordination, and STUN registration.
	beaconAddr *net.UDPAddr

	// relayPeers marks peers that need to be reached via the beacon
	// (symmetric NAT, dead direct path, ICMP-unreachable threshold tripped).
	relayPeers map[uint32]bool

	// relayPinned marks peers whose relay flag was set by an authoritative
	// signal. ClearRelayOnDirect is a no-op for pinned peers.
	relayPinned map[uint32]bool

	// lastDirectRecv tracks when each peer was last heard from on a
	// direct (non-beacon) UDP path. Used by WriteFrame to flip an
	// established connection into relay mode when the direct path goes
	// silent.
	lastDirectRecv map[uint32]time.Time

	// blackholeMissCount counts consecutive WriteFrame observations of
	// "lastDirectRecv stale" per peer. The flip to relay only fires
	// once the count reaches BlackholeMissesRequired.
	blackholeMissCount map[uint32]int

	// directClearCount is the symmetric counter for the relay→direct
	// auto-clear path.
	directClearCount map[uint32]int

	// sendErrCount counts consecutive ICMP-unreachable errors returned
	// by WriteFrame to a given peer.
	sendErrCount map[uint32]int

	// lastOutboundSend tracks when we last successfully sent a frame
	// to each peer. Used by NAT-keepalive logic.
	lastOutboundSend map[uint32]time.Time

	// firstOutboundSend tracks when we FIRST sent to each peer. Unlike
	// lastOutboundSend it is never updated after the initial write.
	// Used by MaybeFlipBlackhole as the blackhole-detection baseline
	// for brand-new peers that have no lastDirectRecv entry yet.
	firstOutboundSend map[uint32]time.Time

	// localNodeIDFn supplies our own node ID for relay-wrapping headers.
	localNodeIDFn LocalNodeIDFn

	// forceRelay, when true, makes WriteFrame always wrap outbound
	// frames in BeaconMsgRelay regardless of blackhole heuristics or
	// pinning. Set by TunnelManager.ConnectCompat for compat-mode
	// daemons whose only path to peers is the beacon's WSS bridge.
	// Without this, fresh peers receive raw L2 frames through the WSS
	// pipe; the beacon's handlePacket sees no BeaconMsg prefix and
	// drops them silently — outbound-initiated handshakes never
	// complete and the daemon looks dead from the peer's side.
	forceRelay atomic.Bool
}

// SetForceRelay toggles the every-send-must-be-relayed flag. Called
// by TunnelManager.ConnectCompat. Idempotent.
func (m *Manager) SetForceRelay(v bool) {
	m.forceRelay.Store(v)
}

// ForceRelay reports the current forceRelay flag. Exposed for tests
// and the dashboard.
func (m *Manager) ForceRelay() bool {
	return m.forceRelay.Load()
}

// New returns a fresh Manager with empty state. The Socket may be nil
// initially and set later via SetSocket once the L2 listener is bound.
func New() *Manager {
	return &Manager{
		relayPeers:         make(map[uint32]bool),
		relayPinned:        make(map[uint32]bool),
		lastDirectRecv:     make(map[uint32]time.Time),
		blackholeMissCount: make(map[uint32]int),
		directClearCount:   make(map[uint32]int),
		sendErrCount:       make(map[uint32]int),
		lastOutboundSend:   make(map[uint32]time.Time),
		firstOutboundSend:  make(map[uint32]time.Time),
	}
}

// SetSocket wires the L2 socket. Called by TunnelManager.Listen once
// the UDP listener is bound.
func (m *Manager) SetSocket(s SocketSender) {
	m.mu.Lock()
	m.sock = s
	m.mu.Unlock()
}

// SetLocalNodeIDFn supplies the closure used to read our own node ID.
func (m *Manager) SetLocalNodeIDFn(f LocalNodeIDFn) {
	m.mu.Lock()
	m.localNodeIDFn = f
	m.mu.Unlock()
}

// SetBeaconAddr resolves and stores the beacon address.
func (m *Manager) SetBeaconAddr(addr string) error {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.beaconAddr = a
	m.mu.Unlock()
	return nil
}

// SetBeaconAddrUDP stores an already-resolved beacon address. Used by
// tests that construct a fake beacon on a test loopback port.
func (m *Manager) SetBeaconAddrUDP(a *net.UDPAddr) {
	m.mu.Lock()
	m.beaconAddr = a
	m.mu.Unlock()
}

// BeaconAddr returns the currently-set beacon UDP endpoint (or nil).
func (m *Manager) BeaconAddr() *net.UDPAddr {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.beaconAddr
}

// IsFromBeacon reports whether `from` matches the configured beacon's
// IP and port. Cheap helper used by the caller's address-learning paths
// to avoid pinning a peer to the beacon's listen port.
func (m *Manager) IsFromBeacon(from *net.UDPAddr) bool {
	if from == nil {
		return false
	}
	m.mu.RLock()
	b := m.beaconAddr
	m.mu.RUnlock()
	if b == nil {
		return false
	}
	return from.IP.Equal(b.IP) && from.Port == b.Port
}

func (m *Manager) localNodeID() uint32 {
	m.mu.RLock()
	fn := m.localNodeIDFn
	m.mu.RUnlock()
	if fn == nil {
		return 0
	}
	return fn()
}

// Atomic counter handles. The Manager itself does NOT track packet/byte
// stats — TunnelManager owns the public PktsSent/BytesSent atomics for
// API compatibility. These accessors are exposed only for tests that
// want to assert no-op behavior.

// CounterTarget is supplied by TunnelManager so WriteFrame can bump the
// public PktsSent / BytesSent atomics on every successful transmit.
type CounterTarget struct {
	PktsSent  *uint64
	BytesSent *uint64
}

var counterPlaceholderPkts uint64
var counterPlaceholderBytes uint64

func (t CounterTarget) recordSend(bytes int) {
	if t.PktsSent != nil {
		atomic.AddUint64(t.PktsSent, 1)
	}
	if t.BytesSent != nil {
		atomic.AddUint64(t.BytesSent, uint64(bytes))
	}
}

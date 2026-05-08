// SPDX-License-Identifier: AGPL-3.0-or-later

// Package keyexchange is L5 — establishes the per-peer AEAD session
// key (with optional Ed25519 authentication of identity).
//
// The Manager owns:
//   - pendingRekey map[uint32]*PendingRekeyState — tracks key
//     exchanges we sent and are awaiting a reply on. Drives the
//     retransmit loop.
//   - peerPubKeys map[uint32]ed25519.PublicKey — cached peer Ed25519
//     pubkeys (filled from the verifyFunc callback).
//   - lastInboundDecrypt map[uint32]time.Time — used by the
//     handleAuthKeyExchange "stale reply" gate.
//   - the rekey retransmit goroutine (Loop).
//
// It owns the L5 Store — the per-peer Crypto registry. L6 (envelope)
// imports Store to look up keys when wrapping/unwrapping AEAD frames.
//
// Per docs/architecture/01-LAYERS.md L5:
//
//	Role: establish the per-peer AEAD session key (with optional
//	  Ed25519 authentication of identity).
//	Owns: pendingRekey, peerPubKeys cache, the rekeyRetransmitLoop
//	  goroutine, AND (post T5.x-followup) the per-peer Crypto Store +
//	  replay window + salvage ring + decryptFailCount.
//	Consumes: L1, L2 (sends bootstrap frames; first auth-key-exchange
//	  is the only frame that bypasses L6 envelope), L3 (signs/verifies),
//	  L4 (routes the frame).
//	Exposes: Establish(peer) → SessionKey, RekeyTrigger(peer),
//	  key-install events.
//
// Per docs/architecture/03-INVARIANTS.md §3 (lock graph): rkPendingMu
// is a LEAF lock — never held while taking any TunnelManager mutex.
// All callers obey this by reading state under rkPendingMu, releasing,
// then mutating tm-side state in a separate critical section.
//
// Per docs/architecture/03-INVARIANTS.md §9 (horizontal-incest): L6 →
// L5 is the canonical downward import. keyexchange/ MUST NOT import
// envelope/ — that would be upward and contradict 01-LAYERS.md §"Layer
// dependencies".
package keyexchange

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"net"
	"sync"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// Tunable timing constants. Frozen wire-adjacent behavior — changing
// these affects observable retransmit cadence + stale-reply gating.
const (
	// RekeyRetransmitInterval is how long we wait for an inbound encrypted
	// packet to confirm the peer received our key_exchange. After this we
	// retransmit on the assumption either our key_exchange or the peer's
	// reply was dropped.
	RekeyRetransmitInterval = 4 * time.Second

	// MaxRekeyAttempts caps the retransmit loop. The first send + this
	// many retries = 1 + MaxRekeyAttempts total attempts. After that we
	// give up — peer is presumed gone.
	MaxRekeyAttempts = 5

	// KeyExchangeReplyStaleThreshold: when an auth_key_exchange arrives
	// and we already have crypto for the peer with no inbound traffic in
	// this window, reply with our key_exchange too (in case our previous
	// reply was dropped). Loosens handleAuthKeyExchange's "send back" gate.
	KeyExchangeReplyStaleThreshold = 6 * time.Second
)

// PendingRekeyState tracks a key-exchange we sent and are waiting on.
// Cleared when handleEncrypted records a successful decrypt from peer
// (proof their crypto matches ours). The retransmit loop bumps
// LastSentAt and Attempts on each retry; gives up after MaxRekeyAttempts
// to avoid hammering a peer that's just gone.
type PendingRekeyState struct {
	FirstSentAt time.Time
	LastSentAt  time.Time
	Attempts    int
}

// FrameSender is L2's contribution to L5: ship a raw UDP frame to a
// peer (relay-aware). tunnel.go satisfies this with writeFrame.
//
// When sub-pass 4 extracts L2, this becomes an L2 interface; for now
// the daemon supplies a closure capturing tm.writeFrame.
type FrameSender func(peerNodeID uint32, addr *net.UDPAddr, frame []byte) error

// PeerAddrLookup returns the currently-known UDP address for peerNodeID.
// Used by sendKeyExchangeToNode to find the destination. tunnel.go
// satisfies this with a closure reading tm.peers under tm.mu.
type PeerAddrLookup func(peerNodeID uint32) *net.UDPAddr

// VerifyFunc fetches the canonical Ed25519 public key for nodeID
// (typically from the registry).
type VerifyFunc func(nodeID uint32) (ed25519.PublicKey, error)

// EventPublisher is the daemon's event-bus surface; nil-safe.
// Provided by tunnel.go via a closure over tm.publishEvent.
type EventPublisher func(topic string, payload map[string]any)

// PostInstallHook is invoked AFTER a successful HandleAuthFrame /
// HandleUnauthFrame installs (or refreshes) a Crypto. Carries enough
// context for the daemon to do peer-endpoint bookkeeping, salvage
// replay, flushPending, etc. Implemented in tunnel.go.
type PostInstallHook func(ev PostInstallEvent)

// PostInstallEvent describes a freshly-installed Crypto.
type PostInstallEvent struct {
	PeerNodeID    uint32
	From          *net.UDPAddr
	FromRelay     bool
	Authenticated bool
	HadCrypto     bool      // true if an entry existed before
	KeyChanged    bool      // true if the peer's X25519 ephemeral key actually changed
	OldCrypto     *Crypto
	NewCrypto     *Crypto
	PeerEd25519   ed25519.PublicKey // non-nil for auth path
}

// Manager owns the L5 state.
type Manager struct {
	env *Store

	// Local identity material — populated by SetIdentity/SetPeerVerifyFunc.
	idMu       sync.RWMutex
	identity   *crypto.Identity
	verifyFunc VerifyFunc

	// X25519 keypair for ECDH. Set via SetX25519Keys.
	keyMu   sync.RWMutex
	privKey *ecdh.PrivateKey
	pubKey  []byte

	// localNodeID is our own node ID; written into outbound key-exchange
	// frames and the auth challenge.
	localNodeIDFn func() uint32

	// peerPubKeys caches Ed25519 keys fetched via verifyFunc.
	pubKeysMu   sync.RWMutex
	peerPubKeys map[uint32]ed25519.PublicKey

	// rkPendingMu is the LEAF lock guarding pendingRekey +
	// lastInboundDecrypt. NEVER held while taking any TunnelManager
	// mutex (per 03-INVARIANTS.md §3).
	rkPendingMu        sync.Mutex
	pendingRekey       map[uint32]*PendingRekeyState
	lastInboundDecrypt map[uint32]time.Time

	// Side-effect hooks plumbed in from the daemon.
	sender      FrameSender
	addrLookup  PeerAddrLookup
	publisher   EventPublisher
	postInstall PostInstallHook
}

// New returns a fresh Manager. The Manager installs into store; pass
// store=nil to have New construct one. The same Store pointer is
// imported by L6 (envelope) for AEAD encrypt/decrypt operations.
func New(store *Store) *Manager {
	if store == nil {
		store = NewStore()
	}
	return &Manager{
		env:                store,
		peerPubKeys:        make(map[uint32]ed25519.PublicKey),
		pendingRekey:       make(map[uint32]*PendingRekeyState),
		lastInboundDecrypt: make(map[uint32]time.Time),
	}
}

// Store returns the per-peer Crypto registry owned by this Manager.
// L6 (envelope) imports it to wrap/unwrap AEAD frames; L7 (tunnel)
// imports it for membership probes (Has/IsReady) and bookkeeping
// (Install/Drop) on rekey paths.
func (m *Manager) Store() *Store { return m.env }

// SetSender wires L2's frame-send hook.
func (m *Manager) SetSender(s FrameSender) { m.sender = s }

// SetAddrLookup wires the peer-address resolver.
func (m *Manager) SetAddrLookup(f PeerAddrLookup) { m.addrLookup = f }

// SetPublisher wires the daemon's event bus (nil-safe).
func (m *Manager) SetPublisher(p EventPublisher) { m.publisher = p }

// SetPostInstallHook wires the post-install daemon callback (peer
// endpoint bookkeeping, salvage replay, etc.).
func (m *Manager) SetPostInstallHook(h PostInstallHook) { m.postInstall = h }

// SetLocalNodeIDFn supplies the closure used to read our own node ID
// (atomic read living in the daemon).
func (m *Manager) SetLocalNodeIDFn(f func() uint32) { m.localNodeIDFn = f }

// SetIdentity sets our Ed25519 identity for signing authenticated key
// exchanges. May be called concurrently with HandleAuthFrame / Send.
func (m *Manager) SetIdentity(id *crypto.Identity) {
	m.idMu.Lock()
	m.identity = id
	m.idMu.Unlock()
}

// Identity returns the currently-set identity (or nil).
func (m *Manager) Identity() *crypto.Identity {
	m.idMu.RLock()
	defer m.idMu.RUnlock()
	return m.identity
}

// HasIdentity is a fast path used to gate auth/unauth frame selection.
func (m *Manager) HasIdentity() bool {
	m.idMu.RLock()
	defer m.idMu.RUnlock()
	return m.identity != nil
}

// SetPeerVerifyFunc sets the callback used to fetch a peer's Ed25519
// public key from the registry on cache miss.
func (m *Manager) SetPeerVerifyFunc(f VerifyFunc) {
	m.idMu.Lock()
	m.verifyFunc = f
	m.idMu.Unlock()
}

// SetX25519Keys installs our X25519 keypair (used for ECDH on inbound
// key-exchange frames and for the pubkey slot in outbound frames).
func (m *Manager) SetX25519Keys(priv *ecdh.PrivateKey, pub []byte) {
	m.keyMu.Lock()
	m.privKey = priv
	m.pubKey = pub
	m.keyMu.Unlock()
}

// PubKey returns the local X25519 public key (32 bytes). May be nil
// if SetX25519Keys was never called.
func (m *Manager) PubKey() []byte {
	m.keyMu.RLock()
	defer m.keyMu.RUnlock()
	return m.pubKey
}

// PrivKey returns the local X25519 private key.
func (m *Manager) PrivKey() *ecdh.PrivateKey {
	m.keyMu.RLock()
	defer m.keyMu.RUnlock()
	return m.privKey
}

// localNodeID is a nil-safe wrapper.
func (m *Manager) localNodeID() uint32 {
	if m.localNodeIDFn == nil {
		return 0
	}
	return m.localNodeIDFn()
}

// publish is a nil-safe event publish.
func (m *Manager) publish(topic string, payload map[string]any) {
	if m.publisher != nil {
		m.publisher(topic, payload)
	}
}

// GetPeerPubKey returns the cached Ed25519 public key for a peer,
// fetching from the registry (via verifyFunc) on cache miss.
func (m *Manager) GetPeerPubKey(nodeID uint32) (ed25519.PublicKey, error) {
	m.pubKeysMu.RLock()
	if pk, ok := m.peerPubKeys[nodeID]; ok {
		m.pubKeysMu.RUnlock()
		return pk, nil
	}
	m.pubKeysMu.RUnlock()

	m.idMu.RLock()
	fn := m.verifyFunc
	m.idMu.RUnlock()
	if fn == nil {
		return nil, errNoVerify
	}

	pk, err := fn(nodeID)
	if err != nil {
		return nil, err
	}
	m.pubKeysMu.Lock()
	m.peerPubKeys[nodeID] = pk
	m.pubKeysMu.Unlock()
	return pk, nil
}

// SetPeerPubKey installs a cache entry directly. Used by handle paths
// after verifying a packet-carried Ed25519 pubkey against the registry.
func (m *Manager) SetPeerPubKey(nodeID uint32, pk ed25519.PublicKey) {
	m.pubKeysMu.Lock()
	m.peerPubKeys[nodeID] = pk
	m.pubKeysMu.Unlock()
}

// InvalidatePeerPubKey deletes a cache entry.
func (m *Manager) InvalidatePeerPubKey(nodeID uint32) {
	m.pubKeysMu.Lock()
	delete(m.peerPubKeys, nodeID)
	m.pubKeysMu.Unlock()
}

// HasPeerPubKey reports whether the cache currently holds an entry for nodeID.
func (m *Manager) HasPeerPubKey(nodeID uint32) bool {
	m.pubKeysMu.RLock()
	defer m.pubKeysMu.RUnlock()
	_, ok := m.peerPubKeys[nodeID]
	return ok
}

// MarkPendingRekey records that we sent a key_exchange to peerNodeID
// and are awaiting confirmation. Idempotent — re-calls bump LastSentAt
// and Attempts but preserve FirstSentAt.
func (m *Manager) MarkPendingRekey(peerNodeID uint32) {
	now := time.Now()
	m.rkPendingMu.Lock()
	st, ok := m.pendingRekey[peerNodeID]
	if !ok {
		st = &PendingRekeyState{FirstSentAt: now}
		m.pendingRekey[peerNodeID] = st
	}
	st.LastSentAt = now
	st.Attempts++
	m.rkPendingMu.Unlock()
}

// ClearPendingRekey is called after a successful decrypt from peer —
// proves peer has matching crypto, so any in-flight key_exchange is
// no longer pending.
func (m *Manager) ClearPendingRekey(peerNodeID uint32) {
	m.rkPendingMu.Lock()
	delete(m.pendingRekey, peerNodeID)
	m.rkPendingMu.Unlock()
}

// PendingRekeyAttempts returns the current attempts count (0 if not pending).
func (m *Manager) PendingRekeyAttempts(peerNodeID uint32) int {
	m.rkPendingMu.Lock()
	defer m.rkPendingMu.Unlock()
	if st, ok := m.pendingRekey[peerNodeID]; ok {
		return st.Attempts
	}
	return 0
}

// PendingRekeyHas reports whether an entry exists.
func (m *Manager) PendingRekeyHas(peerNodeID uint32) bool {
	m.rkPendingMu.Lock()
	defer m.rkPendingMu.Unlock()
	_, ok := m.pendingRekey[peerNodeID]
	return ok
}

// PendingRekeyForTest returns the live PendingRekeyState pointer (or nil)
// for a peer. Exposed so package-internal tests can inspect the
// FirstSentAt / LastSentAt timestamps without re-deriving them via the
// public counters. Acquires rkPendingMu briefly; safe for concurrent use.
func (m *Manager) PendingRekeyForTest(peerNodeID uint32) *PendingRekeyState {
	m.rkPendingMu.Lock()
	defer m.rkPendingMu.Unlock()
	return m.pendingRekey[peerNodeID]
}

// InjectPendingRekeyForTest sets a state directly. Test-only; production
// code never bypasses MarkPendingRekey.
func (m *Manager) InjectPendingRekeyForTest(peerNodeID uint32, st *PendingRekeyState) {
	m.rkPendingMu.Lock()
	if st == nil {
		delete(m.pendingRekey, peerNodeID)
	} else {
		m.pendingRekey[peerNodeID] = st
	}
	m.rkPendingMu.Unlock()
}

// RecordInboundDecrypt updates the per-peer last-decrypt timestamp.
func (m *Manager) RecordInboundDecrypt(peerNodeID uint32) {
	m.rkPendingMu.Lock()
	m.lastInboundDecrypt[peerNodeID] = time.Now()
	m.rkPendingMu.Unlock()
}

// SetLastInboundDecryptForTest writes a timestamp directly.
func (m *Manager) SetLastInboundDecryptForTest(peerNodeID uint32, t time.Time) {
	m.rkPendingMu.Lock()
	m.lastInboundDecrypt[peerNodeID] = t
	m.rkPendingMu.Unlock()
}

// LastInboundDecryptHas reports whether we've recorded any successful
// decrypt timestamp for the peer.
func (m *Manager) LastInboundDecryptHas(peerNodeID uint32) bool {
	m.rkPendingMu.Lock()
	defer m.rkPendingMu.Unlock()
	_, ok := m.lastInboundDecrypt[peerNodeID]
	return ok
}

// InboundDecryptStale returns true if we haven't successfully
// decrypted any packet from peerNodeID within the staleness window.
func (m *Manager) InboundDecryptStale(peerNodeID uint32) bool {
	m.rkPendingMu.Lock()
	t, ok := m.lastInboundDecrypt[peerNodeID]
	m.rkPendingMu.Unlock()
	if !ok {
		return true
	}
	return time.Since(t) > KeyExchangeReplyStaleThreshold
}

// RemovePeer wipes per-peer L5 state (called from TunnelManager.RemovePeer).
func (m *Manager) RemovePeer(nodeID uint32) {
	m.pubKeysMu.Lock()
	delete(m.peerPubKeys, nodeID)
	m.pubKeysMu.Unlock()

	m.rkPendingMu.Lock()
	delete(m.pendingRekey, nodeID)
	delete(m.lastInboundDecrypt, nodeID)
	m.rkPendingMu.Unlock()
}

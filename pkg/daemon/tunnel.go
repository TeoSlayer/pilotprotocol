// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/envelope"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/keyexchange"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/routing"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/udpio"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// Type aliases letting existing pkg/daemon code (tests + L5/L7) refer
// to L5-owned types by their historical names. The canonical type is
// keyexchange.Crypto / keyexchange.SalvageEntry; these aliases keep
// pre-T5.x-followup call sites mechanically compatible.
//
// Why L5: per docs/architecture/01-LAYERS.md, per-peer Crypto is owned
// by L5 (key state) and consumed by L6 (envelope) — the L6 framing
// path operates on Crypto values supplied from the L5 Store. The
// T5.x-followup invert moved Crypto + SalvageEntry + Store into
// keyexchange/ so the L6 → L5 import edge is canonical (downward).
type peerCrypto = keyexchange.Crypto
type salvageEntry = keyexchange.SalvageEntry

// LOCK ORDERING INVARIANTS — daemon side. See pkg/registry/server.go for the
// full invariants doc; the daemon-specific rules:
//
//   policyMu  >  pr.mu (per-runner) — never reverse.
//   memberTagsMu — independent; nested under nothing else.
//   tunnel:  pendMu, rkPendingMu, salvageMu — all isolated, never nested.
//   conn:    Mu, RetxMu, NagleMu, RecvMu, AckMu — five separate per-conn
//            mutexes; ordering between them is currently safe but acquiring
//            two simultaneously is a smell. ProcessAck/ProcessSACK use the
//            documented Mu → RetxMu order; do not introduce reverse paths.
//
// CORRECTNESS RULE — same as registry side:
//   No signature verify, no encoding/decoding, no network I/O while holding
//   any mutex. CPU work goes outside the lock.

// Re-export L5-owned consts under their pre-extraction names so
// existing tests and L7 references still compile. These are aliases —
// the canonical definitions live at pkg/daemon/keyexchange/crypto.go.
const (
	replayWindowSize         = keyexchange.ReplayWindowSize
	salvageMaxEntries        = keyexchange.SalvageMaxEntries
	salvageMaxAge            = keyexchange.SalvageMaxAge
	decryptFailDropThreshold = keyexchange.DecryptFailDropThreshold
	decryptFailDropGrace     = keyexchange.DecryptFailDropGrace
)

// TunnelManager manages real UDP tunnels to peer daemons.
type TunnelManager struct {
	mu sync.RWMutex
	// sock is the L2 datagram-I/O socket. Owns the *net.UDPConn FD and
	// the pool-backed read buffer. Send / Recv on tm.sock are "dumb"
	// primitives — relay wrapping, per-peer counters, and magic-byte
	// dispatch all live in this file (L4 routing). See pkg/daemon/udpio.
	sock *udpio.Socket
	// peers maps node_id → real UDP endpoint. Owned by L4 (routing).
	peers map[uint32]*net.UDPAddr
	// envelope is the L5-owned per-peer crypto Store (named "envelope"
	// for historical reasons — pre-T5.x-followup the Store lived in
	// pkg/daemon/envelope). Accessed by:
	//   - L5 key-exchange handlers (Install / Get / Drop on rekey)
	//   - L6 encrypt/decrypt path (envelope.EncryptFrame / DecryptFrame)
	//   - L4 routing for "is encrypted yet?" probe checks
	// keyexchange.Store has its own RWMutex; tm.mu does NOT cover it,
	// so envelope state can be inspected without taking the
	// routing lock (preserves the leaf-lock invariant from
	// 03-INVARIANTS.md §3).
	envelope  *keyexchange.Store
	recvCh    chan *IncomingPacket
	done      chan struct{}  // closed on Close() to stop readLoop sends
	readWg    sync.WaitGroup // tracks readLoop goroutine for clean shutdown
	closeOnce sync.Once

	// Encryption config
	encrypt bool             // if true, attempt encrypted tunnels
	privKey *ecdh.PrivateKey // our X25519 private key
	pubKey  []byte           // our X25519 public key (32 bytes)
	nodeID  uint32           // our node ID (set after registration)

	// kx is the L5 key-exchange manager. It owns:
	//   - Ed25519 identity + verifyFunc callback
	//   - peerPubKeys cache (node_id → Ed25519 pubkey)
	//   - pendingRekey + lastInboundDecrypt (rkPendingMu leaf-locked)
	//   - the rekey retransmit goroutine
	//
	// Methods on TunnelManager that L7/tests refer to (handleAuthKeyExchange,
	// handleKeyExchange, sendKeyExchangeToNode, markPendingRekey, etc.)
	// are thin shims that delegate to kx.
	kx       *keyexchange.Manager
	kxCtx    context.Context
	kxCancel context.CancelFunc

	// Pending sends waiting for key exchange to complete
	pendMu  sync.Mutex
	pending map[uint32][][]byte // node_id → queued frames

	// Rate-limit rekey-request responses triggered by "encrypted packet but no
	// key" events. Prevents amplification if a peer floods us with gibberish.
	rekeyMu      sync.Mutex
	lastRekeyReq map[uint32]time.Time

	// routing is the L4 manager. It owns:
	//   - relayPeers, relayPinned, blackholeMissCount, directClearCount,
	//     sendErrCount, lastDirectRecv, lastOutboundSend maps
	//   - beaconAddr (the picked beacon's UDP endpoint)
	//   - relay-vs-direct routing decisions (WriteFrame)
	//   - NAT punch coordination (RegisterWithBeacon, RequestHolePunch,
	//     HandlePunchCommand)
	//   - blackhole detection + ICMP-unreachable handling
	//
	// routing.Manager has its own RWMutex; tm.mu does NOT cover it, so
	// routing state can be inspected without taking any tunnel-side lock
	// (preserves the leaf-lock invariant from 03-INVARIANTS.md §3).
	routing *routing.Manager

	// Event bus — replaces inline tm.webhook.Emit calls. Set via
	// SetEventBus from daemon during construction. May be nil in
	// tests; tm.publishEvent handles that. Webhook delivery is a
	// bus subscriber — see Daemon.subscribeWebhookToBus.
	bus *inProcessBus

	// Metrics
	BytesSent   uint64
	BytesRecv   uint64
	PktsSent    uint64
	PktsRecv    uint64
	EncryptOK   uint64
	EncryptFail uint64
	// P1-008: packets dropped from the per-peer pending queue while waiting
	// for key exchange. Exposed so operators can tell a congested overlay
	// apart from a silent crypto stall.
	PendingDrops uint64
}

type IncomingPacket struct {
	Packet *protocol.Packet
	From   *net.UDPAddr
}

// maxPendingPerPeer limits how many packets can be queued per peer
// while waiting for key exchange to complete. Prevents unbounded growth
// if key exchange is slow or fails.
const maxPendingPerPeer = 64

// maxPendingPeers limits the total number of peers with pending key exchanges.
const maxPendingPeers = 256

// ErrPendingDropped is returned by sendEncryptedToNode when the per-peer
// pending queue was already at maxPendingPerPeer and the oldest queued
// packet had to be dropped to make room for the new one. The CALLER's
// packet is still queued — it will be sent as soon as key exchange
// finishes — but an older packet was lost to back-pressure.
//
// Callers that distinguish this error from a hard failure can choose to
// retry (the dial path does this; one of the SYN retransmits will land
// after the queue drains). Surfacing it as a typed error also lets
// pilotctl render a "tunnel handshaking" hint instead of an opaque
// "send SYN: pending queue full" message.
var ErrPendingDropped = errors.New("pending queue full: oldest queued packet dropped while key exchange pending")

// RecvChSize is the capacity of the incoming packet channel.
// Increased from 1024 to 8192 for 1M-node scale to prevent drops during
// bursts (e.g., many peers sending simultaneously after a cron trigger).
const RecvChSize = 8192

func NewTunnelManager() *TunnelManager {
	store := keyexchange.NewStore()
	tm := &TunnelManager{
		peers:        make(map[uint32]*net.UDPAddr),
		envelope:     store,
		pending:      make(map[uint32][][]byte),
		lastRekeyReq: make(map[uint32]time.Time),
		recvCh:       make(chan *IncomingPacket, RecvChSize),
		done:         make(chan struct{}),
		routing:      routing.New(),
	}
	tm.routing.SetLocalNodeIDFn(tm.loadNodeID)
	tm.kx = keyexchange.New(store)
	tm.kx.SetSender(tm.writeFrame)
	tm.kx.SetAddrLookup(tm.peerAddr)
	tm.kx.SetPublisher(tm.publishEvent)
	tm.kx.SetLocalNodeIDFn(tm.loadNodeID)
	tm.kx.SetPostInstallHook(tm.onKeyInstalled)
	return tm
}

// peerAddr is the L4-side hook the keyexchange manager uses to find a
// peer's UDP address before sending a key-exchange frame. Reads
// tm.peers under tm.mu.
func (tm *TunnelManager) peerAddr(peerNodeID uint32) *net.UDPAddr {
	tm.mu.RLock()
	addr := tm.peers[peerNodeID]
	tm.mu.RUnlock()
	return addr
}

// pendingRekeyState is re-exposed under its pre-extraction name for the
// few in-package tests that construct one directly. Canonical home is
// keyexchange.PendingRekeyState.
type pendingRekeyState = keyexchange.PendingRekeyState

// Re-export L5 timing constants under their pre-extraction names so
// existing test code and any same-package reference still compiles.
// Canonical definitions live at pkg/daemon/keyexchange.
const (
	rekeyRetransmitInterval        = keyexchange.RekeyRetransmitInterval
	maxRekeyAttempts               = keyexchange.MaxRekeyAttempts
	keyExchangeReplyStaleThreshold = keyexchange.KeyExchangeReplyStaleThreshold
)

// rekeyRequestInterval is the minimum interval between unsolicited key-exchange
// requests triggered by "encrypted packet but no key" events for the same peer.
// Prevents amplification if a peer streams unreadable frames at us.
const rekeyRequestInterval = 3 * time.Second

// maxRekeyRequesters caps lastRekeyReq so a peer spraying unreadable frames
// from rotated/spoofed node IDs cannot grow the map without bound. Real
// networks never approach this; the bound exists to kill the DoS vector.
const maxRekeyRequesters = 4096

// pruneRekeyBudgetLocked deletes rate-limit entries whose window has already
// elapsed (deleting them is safe — they'd be re-created on the next packet
// from that peer anyway). Returns true if the map has room for a new entry
// after pruning. Caller must hold rekeyMu.
func (tm *TunnelManager) pruneRekeyBudgetLocked(now time.Time) bool {
	if len(tm.lastRekeyReq) < maxRekeyRequesters {
		return true
	}
	for id, t := range tm.lastRekeyReq {
		if now.Sub(t) >= rekeyRequestInterval {
			delete(tm.lastRekeyReq, id)
		}
	}
	return len(tm.lastRekeyReq) < maxRekeyRequesters
}

// maybeRequestRekey conditionally sends a key-exchange to a peer that sent us
// an encrypted packet we can't decrypt. Rate-limited per peer. Returns true if
// we actually sent one.
func (tm *TunnelManager) maybeRequestRekey(peerNodeID uint32, from *net.UDPAddr) bool {
	if tm.sock == nil {
		return false
	}
	tm.rekeyMu.Lock()
	last, known := tm.lastRekeyReq[peerNodeID]
	now := time.Now()
	if known && now.Sub(last) < rekeyRequestInterval {
		tm.rekeyMu.Unlock()
		return false
	}
	if !known && !tm.pruneRekeyBudgetLocked(now) {
		tm.rekeyMu.Unlock()
		return false
	}
	tm.lastRekeyReq[peerNodeID] = now
	tm.rekeyMu.Unlock()

	// Remember the peer's UDP endpoint so sendKeyExchangeToNode can reach
	// them. If the un-decryptable packet arrived via the beacon (from ==
	// beaconAddr), mark the peer as relay-reachable so the key-exchange
	// we send back is wrapped in MsgRelay rather than sprayed at the
	// beacon's listen port (where it would be silently dropped). This is
	// how a freshly-restarted peer — with empty tunnel state — learns how
	// to re-key a peer that's still speaking to us through relay.
	tm.mu.Lock()
	if _, ok := tm.peers[peerNodeID]; !ok && from != nil {
		tm.peers[peerNodeID] = from
	}
	tm.mu.Unlock()
	if tm.routing.IsFromBeacon(from) {
		// Beacon-sourced key exchange = empirical proof relay path
		// is the working one. Pin so ClearRelayOnDirect can't
		// flap us back to direct on a stray non-beacon packet.
		tm.routing.AdmitRelayFromBeacon(peerNodeID)
	}

	tm.sendKeyExchangeToNode(peerNodeID)
	return true
}

// SetEventBus wires the daemon's pub/sub bus into the tunnel layer.
// Replaces the inline tm.webhook.Emit pattern: core layers Publish,
// observability plugins (webhook, future eventstream broker)
// Subscribe via daemonEventBus.
func (tm *TunnelManager) SetEventBus(bus *inProcessBus) {
	tm.mu.Lock()
	tm.bus = bus
	tm.mu.Unlock()
}

// publishEvent is a nil-safe wrapper for tm.bus.Publish. All
// in-tunnel publishers go through this so a nil bus (test setups
// that don't construct a Daemon) is a no-op rather than a panic.
func (tm *TunnelManager) publishEvent(topic string, payload map[string]any) {
	if tm.bus != nil {
		tm.bus.Publish(topic, payload)
	}
}

// EnableEncryption generates an X25519 keypair and enables tunnel encryption.
func (tm *TunnelManager) EnableEncryption() error {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate tunnel key: %w", err)
	}
	tm.privKey = priv
	tm.pubKey = priv.PublicKey().Bytes()
	tm.encrypt = true
	tm.kx.SetX25519Keys(priv, tm.pubKey)
	slog.Info("tunnel encryption enabled", "scheme", "X25519+AES-256-GCM")
	return nil
}

// SetNodeID sets our node ID (called after registration). Propagates
// to the envelope store so the encrypt-side AAD / frame-header use the
// same value.
func (tm *TunnelManager) SetNodeID(id uint32) {
	atomic.StoreUint32(&tm.nodeID, id)
	if tm.envelope != nil {
		tm.envelope.SetLocalNodeID(id)
	}
}

// DropCrypto removes the encryption context for a peer, forcing a fresh
// key exchange on the next encrypted send. Used by the dial-timeout
// exhausted path to recover from peer-side AEAD key divergence (older
// daemon versions can drift into a state where their derived key no
// longer matches ours despite stable X25519 pubkeys; the only recovery
// is a full re-handshake). Also clears any pending-rekey state so the
// retransmit loop doesn't immediately fire — the next dial's
// sendKeyExchangeToNode will re-arm it.
func (tm *TunnelManager) DropCrypto(peerNodeID uint32) {
	tm.envelope.Drop(peerNodeID)
	tm.kx.RemovePeer(peerNodeID)
}

// loadNodeID atomically loads our node ID.
func (tm *TunnelManager) loadNodeID() uint32 {
	return atomic.LoadUint32(&tm.nodeID)
}

// SetIdentity sets our Ed25519 identity for signing authenticated key
// exchanges. Forwards to keyexchange.Manager (L5 owner of identity).
func (tm *TunnelManager) SetIdentity(id *crypto.Identity) {
	tm.kx.SetIdentity(id)
}

// SetPeerVerifyFunc sets a callback to fetch a peer's Ed25519 public
// key from the registry. Forwards to keyexchange.Manager.
func (tm *TunnelManager) SetPeerVerifyFunc(fn func(uint32) (ed25519.PublicKey, error)) {
	tm.kx.SetPeerVerifyFunc(keyexchange.VerifyFunc(fn))
}

// SetBeaconAddr configures the beacon address for NAT hole-punching and relay.
// Thin shim over routing.Manager.SetBeaconAddr.
func (tm *TunnelManager) SetBeaconAddr(addr string) error {
	if err := tm.routing.SetBeaconAddr(addr); err != nil {
		return fmt.Errorf("resolve beacon: %w", err)
	}
	return nil
}

// SetRelayPeer marks a peer as needing relay through the beacon (symmetric NAT).
// Thin shim over routing.Manager.SetRelayPeer.
func (tm *TunnelManager) SetRelayPeer(nodeID uint32, relay bool) {
	tm.routing.SetRelayPeer(nodeID, relay)
	if relay {
		slog.Info("peer marked for relay", "node_id", nodeID)
	}
}

// IsRelayPeer returns true if the peer is in relay mode.
// Thin shim over routing.Manager.IsRelayPeer.
func (tm *TunnelManager) IsRelayPeer(nodeID uint32) bool {
	return tm.routing.IsRelayPeer(nodeID)
}

// RelayPeerIDs returns the node IDs of all relay-flagged peers.
// Thin shim over routing.Manager.RelayPeerIDs.
func (tm *TunnelManager) RelayPeerIDs() []uint32 {
	return tm.routing.RelayPeerIDs()
}

// RegisterWithBeacon sends a MsgDiscover to the beacon from the tunnel socket
// using the real nodeID, so the beacon knows our endpoint for punch coordination.
// Thin shim over routing.Manager.RegisterWithBeacon.
func (tm *TunnelManager) RegisterWithBeacon() {
	if err := tm.routing.RegisterWithBeacon(); err != nil {
		slog.Warn("beacon registration failed", "error", err)
		return
	}
	if b := tm.routing.BeaconAddr(); b != nil && tm.sock != nil {
		slog.Debug("registered with beacon", "node_id", tm.loadNodeID(), "beacon", b)
	}
}

// RequestHolePunch asks the beacon to coordinate NAT hole-punching with a target peer.
// Thin shim over routing.Manager.RequestHolePunch.
func (tm *TunnelManager) RequestHolePunch(targetNodeID uint32) {
	if err := tm.routing.RequestHolePunch(targetNodeID); err != nil {
		slog.Debug("hole punch request failed", "target", targetNodeID, "error", err)
	} else if tm.routing.BeaconAddr() != nil && tm.sock != nil {
		slog.Debug("hole punch requested", "target", targetNodeID)
	}
}

// directBlackholeThreshold is the legacy alias for routing.DirectBlackholeThreshold.
const directBlackholeThreshold = routing.DirectBlackholeThreshold

// blackholeMissesRequired is the legacy alias for routing.BlackholeMissesRequired.
const blackholeMissesRequired = routing.BlackholeMissesRequired

// directClearsRequired is the legacy alias for routing.DirectClearsRequired.
const directClearsRequired = routing.DirectClearsRequired

// sendErrThreshold is the legacy alias for routing.SendErrThreshold.
const sendErrThreshold = routing.SendErrThreshold

// writeFrame sends a raw frame to a peer, using relay through the beacon
// if needed. Thin coordinator over routing.Manager.WriteFrame — bumps
// the public BytesSent / PktsSent atomics and logs flips that the
// routing-side heuristic triggers.
func (tm *TunnelManager) writeFrame(nodeID uint32, addr *net.UDPAddr, frame []byte) error {
	// Pre-check blackhole heuristic so we can log flips with the same
	// detail the pre-extraction code emitted.
	wasRelay := tm.routing.IsRelayPeer(nodeID)
	silentFor := time.Since(tm.routing.LastDirectRecv(nodeID))
	preMisses := tm.routing.BlackholeMissCount(nodeID)

	counters := routing.CounterTarget{
		PktsSent:  &tm.PktsSent,
		BytesSent: &tm.BytesSent,
	}
	_, err := tm.routing.WriteFrame(nodeID, addr, frame, counters)

	// Detect blackhole flip / ICMP flip after the call. routing.WriteFrame
	// already mutated state; check post-conditions to log the same event
	// the pre-extraction code logged.
	if !wasRelay && tm.routing.IsRelayPeer(nodeID) {
		if preMisses >= 0 && silentFor > directBlackholeThreshold {
			slog.Info("direct path silent, flipping to relay",
				"peer_node_id", nodeID,
				"silent_for", silentFor.String(),
				"misses", preMisses+1)
		} else if err != nil && isICMPUnreachable(err) {
			slog.Info("direct path ICMP-unreachable, flipping to relay",
				"peer_node_id", nodeID,
				"error", err)
		}
		// Reset the key-exchange attempt counter so the peer gets a fresh
		// set of relay-based retransmit slots. Without this, Attempts has
		// already reached MaxRekeyAttempts+1 from the failed direct attempts
		// and the next tick immediately gives up before any relay frame lands.
		tm.kx.ResetPendingRekeyAttempts(nodeID)
	}

	if errors.Is(err, routing.ErrNoAddress) {
		return fmt.Errorf("no address for node %d", nodeID)
	}
	return err
}

// recordOutboundSend stamps the lastOutboundSend timestamp for a peer.
// Used by keepaliveSweep to identify peers whose NAT mapping is at risk
// of idle-timeout (no send in keepaliveInterval). Thin shim over
// routing.Manager.RecordOutboundSend.
func (tm *TunnelManager) recordOutboundSend(nodeID uint32) {
	tm.routing.RecordOutboundSend(nodeID, time.Now())
}

// handleSendError is the test-shim retained for the icmp_prune_bug_test
// surface. Production code calls routing.Manager.HandleSendError via
// WriteFrame; this wrapper mirrors the legacy log-on-flip behavior so
// existing tests keep their assertion shape.
func (tm *TunnelManager) handleSendError(nodeID uint32, err error) {
	flipped, count := tm.routing.HandleSendError(nodeID, err)
	if flipped {
		slog.Info("direct path ICMP-unreachable, flipping to relay",
			"peer_node_id", nodeID,
			"consecutive_errors", count,
			"error", err)
	}
}

// isICMPUnreachable returns true if err is one of the syscall errors
// the Linux kernel surfaces on a subsequent UDP send after receiving
// an ICMP unreachable from the peer's stack. Pre-extraction helper
// kept for in-package tests; canonical implementation now lives in
// routing/blackhole.go (unexported there).
func isICMPUnreachable(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}

// TunnelKeepaliveInterval is the minimum gap between successive sends to
// a peer before keepaliveSweep enqueues a NAT-keepalive frame. Set below
// the 30 s lower bound of consumer-NAT UDP idle timeout. Tunable for
// tests via direct assignment.
var TunnelKeepaliveInterval = 25 * time.Second

// keepaliveSweep examines tm.peers and sends a tiny encrypted keepalive
// frame to every peer whose lastOutboundSend is older than
// TunnelKeepaliveInterval. Returns the number of keepalives sent.
//
// The keepalive frame is an empty ProtoControl packet on PortPing —
// handleEncrypted recognises this combination and silently drops it
// before recvCh delivery, so application code never sees a spurious
// "ping" packet. The encrypted payload still authenticates as us
// (peer's AEAD verifies our nodeID AAD), so an attacker can't forge
// keepalives to keep stale entries warm.
func (tm *TunnelManager) keepaliveSweep(now time.Time) int {
	type peerInfo struct {
		id   uint32
		addr *net.UDPAddr
		pc   *peerCrypto
	}
	tm.mu.RLock()
	stale := make([]peerInfo, 0, len(tm.peers))
	for nodeID, addr := range tm.peers {
		last, ok := tm.routing.LastOutboundSend(nodeID)
		if ok && now.Sub(last) < TunnelKeepaliveInterval {
			continue
		}
		pc := tm.envelope.Get(nodeID)
		if pc == nil || !pc.Ready {
			continue
		}
		stale = append(stale, peerInfo{nodeID, addr, pc})
	}
	tm.mu.RUnlock()

	sent := 0
	for _, p := range stale {
		ka := &protocol.Packet{
			Version:  protocol.Version,
			Protocol: protocol.ProtoControl,
			DstPort:  protocol.PortPing,
		}
		plaintext, err := ka.Marshal()
		if err != nil {
			continue
		}
		frame := tm.encryptFrame(p.pc, plaintext)
		if err := tm.writeFrame(p.id, p.addr, frame); err != nil {
			slog.Debug("keepalive send failed", "peer_node_id", p.id, "error", err)
			continue
		}
		sent++
	}
	return sent
}

// keepaliveTickerInterval is how often keepaliveLoop wakes up to scan
// for stale peers. Set to a fraction of TunnelKeepaliveInterval so a
// peer that goes idle right after a tick still gets a keepalive within
// roughly TunnelKeepaliveInterval + this period.
var keepaliveTickerInterval = 5 * time.Second

// keepaliveLoop runs the periodic NAT-keepalive sweep until tm.done
// closes. Spawned by Listen() once the UDP socket is bound.
func (tm *TunnelManager) keepaliveLoop() {
	ticker := time.NewTicker(keepaliveTickerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-tm.done:
			return
		case <-ticker.C:
			tm.keepaliveSweep(time.Now())
		}
	}
}

// isTunnelKeepalive returns true for the packets that keepaliveSweep
// emits — empty ProtoControl on PortPing. handleEncrypted drops these
// before recvCh delivery so application code never sees a spurious ping.
func isTunnelKeepalive(pkt *protocol.Packet) bool {
	return pkt != nil &&
		pkt.Protocol == protocol.ProtoControl &&
		pkt.DstPort == protocol.PortPing &&
		len(pkt.Payload) == 0
}

// getPeerPubKey returns the cached Ed25519 public key for a peer,
// fetching from registry on cache miss. Thin shim over
// keyexchange.Manager.GetPeerPubKey.
func (tm *TunnelManager) getPeerPubKey(nodeID uint32) (ed25519.PublicKey, error) {
	return tm.kx.GetPeerPubKey(nodeID)
}

// Listen starts the UDP listener for incoming tunnel traffic.
func (tm *TunnelManager) Listen(addr string) error {
	sock, err := udpio.Listen(addr)
	if err != nil {
		// Preserve the legacy error-prefix shape ("resolve: …" / "listen
		// udp: …") that callers/tests assert against. udpio.Listen
		// already wraps with the same prefixes, so we forward the
		// error verbatim.
		return err
	}
	tm.sock = sock
	tm.routing.SetSocket(sock)

	tm.readWg.Add(1)
	go tm.readLoop()
	// P1-010 tunnel-state half: retransmit pending key exchanges if peer
	// hasn't responded within rekeyRetransmitInterval. Without this, a
	// single dropped reply leaves the tunnel wedged until the next
	// 5-minute relay probe.
	tm.kxCtx, tm.kxCancel = context.WithCancel(context.Background())
	go tm.kx.Loop(tm.kxCtx)
	// v1.9.1 NAT-keepalive: send a tiny encrypted ping every
	// TunnelKeepaliveInterval to peers we've been silent to, preventing
	// consumer-NAT idle-timeout from silently breaking long-lived
	// peer relationships with bursty connection cycles.
	go tm.keepaliveLoop()
	return nil
}

func (tm *TunnelManager) Close() error {
	var connErr error
	tm.closeOnce.Do(func() {
		close(tm.done) // signal readLoop to stop sending
		if tm.kxCancel != nil {
			tm.kxCancel() // stop the L5 retransmit loop
		}
		if tm.sock != nil {
			connErr = tm.sock.Close() // causes readLoop to exit on ReadFromUDP error
		}
		tm.readWg.Wait() // wait for readLoop to fully exit before closing recvCh
		close(tm.recvCh) // unblock routeLoop (H5 fix — prevents goroutine leak)
	})
	return connErr
}

func (tm *TunnelManager) LocalAddr() net.Addr {
	if tm.sock != nil {
		if a := tm.sock.LocalAddr(); a != nil {
			return a
		}
	}
	return nil
}

func (tm *TunnelManager) readLoop() {
	defer tm.readWg.Done()

	for {
		keepGoing, stopped := tm.readLoopOneIter()
		if stopped {
			return
		}
		// keepGoing=false means a panic was caught; we drop the frame
		// and continue. udpio.Recv errors (socket closed, etc.) flag
		// stopped=true and we exit cleanly.
		_ = keepGoing
	}
}

// readLoopOneIter performs a single Recv + dispatch. Wrapped in a
// defer/recover so a panic in any handler (handleBeaconMessage,
// handleEncrypted, handleAuthKeyExchange, handleKeyExchange, or
// protocol.Unmarshal) drops the *frame* rather than killing the
// daemon.
//
// L2/L4 panic boundary (architecture-notes/03-INVARIANTS.md §8): the
// read loop is the single goroutine that drives udpio.Recv; if it dies
// the daemon is permanently disconnected even though the process keeps
// running. The boundary lives at iteration scope so one bad frame
// can't tear down the loop, but a closed socket (udpio.ErrClosed) still
// cleanly stops via the stopped return.
//
// Buffer reuse: tm.sock.Recv returns a slice into a pool-backed buffer
// it owns. The slice is valid only until the next Recv call; this is
// safe here because every dispatch path either copies (TunnelMagic
// branch) or processes synchronously (other magics) before the next
// loop iteration. The §6 unbuffered-recvCh contract is preserved
// because the magic-branches that push onto tm.recvCh do so from this
// goroutine, blocking until routeLoop accepts.
func (tm *TunnelManager) readLoopOneIter() (cont bool, stopped bool) {
	defer recoverLayer("L2", "readLoop", tm.bus, nil)

	frame, remote, err := tm.sock.Recv()
	if err != nil {
		if errors.Is(err, udpio.ErrClosed) {
			slog.Debug("tunnel read loop stopped", "reason", "conn closed")
		} else {
			slog.Error("tunnel read error", "error", err)
		}
		return false, true
	}

	n := len(frame)
	if n < 1 {
		return true, false
	}

	// Beacon messages use single-byte type codes < 0x10.
	// All tunnel magic starts with 'P' (0x50), so no collision.
	if frame[0] < 0x10 {
		tm.handleBeaconMessage(frame, remote)
		return true, false
	}

	if n < 4 {
		return true, false
	}

	magic := [4]byte{frame[0], frame[1], frame[2], frame[3]}

	switch magic {
	case protocol.TunnelMagicAuthEx:
		// Authenticated key exchange: [PILA][4-byte nodeID][32-byte X25519][32-byte Ed25519][64-byte sig]
		tm.handleAuthKeyExchange(frame[4:], remote, false)
		return true, false

	case protocol.TunnelMagicKeyEx:
		// Key exchange packet: [PILK][4-byte nodeID][32-byte pubkey]
		tm.handleKeyExchange(frame[4:], remote, false)
		return true, false

	case protocol.TunnelMagicSecure:
		// Encrypted packet: [PILS][4-byte nodeID][12-byte nonce][ciphertext+tag]
		tm.handleEncrypted(frame[4:], remote)
		return true, false

	case protocol.TunnelMagicPunch:
		// NAT punch packet — expected during hole-punching, silently acknowledged
		slog.Debug("NAT punch received", "from", remote)
		return true, false

	case protocol.TunnelMagic:
		// Plaintext packet
		if n < 4+protocol.PacketHeaderSize() {
			return true, false
		}
		// Copy out of the pool-backed Recv buffer before pushing onto
		// recvCh — the buffer is reused on the next Recv iteration, so
		// any retained slice would be corrupted.
		data := make([]byte, n-4)
		copy(data, frame[4:])

		pkt, err := protocol.Unmarshal(data)
		if err != nil {
			slog.Error("tunnel unmarshal error", "remote", remote, "error", err)
			return true, false
		}

		atomic.AddUint64(&tm.PktsRecv, 1)
		atomic.AddUint64(&tm.BytesRecv, uint64(n))
		select {
		case tm.recvCh <- &IncomingPacket{Packet: pkt, From: remote}:
		case <-tm.done:
			return false, true
		}
		return true, false

	default:
		return true, false // unknown magic
	}
}

// handleAuthKeyExchange processes an authenticated key exchange packet.
// Format: [4-byte nodeID][32-byte X25519 pubkey][32-byte Ed25519 pubkey][64-byte Ed25519 signature]
// The signature is over: "auth:" + nodeID(4 bytes) + X25519-pubkey(32 bytes)
// fromRelay indicates this was received via beacon relay — don't update peer endpoint.
//
// L5 panic boundary (architecture-notes/03-INVARIANTS.md §8): the key
// exchange path runs untrusted bytes through Ed25519 verify, X25519
// scalar mult, registry lookups, and crypto-state mutation. A panic
// must drop only this frame.
func (tm *TunnelManager) handleAuthKeyExchange(data []byte, from *net.UDPAddr, fromRelay bool) {
	defer recoverLayer("L5", "handleAuthKeyExchange", tm.bus, nil)
	if !tm.encrypt || tm.privKey == nil {
		return
	}
	tm.kx.HandleAuthFrame(data, from, fromRelay)
}

// handleKeyExchange processes an incoming unauthenticated key exchange packet.
// Format: [4-byte nodeID][32-byte X25519 pubkey]
// If we have an identity and the peer has a registered pubkey, reject unauthenticated
// exchange and require authenticated (PILA) instead.
// fromRelay indicates this was received via beacon relay — don't update peer endpoint.
//
// L5 panic boundary (architecture-notes/03-INVARIANTS.md §8): unauth
// key exchange admits anyone — caps protect against resource exhaustion
// but a malformed pubkey or registry race could panic during scalar
// mult / map insert. Drop the frame on panic.
func (tm *TunnelManager) handleKeyExchange(data []byte, from *net.UDPAddr, fromRelay bool) {
	defer recoverLayer("L5", "handleKeyExchange", tm.bus, nil)
	if !tm.encrypt || tm.privKey == nil {
		return
	}
	tm.kx.HandleUnauthFrame(data, from, fromRelay)
}

// onKeyInstalled is the post-install daemon hook invoked by
// keyexchange.Manager after a successful HandleAuth/UnauthFrame.
// Handles peer-endpoint bookkeeping (direct vs. relay), salvage replay
// of stale-keyed plaintext, and pending-frame flush.
func (tm *TunnelManager) onKeyInstalled(ev keyexchange.PostInstallEvent) {
	peerNodeID := ev.PeerNodeID
	from := ev.From
	fromRelay := ev.FromRelay

	tm.mu.Lock()
	if !fromRelay {
		if from != nil {
			tm.peers[peerNodeID] = from
		}
	} else if bAddr := tm.routing.BeaconAddr(); bAddr != nil {
		// fromRelay=true: peer's key exchange arrived via the beacon, so
		// the relay path is the empirically-working one. Overwrite the
		// peers entry to the beacon and set+pin relay regardless of any
		// prior ensureTunnel registration. Without overwriting, writeFrame
		// would continue sending to the (unreachable) direct address and
		// only flip to relay after writeFrame's ~60s silent-detection
		// timer — during which encrypted sends fail and rekey attempts
		// rotate session keys faster than they settle. Issue #199 was
		// the original "open the relay slot if peer is unknown" patch;
		// this generalizes it to "always trust the working empirical
		// signal."
		tm.peers[peerNodeID] = bAddr
		tm.routing.AdmitRelayFromBeacon(peerNodeID)
	}
	tm.mu.Unlock()

	// P1-010 desync salvage: if the rekey REPLACED an existing crypto
	// context (peer restarted or rekeyed mid-flight), data we sent
	// under the old key was dropped by the peer. Replay the recent-send
	// ring buffer with the new key so application-layer fire-and-forget
	// paths (send-message, send-file) actually deliver.
	if ev.KeyChanged && ev.OldCrypto != nil {
		tm.mu.RLock()
		replayAddr := tm.peers[peerNodeID]
		tm.mu.RUnlock()
		tm.replaySalvage(ev.OldCrypto, ev.NewCrypto, peerNodeID, replayAddr)
	}

	tm.flushPending(peerNodeID)
}

// handleEncrypted decrypts an incoming encrypted packet.
// Format: [4-byte nodeID][12-byte nonce][ciphertext+GCM tag]
//
// L6 panic boundary (architecture-notes/03-INVARIANTS.md §8): AEAD
// decrypt + replay-window bookkeeping + nested handleEncrypted call
// for the inner plaintext. A panic at any depth must drop the frame.
//
// The decrypt + replay-window + AEAD-Open + decryptFailCount
// bookkeeping is owned by envelope.Store (L6). This function is the
// L7-side glue: dispatch the result to the right side-effect (rekey
// request, security event, NAT-remap learning, recvCh delivery).
func (tm *TunnelManager) handleEncrypted(data []byte, from *net.UDPAddr) {
	defer recoverLayer("L6", "handleEncrypted", tm.bus, nil)

	res := envelope.DecryptFrame(tm.envelope, data)
	peerNodeID := res.PeerNodeID

	switch res.Err {
	case envelope.ErrTooShort:
		return
	case keyexchange.ErrNoKey:
		// We have no key for this peer. Typically this happens after a local
		// restart: the remote still has a cached crypto context from the
		// previous session and keeps sending packets we can't decrypt. Reply
		// with a key-exchange so the sender detects the rekey, invalidates
		// their cached context, and establishes a fresh tunnel. Rate-limited
		// to prevent amplification.
		sent := tm.maybeRequestRekey(peerNodeID, from)
		slog.Warn("encrypted packet from node but no key",
			"peer_node_id", peerNodeID, "rekey_sent", sent)
		return
	case envelope.ErrOutsideWindow:
		slog.Warn("tunnel packet outside replay window",
			"peer_node_id", peerNodeID, "counter", res.Counter, "max", res.MaxRecvNonce)
		// ErrOutsideWindow means the frame authenticated (valid AEAD) but the
		// nonce counter is more than ReplayWindowSize behind the current max.
		// This is a very late relay-buffered frame from the same key session,
		// not a peer restart. If the peer restarted with a new key, their frames
		// cannot authenticate against our old key (different AEAD key from new
		// X25519 exchange) — those land as ErrAEAD, not here. Triggering rekey
		// here caused the same storm as ErrReplay: each rekey produces early
		// counters that the relay re-delivers far into the session as ErrOutsideWindow,
		// firing another rekey, indefinitely.
		return
	case envelope.ErrReplay:
		slog.Warn("tunnel nonce replay detected",
			"peer_node_id", peerNodeID, "counter", res.Counter, "max", res.MaxRecvNonce)
		tm.publishEvent("security.nonce_replay", map[string]interface{}{
			"peer_node_id": peerNodeID, "counter": res.Counter,
		})
		// ErrReplay means the frame authenticated (valid AEAD) but the nonce
		// counter was already seen. This is duplicate delivery — the same
		// encrypted frame arrived on both direct and relay paths, or the relay
		// re-delivered a buffered frame. A peer restart sends KeyInit first
		// (handled in the KeyInit path), then data frames with a fresh counter
		// that authenticate against the new key. Those new-key frames produce
		// ErrAEAD against our old key (handled below), not ErrReplay. Triggering
		// a rekey here caused a storm: each rekey produces early low-counter
		// frames (1–40) that the relay then re-delivers, all land as replay, all
		// fire another rekey, ad infinitum.
		return
	case envelope.ErrAEAD:
		atomic.AddUint64(&tm.EncryptFail, 1)
		slog.Error("tunnel decrypt error", "peer_node_id", peerNodeID, "error", res.Err)
		// Track consecutive AEAD failures. When the count exceeds
		// decryptFailDropThreshold the peer's session keys have demonstrably
		// diverged from ours (older daemon versions drift into states where
		// their derived AEAD key no longer matches even with the same X25519
		// pubkey — likely an HKDF info-string or session-id mismatch).
		// Drop the peerCrypto and request a fresh exchange. Equivalent to
		// the "stop and start the daemon" recovery, but automatic.
		//
		// Grace period: never drop a peerCrypto that was installed less
		// than decryptFailDropGrace ago. Just-installed crypto is the
		// common case for stale in-flight packets — peer rekeyed, our
		// new session has counter 0 / new AEAD key, but packets sent by
		// peer before the rekey landed are in flight on the relay path
		// and arrive at us with the OLD key. They fail AEAD here. Without
		// the grace period, 5 stale frames at >1/s would tear down the
		// pc we just installed, request another rekey, peer rotates again,
		// peer's new stale frames arrive, we tear down again — a self-
		// perpetuating storm that scales with the relay's queue depth.
		// 3 s is much longer than a relay RTT (<200 ms) so genuine in-
		// flight packets drain; persistent divergence (the original case
		// decryptFailDropThreshold was added for) is still caught after
		// the grace expires.
		pc := tm.envelope.Get(peerNodeID)
		if tm.envelope.ShouldDropOnDecryptFail(peerNodeID, pc) {
			if tm.envelope.CompareAndDrop(peerNodeID, pc) {
				slog.Warn("tunnel: peer crypto key divergence detected, dropping session and re-handshaking",
					"peer_node_id", peerNodeID, "consecutive_decrypt_failures", pc.DecryptFailCount)
				tm.maybeRequestRekey(peerNodeID, from)
			}
		}
		return
	}

	plaintext := res.Plaintext

	pkt, err := protocol.Unmarshal(plaintext)
	if err != nil {
		slog.Error("tunnel unmarshal error after decrypt", "peer_node_id", peerNodeID, "error", err)
		return
	}

	// v1.9.1 NAT-keepalive: drop tunnel-keepalive packets before recvCh
	// delivery. They're authenticated (the AEAD verified the sender's
	// nodeID AAD) so we still want all the side-effects below (recordInbound
	// Decrypt, clearRelayOnDirect, address-learning), but the application
	// layer should never see them. Doing this BEFORE the recordInbound
	// side-effects would lose the liveness signal the keepalive is meant
	// to provide; doing it after but BEFORE the recvCh send keeps the
	// signal flowing without polluting the application stream.

	// P1-010 tunnel-state half: successful decrypt = peer has matching
	// crypto. Clear any pending rekey state so rekeyRetransmitLoop stops
	// hammering. Update the lastInboundDecrypt timestamp for the
	// handleAuthKeyExchange "stale reply" gate.
	tm.recordInboundDecrypt(peerNodeID)
	tm.clearPendingRekey(peerNodeID)

	// P1-010 fix: a successfully-decrypted packet from a non-beacon address
	// proves the direct path has recovered. Clear the relay flag so
	// subsequent sends go direct (and the relay probe loop stops firing).
	// Also record the timestamp so writeFrame can detect direct-path
	// blackholes and flip to relay (B1 relay regression fix).
	//
	// v1.9.1 NAT-remap address learning: also update tm.peers[peerNodeID]
	// to the source addr of every authenticated direct decrypt. Symmetric
	// or port-restricted NATs rotate source ports (idle timeout, NAT box
	// reboot, CGNAT churn). Without this, our cached peers[] entry stays
	// stuck at the pre-rotation addr until the peer happens to send a
	// fresh key_exchange — silently black-holing every outbound send in
	// between. Skipping the beacon-source case prevents pinning the peer
	// to the beacon's listen port (relay traffic carries the original
	// from=beaconAddr, which is not the peer's real direct addr).
	cleared := tm.routing.ClearRelayOnDirect(peerNodeID, from)
	if from != nil && !tm.routing.IsFromBeacon(from) {
		tm.routing.RecordDirectRecv(peerNodeID, time.Now())
		tm.mu.Lock()
		tm.peers[peerNodeID] = from
		tm.mu.Unlock()
	}
	if cleared {
		slog.Info("relay→direct auto-cleared on direct packet receipt",
			"peer_node_id", peerNodeID, "endpoint", from)
	}

	atomic.AddUint64(&tm.PktsRecv, 1)
	atomic.AddUint64(&tm.BytesRecv, uint64(len(data)+4)) // +4 for PILS magic

	// Drop tunnel keepalives before recvCh delivery — they exist purely
	// to keep NAT mappings warm; the application layer should never see
	// them. All liveness/address-learning side-effects above already ran.
	if isTunnelKeepalive(pkt) {
		return
	}

	select {
	case tm.recvCh <- &IncomingPacket{Packet: pkt, From: from}:
	case <-tm.done:
	}
}

// deriveSecret computes a shared AES-256-GCM cipher from the peer's
// public key. Thin shim over keyexchange.Manager.DeriveSecret.
func (tm *TunnelManager) deriveSecret(peerPubKeyBytes []byte) (*peerCrypto, error) {
	return tm.kx.DeriveSecret(peerPubKeyBytes)
}

// sendKeyExchangeToNode sends an authenticated key exchange if identity
// is available, otherwise falls back to unauthenticated. Thin shim over
// keyexchange.Manager.SendKeyExchangeToNode (which carries the
// BOOTSTRAP-EXCEPTION marker — moved with the function).
func (tm *TunnelManager) sendKeyExchangeToNode(peerNodeID uint32) {
	tm.kx.SendKeyExchangeToNode(peerNodeID)
}

// markPendingRekey is the legacy shim for keyexchange.Manager.MarkPendingRekey.
func (tm *TunnelManager) markPendingRekey(peerNodeID uint32) {
	tm.kx.MarkPendingRekey(peerNodeID)
}

// clearPendingRekey is the legacy shim for keyexchange.Manager.ClearPendingRekey.
func (tm *TunnelManager) clearPendingRekey(peerNodeID uint32) {
	tm.kx.ClearPendingRekey(peerNodeID)
}

// recordInboundDecrypt updates the per-peer last-decrypt timestamp +
// clears send-error count (ICMP-aware fix).
func (tm *TunnelManager) recordInboundDecrypt(peerNodeID uint32) {
	tm.kx.RecordInboundDecrypt(peerNodeID)
	// Successful decrypt = bidirectional crypto works. Lift any give-up
	// cooldown so future rekeying can start immediately if needed.
	tm.kx.ClearRekeyGaveUp(peerNodeID)
	// v1.9.1 ICMP-aware fix: a successful inbound decrypt is proof the
	// peer is alive and reachable. Clear any accumulated send-error
	// count so a future transient ICMP-unreachable burst doesn't
	// trip the relay flip on a freshly-recovered peer.
	tm.routing.ClearSendErrCount(peerNodeID)
}

// inboundDecryptStale is the legacy shim for keyexchange.Manager.InboundDecryptStale.
func (tm *TunnelManager) inboundDecryptStale(peerNodeID uint32) bool {
	return tm.kx.InboundDecryptStale(peerNodeID)
}

// rekeyRetransmitTick is the legacy shim for tests that drive the
// retransmit loop's body directly.
func (tm *TunnelManager) rekeyRetransmitTick() {
	tm.kx.RekeyRetransmitTick()
}

// buildAuthKeyExchangeFrame is the legacy shim for tests.
func (tm *TunnelManager) buildAuthKeyExchangeFrame() []byte {
	return tm.kx.BuildAuthFrame()
}

// buildKeyExchangeFrame is the legacy shim for tests.
func (tm *TunnelManager) buildKeyExchangeFrame() []byte {
	return tm.kx.BuildUnauthFrame()
}

// recordSalvage stashes a plaintext send into the per-peerCrypto ring
// buffer. Thin wrapper over envelope.Store.RecordSalvage so older
// daemon code (and tests) can keep the original call shape.
func (tm *TunnelManager) recordSalvage(pc *peerCrypto, plaintext []byte) {
	tm.envelope.RecordSalvage(pc, plaintext)
}

// replaySalvage re-encrypts plaintext from oldPC's ring buffer with
// newPC's key and ships it via writeFrame. Called when
// handleAuthKeyExchange or handleKeyExchange installs a fresh crypto
// context that replaces a previous one (keyChanged=true). This is the
// data-recovery half of the P1-010 fix — the rekey itself was already
// in place, but the data sent under the stale key was being lost.
func (tm *TunnelManager) replaySalvage(oldPC, newPC *peerCrypto, peerNodeID uint32, addr *net.UDPAddr) {
	if oldPC == nil || newPC == nil || addr == nil {
		return
	}
	entries := tm.envelope.DrainSalvage(oldPC)
	if len(entries) == 0 {
		return
	}
	replayed := 0
	for _, e := range entries {
		encrypted := tm.encryptFrame(newPC, e.Plaintext)
		if err := tm.writeFrame(peerNodeID, addr, encrypted); err != nil {
			slog.Debug("desync salvage replay write failed",
				"peer_node_id", peerNodeID, "error", err)
			continue
		}
		replayed++
	}
	if replayed > 0 {
		slog.Info("desync salvage replayed",
			"peer_node_id", peerNodeID, "count", replayed)
		tm.publishEvent("tunnel.desync_salvage", map[string]interface{}{
			"peer_node_id": peerNodeID,
			"replayed":     replayed,
		})
	}
}

// flushPending sends any queued packets for a peer now that encryption is ready.
func (tm *TunnelManager) flushPending(nodeID uint32) {
	tm.pendMu.Lock()
	frames := tm.pending[nodeID]
	delete(tm.pending, nodeID)
	tm.pendMu.Unlock()

	if len(frames) == 0 {
		return
	}

	tm.mu.RLock()
	addr := tm.peers[nodeID]
	tm.mu.RUnlock()
	pc := tm.envelope.Get(nodeID)

	if pc == nil || !pc.Ready {
		return
	}

	// Audit #3 fix: re-check the installed Crypto pointer before each
	// encrypt. Without this, a concurrent rekey installs a fresh
	// envelope.Crypto and our encrypt-with-stale-pc produces frames the
	// peer cannot decrypt (frames lost). The lookup is on the
	// envelope.Store leaf lock, so it does not contend with tm.mu.
	for _, plaintext := range frames {
		current := tm.envelope.Get(nodeID)
		if current != pc {
			slog.Debug("flush aborted: concurrent rekey",
				"node_id", nodeID, "remaining", len(frames))
			return
		}
		encrypted := tm.encryptFrame(pc, plaintext)
		if err := tm.writeFrame(nodeID, addr, encrypted); err != nil {
			slog.Error("flush pending to node failed", "node_id", nodeID, "error", err)
		}
	}
	slog.Debug("flushed pending packets", "node_id", nodeID, "count", len(frames))
}

// encryptFrame encrypts a marshaled packet and returns a full tunnel
// frame. Thin wrapper over envelope.Store.EncryptWith — kept on
// TunnelManager so existing tests and call sites compile unchanged.
// Format: [PILS][4-byte nodeID][12-byte nonce][ciphertext+GCM tag]
//
// Maintains tm.EncryptOK alongside tm.envelope.EncryptOK so external
// metrics readers (ipc.go, tests) keep their existing snapshot
// surface during the L6 extraction transition.
func (tm *TunnelManager) encryptFrame(pc *peerCrypto, plaintext []byte) []byte {
	frame := envelope.EncryptWith(tm.envelope, pc, plaintext)
	atomic.AddUint64(&tm.EncryptOK, 1)
	return frame
}

// Send encapsulates and sends a packet to the given node.
func (tm *TunnelManager) Send(nodeID uint32, pkt *protocol.Packet) error {
	tm.mu.RLock()
	addr, ok := tm.peers[nodeID]
	tm.mu.RUnlock()

	if !ok {
		return fmt.Errorf("no tunnel to node %d", nodeID)
	}

	return tm.SendTo(addr, nodeID, pkt)
}

// SendDirectProbe sends an encrypted packet straight to the peer's last-known
// direct UDP endpoint, bypassing the relay wrapping that Send/SendTo would
// apply if relayPeers[nodeID] is true. Used by relayProbeLoop to test whether
// the direct path has recovered without tearing down the relay flag for
// concurrent traffic. Returns an error if no direct endpoint is known or if
// the peer's stored addr is the beacon (meaning we never learned a real
// direct addr for this peer).
//
// P1-010 fix: previously relayProbeLoop temporarily flipped SetRelayPeer
// (nodeID, false), sent the probe via Send, then restored the flag after 2s.
// During that window every concurrent send — including key-exchange replies
// triggered by the peer's "no key" warnings — bypassed relay too. If the
// direct path was still dead (e.g. symmetric NAT + stale mapping), those
// replies were silently dropped, leaving crypto desynced indefinitely.
// SendDirectProbe isolates the probe without disturbing other traffic.
func (tm *TunnelManager) SendDirectProbe(nodeID uint32, pkt *protocol.Packet) error {
	tm.mu.RLock()
	addr := tm.peers[nodeID]
	tm.mu.RUnlock()
	pc := tm.envelope.Get(nodeID)

	if addr == nil {
		return fmt.Errorf("no peer endpoint for node %d", nodeID)
	}
	if tm.routing.IsFromBeacon(addr) {
		return fmt.Errorf("stored endpoint for node %d is beacon placeholder", nodeID)
	}

	data, err := pkt.Marshal()
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	var frame []byte
	if tm.encrypt {
		if pc == nil || !pc.Ready {
			return fmt.Errorf("no crypto for node %d", nodeID)
		}
		frame = tm.encryptFrame(pc, data)
	} else {
		frame = make([]byte, 4+len(data))
		copy(frame[0:4], protocol.TunnelMagic[:])
		copy(frame[4:], data)
	}

	n, werr := tm.sock.Send(frame, addr)
	if werr == nil {
		atomic.AddUint64(&tm.PktsSent, 1)
		atomic.AddUint64(&tm.BytesSent, uint64(n))
	}
	return werr
}

// clearRelayOnDirectLocked is the legacy shim for tests that drive
// clear-on-direct directly. Delegates to routing.Manager.ClearRelayOnDirect.
func (tm *TunnelManager) clearRelayOnDirectLocked(peerNodeID uint32, from *net.UDPAddr) bool {
	return tm.routing.ClearRelayOnDirect(peerNodeID, from)
}

// SetRelayPeerPinned is like SetRelayPeer but also marks the relay flag
// as authoritative — ClearRelayOnDirect will never auto-flip a pinned
// peer back to direct based on observed packet sources. Thin shim over
// routing.Manager.SetRelayPeerPinned.
func (tm *TunnelManager) SetRelayPeerPinned(nodeID uint32, relay bool) {
	tm.routing.SetRelayPeerPinned(nodeID, relay)
}

// SendTo sends a packet to a specific UDP address (relay-aware).
func (tm *TunnelManager) SendTo(addr *net.UDPAddr, nodeID uint32, pkt *protocol.Packet) error {
	data, err := pkt.Marshal()
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	// Check if we should encrypt
	if tm.encrypt {
		pc := tm.envelope.Get(nodeID)

		if pc != nil && pc.Ready {
			// Record plaintext for desync salvage BEFORE encrypting. If the
			// peer has lost their key (silent restart, packet-loss-induced
			// rekey), they'll drop this frame and send us a rekey request;
			// handleAuthKeyExchange will replay the salvage with the new
			// key. See P1-010.
			tm.envelope.RecordSalvage(pc, data)
			frame := tm.encryptFrame(pc, data)
			return tm.writeFrame(nodeID, addr, frame)
		}

		// No key yet — initiate key exchange and queue the packet (C1 fix: no plaintext fallback).
		// Only trigger a new key exchange if one isn't already in-flight; the
		// retransmit loop handles subsequent retries. Without this guard, rapid
		// outbound traffic (e.g. SYN retransmits every 250ms during dial) calls
		// sendKeyExchangeToNode repeatedly, each incrementing Attempts until it
		// reaches MaxRekeyAttempts+1 within seconds and the peer gives up before
		// the relay path is even established.
		if !tm.kx.PendingRekeyHas(nodeID) {
			tm.sendKeyExchangeToNode(nodeID)
		}
		if tm.kx.PeerInRekeyGaveUp(nodeID) {
			return fmt.Errorf("%w (peer_node_id=%d)", ErrPendingDropped, nodeID)
		}
		tm.pendMu.Lock()
		if _, exists := tm.pending[nodeID]; !exists && len(tm.pending) >= maxPendingPeers {
			tm.pendMu.Unlock()
			return fmt.Errorf("too many pending key exchanges")
		}
		q := tm.pending[nodeID]
		dropped := false
		if len(q) >= maxPendingPerPeer {
			// P1-008: queue full — drop oldest and surface the drop instead
			// of silently masking loss. Callers see a non-fatal error so
			// retx/application layers can react; the newest packet still
			// gets queued because losing the freshest data would be worse.
			q = q[1:]
			dropped = true
			atomic.AddUint64(&tm.PendingDrops, 1)
		}
		tm.pending[nodeID] = append(q, data)
		qlen := len(tm.pending[nodeID])
		tm.pendMu.Unlock()
		if dropped {
			slog.Warn("tunnel pending queue full; dropped oldest",
				"peer_node_id", nodeID,
				"queue_len", qlen,
				"limit", maxPendingPerPeer)
			// The new packet IS queued (line above appended it). What was
			// dropped is the oldest packet, not this one. Callers that
			// errors.Is(err, ErrPendingDropped) can treat this as transient
			// — a SYN retransmit will succeed once the queue drains.
			return fmt.Errorf("%w (peer_node_id=%d)", ErrPendingDropped, nodeID)
		}
		return nil // queued, will be sent encrypted after key exchange
	}

	return tm.sendPlaintextToNode(nodeID, addr, data)
}

// sendPlaintextToNode sends a marshaled packet with PILT magic (relay-aware).
func (tm *TunnelManager) sendPlaintextToNode(nodeID uint32, addr *net.UDPAddr, data []byte) error {
	frame := make([]byte, 4+len(data))
	copy(frame[0:4], protocol.TunnelMagic[:])
	copy(frame[4:], data)
	return tm.writeFrame(nodeID, addr, frame)
}

// AddPeer registers a peer's real UDP endpoint.
func (tm *TunnelManager) AddPeer(nodeID uint32, addr *net.UDPAddr) {
	tm.mu.Lock()
	tm.peers[nodeID] = addr
	tm.mu.Unlock()
	slog.Debug("added peer", "node_id", nodeID, "addr", addr)

	// If encryption is enabled, initiate key exchange (relay-aware).
	// Guard matches writeToNode's PendingRekeyHas check: concurrent AddPeer
	// calls for the same node (e.g. two parallel dial goroutines) must not
	// each increment Attempts, which would exhaust MaxRekeyAttempts before
	// the retransmit loop can pace retries at RekeyRetransmitInterval.
	if tm.encrypt && !tm.kx.PendingRekeyHas(nodeID) {
		tm.sendKeyExchangeToNode(nodeID)
	}
}

// RemovePeer removes a peer and all per-peer metadata. Long-running
// daemons with peer churn (handshake revocations, network leaves)
// previously leaked entries in lastDirectRecv, blackholeMissCount,
// directClearCount, relayPeers, peerPubKeys, pendingRekey, and
// lastInboundDecrypt — none of which had any other deletion path.
// A reused nodeID would also inherit stale state (e.g. trip the relay
// flip on the third miss because blackholeMissCount=2 from the
// previous tenant).
func (tm *TunnelManager) RemovePeer(nodeID uint32) {
	tm.envelope.Drop(nodeID)
	tm.mu.Lock()
	delete(tm.peers, nodeID)
	tm.mu.Unlock()

	// L4-owned per-peer state (relayPeers, relayPinned, lastDirectRecv,
	// blackholeMissCount, directClearCount, sendErrCount, lastOutboundSend).
	tm.routing.RemovePeer(nodeID)

	// L5-owned per-peer state (peerPubKeys, pendingRekey, lastInboundDecrypt).
	tm.kx.RemovePeer(nodeID)
}

// HasPeer checks if we have a tunnel to a node.
func (tm *TunnelManager) HasPeer(nodeID uint32) bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	_, ok := tm.peers[nodeID]
	return ok
}

// HasCrypto returns true if we have an encryption context for a peer (proving prior key exchange).
func (tm *TunnelManager) HasCrypto(nodeID uint32) bool {
	return tm.envelope.Has(nodeID)
}

// IsEncrypted returns true if the tunnel to a peer is encrypted.
func (tm *TunnelManager) IsEncrypted(nodeID uint32) bool {
	return tm.envelope.IsReady(nodeID)
}

// PeerCount returns the number of known peers.
func (tm *TunnelManager) PeerCount() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return len(tm.peers)
}

// PeerInfo describes a known peer.
type PeerInfo struct {
	NodeID        uint32
	Endpoint      string
	Encrypted     bool
	Authenticated bool // true if peer proved Ed25519 identity
	Relay         bool // true if using beacon relay (symmetric NAT)
}

// PeerList returns all known peers and their endpoints.
func (tm *TunnelManager) PeerList() []PeerInfo {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	var list []PeerInfo
	for id, addr := range tm.peers {
		pc := tm.envelope.Get(id)
		list = append(list, PeerInfo{
			NodeID:        id,
			Endpoint:      addr.String(),
			Encrypted:     pc != nil && pc.Ready,
			Authenticated: pc != nil && pc.Authenticated,
			Relay:         tm.routing.IsRelayPeer(id),
		})
	}
	return list
}

// handleBeaconMessage processes beacon protocol messages received on the tunnel socket.
//
// L4 panic boundary (architecture-notes/03-INVARIANTS.md §8): beacon
// messages parse caller-supplied bytes (potentially adversarial — a
// hostile beacon can spoof srcNodeIDs in MsgRelayDeliver). A panic in
// dispatch must drop only this message, not the readLoop.
func (tm *TunnelManager) handleBeaconMessage(data []byte, from *net.UDPAddr) {
	defer recoverLayer("L4", "handleBeaconMessage", tm.bus, nil)

	if len(data) < 1 {
		return
	}
	switch data[0] {
	case protocol.BeaconMsgDiscoverReply:
		slog.Debug("beacon discover reply on tunnel socket", "from", from)
	case protocol.BeaconMsgPunchCommand:
		tm.handlePunchCommand(data[1:])
	case protocol.BeaconMsgRelayDeliver:
		tm.handleRelayDeliver(data[1:])
	default:
		slog.Debug("unknown beacon message on tunnel socket", "type", data[0], "from", from)
	}
}

// handlePunchCommand processes a beacon punch command, sending a punch packet
// to the specified target to create a NAT mapping. Thin shim over
// routing.Manager.HandlePunchCommand.
func (tm *TunnelManager) handlePunchCommand(data []byte) {
	tm.routing.HandlePunchCommand(data)
}

// maxRelayPeers is the legacy alias for routing.MaxRelayPeers.
const maxRelayPeers = routing.MaxRelayPeers

// maxCryptoPeers caps the crypto map for unauth key-exchange insertions.
// handleAuthKeyExchange is implicitly bounded by the registry-verified pubkey
// lookup, but handleKeyExchange (unauth) accepts any peerNodeID and performs
// an X25519 scalar multiplication per packet. Without a cap, a peer spraying
// unauth key-exchange frames with random node IDs can grow crypto to 2^32
// entries while also burning CPU on derivation. Set high enough that real
// deployments never hit it.
const maxCryptoPeers = 16384

// handleRelayDeliver processes a beacon relay delivery, extracting the inner tunnel frame.
func (tm *TunnelManager) handleRelayDeliver(data []byte) {
	// Format: [srcNodeID(4)][payload...]
	if len(data) < 5 {
		return
	}
	srcNodeID := binary.BigEndian.Uint32(data[0:4])
	payload := data[4:]

	// Issue #199: the beacon is not fully trusted — srcNodeID is
	// caller-supplied and can be spoofed. Don't add *unknown* peers to the
	// peers/relayPeers maps here; instead, delegate to the verified paths:
	//
	//   - TunnelMagicSecure    → handleEncrypted decrypts with an existing
	//                            peer key; without one, we reply with a
	//                            rate-limited rekey and return.
	//   - TunnelMagicAuthEx    → handleAuthKeyExchange verifies the peer's
	//                            ed25519 signature against their registered
	//                            pubkey before inserting crypto state.
	//   - TunnelMagicKeyEx     → unauth key exchange; handleKeyExchange
	//                            applies maxCryptoPeers + identity-aware
	//                            rejection.
	//
	// For peers we already have crypto context for, the beacon-addr
	// placeholder is safe — they've proven their ID via prior key exchange.
	// For unknown peers, the *crypto handler* is responsible for admitting
	// them; we just pass the payload through.
	hadCrypto := tm.envelope.Has(srcNodeID)
	admitted, newlyActivated, shouldAlias := tm.routing.MarkRelayActivatedIfHadCrypto(srcNodeID, hadCrypto)
	if !admitted {
		slog.Warn("relay peers cap reached, dropping relay packet", "src_node_id", srcNodeID)
		return
	}
	if shouldAlias {
		bAddr := tm.routing.BeaconAddr()
		if bAddr != nil {
			tm.mu.Lock()
			if _, ok := tm.peers[srcNodeID]; !ok {
				tm.peers[srcNodeID] = bAddr
			}
			tm.mu.Unlock()
		}
	}
	if newlyActivated {
		tm.publishEvent("tunnel.relay_activated", map[string]interface{}{
			"peer_node_id": srcNodeID,
		})
	}

	if len(payload) < 4 {
		return
	}

	// Get peer's stored address for packet handling. For relay-delivered
	// packets the *physical* source was the beacon; handleEncrypted's
	// clearRelayOnDirect uses `from` to decide whether the direct
	// path has recovered, so we must report the beacon as the source
	// rather than a stale peers[] entry (which on the dialer side is the
	// direct endpoint returned by ensureTunnel). Passing a non-beacon
	// `from` would incorrectly auto-clear the relay flag on the very
	// first relay-delivered packet, causing subsequent sends to try
	// direct again — fatal under dual-symmetric NAT.
	srcAddr := tm.routing.BeaconAddr()
	if srcAddr == nil {
		srcAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}

	// Process the inner tunnel frame
	magic := [4]byte{payload[0], payload[1], payload[2], payload[3]}
	switch magic {
	case protocol.TunnelMagicAuthEx:
		tm.handleAuthKeyExchange(payload[4:], srcAddr, true)
	case protocol.TunnelMagicKeyEx:
		tm.handleKeyExchange(payload[4:], srcAddr, true)
	case protocol.TunnelMagicSecure:
		tm.handleEncrypted(payload[4:], srcAddr)
	case protocol.TunnelMagic:
		if len(payload) < 4+protocol.PacketHeaderSize() {
			return
		}
		frameData := make([]byte, len(payload)-4)
		copy(frameData, payload[4:])
		pkt, err := protocol.Unmarshal(frameData)
		if err != nil {
			slog.Error("tunnel unmarshal error from relay", "src_node", srcNodeID, "error", err)
			return
		}
		atomic.AddUint64(&tm.PktsRecv, 1)
		atomic.AddUint64(&tm.BytesRecv, uint64(len(payload)))
		select {
		case tm.recvCh <- &IncomingPacket{Packet: pkt, From: srcAddr}:
		case <-tm.done:
		}
	}
}

// RecvCh returns the channel for incoming packets.
func (tm *TunnelManager) RecvCh() <-chan *IncomingPacket {
	return tm.recvCh
}

// DiscoverEndpoint sends a STUN discover to the beacon and returns the
// observed public endpoint. Thin shim over routing.DiscoverEndpoint —
// the canonical implementation lives at pkg/daemon/routing/discover.go.
func DiscoverEndpoint(beaconAddr string, nodeID uint32, conn *net.UDPConn) (*net.UDPAddr, error) {
	return routing.DiscoverEndpoint(beaconAddr, nodeID, conn, fixedTimeout())
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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
	"github.com/TeoSlayer/pilotprotocol/internal/pool"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

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

// replayWindowSize is the number of nonces tracked in the sliding window bitmap
// for replay detection (H8 fix). Nonces within [maxNonce-replayWindowSize, maxNonce]
// are tracked; nonces below the window are rejected.
const replayWindowSize = 256

// peerCrypto holds per-peer encryption state.
type peerCrypto struct {
	aead        cipher.AEAD
	nonce       uint64  // monotonic send counter (atomic)
	noncePrefix [4]byte // random prefix for nonce domain separation
	// Replay detection (H8 fix): sliding window bitmap instead of simple high-water mark.
	replayMu      sync.Mutex
	maxRecvNonce  uint64                        // highest nonce received
	replayBitmap  [replayWindowSize / 64]uint64 // bitmap for nonces in [max-windowSize, max]
	ready         bool                          // true once key exchange is complete
	authenticated bool                          // true if peer proved Ed25519 identity
	peerX25519Key [32]byte                      // peer's X25519 public key (for detecting rekeying)
	// decryptFailCount tracks consecutive AEAD authentication failures
	// since the last successful decrypt. Older-version peer daemons drift
	// into a state where their derived AEAD key no longer matches ours
	// (likely a session-id or info-string mismatch in HKDF), at which
	// point every encrypted packet from the peer fails with "cipher:
	// message authentication failed". Once this counter exceeds
	// decryptFailDropThreshold the daemon drops this peerCrypto entirely
	// and triggers a fresh key exchange — equivalent to a daemon-restart
	// recovery without actually restarting. Reset to 0 on any successful
	// decrypt. Only mutated under tm.mu to avoid an extra mutex.
	decryptFailCount int
	// createdAt is when this peerCrypto was installed in tm.crypto. Used
	// by handleAuthKeyExchange to decide between preserving existing state
	// (fresh handshake retransmit/reply within seconds) and resetting it
	// (long-lived peer's own state desynced — e.g. older-version daemon
	// rotated its send counter without rotating X25519 keys, which
	// otherwise leaves us with a high maxRecvNonce that rejects the
	// peer's resumed packets as replays).
	createdAt time.Time

	// P1-010 desync salvage: ring buffer of recent plaintext sent with this
	// key. On a peer-initiated rekey (keyChanged in handleAuthKeyExchange),
	// these are re-encrypted with the new key and re-sent — recovering the
	// data that was vaporized when the peer dropped our stale-keyed frames.
	salvageMu sync.Mutex
	salvage   []salvageEntry
}

type salvageEntry struct {
	plaintext []byte
	when      time.Time
}

// salvageMaxEntries bounds memory + replay-storm size. Originally 32,
// but a 32-frame burst replayed on rekey caused receiver-side nonce
// confusion (concurrent dataexchange retransmits filling salvage +
// out-of-order delivery on the wire). 4 covers the typical "task
// submit + send-results + a couple of retries" without overwhelming
// the receiver. Memory at max: 4 × ~1500 B = 6 KiB / peer, ~6 MiB
// across maxCryptoPeers (1024).
const salvageMaxEntries = 4

// salvageMaxAge is how far back we replay sends after a rekey. The rekey
// round-trip itself is ~1 RTT plus the rate-limit window (3 s); 5 s gives
// margin for slow handshakes under loss.
const salvageMaxAge = 5 * time.Second


// decryptFailDropThreshold is how many consecutive AEAD-authentication
// failures from a single peer trigger a full peerCrypto drop +
// re-handshake. Sized to swallow a small burst of legitimate packet
// corruption (kernel buffer overruns, mid-flight key rotation crossing
// the wire) while still recovering from peer-side AEAD-key divergence
// within a few seconds — a daemon restart on either side cycles the
// peer through a fresh handshake; this is the "equivalent recovery
// without restarting" path.
const decryptFailDropThreshold = 5

// checkAndRecordNonce returns true if the nonce is valid (not replayed, not too old).
// Must be called with replayMu held.
//
// Note on nonce wraparound: the counter is uint64, so it wraps after 2^64 packets.
// At 1 billion packets/sec this takes ~585 years — purely theoretical. If a
// connection ever approaches this limit, rekeying (new secure handshake) resets
// the counter naturally.
func (pc *peerCrypto) checkAndRecordNonce(counter uint64) bool {
	if pc.maxRecvNonce == 0 {
		// First packet ever
		pc.maxRecvNonce = counter
		pc.setReplayBit(counter)
		return true
	}

	if counter > pc.maxRecvNonce {
		// New maximum — shift window forward
		shift := counter - pc.maxRecvNonce
		if shift >= replayWindowSize {
			// Clear entire bitmap
			pc.replayBitmap = [replayWindowSize / 64]uint64{}
		} else {
			// Clear the new positions that the shifted window will occupy
			for s := uint64(0); s < shift; s++ {
				newBit := (counter - s) % replayWindowSize
				pc.replayBitmap[newBit/64] &^= 1 << (newBit % 64)
			}
		}
		pc.maxRecvNonce = counter
		pc.setReplayBit(counter)
		return true
	}

	// counter <= maxRecvNonce
	diff := pc.maxRecvNonce - counter
	if diff >= replayWindowSize {
		return false // too old
	}

	// Check if already seen
	bit := counter % replayWindowSize
	if pc.replayBitmap[bit/64]&(1<<(bit%64)) != 0 {
		return false // replay
	}
	pc.setReplayBit(counter)
	return true
}

func (pc *peerCrypto) setReplayBit(counter uint64) {
	bit := counter % replayWindowSize
	pc.replayBitmap[bit/64] |= 1 << (bit % 64)
}

// TunnelManager manages real UDP tunnels to peer daemons.
type TunnelManager struct {
	mu        sync.RWMutex
	conn      *net.UDPConn
	peers     map[uint32]*net.UDPAddr // node_id → real UDP endpoint
	crypto    map[uint32]*peerCrypto  // node_id → encryption state
	recvCh    chan *IncomingPacket
	done      chan struct{}  // closed on Close() to stop readLoop sends
	readWg    sync.WaitGroup // tracks readLoop goroutine for clean shutdown
	closeOnce sync.Once

	// Encryption config
	encrypt bool             // if true, attempt encrypted tunnels
	privKey *ecdh.PrivateKey // our X25519 private key
	pubKey  []byte           // our X25519 public key (32 bytes)
	nodeID  uint32           // our node ID (set after registration)

	// Identity authentication (Ed25519)
	identity    *crypto.Identity                        // our Ed25519 identity for signing
	peerPubKeys map[uint32]ed25519.PublicKey            // node_id → Ed25519 pubkey (from registry)
	verifyFunc  func(uint32) (ed25519.PublicKey, error) // callback to fetch peer pubkey

	// Pending sends waiting for key exchange to complete
	pendMu  sync.Mutex
	pending map[uint32][][]byte // node_id → queued frames

	// Rate-limit rekey-request responses triggered by "encrypted packet but no
	// key" events. Prevents amplification if a peer floods us with gibberish.
	rekeyMu       sync.Mutex
	lastRekeyReq  map[uint32]time.Time

	// P1-010 tunnel-state half: track in-flight key exchanges so a single
	// dropped reply under packet loss doesn't leave the tunnel wedged for
	// 5 min until the next relayProbeLoop tick. Sweeper goroutine
	// rekeyRetransmitLoop retransmits stale entries every
	// rekeyRetransmitInterval up to maxRekeyAttempts. Cleared on first
	// successful inbound decrypt from peer.
	rkPendingMu        sync.Mutex
	pendingRekey       map[uint32]*pendingRekeyState
	lastInboundDecrypt map[uint32]time.Time

	// NAT traversal: beacon-coordinated hole-punching and relay
	beaconAddr *net.UDPAddr    // beacon address for punch/relay
	relayPeers map[uint32]bool // peers that need relay (symmetric NAT)


	// relayPinned marks peers whose relay flag was set by an authoritative
	// signal (registry's relay_only=true on the resolve response, OR an
	// operator forcing relay via SetRelayPeer with pin=true). For pinned
	// peers, clearRelayOnDirectLocked is a no-op — we never auto-flip
	// back to direct based on packet observations alone. Without this,
	// a stray non-beacon-sourced packet (e.g. a NAT punch reply, a
	// beacon ICMP unreachable, or just GCP reply-source-ip variance)
	// triggered the directClear hysteresis after 3 such packets, the
	// peer flipped to direct, the next outgoing packet went direct
	// (and dropped, since the peer is unreachable), the writeFrame
	// blackhole counter then took ~60s to flip BACK to relay, and
	// during the flap window each fresh key_exchange rotated session
	// keys faster than encrypted packets could decrypt. The user-
	// visible symptom was "ping works for a minute then dial timeout".
	relayPinned map[uint32]bool

	// lastDirectRecv tracks when each peer was last heard from on a direct
	// (non-beacon) UDP path. Used by writeFrame to flip an established
	// connection into relay mode when the direct path goes silent —
	// covers the case where SYN succeeded directly but the data-plane
	// path later dies (NAT-mapping refresh window, mid-flight partition).
	lastDirectRecv map[uint32]time.Time

	// blackholeMissCount counts consecutive writeFrame observations of
	// "lastDirectRecv stale" per peer. The flip to relay only fires once
	// the count reaches blackholeMissesRequired (3) — single transient
	// ACK gaps caused by GC pauses, scheduler jitter, or brief packet
	// reordering no longer flap the entire tunnel onto the relay path.
	// Resets to 0 on any direct packet receipt (see clearRelayOnDirect
	// path) and on a successful flip.
	//
	// directClearCount is the symmetric counter for the relay→direct
	// auto-clear path: clearing the relay flag now requires
	// directClearsRequired (3) consecutive direct-from-peer packets, so
	// a brief direct burst during a relay stretch can't bounce us back.
	blackholeMissCount map[uint32]int
	directClearCount   map[uint32]int

	// lastOutboundSend tracks when we last successfully sent a frame to
	// each peer. Used by keepaliveSweep to identify peers whose NAT
	// mapping is at risk of idle-timeout. Updated by writeFrame on every
	// successful UDP write (direct or relay). Pruned when a peer is
	// removed via RemovePeer.
	lastOutboundSend map[uint32]time.Time

	// sendErrCount counts consecutive ICMP-unreachable errors (ECONNREFUSED,
	// EHOSTUNREACH, ENETUNREACH) returned by writeFrame to a given peer.
	// Linux delivers these errors on a subsequent write after the kernel
	// receives an ICMP unreachable from the peer's stack. On reaching
	// sendErrThreshold, the peer is flipped to relay mode (faster recovery
	// than the 24+ s blackhole-heuristic flip). Cleared on any inbound
	// successful decrypt from the peer (see recordInboundDecrypt).
	sendErrCount map[uint32]int

	// Webhook
	webhook *WebhookClient

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
	return &TunnelManager{
		peers:              make(map[uint32]*net.UDPAddr),
		crypto:             make(map[uint32]*peerCrypto),
		peerPubKeys:        make(map[uint32]ed25519.PublicKey),
		pending:            make(map[uint32][][]byte),
		relayPeers:         make(map[uint32]bool),
		relayPinned:        make(map[uint32]bool),
		lastDirectRecv:     make(map[uint32]time.Time),
		blackholeMissCount: make(map[uint32]int),
		directClearCount:   make(map[uint32]int),
		lastOutboundSend:   make(map[uint32]time.Time),
		sendErrCount:       make(map[uint32]int),
		lastRekeyReq:       make(map[uint32]time.Time),
		pendingRekey:       make(map[uint32]*pendingRekeyState),
		lastInboundDecrypt: make(map[uint32]time.Time),
		recvCh:             make(chan *IncomingPacket, RecvChSize),
		done:               make(chan struct{}),
	}
}

// pendingRekeyState tracks a key-exchange we sent and are waiting on.
// Cleared when handleEncrypted records a successful decrypt from peer
// (proof their crypto matches ours). The retransmit loop bumps lastSentAt
// and attempts on each retry; gives up after maxRekeyAttempts to avoid
// hammering a peer that's just gone.
type pendingRekeyState struct {
	firstSentAt time.Time
	lastSentAt  time.Time
	attempts    int
}

const (
	// rekeyRetransmitInterval is how long we wait for an inbound encrypted
	// packet to confirm the peer received our key_exchange. After this we
	// retransmit on the assumption either our key_exchange or the peer's
	// reply was dropped.
	rekeyRetransmitInterval = 4 * time.Second

	// maxRekeyAttempts caps the retransmit loop. The first send + this
	// many retries = 1 + maxRekeyAttempts total attempts. After that we
	// give up — peer is presumed gone.
	maxRekeyAttempts = 5

	// keyExchangeReplyStaleThreshold: when an auth_key_exchange arrives
	// and we already have crypto for the peer with no inbound traffic in
	// this window, reply with our key_exchange too (in case our previous
	// reply was dropped). Loosens handleAuthKeyExchange's "send back" gate.
	keyExchangeReplyStaleThreshold = 6 * time.Second
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
	if tm.conn == nil {
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
	if tm.beaconAddr != nil && from != nil &&
		from.IP.Equal(tm.beaconAddr.IP) && from.Port == tm.beaconAddr.Port {
		if _, capped := tm.relayPeers[peerNodeID]; !capped && len(tm.relayPeers) < maxRelayPeers {
			tm.relayPeers[peerNodeID] = true
			// Beacon-sourced key exchange = empirical proof relay path
			// is the working one. Pin so clearRelayOnDirectLocked can't
			// flap us back to direct on a stray non-beacon packet.
			tm.relayPinned[peerNodeID] = true
		}
	}
	tm.mu.Unlock()

	tm.sendKeyExchangeToNode(peerNodeID)
	return true
}

// SetWebhook configures the webhook client for event notifications.
func (tm *TunnelManager) SetWebhook(wc *WebhookClient) {
	tm.mu.Lock()
	tm.webhook = wc
	tm.mu.Unlock()
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
	slog.Info("tunnel encryption enabled", "scheme", "X25519+AES-256-GCM")
	return nil
}

// SetNodeID sets our node ID (called after registration).
func (tm *TunnelManager) SetNodeID(id uint32) {
	atomic.StoreUint32(&tm.nodeID, id)
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
	tm.mu.Lock()
	delete(tm.crypto, peerNodeID)
	tm.mu.Unlock()
	tm.rkPendingMu.Lock()
	delete(tm.pendingRekey, peerNodeID)
	delete(tm.lastInboundDecrypt, peerNodeID)
	tm.rkPendingMu.Unlock()
}

// loadNodeID atomically loads our node ID.
func (tm *TunnelManager) loadNodeID() uint32 {
	return atomic.LoadUint32(&tm.nodeID)
}

// SetIdentity sets our Ed25519 identity for signing authenticated key exchanges.
func (tm *TunnelManager) SetIdentity(id *crypto.Identity) {
	tm.mu.Lock()
	tm.identity = id
	tm.mu.Unlock()
}

// SetPeerVerifyFunc sets a callback to fetch a peer's Ed25519 public key from the registry.
func (tm *TunnelManager) SetPeerVerifyFunc(fn func(uint32) (ed25519.PublicKey, error)) {
	tm.mu.Lock()
	tm.verifyFunc = fn
	tm.mu.Unlock()
}

// SetBeaconAddr configures the beacon address for NAT hole-punching and relay.
func (tm *TunnelManager) SetBeaconAddr(addr string) error {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve beacon: %w", err)
	}
	tm.mu.Lock()
	tm.beaconAddr = a
	tm.mu.Unlock()
	return nil
}

// SetRelayPeer marks a peer as needing relay through the beacon (symmetric NAT).
func (tm *TunnelManager) SetRelayPeer(nodeID uint32, relay bool) {
	tm.mu.Lock()
	tm.relayPeers[nodeID] = relay
	tm.mu.Unlock()
	if relay {
		slog.Info("peer marked for relay", "node_id", nodeID)
	}
}

// IsRelayPeer returns true if the peer is in relay mode.
func (tm *TunnelManager) IsRelayPeer(nodeID uint32) bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.relayPeers[nodeID]
}

// RelayPeerIDs returns the node IDs of all relay-flagged peers.
func (tm *TunnelManager) RelayPeerIDs() []uint32 {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	var ids []uint32
	for id, isRelay := range tm.relayPeers {
		if isRelay {
			ids = append(ids, id)
		}
	}
	return ids
}

// RegisterWithBeacon sends a MsgDiscover to the beacon from the tunnel socket
// using the real nodeID, so the beacon knows our endpoint for punch coordination.
func (tm *TunnelManager) RegisterWithBeacon() {
	tm.mu.RLock()
	bAddr := tm.beaconAddr
	tm.mu.RUnlock()
	if bAddr == nil || tm.conn == nil {
		return
	}
	msg := make([]byte, 5)
	msg[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(msg[1:5], tm.loadNodeID())
	if _, err := tm.conn.WriteToUDP(msg, bAddr); err != nil {
		slog.Warn("beacon registration failed", "error", err)
	} else {
		slog.Debug("registered with beacon", "node_id", tm.loadNodeID(), "beacon", bAddr)
	}
}

// RequestHolePunch asks the beacon to coordinate NAT hole-punching with a target peer.
func (tm *TunnelManager) RequestHolePunch(targetNodeID uint32) {
	tm.mu.RLock()
	bAddr := tm.beaconAddr
	tm.mu.RUnlock()
	if bAddr == nil || tm.conn == nil {
		return
	}
	// Format: [MsgPunchRequest(1)][ourNodeID(4)][targetNodeID(4)]
	msg := make([]byte, 9)
	msg[0] = protocol.BeaconMsgPunchRequest
	binary.BigEndian.PutUint32(msg[1:5], tm.loadNodeID())
	binary.BigEndian.PutUint32(msg[5:9], targetNodeID)
	if _, err := tm.conn.WriteToUDP(msg, bAddr); err != nil {
		slog.Debug("hole punch request failed", "target", targetNodeID, "error", err)
	} else {
		slog.Debug("hole punch requested", "target", targetNodeID)
	}
}

// directBlackholeThreshold is how long a peer can go without a direct
// recv before writeFrame auto-flips to relay. Tuned for force_relay_*
// integration tests which sleep 10s after partitioning UDP between peers.
const directBlackholeThreshold = 8 * time.Second

// blackholeMissesRequired is the number of consecutive writeFrame
// observations of "direct path silent for >threshold" needed before
// the tunnel flips to relay. With a single window check, transient
// ACK gaps (GC pauses, OS scheduler jitter, brief loss bursts) flapped
// the entire tunnel onto the relay path mid-transfer — observed in
// the autoscale bench as 4 MB/s ↔ 0.06 MB/s bimodality. Three
// consecutive misses ≈ 24+ s of legitimate silence before fail-over,
// which still beats the application-layer 30+ s retransmit budget.
const blackholeMissesRequired = 3

// directClearsRequired is the symmetric hysteresis on the relay→direct
// auto-clear path. Clearing the relay flag now requires N consecutive
// direct-from-peer packets so a single direct burst during a relay
// stretch (e.g. one stray packet from a brief NAT path opening) can't
// bounce us back to direct only to flap immediately.
const directClearsRequired = 3

// writeFrame sends a raw frame to a peer, using relay through the beacon if needed.
func (tm *TunnelManager) writeFrame(nodeID uint32, addr *net.UDPAddr, frame []byte) error {
	tm.mu.RLock()
	relay := tm.relayPeers[nodeID]
	bAddr := tm.beaconAddr
	lastRecv, hasRecv := tm.lastDirectRecv[nodeID]
	tm.mu.RUnlock()

	// Direct-blackhole detection with hysteresis (v1.9.1).
	// A single 8 s gap is no longer enough — the heuristic now requires
	// blackholeMissesRequired consecutive observations of staleness
	// before flipping. The miss counter resets to 0 on any direct
	// packet receipt (clearRelayOnDirectLocked) and on the flip itself.
	// hasRecv check ensures we don't flip peers we've never heard from
	// directly (those go through the standard DialConnection auto-switch
	// at daemon.go:2097 instead).
	if !relay && bAddr != nil && hasRecv && time.Since(lastRecv) > directBlackholeThreshold {
		tm.mu.Lock()
		// Re-check under write lock to avoid racing with clearRelayOnDirectLocked
		if !tm.relayPeers[nodeID] {
			tm.blackholeMissCount[nodeID]++
			misses := tm.blackholeMissCount[nodeID]
			if misses >= blackholeMissesRequired {
				tm.relayPeers[nodeID] = true
				// Direct path went silent for blackholeMissesRequired
				// observations. The peer is empirically not reachable
				// directly. Pin so we don't flap back. (Without the pin,
				// a single non-beacon-sourced reply via relay-mesh could
				// trigger clearRelayOnDirect after 3 such packets.)
				tm.relayPinned[nodeID] = true
				tm.blackholeMissCount[nodeID] = 0 // reset for next cycle
				slog.Info("direct path silent, flipping to relay",
					"peer_node_id", nodeID,
					"silent_for", time.Since(lastRecv).String(),
					"misses", misses)
				relay = true
			}
		}
		tm.mu.Unlock()
	}

	if relay && bAddr != nil {
		// MsgRelay: [0x05][senderNodeID(4)][destNodeID(4)][frame...]
		msg := make([]byte, 1+4+4+len(frame))
		msg[0] = protocol.BeaconMsgRelay
		binary.BigEndian.PutUint32(msg[1:5], tm.loadNodeID())
		binary.BigEndian.PutUint32(msg[5:9], nodeID)
		copy(msg[9:], frame)
		n, err := tm.conn.WriteToUDP(msg, bAddr)
		if err == nil {
			atomic.AddUint64(&tm.PktsSent, 1)
			atomic.AddUint64(&tm.BytesSent, uint64(n))
			tm.recordOutboundSend(nodeID)
		} else {
			tm.handleSendError(nodeID, err)
		}
		return err
	}

	if addr == nil {
		return fmt.Errorf("no address for node %d", nodeID)
	}
	n, err := tm.conn.WriteToUDP(frame, addr)
	if err == nil {
		atomic.AddUint64(&tm.PktsSent, 1)
		atomic.AddUint64(&tm.BytesSent, uint64(n))
		tm.recordOutboundSend(nodeID)
	} else {
		tm.handleSendError(nodeID, err)
	}
	return err
}

// recordOutboundSend stamps the lastOutboundSend timestamp for a peer.
// Used by keepaliveSweep to identify peers whose NAT mapping is at risk
// of idle-timeout (no send in keepaliveInterval).
func (tm *TunnelManager) recordOutboundSend(nodeID uint32) {
	tm.mu.Lock()
	tm.lastOutboundSend[nodeID] = time.Now()
	tm.mu.Unlock()
}

// sendErrThreshold is the number of consecutive ICMP-unreachable errors
// from a single peer required before handleSendError flips them to relay
// mode. Three matches the symmetric blackhole-miss / direct-clear
// thresholds so transient single-error blips don't cause flapping.
const sendErrThreshold = 3

// handleSendError is invoked from writeFrame's UDP-write error path. On
// a Linux kernel that has received an ICMP-unreachable from the peer's
// stack, the next WriteToUDP returns ECONNREFUSED / EHOSTUNREACH /
// ENETUNREACH. After sendErrThreshold consecutive matching errors, the
// peer is promoted to relay mode for fast recovery (vs. waiting ~24 s
// for the lastDirectRecv-based blackhole heuristic).
//
// Non-ICMP errors (generic write failure, EAGAIN, etc.) are ignored —
// they don't carry the same "peer is reachably-dead" signal.
func (tm *TunnelManager) handleSendError(nodeID uint32, err error) {
	if !isICMPUnreachable(err) {
		return
	}

	tm.mu.Lock()
	tm.sendErrCount[nodeID]++
	count := tm.sendErrCount[nodeID]
	flipped := false
	if count >= sendErrThreshold && !tm.relayPeers[nodeID] {
		if len(tm.relayPeers) < maxRelayPeers {
			tm.relayPeers[nodeID] = true
			// ICMP-unreachable threshold tripped — kernel keeps telling us
			// the peer's direct path is dead. Pin so observation can't flap
			// us back to direct.
			tm.relayPinned[nodeID] = true
			tm.sendErrCount[nodeID] = 0 // reset for next cycle
			flipped = true
		}
	}
	tm.mu.Unlock()

	if flipped {
		slog.Info("direct path ICMP-unreachable, flipping to relay",
			"peer_node_id", nodeID,
			"consecutive_errors", count,
			"error", err)
	}
}

// isICMPUnreachable returns true if err is one of the syscall errors
// the Linux kernel surfaces on a subsequent UDP send after receiving
// an ICMP unreachable from the peer's stack.
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
		last, ok := tm.lastOutboundSend[nodeID]
		if ok && now.Sub(last) < TunnelKeepaliveInterval {
			continue
		}
		pc := tm.crypto[nodeID]
		if pc == nil || !pc.ready {
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

// getPeerPubKey returns the cached Ed25519 public key for a peer, fetching from
// registry if needed.
func (tm *TunnelManager) getPeerPubKey(nodeID uint32) (ed25519.PublicKey, error) {
	tm.mu.RLock()
	if pk, ok := tm.peerPubKeys[nodeID]; ok {
		tm.mu.RUnlock()
		return pk, nil
	}
	fn := tm.verifyFunc
	tm.mu.RUnlock()

	if fn == nil {
		return nil, fmt.Errorf("no verify function")
	}

	pk, err := fn(nodeID)
	if err != nil {
		return nil, err
	}

	tm.mu.Lock()
	tm.peerPubKeys[nodeID] = pk
	tm.mu.Unlock()
	return pk, nil
}

// Listen starts the UDP listener for incoming tunnel traffic.
func (tm *TunnelManager) Listen(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	tm.conn = conn

	tm.readWg.Add(1)
	go tm.readLoop()
	// P1-010 tunnel-state half: retransmit pending key exchanges if peer
	// hasn't responded within rekeyRetransmitInterval. Without this, a
	// single dropped reply leaves the tunnel wedged until the next
	// 5-minute relay probe.
	go tm.rekeyRetransmitLoop()
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
		if tm.conn != nil {
			connErr = tm.conn.Close() // causes readLoop to exit on ReadFromUDP error
		}
		tm.readWg.Wait() // wait for readLoop to fully exit before closing recvCh
		close(tm.recvCh) // unblock routeLoop (H5 fix — prevents goroutine leak)
	})
	return connErr
}

func (tm *TunnelManager) LocalAddr() net.Addr {
	if tm.conn != nil {
		return tm.conn.LocalAddr()
	}
	return nil
}

func (tm *TunnelManager) readLoop() {
	defer tm.readWg.Done()
	bufPtr := pool.GetLarge()
	defer pool.PutLarge(bufPtr)
	buf := *bufPtr

	for {
		n, remote, err := tm.conn.ReadFromUDP(buf)
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				slog.Debug("tunnel read loop stopped", "reason", "conn closed")
			} else {
				slog.Error("tunnel read error", "error", err)
			}
			return
		}

		if n < 1 {
			continue
		}

		// Beacon messages use single-byte type codes < 0x10.
		// All tunnel magic starts with 'P' (0x50), so no collision.
		if buf[0] < 0x10 {
			tm.handleBeaconMessage(buf[:n], remote)
			continue
		}

		if n < 4 {
			continue
		}

		magic := [4]byte{buf[0], buf[1], buf[2], buf[3]}

		switch magic {
		case protocol.TunnelMagicAuthEx:
			// Authenticated key exchange: [PILA][4-byte nodeID][32-byte X25519][32-byte Ed25519][64-byte sig]
			tm.handleAuthKeyExchange(buf[4:n], remote, false)
			continue

		case protocol.TunnelMagicKeyEx:
			// Key exchange packet: [PILK][4-byte nodeID][32-byte pubkey]
			tm.handleKeyExchange(buf[4:n], remote, false)
			continue

		case protocol.TunnelMagicSecure:
			// Encrypted packet: [PILS][4-byte nodeID][12-byte nonce][ciphertext+tag]
			tm.handleEncrypted(buf[4:n], remote)
			continue

		case protocol.TunnelMagicPunch:
			// NAT punch packet — expected during hole-punching, silently acknowledged
			slog.Debug("NAT punch received", "from", remote)
			continue

		case protocol.TunnelMagic:
			// Plaintext packet
			if n < 4+protocol.PacketHeaderSize() {
				continue
			}
			data := make([]byte, n-4)
			copy(data, buf[4:n])

			pkt, err := protocol.Unmarshal(data)
			if err != nil {
				slog.Error("tunnel unmarshal error", "remote", remote, "error", err)
				continue
			}

			atomic.AddUint64(&tm.PktsRecv, 1)
			atomic.AddUint64(&tm.BytesRecv, uint64(n))
			select {
			case tm.recvCh <- &IncomingPacket{Packet: pkt, From: remote}:
			case <-tm.done:
				return
			}

		default:
			continue // unknown magic
		}
	}
}

// handleAuthKeyExchange processes an authenticated key exchange packet.
// Format: [4-byte nodeID][32-byte X25519 pubkey][32-byte Ed25519 pubkey][64-byte Ed25519 signature]
// The signature is over: "auth:" + nodeID(4 bytes) + X25519-pubkey(32 bytes)
// fromRelay indicates this was received via beacon relay — don't update peer endpoint.
func (tm *TunnelManager) handleAuthKeyExchange(data []byte, from *net.UDPAddr, fromRelay bool) {
	if len(data) < 4+32+32+64 {
		return
	}

	peerNodeID := binary.BigEndian.Uint32(data[0:4])
	peerX25519PubKey := data[4:36]
	peerEd25519PubKey := ed25519.PublicKey(data[36:68])
	signature := data[68:132]

	if !tm.encrypt || tm.privKey == nil {
		return
	}

	// (rate-limit removed v1.9.1-rc4: it deadlocked recovery when peer's
	// decryptFailDropThreshold dropped crypto for us and tried to
	// rebuild via key_exchange — our rate-limit suppressed those
	// rebuild attempts, leaving both sides stuck in "no key" state.
	// The handler is idempotent for same-pubkey duplicates so
	// processing them all is cheap.)

	// Verify the Ed25519 signature over the auth challenge
	challenge := make([]byte, 4+4+32)
	copy(challenge[0:4], []byte("auth"))
	binary.BigEndian.PutUint32(challenge[4:8], peerNodeID)
	copy(challenge[8:40], peerX25519PubKey)

	// Fetch expected pubkey from registry FIRST — reject if unavailable
	expectedPubKey, err := tm.getPeerPubKey(peerNodeID)
	if err != nil || expectedPubKey == nil {
		slog.Warn("auth key exchange rejected: cannot verify peer identity from registry", "peer_node_id", peerNodeID, "error", err)
		return
	}

	// Verify the packet-provided Ed25519 pubkey matches the registry.
	// On mismatch, invalidate cache and re-fetch — the peer may have restarted
	// with a new identity since we last cached their key.
	if !peerEd25519PubKey.Equal(expectedPubKey) {
		tm.mu.Lock()
		delete(tm.peerPubKeys, peerNodeID)
		tm.mu.Unlock()
		expectedPubKey, err = tm.getPeerPubKey(peerNodeID)
		if err != nil || expectedPubKey == nil {
			slog.Warn("auth key exchange rejected: cannot re-verify peer identity", "peer_node_id", peerNodeID, "error", err)
			return
		}
		if !peerEd25519PubKey.Equal(expectedPubKey) {
			slog.Error("auth key exchange: Ed25519 pubkey mismatch with registry", "peer_node_id", peerNodeID)
			return
		}
		slog.Info("auth key exchange: peer pubkey updated from registry", "peer_node_id", peerNodeID)
	}

	// Verify signature against the registry-verified key
	if !crypto.Verify(expectedPubKey, challenge, signature) {
		slog.Error("auth key exchange signature verification failed", "peer_node_id", peerNodeID)
		return
	}

	authenticated := true

	// Derive shared secret from X25519
	pc, err := tm.deriveSecret(peerX25519PubKey)
	if err != nil {
		slog.Error("auth key exchange failed", "peer_node_id", peerNodeID, "error", err)
		return
	}
	pc.authenticated = authenticated

	tm.mu.Lock()
	oldPC := tm.crypto[peerNodeID]
	hadCrypto := oldPC != nil
	keyChanged := hadCrypto && oldPC.peerX25519Key != pc.peerX25519Key
	// Only replace tm.crypto when there is no existing entry OR the
	// peer's X25519 ephemeral key actually changed. Replacing on a
	// duplicate key_exchange (same pubkey — common under our retransmit
	// loop or a peer's reply crossing on the wire) would reset the
	// nonce counter and replay-window bitmap, causing our subsequent
	// encrypted sends and any in-flight peer packets to look wrong on
	// the wire. The shared secret derived from the same pubkey is
	// identical; the existing peerCrypto is the correct one.
	// Pinned by TestHandleKeyExchangeDuplicatePreservesCryptoState.
	if !hadCrypto || keyChanged {
		tm.crypto[peerNodeID] = pc
	}
	if !fromRelay {
		tm.peers[peerNodeID] = from
	} else {
		// fromRelay=true means the auth key exchange arrived via the
		// beacon — empirical proof the relay path is the working one
		// for this peer. Always overwrite the peers entry to point at
		// the beacon and set+pin the relay flag, even if ensureTunnel
		// previously added the peer with its registry-published direct
		// address. Without overwriting, writeFrame would continue sending
		// to the (unreachable) direct address and only flip to relay
		// after writeFrame's ~60s silent-detection timer — during which
		// encrypted sends fail and rekey attempts rotate session keys
		// faster than they settle. Issue #199 was the original "open the
		// relay slot if peer is unknown" patch; this generalizes it to
		// "always trust the working empirical signal."
		if tm.beaconAddr != nil {
			tm.peers[peerNodeID] = tm.beaconAddr
			if _, alreadyRelay := tm.relayPeers[peerNodeID]; !alreadyRelay && len(tm.relayPeers) >= maxRelayPeers {
				// Don't admit new relay peers if cap is reached; existing
				// relay peers stay relay (handled below).
			} else {
				tm.relayPeers[peerNodeID] = true
				tm.relayPinned[peerNodeID] = true
			}
		}
	}
	// Cache the peer's Ed25519 pubkey
	tm.peerPubKeys[peerNodeID] = peerEd25519PubKey
	tm.mu.Unlock()

	if keyChanged {
		slog.Info("peer rekeyed (auth), re-establishing tunnel", "peer_node_id", peerNodeID)
	} else {
		slog.Info("encrypted tunnel established", "auth", authenticated, "peer_node_id", peerNodeID, "endpoint", from, "relay", fromRelay)
	}
	tm.webhook.Emit("tunnel.established", map[string]interface{}{
		"peer_node_id": peerNodeID, "authenticated": authenticated,
		"relay": fromRelay, "rekeyed": keyChanged,
	})

	if !hadCrypto || keyChanged {
		tm.sendKeyExchangeToNode(peerNodeID)
	}

	// P1-010 desync salvage: if the rekey REPLACED an existing crypto
	// context (peer restarted or rekeyed mid-flight), data we sent under
	// the old key was dropped by the peer. Replay the recent-send ring
	// buffer with the new key so application-layer fire-and-forget paths
	// (task submit, send-results) actually deliver.
	if keyChanged && oldPC != nil {
		tm.mu.RLock()
		replayAddr := tm.peers[peerNodeID]
		tm.mu.RUnlock()
		tm.replaySalvage(oldPC, pc, peerNodeID, replayAddr)
	}

	tm.flushPending(peerNodeID)
}

// handleKeyExchange processes an incoming unauthenticated key exchange packet.
// Format: [4-byte nodeID][32-byte X25519 pubkey]
// If we have an identity and the peer has a registered pubkey, reject unauthenticated
// exchange and require authenticated (PILA) instead.
// fromRelay indicates this was received via beacon relay — don't update peer endpoint.
func (tm *TunnelManager) handleKeyExchange(data []byte, from *net.UDPAddr, fromRelay bool) {
	if len(data) < 36 {
		return
	}

	peerNodeID := binary.BigEndian.Uint32(data[0:4])
	peerPubKey := data[4:36]

	// If we don't have encryption enabled, ignore key exchange silently
	if !tm.encrypt || tm.privKey == nil {
		return
	}

	// If we have identity, check if peer has a registered pubkey — if so,
	// reject unauthenticated exchange and respond with authenticated instead
	tm.mu.RLock()
	hasIdentity := tm.identity != nil
	_, hadCryptoPre := tm.crypto[peerNodeID]
	cryptoSize := len(tm.crypto)
	tm.mu.RUnlock()
	if hasIdentity {
		expectedPubKey, err := tm.getPeerPubKey(peerNodeID)
		if err == nil && expectedPubKey != nil {
			slog.Warn("rejecting unauthenticated key exchange from peer with known identity", "peer_node_id", peerNodeID)
			tm.sendKeyExchangeToNode(peerNodeID)
			return
		}
	}

	// Budget check BEFORE the expensive scalar multiplication. Without this,
	// an attacker spraying unauth key-exchange frames at us can force CPU
	// burn even if the map-insert is later rejected. The TOCTOU here is
	// benign: concurrent bursts may overshoot by a handful of entries, but
	// the next call will see the raised count and reject.
	if !hadCryptoPre && cryptoSize >= maxCryptoPeers {
		slog.Warn("crypto peers cap reached, dropping unauth key exchange",
			"peer_node_id", peerNodeID, "from", from)
		return
	}

	// Derive shared secret
	pc, err := tm.deriveSecret(peerPubKey)
	if err != nil {
		slog.Error("key exchange failed", "peer_node_id", peerNodeID, "error", err)
		return
	}

	tm.mu.Lock()
	oldPC := tm.crypto[peerNodeID]
	hadCrypto := oldPC != nil
	// Detect rekeying: peer restarted with a new keypair
	keyChanged := hadCrypto && oldPC.peerX25519Key != pc.peerX25519Key
	// Same rationale as handleAuthKeyExchange: don't replace on a
	// duplicate key_exchange (same pubkey) — the nonce counter +
	// replay-window reset would invalidate in-flight ciphertexts.
	if !hadCrypto || keyChanged {
		tm.crypto[peerNodeID] = pc
	}
	if !fromRelay {
		tm.peers[peerNodeID] = from
	} else if tm.beaconAddr != nil {
		// fromRelay=true: peer's key exchange arrived via the beacon, so
		// the relay path is the empirically-working one. Overwrite the
		// peers entry to the beacon and set+pin relay regardless of any
		// prior ensureTunnel registration — see the matching block in
		// handleAuthKeyExchange for the full rationale.
		tm.peers[peerNodeID] = tm.beaconAddr
		if _, alreadyRelay := tm.relayPeers[peerNodeID]; !alreadyRelay && len(tm.relayPeers) >= maxRelayPeers {
			// cap reached; keep existing entry as-is
		} else {
			tm.relayPeers[peerNodeID] = true
			tm.relayPinned[peerNodeID] = true
		}
	}
	tm.mu.Unlock()

	if keyChanged {
		slog.Info("peer rekeyed, re-establishing tunnel", "peer_node_id", peerNodeID)
	} else {
		slog.Info("encrypted tunnel established", "peer_node_id", peerNodeID, "endpoint", from, "relay", fromRelay)
	}
	tm.webhook.Emit("tunnel.established", map[string]interface{}{
		"peer_node_id": peerNodeID, "authenticated": false,
		"relay": fromRelay, "rekeyed": keyChanged,
	})

	// Respond with our key if this is a new peer or the peer rekeyed
	if !hadCrypto || keyChanged {
		tm.sendKeyExchangeToNode(peerNodeID)
	}

	// P1-010 desync salvage: see handleAuthKeyExchange for rationale.
	if keyChanged && oldPC != nil {
		tm.mu.RLock()
		replayAddr := tm.peers[peerNodeID]
		tm.mu.RUnlock()
		tm.replaySalvage(oldPC, pc, peerNodeID, replayAddr)
	}

	// Flush any pending packets now that encryption is ready
	tm.flushPending(peerNodeID)
}

// handleEncrypted decrypts an incoming encrypted packet.
// Format: [4-byte nodeID][12-byte nonce][ciphertext+GCM tag]
func (tm *TunnelManager) handleEncrypted(data []byte, from *net.UDPAddr) {
	if len(data) < 4+12+16 { // nodeID + nonce + min GCM tag
		return
	}

	peerNodeID := binary.BigEndian.Uint32(data[0:4])
	nonce := data[4:16]
	ciphertext := data[16:]

	tm.mu.RLock()
	pc := tm.crypto[peerNodeID]
	tm.mu.RUnlock()

	if pc == nil || !pc.ready {
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
	}

	// Replay detection using sliding window bitmap (H8 fix)
	recvCounter := binary.BigEndian.Uint64(nonce[len(nonce)-8:])
	pc.replayMu.Lock()
	ok := pc.checkAndRecordNonce(recvCounter)
	maxN := pc.maxRecvNonce
	pc.replayMu.Unlock()
	if !ok {
		// Distinguish "packet older than our window" (common under
		// reordering / late retransmission in high-throughput traffic)
		// from a real replay (counter we've already accepted). Only the
		// latter is a security event worth paging on.
		if recvCounter < maxN && maxN-recvCounter >= replayWindowSize {
			slog.Warn("tunnel packet outside replay window",
				"peer_node_id", peerNodeID, "counter", recvCounter, "max", maxN)
			// A counter that is dramatically smaller than our max strongly
			// suggests the peer replaced their peerCrypto (e.g. after a
			// half-rekey whose reply to us was lost) and is now sending from
			// a fresh counter while our state is frozen at the old high
			// max. Send a rate-limited key-exchange so the peer re-establishes
			// symmetrically; on the reply we'll install a fresh peerCrypto
			// ourselves and start accepting their new-session packets.
			if recvCounter < 1024 {
				tm.maybeRequestRekey(peerNodeID, from)
			}
		} else {
			slog.Warn("tunnel nonce replay detected",
				"peer_node_id", peerNodeID, "counter", recvCounter, "max", maxN)
			tm.webhook.Emit("security.nonce_replay", map[string]interface{}{
				"peer_node_id": peerNodeID, "counter": recvCounter,
			})
			// v1.9.1 peer-restart resync: a "replay" with a counter in the
			// low-counter zone (< 1024) is far more likely to be a peer
			// that just restarted and resumed from 1 than a real replay
			// attack. Real attacks reuse a HIGH counter captured from the
			// active session — the attacker has no way to lower their
			// own counter without our private key. Trigger a rate-limited
			// rekey so the peer (still alive on the wire) can re-establish
			// crypto. Rate limiting (rekeyRequestInterval) prevents
			// amplification if a real attacker tries to force key rotation
			// by spraying low-counter ciphertexts.
			if recvCounter < 1024 {
				tm.maybeRequestRekey(peerNodeID, from)
			}
		}
		return
	}

	// H3 fix: verify sender's nodeID as AAD
	aad := make([]byte, 4)
	binary.BigEndian.PutUint32(aad, peerNodeID)
	plaintext, err := pc.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		atomic.AddUint64(&tm.EncryptFail, 1)
		slog.Error("tunnel decrypt error", "peer_node_id", peerNodeID, "error", err)
		// Undo the nonce record on decrypt failure — it was not a valid packet
		pc.replayMu.Lock()
		bit := recvCounter % replayWindowSize
		pc.replayBitmap[bit/64] &^= 1 << (bit % 64)
		pc.replayMu.Unlock()
		// Track consecutive AEAD failures. When the count exceeds
		// decryptFailDropThreshold the peer's session keys have demonstrably
		// diverged from ours (older daemon versions drift into states where
		// their derived AEAD key no longer matches even with the same X25519
		// pubkey — likely an HKDF info-string or session-id mismatch).
		// Drop the peerCrypto and request a fresh exchange. Equivalent to
		// the "stop and start the daemon" recovery, but automatic.
		tm.mu.Lock()
		pc.decryptFailCount++
		failures := pc.decryptFailCount
		shouldDrop := failures >= decryptFailDropThreshold && tm.crypto[peerNodeID] == pc
		if shouldDrop {
			delete(tm.crypto, peerNodeID)
		}
		tm.mu.Unlock()
		if shouldDrop {
			slog.Warn("tunnel: peer crypto key divergence detected, dropping session and re-handshaking",
				"peer_node_id", peerNodeID, "consecutive_decrypt_failures", failures)
			tm.maybeRequestRekey(peerNodeID, from)
		}
		return
	}
	// Successful decrypt — reset the AEAD failure counter.
	if pc.decryptFailCount != 0 {
		tm.mu.Lock()
		pc.decryptFailCount = 0
		tm.mu.Unlock()
	}

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
	tm.mu.Lock()
	cleared := tm.clearRelayOnDirectLocked(peerNodeID, from)
	if from != nil {
		fromBeacon := tm.beaconAddr != nil &&
			from.IP.Equal(tm.beaconAddr.IP) && from.Port == tm.beaconAddr.Port
		if !fromBeacon {
			tm.lastDirectRecv[peerNodeID] = time.Now()
			tm.peers[peerNodeID] = from
		}
	}
	tm.mu.Unlock()
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

// deriveSecret computes a shared AES-256-GCM cipher from the peer's public key.
func (tm *TunnelManager) deriveSecret(peerPubKeyBytes []byte) (*peerCrypto, error) {
	if tm.privKey == nil {
		return nil, fmt.Errorf("no private key")
	}

	curve := ecdh.X25519()
	peerKey, err := curve.NewPublicKey(peerPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse peer key: %w", err)
	}

	shared, err := tm.privKey.ECDH(peerKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}

	// HKDF-SHA256 key derivation (H1 fix)
	mac := hmac.New(sha256.New, nil) // HKDF-Extract: PRK = HMAC-SHA256(nil salt, IKM)
	mac.Write(shared)
	prk := mac.Sum(nil)
	mac = hmac.New(sha256.New, prk) // HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
	mac.Write([]byte("pilot-tunnel-v1"))
	mac.Write([]byte{0x01})
	key := mac.Sum(nil)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	// Zero intermediate key material (H4 fix)
	for i := range shared {
		shared[i] = 0
	}
	for i := range key {
		key[i] = 0
	}
	for i := range prk {
		prk[i] = 0
	}

	// Generate random nonce prefix for domain separation
	pc := &peerCrypto{aead: aead, ready: true, createdAt: time.Now()}
	copy(pc.peerX25519Key[:], peerPubKeyBytes)
	if _, err := rand.Read(pc.noncePrefix[:]); err != nil {
		return nil, fmt.Errorf("nonce prefix: %w", err)
	}

	return pc, nil
}

// sendKeyExchangeToNode sends an authenticated key exchange if identity is available,
// otherwise falls back to unauthenticated. Uses nodeID-based routing (relay-aware).
func (tm *TunnelManager) sendKeyExchangeToNode(peerNodeID uint32) {
	tm.mu.RLock()
	hasIdentity := tm.identity != nil
	addr := tm.peers[peerNodeID]
	tm.mu.RUnlock()

	frame := tm.buildKeyExchangeFrame()
	if frame == nil {
		return
	}

	if hasIdentity {
		authFrame := tm.buildAuthKeyExchangeFrame()
		if authFrame != nil {
			frame = authFrame
		}
	}

	if err := tm.writeFrame(peerNodeID, addr, frame); err != nil {
		slog.Error("send key exchange failed", "peer_node_id", peerNodeID, "error", err)
		return
	}

	// P1-010 tunnel-state half: register that we're waiting on a reply,
	// so rekeyRetransmitLoop can retransmit if the peer's response (or
	// our request) was dropped under loss.
	tm.markPendingRekey(peerNodeID)
}

// markPendingRekey records that we sent a key_exchange to peerNodeID and
// are awaiting confirmation (a successful decrypt from peer). Idempotent —
// re-calls bump lastSentAt and attempts but preserve firstSentAt.
func (tm *TunnelManager) markPendingRekey(peerNodeID uint32) {
	now := time.Now()
	tm.rkPendingMu.Lock()
	st, ok := tm.pendingRekey[peerNodeID]
	if !ok {
		st = &pendingRekeyState{firstSentAt: now}
		tm.pendingRekey[peerNodeID] = st
	}
	st.lastSentAt = now
	st.attempts++
	tm.rkPendingMu.Unlock()
}

// clearPendingRekey is called after a successful decrypt from peer — proves
// peer has matching crypto, so any in-flight key_exchange is no longer
// pending.
func (tm *TunnelManager) clearPendingRekey(peerNodeID uint32) {
	tm.rkPendingMu.Lock()
	delete(tm.pendingRekey, peerNodeID)
	tm.rkPendingMu.Unlock()
}

// recordInboundDecrypt updates the per-peer last-decrypt timestamp. Used
// by handleAuthKeyExchange to gate its "reply with our key_exchange too"
// loosening (don't reply if we just decrypted from peer — they have a
// matching key).
func (tm *TunnelManager) recordInboundDecrypt(peerNodeID uint32) {
	tm.rkPendingMu.Lock()
	tm.lastInboundDecrypt[peerNodeID] = time.Now()
	tm.rkPendingMu.Unlock()

	// v1.9.1 ICMP-aware fix: a successful inbound decrypt is proof the
	// peer is alive and reachable. Clear any accumulated send-error
	// count so a future transient ICMP-unreachable burst doesn't
	// trip the relay flip on a freshly-recovered peer.
	tm.mu.Lock()
	delete(tm.sendErrCount, peerNodeID)
	tm.mu.Unlock()
}

// inboundDecryptStale returns true if we haven't successfully decrypted
// any packet from peerNodeID within the staleness window. Used to decide
// whether to re-reply with our key_exchange when peer keeps sending us
// theirs (suggests our previous reply was dropped).
func (tm *TunnelManager) inboundDecryptStale(peerNodeID uint32) bool {
	tm.rkPendingMu.Lock()
	t, ok := tm.lastInboundDecrypt[peerNodeID]
	tm.rkPendingMu.Unlock()
	if !ok {
		return true
	}
	return time.Since(t) > keyExchangeReplyStaleThreshold
}

// rekeyRetransmitLoop runs every rekeyRetransmitInterval, scans
// pendingRekey, and retransmits stale entries. Caps retries at
// maxRekeyAttempts to avoid hammering an unreachable peer indefinitely.
// Exits on tm.done.
func (tm *TunnelManager) rekeyRetransmitLoop() {
	t := time.NewTicker(rekeyRetransmitInterval)
	defer t.Stop()
	for {
		select {
		case <-tm.done:
			return
		case <-t.C:
			tm.rekeyRetransmitTick()
		}
	}
}

// rekeyRetransmitTick is the per-tick body of rekeyRetransmitLoop, split
// out so it's directly testable without a real ticker.
func (tm *TunnelManager) rekeyRetransmitTick() {
	now := time.Now()
	type retry struct {
		peerNodeID uint32
		attempts   int
	}
	var toRetry []retry
	var toGiveUp []uint32

	tm.rkPendingMu.Lock()
	for peerNodeID, st := range tm.pendingRekey {
		if st.attempts >= maxRekeyAttempts+1 {
			toGiveUp = append(toGiveUp, peerNodeID)
			continue
		}
		if now.Sub(st.lastSentAt) < rekeyRetransmitInterval {
			continue
		}
		toRetry = append(toRetry, retry{peerNodeID: peerNodeID, attempts: st.attempts})
	}
	for _, id := range toGiveUp {
		delete(tm.pendingRekey, id)
	}
	tm.rkPendingMu.Unlock()

	for _, r := range toRetry {
		slog.Info("rekey retransmit",
			"peer_node_id", r.peerNodeID,
			"attempt", r.attempts+1,
			"max", maxRekeyAttempts+1)
		// sendKeyExchangeToNode calls markPendingRekey, which bumps the
		// counter and lastSentAt — we don't need to do that ourselves.
		tm.sendKeyExchangeToNode(r.peerNodeID)
	}
	for _, id := range toGiveUp {
		slog.Warn("rekey retransmit gave up after maxRekeyAttempts",
			"peer_node_id", id, "max", maxRekeyAttempts+1)
		if tm.webhook != nil {
			tm.webhook.Emit("tunnel.rekey_gave_up", map[string]interface{}{
				"peer_node_id": id,
			})
		}
	}
}

// buildAuthKeyExchangeFrame builds an authenticated key exchange frame.
// Returns nil if identity is not available.
func (tm *TunnelManager) buildAuthKeyExchangeFrame() []byte {
	tm.mu.RLock()
	id := tm.identity
	tm.mu.RUnlock()
	if tm.pubKey == nil || id == nil {
		return nil
	}

	challenge := make([]byte, 4+4+32)
	copy(challenge[0:4], []byte("auth"))
	binary.BigEndian.PutUint32(challenge[4:8], tm.loadNodeID())
	copy(challenge[8:40], tm.pubKey)
	signature := id.Sign(challenge)

	ed25519PubKey := []byte(id.PublicKey)

	frame := make([]byte, 4+4+32+32+64)
	copy(frame[0:4], protocol.TunnelMagicAuthEx[:])
	binary.BigEndian.PutUint32(frame[4:8], tm.loadNodeID())
	copy(frame[8:40], tm.pubKey)
	copy(frame[40:72], ed25519PubKey)
	copy(frame[72:136], signature)
	return frame
}

// buildKeyExchangeFrame builds an unauthenticated key exchange frame.
func (tm *TunnelManager) buildKeyExchangeFrame() []byte {
	if tm.pubKey == nil {
		return nil
	}
	frame := make([]byte, 4+4+32)
	copy(frame[0:4], protocol.TunnelMagicKeyEx[:])
	binary.BigEndian.PutUint32(frame[4:8], tm.loadNodeID())
	copy(frame[8:40], tm.pubKey)
	return frame
}

// recordSalvage stashes a plaintext send into the per-peerCrypto ring buffer.
// On a subsequent peer-initiated rekey, replaySalvage will re-encrypt with the
// new key and re-send — recovering data that the peer dropped because our
// frame was keyed under their now-stale crypto context.
//
// Bounded by salvageMaxEntries and salvageMaxAge. The plaintext is copied,
// not referenced — caller can reuse its buffer.
func (tm *TunnelManager) recordSalvage(pc *peerCrypto, plaintext []byte) {
	if pc == nil {
		return
	}
	now := time.Now()
	cutoff := now.Add(-salvageMaxAge)
	pc.salvageMu.Lock()
	// Trim aged entries from the head.
	for len(pc.salvage) > 0 && pc.salvage[0].when.Before(cutoff) {
		pc.salvage = pc.salvage[1:]
	}
	// Bound size — drop oldest.
	if len(pc.salvage) >= salvageMaxEntries {
		pc.salvage = pc.salvage[1:]
	}
	cp := make([]byte, len(plaintext))
	copy(cp, plaintext)
	pc.salvage = append(pc.salvage, salvageEntry{plaintext: cp, when: now})
	pc.salvageMu.Unlock()
}

// replaySalvage re-encrypts plaintext from oldPC's ring buffer with newPC's
// key and ships it via writeFrame. Called when handleAuthKeyExchange or
// handleKeyExchange installs a fresh crypto context that replaces a previous
// one (keyChanged=true). This is the data-recovery half of the P1-010 fix —
// the rekey itself was already in place, but the data sent under the stale
// key was being lost.
func (tm *TunnelManager) replaySalvage(oldPC, newPC *peerCrypto, peerNodeID uint32, addr *net.UDPAddr) {
	if oldPC == nil || newPC == nil || addr == nil {
		return
	}
	oldPC.salvageMu.Lock()
	entries := oldPC.salvage
	oldPC.salvage = nil
	oldPC.salvageMu.Unlock()
	if len(entries) == 0 {
		return
	}
	cutoff := time.Now().Add(-salvageMaxAge)
	replayed := 0
	for _, e := range entries {
		if e.when.Before(cutoff) {
			continue
		}
		encrypted := tm.encryptFrame(newPC, e.plaintext)
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
		if tm.webhook != nil {
			tm.webhook.Emit("tunnel.desync_salvage", map[string]interface{}{
				"peer_node_id": peerNodeID,
				"replayed":     replayed,
			})
		}
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
	pc := tm.crypto[nodeID]
	tm.mu.RUnlock()

	if pc == nil || !pc.ready {
		return
	}

	for _, plaintext := range frames {
		encrypted := tm.encryptFrame(pc, plaintext)
		if err := tm.writeFrame(nodeID, addr, encrypted); err != nil {
			slog.Error("flush pending to node failed", "node_id", nodeID, "error", err)
		}
	}
	slog.Debug("flushed pending packets", "node_id", nodeID, "count", len(frames))
}

// encryptFrame encrypts a marshaled packet and returns a full tunnel frame.
// Format: [PILS][4-byte nodeID][12-byte nonce][ciphertext+GCM tag]
func (tm *TunnelManager) encryptFrame(pc *peerCrypto, plaintext []byte) []byte {
	nonce := make([]byte, pc.aead.NonceSize())
	copy(nonce[0:4], pc.noncePrefix[:])
	counter := atomic.AddUint64(&pc.nonce, 1)
	binary.BigEndian.PutUint64(nonce[pc.aead.NonceSize()-8:], counter)

	// H3 fix: bind sender's nodeID as AAD
	aad := make([]byte, 4)
	binary.BigEndian.PutUint32(aad, tm.loadNodeID())
	ciphertext := pc.aead.Seal(nil, nonce, plaintext, aad)
	atomic.AddUint64(&tm.EncryptOK, 1)

	frame := make([]byte, 4+4+len(nonce)+len(ciphertext))
	copy(frame[0:4], protocol.TunnelMagicSecure[:])
	binary.BigEndian.PutUint32(frame[4:8], tm.loadNodeID())
	copy(frame[8:8+len(nonce)], nonce)
	copy(frame[8+len(nonce):], ciphertext)

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
	beacon := tm.beaconAddr
	pc := tm.crypto[nodeID]
	tm.mu.RUnlock()

	if addr == nil {
		return fmt.Errorf("no peer endpoint for node %d", nodeID)
	}
	if beacon != nil && addr.IP.Equal(beacon.IP) && addr.Port == beacon.Port {
		return fmt.Errorf("stored endpoint for node %d is beacon placeholder", nodeID)
	}

	data, err := pkt.Marshal()
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	var frame []byte
	if tm.encrypt {
		if pc == nil || !pc.ready {
			return fmt.Errorf("no crypto for node %d", nodeID)
		}
		frame = tm.encryptFrame(pc, data)
	} else {
		frame = make([]byte, 4+len(data))
		copy(frame[0:4], protocol.TunnelMagic[:])
		copy(frame[4:], data)
	}

	n, werr := tm.conn.WriteToUDP(frame, addr)
	if werr == nil {
		atomic.AddUint64(&tm.PktsSent, 1)
		atomic.AddUint64(&tm.BytesSent, uint64(n))
	}
	return werr
}

// clearRelayOnDirectLocked clears the relay flag for a peer when a packet
// arrives from a non-beacon UDP address. Called from handleEncrypted after
// successful decryption. Must be called with tm.mu held for writing.
//
// v1.9.1: hysteresis applied. Clearing now requires directClearsRequired
// consecutive direct-from-peer packets so a single direct burst during a
// relay stretch (a stray packet from a brief NAT path opening) doesn't
// bounce us back to direct only to flap immediately. Each non-beacon
// receipt also resets the blackholeMissCount so writeFrame's flip
// counter accurately tracks "consecutive misses since the last
// confirmed direct packet."
func (tm *TunnelManager) clearRelayOnDirectLocked(peerNodeID uint32, from *net.UDPAddr) bool {
	if from == nil {
		return false
	}
	if tm.beaconAddr != nil && from.IP.Equal(tm.beaconAddr.IP) && from.Port == tm.beaconAddr.Port {
		return false
	}
	// A direct packet just arrived. Reset blackholeMissCount unconditionally
	// — the writeFrame heuristic should restart its counter on every fresh
	// direct receipt, regardless of whether we're in relay mode.
	tm.blackholeMissCount[peerNodeID] = 0

	// v1.9.1-rc2 (2026-05-03): auto-clear DISABLED.
	//
	// The previous heuristic (3 consecutive non-beacon packets → clear
	// relay flag) was unreliable in production environments where:
	//   - GCP NAT can rewrite the source port of beacon-originated UDP
	//     replies, making them appear non-beacon to the IP+port equality
	//     check above.
	//   - Beacon mesh can forward relay packets via a peer beacon, so
	//     replies arrive from a different IP than tm.beaconAddr.
	//   - Stray packets (NAT punch responses, ICMP unreachable) leak in
	//     during relay-stable periods.
	//
	// Once any of those triggers ≥3 fake-direct observations, the relay
	// flag flips to false. The next outgoing packet goes direct, fails
	// (peer is genuinely behind a NAT direct can't traverse), then
	// writeFrame's silent-detection takes ~60s to flip back to relay.
	// During that 60s window, encrypted data sends fail and any rekey
	// attempts rotate session keys faster than they can settle. User-
	// visible symptom: "ping works for a minute then dial timeout for
	// minutes". Repro-reliable in this fleet, fixed by removing the
	// auto-clear. The counter reset above is preserved as a no-op
	// observation; the flag itself stays put. If a peer's relay status
	// genuinely changes (rare — operator scenario), the next dial cycle
	// will rediscover and re-pin via direct/relay/punch logic.
	_ = peerNodeID
	return false
}

// SetRelayPeerPinned is like SetRelayPeer but also marks the relay flag
// as authoritative — clearRelayOnDirectLocked will never auto-flip a
// pinned peer back to direct based on observed packet sources. Used
// by ensureTunnel when the registry's resolve response carries
// relay_only=true.
func (tm *TunnelManager) SetRelayPeerPinned(nodeID uint32, relay bool) {
	tm.mu.Lock()
	tm.relayPeers[nodeID] = relay
	tm.relayPinned[nodeID] = relay
	if !relay {
		// Caller is explicitly clearing both flag and pin.
		delete(tm.relayPinned, nodeID)
	}
	tm.mu.Unlock()
}

// SendTo sends a packet to a specific UDP address (relay-aware).
func (tm *TunnelManager) SendTo(addr *net.UDPAddr, nodeID uint32, pkt *protocol.Packet) error {
	data, err := pkt.Marshal()
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	// Check if we should encrypt
	if tm.encrypt {
		tm.mu.RLock()
		pc := tm.crypto[nodeID]
		tm.mu.RUnlock()

		if pc != nil && pc.ready {
			// Record plaintext for desync salvage BEFORE encrypting. If the
			// peer has lost their key (silent restart, packet-loss-induced
			// rekey), they'll drop this frame and send us a rekey request;
			// handleAuthKeyExchange will replay the salvage with the new
			// key. See P1-010.
			tm.recordSalvage(pc, data)
			frame := tm.encryptFrame(pc, data)
			return tm.writeFrame(nodeID, addr, frame)
		}

		// No key yet — initiate key exchange and queue the packet (C1 fix: no plaintext fallback)
		tm.sendKeyExchangeToNode(nodeID)
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

	// If encryption is enabled, initiate key exchange (relay-aware)
	if tm.encrypt {
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
	tm.mu.Lock()
	delete(tm.peers, nodeID)
	delete(tm.crypto, nodeID)
	delete(tm.lastOutboundSend, nodeID)
	delete(tm.sendErrCount, nodeID)
	delete(tm.lastDirectRecv, nodeID)
	delete(tm.blackholeMissCount, nodeID)
	delete(tm.directClearCount, nodeID)
	delete(tm.relayPeers, nodeID)
	delete(tm.relayPinned, nodeID)
	delete(tm.peerPubKeys, nodeID)
	tm.mu.Unlock()

	// pendingRekey + lastInboundDecrypt live under a separate mutex.
	tm.rkPendingMu.Lock()
	delete(tm.pendingRekey, nodeID)
	delete(tm.lastInboundDecrypt, nodeID)
	tm.rkPendingMu.Unlock()
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
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	_, ok := tm.crypto[nodeID]
	return ok
}

// IsEncrypted returns true if the tunnel to a peer is encrypted.
func (tm *TunnelManager) IsEncrypted(nodeID uint32) bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	pc := tm.crypto[nodeID]
	return pc != nil && pc.ready
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
		pc := tm.crypto[id]
		list = append(list, PeerInfo{
			NodeID:        id,
			Endpoint:      addr.String(),
			Encrypted:     pc != nil && pc.ready,
			Authenticated: pc != nil && pc.authenticated,
			Relay:         tm.relayPeers[id],
		})
	}
	return list
}

// handleBeaconMessage processes beacon protocol messages received on the tunnel socket.
func (tm *TunnelManager) handleBeaconMessage(data []byte, from *net.UDPAddr) {
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
// to the specified target to create a NAT mapping.
func (tm *TunnelManager) handlePunchCommand(data []byte) {
	// Format: [iplen(1)][IP(4 or 16)][port(2)]
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

	// Send punch packets to create NAT mapping (send multiple for reliability)
	punch := make([]byte, 4)
	copy(punch, protocol.TunnelMagicPunch[:])
	for i := 0; i < 3; i++ {
		tm.conn.WriteToUDP(punch, addr)
	}
	slog.Info("NAT punch sent", "target", addr)
}

// maxRelayPeers caps the relayPeers map. The beacon relays packets to us with
// a caller-supplied srcNodeID, so without a bound an attacker who can get the
// beacon to forward frames to us — or who operates a hostile beacon — can
// grow relayPeers indefinitely, pollute the peers map with beaconAddr aliases,
// and emit a "tunnel.relay_activated" webhook per unique spoofed ID. Real
// networks never approach this cap.
const maxRelayPeers = 4096

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
	tm.mu.Lock()
	_, hadCrypto := tm.crypto[srcNodeID]
	wasRelay := tm.relayPeers[srcNodeID]
	if hadCrypto {
		if !wasRelay && len(tm.relayPeers) >= maxRelayPeers {
			tm.mu.Unlock()
			slog.Warn("relay peers cap reached, dropping relay packet", "src_node_id", srcNodeID)
			return
		}
		tm.relayPeers[srcNodeID] = true
		if _, ok := tm.peers[srcNodeID]; !ok && tm.beaconAddr != nil {
			tm.peers[srcNodeID] = tm.beaconAddr
		}
	}
	tm.mu.Unlock()
	if hadCrypto && !wasRelay {
		tm.webhook.Emit("tunnel.relay_activated", map[string]interface{}{
			"peer_node_id": srcNodeID,
		})
	}

	if len(payload) < 4 {
		return
	}

	// Get peer's stored address for packet handling. For relay-delivered
	// packets the *physical* source was the beacon; handleEncrypted's
	// clearRelayOnDirectLocked uses `from` to decide whether the direct
	// path has recovered, so we must report the beacon as the source
	// rather than a stale peers[] entry (which on the dialer side is the
	// direct endpoint returned by ensureTunnel). Passing a non-beacon
	// `from` would incorrectly auto-clear the relay flag on the very
	// first relay-delivered packet, causing subsequent sends to try
	// direct again — fatal under dual-symmetric NAT.
	tm.mu.RLock()
	beaconAddr := tm.beaconAddr
	tm.mu.RUnlock()
	srcAddr := beaconAddr
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

// DiscoverEndpoint sends a STUN discover to the beacon and returns the observed public endpoint.
func DiscoverEndpoint(beaconAddr string, nodeID uint32, conn *net.UDPConn) (*net.UDPAddr, error) {
	bAddr, err := net.ResolveUDPAddr("udp", beaconAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve beacon: %w", err)
	}

	// Send discover message
	msg := make([]byte, 5)
	msg[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(msg[1:5], nodeID)

	if _, err := conn.WriteToUDP(msg, bAddr); err != nil {
		return nil, fmt.Errorf("send discover: %w", err)
	}

	// Read reply
	buf := make([]byte, 64)
	conn.SetReadDeadline(fixedTimeout())
	n, _, err := conn.ReadFromUDP(buf)
	conn.SetReadDeadline(zeroTime())
	if err != nil {
		return nil, fmt.Errorf("discover reply: %w", err)
	}

	// Format: [type(1)][iplen(1)][IP(4 or 16)][port(2)]
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

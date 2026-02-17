package daemon

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/internal/pool"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// replayWindowSize is the number of nonces tracked in the sliding window bitmap
// for replay detection (H8 fix). Nonces within [maxNonce-replayWindowSize, maxNonce]
// are tracked; nonces below the window are rejected.
const replayWindowSize = 256

// peerCrypto holds per-peer encryption state.
type peerCrypto struct {
	aead          cipher.AEAD
	nonce         uint64   // monotonic send counter (atomic)
	noncePrefix   [4]byte  // random prefix for nonce domain separation
	// Replay detection (H8 fix): sliding window bitmap instead of simple high-water mark.
	replayMu      sync.Mutex
	maxRecvNonce  uint64                         // highest nonce received
	replayBitmap  [replayWindowSize / 64]uint64  // bitmap for nonces in [max-windowSize, max]
	ready         bool     // true once key exchange is complete
	authenticated bool     // true if peer proved Ed25519 identity
	peerX25519Key [32]byte // peer's X25519 public key (for detecting rekeying)
}

// checkAndRecordNonce returns true if the nonce is valid (not replayed, not too old).
// Must be called with replayMu held.
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
	peers     map[uint32]*net.UDPAddr  // node_id → real UDP endpoint
	crypto    map[uint32]*peerCrypto   // node_id → encryption state
	recvCh    chan *IncomingPacket
	done      chan struct{}             // closed on Close() to stop readLoop sends
	readWg    sync.WaitGroup           // tracks readLoop goroutine for clean shutdown
	closeOnce sync.Once

	// Encryption config
	encrypt bool                  // if true, attempt encrypted tunnels
	privKey *ecdh.PrivateKey      // our X25519 private key
	pubKey  []byte                // our X25519 public key (32 bytes)
	nodeID  uint32                // our node ID (set after registration)

	// Identity authentication (Ed25519)
	identity    *crypto.Identity                  // our Ed25519 identity for signing
	peerPubKeys map[uint32]ed25519.PublicKey       // node_id → Ed25519 pubkey (from registry)
	verifyFunc  func(uint32) (ed25519.PublicKey, error) // callback to fetch peer pubkey

	// Pending sends waiting for key exchange to complete
	pendMu   sync.Mutex
	pending  map[uint32][][]byte  // node_id → queued frames

	// NAT traversal: beacon-coordinated hole-punching and relay
	beaconAddr *net.UDPAddr            // beacon address for punch/relay
	relayPeers map[uint32]bool         // peers that need relay (symmetric NAT)

	// Webhook
	webhook *WebhookClient

	// Metrics
	BytesSent uint64
	BytesRecv uint64
	PktsSent  uint64
	PktsRecv  uint64
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

// RecvChSize is the capacity of the incoming packet channel.
const RecvChSize = 1024

func NewTunnelManager() *TunnelManager {
	return &TunnelManager{
		peers:       make(map[uint32]*net.UDPAddr),
		crypto:      make(map[uint32]*peerCrypto),
		peerPubKeys: make(map[uint32]ed25519.PublicKey),
		pending:     make(map[uint32][][]byte),
		relayPeers:  make(map[uint32]bool),
		recvCh:      make(chan *IncomingPacket, RecvChSize),
		done:        make(chan struct{}),
	}
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

// SetPeerPubKey caches a peer's Ed25519 public key for authentication.
func (tm *TunnelManager) SetPeerPubKey(nodeID uint32, pubKey ed25519.PublicKey) {
	tm.mu.Lock()
	tm.peerPubKeys[nodeID] = pubKey
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

// writeFrame sends a raw frame to a peer, using relay through the beacon if needed.
func (tm *TunnelManager) writeFrame(nodeID uint32, addr *net.UDPAddr, frame []byte) error {
	tm.mu.RLock()
	relay := tm.relayPeers[nodeID]
	bAddr := tm.beaconAddr
	tm.mu.RUnlock()

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
	}
	return err
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
	return nil
}

func (tm *TunnelManager) Close() error {
	var connErr error
	tm.closeOnce.Do(func() {
		close(tm.done) // signal readLoop to stop sending
		if tm.conn != nil {
			connErr = tm.conn.Close() // causes readLoop to exit on ReadFromUDP error
		}
		tm.readWg.Wait()  // wait for readLoop to fully exit before closing recvCh
		close(tm.recvCh)  // unblock routeLoop (H5 fix — prevents goroutine leak)
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

	// Verify the packet-provided Ed25519 pubkey matches the registry
	if !peerEd25519PubKey.Equal(expectedPubKey) {
		slog.Error("auth key exchange: Ed25519 pubkey mismatch with registry", "peer_node_id", peerNodeID)
		return
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
	tm.crypto[peerNodeID] = pc
	if !fromRelay {
		tm.peers[peerNodeID] = from
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
	tm.mu.RUnlock()
	if hasIdentity {
		expectedPubKey, err := tm.getPeerPubKey(peerNodeID)
		if err == nil && expectedPubKey != nil {
			slog.Warn("rejecting unauthenticated key exchange from peer with known identity", "peer_node_id", peerNodeID)
			tm.sendKeyExchangeToNode(peerNodeID)
			return
		}
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
	tm.crypto[peerNodeID] = pc
	if !fromRelay {
		tm.peers[peerNodeID] = from
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
		slog.Warn("encrypted packet from node but no key", "peer_node_id", peerNodeID)
		return
	}

	// Replay detection using sliding window bitmap (H8 fix)
	recvCounter := binary.BigEndian.Uint64(nonce[len(nonce)-8:])
	pc.replayMu.Lock()
	if !pc.checkAndRecordNonce(recvCounter) {
		pc.replayMu.Unlock()
		slog.Warn("tunnel nonce replay detected", "peer_node_id", peerNodeID, "counter", recvCounter, "max", pc.maxRecvNonce)
		tm.webhook.Emit("security.nonce_replay", map[string]interface{}{
			"peer_node_id": peerNodeID, "counter": recvCounter,
		})
		return
	}
	pc.replayMu.Unlock()

	plaintext, err := pc.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		slog.Error("tunnel decrypt error", "peer_node_id", peerNodeID, "error", err)
		// Undo the nonce record on decrypt failure — it was not a valid packet
		pc.replayMu.Lock()
		bit := recvCounter % replayWindowSize
		pc.replayBitmap[bit/64] &^= 1 << (bit % 64)
		pc.replayMu.Unlock()
		return
	}

	pkt, err := protocol.Unmarshal(plaintext)
	if err != nil {
		slog.Error("tunnel unmarshal error after decrypt", "peer_node_id", peerNodeID, "error", err)
		return
	}

	atomic.AddUint64(&tm.PktsRecv, 1)
	atomic.AddUint64(&tm.BytesRecv, uint64(len(data)+4)) // +4 for PILS magic
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

	// Derive key with domain separator
	h := sha256.New()
	h.Write([]byte("pilot-tunnel-v1:"))
	h.Write(shared)
	key := h.Sum(nil)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	// Generate random nonce prefix for domain separation
	pc := &peerCrypto{aead: aead, ready: true}
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

// sendKeyExchangeAuto sends an authenticated key exchange if identity is available,
// otherwise falls back to unauthenticated. Uses addr-based direct send (for backward compat).
func (tm *TunnelManager) sendKeyExchangeAuto(addr *net.UDPAddr) {
	tm.mu.RLock()
	hasIdentity := tm.identity != nil
	tm.mu.RUnlock()
	if hasIdentity {
		tm.sendAuthKeyExchange(addr)
	} else {
		tm.sendKeyExchange(addr)
	}
}

// sendAuthKeyExchange sends our X25519 public key + Ed25519 signature to a peer (direct).
func (tm *TunnelManager) sendAuthKeyExchange(addr *net.UDPAddr) {
	frame := tm.buildAuthKeyExchangeFrame()
	if frame == nil {
		tm.sendKeyExchange(addr)
		return
	}
	if _, err := tm.conn.WriteToUDP(frame, addr); err != nil {
		slog.Error("send auth key exchange failed", "addr", addr, "error", err)
	}
}

// sendKeyExchange sends our public key to a peer (unauthenticated, direct).
func (tm *TunnelManager) sendKeyExchange(addr *net.UDPAddr) {
	frame := tm.buildKeyExchangeFrame()
	if frame == nil {
		return
	}
	if _, err := tm.conn.WriteToUDP(frame, addr); err != nil {
		slog.Error("send key exchange failed", "addr", addr, "error", err)
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

	ciphertext := pc.aead.Seal(nil, nonce, plaintext, nil)

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
			frame := tm.encryptFrame(pc, data)
			return tm.writeFrame(nodeID, addr, frame)
		}

		// No key yet — initiate key exchange and queue the packet
		tm.sendKeyExchangeToNode(nodeID)
		tm.pendMu.Lock()
		if _, exists := tm.pending[nodeID]; !exists && len(tm.pending) >= maxPendingPeers {
			tm.pendMu.Unlock()
			return tm.sendPlaintextToNode(nodeID, addr, data)
		}
		q := tm.pending[nodeID]
		if len(q) >= maxPendingPerPeer {
			q = q[1:]
		}
		tm.pending[nodeID] = append(q, data)
		tm.pendMu.Unlock()

		// Also send plaintext so the connection isn't blocked
		return tm.sendPlaintextToNode(nodeID, addr, data)
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

// RemovePeer removes a peer.
func (tm *TunnelManager) RemovePeer(nodeID uint32) {
	tm.mu.Lock()
	delete(tm.peers, nodeID)
	delete(tm.crypto, nodeID)
	tm.mu.Unlock()
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

// handleRelayDeliver processes a beacon relay delivery, extracting the inner tunnel frame.
func (tm *TunnelManager) handleRelayDeliver(data []byte) {
	// Format: [srcNodeID(4)][payload...]
	if len(data) < 5 {
		return
	}
	srcNodeID := binary.BigEndian.Uint32(data[0:4])
	payload := data[4:]

	// Mark this peer as relay-capable (they sent through relay, so they're behind NAT)
	tm.mu.Lock()
	wasRelay := tm.relayPeers[srcNodeID]
	tm.relayPeers[srcNodeID] = true
	// Ensure we have a peer entry (use beacon addr as placeholder for relay peers)
	if _, ok := tm.peers[srcNodeID]; !ok && tm.beaconAddr != nil {
		tm.peers[srcNodeID] = tm.beaconAddr
	}
	tm.mu.Unlock()
	if !wasRelay {
		tm.webhook.Emit("tunnel.relay_activated", map[string]interface{}{
			"peer_node_id": srcNodeID,
		})
	}

	if len(payload) < 4 {
		return
	}

	// Get peer's stored address for packet handling
	tm.mu.RLock()
	srcAddr := tm.peers[srcNodeID]
	tm.mu.RUnlock()
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

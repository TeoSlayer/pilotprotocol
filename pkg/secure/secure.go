package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// MaxEncryptedMessageLen limits the maximum decrypted message size to prevent
// memory exhaustion from a malicious peer advertising a huge msgLen.
const MaxEncryptedMessageLen = 16 * 1024 * 1024 // 16 MB

// HandshakeTimeout is the maximum time allowed for the ECDH handshake.
const HandshakeTimeout = 10 * time.Second

// authFrameLen is the total size of an auth frame:
// nodeID(4) + timestamp(8) + nonce(16) + ed25519_signature(64) = 92 bytes.
const authFrameLen = 4 + 8 + 16 + 64

// authTimestampSkew is the maximum allowed time difference for auth timestamps.
const authTimestampSkew = 5 * time.Second

// replayCacheExpiry is how long nonces are kept in the replay cache.
const replayCacheExpiry = 1 * time.Hour

// HandshakeConfig holds identity authentication parameters for the secure
// channel handshake. If nil is passed to Handshake, authentication is skipped
// (backward compatibility for tests and unauthenticated channels).
type HandshakeConfig struct {
	NodeID     uint32
	Signer     ed25519.PrivateKey
	PeerPubKey ed25519.PublicKey
}

// replayCache prevents reuse of auth nonces within a 1-hour window.
var replayCache = struct {
	sync.Mutex
	nonces map[[16]byte]time.Time
}{nonces: make(map[[16]byte]time.Time)}

func init() {
	go replayCacheCleaner()
}

// replayCacheCleaner periodically removes expired nonce entries.
func replayCacheCleaner() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		now := time.Now()
		replayCache.Lock()
		for k, t := range replayCache.nonces {
			if now.Sub(t) > replayCacheExpiry {
				delete(replayCache.nonces, k)
			}
		}
		replayCache.Unlock()
	}
}

// maxReplayCacheEntries caps the replay cache to prevent memory exhaustion (M1 fix).
const maxReplayCacheEntries = 100000

// checkAndRecordNonce returns an error if the nonce was already seen within
// the replay window, otherwise records it and returns nil.
func checkAndRecordNonce(nonce [16]byte) error {
	replayCache.Lock()
	defer replayCache.Unlock()
	if _, exists := replayCache.nonces[nonce]; exists {
		return fmt.Errorf("auth nonce replay detected")
	}
	if len(replayCache.nonces) >= maxReplayCacheEntries {
		return fmt.Errorf("auth replay cache full")
	}
	replayCache.nonces[nonce] = time.Now()
	return nil
}

// ResetReplayCache clears the replay cache. Exported for testing only.
func ResetReplayCache() {
	replayCache.Lock()
	defer replayCache.Unlock()
	replayCache.nonces = make(map[[16]byte]time.Time)
}

// InjectReplayNonce adds a nonce to the replay cache. Exported for testing only.
func InjectReplayNonce(nonce [16]byte) {
	replayCache.Lock()
	defer replayCache.Unlock()
	replayCache.nonces[nonce] = time.Now()
}

// CheckReplayNonce checks if a nonce is in the replay cache without recording it.
// Exported for testing only.
func CheckReplayNonce(nonce [16]byte) error {
	replayCache.Lock()
	defer replayCache.Unlock()
	if _, exists := replayCache.nonces[nonce]; exists {
		return fmt.Errorf("auth nonce replay detected")
	}
	return nil
}

// HandshakeWithTimestampOffset performs an authenticated handshake but shifts
// the auth frame timestamp by the given offset. Exported for testing only.
func HandshakeWithTimestampOffset(conn net.Conn, isServer bool, cfg *HandshakeConfig, offset time.Duration) (*SecureConn, error) {
	conn.SetDeadline(time.Now().Add(HandshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	localPub := privKey.PublicKey().Bytes()

	var remotePub []byte

	if isServer {
		remotePub, err = readExact(conn, 32)
		if err != nil {
			return nil, fmt.Errorf("read client key: %w", err)
		}
		if _, err := conn.Write(localPub); err != nil {
			return nil, fmt.Errorf("send server key: %w", err)
		}
	} else {
		if _, err := conn.Write(localPub); err != nil {
			return nil, fmt.Errorf("send client key: %w", err)
		}
		remotePub, err = readExact(conn, 32)
		if err != nil {
			return nil, fmt.Errorf("read server key: %w", err)
		}
	}

	peerKey, err := curve.NewPublicKey(remotePub)
	if err != nil {
		return nil, fmt.Errorf("parse peer key: %w", err)
	}

	shared, err := privKey.ECDH(peerKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}

	// HKDF-SHA256 key derivation (H1 fix)
	mac := hmac.New(sha256.New, nil)
	mac.Write(shared)
	prk := mac.Sum(nil)
	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte("pilot-secure-v1"))
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

	sc := &SecureConn{raw: conn, aead: aead}
	if isServer {
		sc.noncePrefix = [4]byte{0x00, 0x00, 0x00, 0x01}
	} else {
		sc.noncePrefix = [4]byte{0x00, 0x00, 0x00, 0x02}
	}

	if cfg != nil && cfg.Signer != nil {
		if err := performAuthWithOffset(sc, cfg, localPub, remotePub, isServer, offset); err != nil {
			sc.Close()
			return nil, fmt.Errorf("auth: %w", err)
		}
	}

	return sc, nil
}

// performAuthWithOffset is like performAuth but applies a timestamp offset.
func performAuthWithOffset(sc *SecureConn, cfg *HandshakeConfig, localX25519Pub, remoteX25519Pub []byte, isServer bool, offset time.Duration) error {
	// Use shifted timestamp
	ts := uint64(time.Now().Add(offset).Unix())

	var authNonce [16]byte
	if _, err := rand.Read(authNonce[:]); err != nil {
		return fmt.Errorf("generate auth nonce: %w", err)
	}

	sigMsg := buildAuthSignMessage(cfg.NodeID, localX25519Pub, ts, authNonce)
	signature := ed25519.Sign(cfg.Signer, sigMsg)

	frame := make([]byte, authFrameLen)
	binary.BigEndian.PutUint32(frame[0:4], cfg.NodeID)
	binary.BigEndian.PutUint64(frame[4:12], ts)
	copy(frame[12:28], authNonce[:])
	copy(frame[28:92], signature)

	now := time.Now() // verifier uses current time

	if isServer {
		if _, err := sc.Write(frame); err != nil {
			return fmt.Errorf("send auth frame: %w", err)
		}
		peerFrame, err := readAuthFrame(sc)
		if err != nil {
			return fmt.Errorf("read peer auth frame: %w", err)
		}
		peerNodeID, err := verifyAuthFrame(peerFrame, cfg.PeerPubKey, remoteX25519Pub, now)
		if err != nil {
			return err
		}
		sc.PeerNodeID = peerNodeID
	} else {
		peerFrame, err := readAuthFrame(sc)
		if err != nil {
			return fmt.Errorf("read peer auth frame: %w", err)
		}
		peerNodeID, err := verifyAuthFrame(peerFrame, cfg.PeerPubKey, remoteX25519Pub, now)
		if err != nil {
			return err
		}
		sc.PeerNodeID = peerNodeID
		if _, err := sc.Write(frame); err != nil {
			return fmt.Errorf("send auth frame: %w", err)
		}
	}

	return nil
}

// SecureConn wraps a net.Conn with AES-256-GCM encryption.
// After a successful ECDH handshake, all reads and writes are encrypted.
type SecureConn struct {
	raw         net.Conn
	aead        cipher.AEAD
	rmu         sync.Mutex
	wmu         sync.Mutex
	nonce       uint64  // monotonic counter for nonces
	noncePrefix [4]byte // role-based prefix for nonce domain separation
	readBuf     []byte  // leftover plaintext from a previous Read
	PeerNodeID  uint32  // authenticated peer node ID (0 if unauthenticated)
}

// Handshake performs an ECDH key exchange over the connection.
// isServer determines which side reads first.
// An optional HandshakeConfig enables mutual Ed25519 authentication inside the
// encrypted channel after the ECDH exchange. Pass nil or omit for unauthenticated
// mode (backward compatible).
// A deadline is set to prevent indefinite blocking (M14 fix).
func Handshake(conn net.Conn, isServer bool, auth ...*HandshakeConfig) (*SecureConn, error) {
	// Set handshake deadline to prevent indefinite blocking (M14 fix)
	conn.SetDeadline(time.Now().Add(HandshakeTimeout))
	defer conn.SetDeadline(time.Time{}) // clear deadline after handshake

	// Generate ephemeral X25519 key pair
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	localPub := privKey.PublicKey().Bytes() // 32 bytes

	var remotePub []byte

	if isServer {
		// Server: read client's public key first, then send ours
		remotePub, err = readExact(conn, 32)
		if err != nil {
			return nil, fmt.Errorf("read client key: %w", err)
		}
		if _, err := conn.Write(localPub); err != nil {
			return nil, fmt.Errorf("send server key: %w", err)
		}
	} else {
		// Client: send our public key first, then read server's
		if _, err := conn.Write(localPub); err != nil {
			return nil, fmt.Errorf("send client key: %w", err)
		}
		remotePub, err = readExact(conn, 32)
		if err != nil {
			return nil, fmt.Errorf("read server key: %w", err)
		}
	}

	// Parse remote public key
	peerKey, err := curve.NewPublicKey(remotePub)
	if err != nil {
		return nil, fmt.Errorf("parse peer key: %w", err)
	}

	// Compute shared secret
	shared, err := privKey.ECDH(peerKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}

	// HKDF-SHA256 key derivation (H1 fix)
	mac := hmac.New(sha256.New, nil)
	mac.Write(shared)
	prk := mac.Sum(nil)
	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte("pilot-secure-v1"))
	mac.Write([]byte{0x01})
	key := mac.Sum(nil)

	// Create AES-GCM cipher
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

	sc := &SecureConn{raw: conn, aead: aead}
	// Use role-based nonce prefix to prevent nonce collision (C3 fix).
	// Both sides share the same AES-GCM key; using deterministic prefixes
	// based on role ensures the nonce spaces never overlap.
	if isServer {
		sc.noncePrefix = [4]byte{0x00, 0x00, 0x00, 0x01} // server prefix
	} else {
		sc.noncePrefix = [4]byte{0x00, 0x00, 0x00, 0x02} // client prefix
	}

	// Perform mutual Ed25519 authentication if config provided.
	// This happens INSIDE the encrypted channel (after ECDH).
	var cfg *HandshakeConfig
	if len(auth) > 0 {
		cfg = auth[0]
	}
	if cfg != nil && cfg.Signer != nil {
		if err := performAuth(sc, cfg, localPub, remotePub, isServer); err != nil {
			sc.Close()
			return nil, fmt.Errorf("auth: %w", err)
		}
	}

	return sc, nil
}

// HandshakeWithLookup is like Handshake with auth, but uses a lookup function
// to resolve the peer's Ed25519 public key by nodeID. This is used by servers
// that don't know the peer's identity until they read the auth frame.
func HandshakeWithLookup(conn net.Conn, isServer bool, cfg *HandshakeConfig, lookup PeerPubKeyLookup) (*SecureConn, error) {
	// Set handshake deadline to prevent indefinite blocking (M14 fix)
	conn.SetDeadline(time.Now().Add(HandshakeTimeout))
	defer conn.SetDeadline(time.Time{}) // clear deadline after handshake

	// Generate ephemeral X25519 key pair
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	localPub := privKey.PublicKey().Bytes() // 32 bytes

	var remotePub []byte

	if isServer {
		remotePub, err = readExact(conn, 32)
		if err != nil {
			return nil, fmt.Errorf("read client key: %w", err)
		}
		if _, err := conn.Write(localPub); err != nil {
			return nil, fmt.Errorf("send server key: %w", err)
		}
	} else {
		if _, err := conn.Write(localPub); err != nil {
			return nil, fmt.Errorf("send client key: %w", err)
		}
		remotePub, err = readExact(conn, 32)
		if err != nil {
			return nil, fmt.Errorf("read server key: %w", err)
		}
	}

	peerKey, err := curve.NewPublicKey(remotePub)
	if err != nil {
		return nil, fmt.Errorf("parse peer key: %w", err)
	}

	shared, err := privKey.ECDH(peerKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}

	// HKDF-SHA256 key derivation (H1 fix)
	mac := hmac.New(sha256.New, nil)
	mac.Write(shared)
	prk := mac.Sum(nil)
	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte("pilot-secure-v1"))
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

	sc := &SecureConn{raw: conn, aead: aead}
	if isServer {
		sc.noncePrefix = [4]byte{0x00, 0x00, 0x00, 0x01}
	} else {
		sc.noncePrefix = [4]byte{0x00, 0x00, 0x00, 0x02}
	}

	if cfg != nil && cfg.Signer != nil {
		if err := performAuthWithLookup(sc, cfg, localPub, remotePub, isServer, lookup); err != nil {
			sc.Close()
			return nil, fmt.Errorf("auth: %w", err)
		}
	}

	return sc, nil
}

// performAuthWithLookup is like performAuth but resolves the peer's Ed25519
// pubkey via a lookup function after reading the peer's auth frame.
func performAuthWithLookup(sc *SecureConn, cfg *HandshakeConfig, localX25519Pub, remoteX25519Pub []byte, isServer bool, lookup PeerPubKeyLookup) error {
	now := time.Now()
	ts := uint64(now.Unix())

	var authNonce [16]byte
	if _, err := rand.Read(authNonce[:]); err != nil {
		return fmt.Errorf("generate auth nonce: %w", err)
	}

	sigMsg := buildAuthSignMessage(cfg.NodeID, localX25519Pub, ts, authNonce)
	signature := ed25519.Sign(cfg.Signer, sigMsg)

	frame := make([]byte, authFrameLen)
	binary.BigEndian.PutUint32(frame[0:4], cfg.NodeID)
	binary.BigEndian.PutUint64(frame[4:12], ts)
	copy(frame[12:28], authNonce[:])
	copy(frame[28:92], signature)

	if isServer {
		if _, err := sc.Write(frame); err != nil {
			return fmt.Errorf("send auth frame: %w", err)
		}
		peerFrame, err := readAuthFrame(sc)
		if err != nil {
			return fmt.Errorf("read peer auth frame: %w", err)
		}
		// Extract peer's nodeID to look up their pubkey
		peerNodeID := binary.BigEndian.Uint32(peerFrame[0:4])
		peerPubKey := lookup(peerNodeID)
		if peerPubKey == nil {
			return fmt.Errorf("unknown peer node %d: no public key found", peerNodeID)
		}
		peerNodeID, err = verifyAuthFrame(peerFrame, peerPubKey, remoteX25519Pub, now)
		if err != nil {
			return err
		}
		sc.PeerNodeID = peerNodeID
	} else {
		peerFrame, err := readAuthFrame(sc)
		if err != nil {
			return fmt.Errorf("read peer auth frame: %w", err)
		}
		peerNodeID := binary.BigEndian.Uint32(peerFrame[0:4])
		peerPubKey := lookup(peerNodeID)
		if peerPubKey == nil {
			return fmt.Errorf("unknown peer node %d: no public key found", peerNodeID)
		}
		peerNodeID, err = verifyAuthFrame(peerFrame, peerPubKey, remoteX25519Pub, now)
		if err != nil {
			return err
		}
		sc.PeerNodeID = peerNodeID
		if _, err := sc.Write(frame); err != nil {
			return fmt.Errorf("send auth frame: %w", err)
		}
	}

	return nil
}

// performAuth executes the mutual Ed25519 authentication protocol inside the
// already-encrypted SecureConn. Both sides send an auth frame and verify the
// peer's frame.
//
// Auth frame format (92 bytes):
//
//	[nodeID(4)][timestamp(8)][nonce(16)][ed25519_signature(64)]
//
// Signature covers:
//
//	"pilot-secure-auth:" + nodeID(4) + X25519_ephemeral_pubkey(32) + timestamp(8) + nonce(16)
//
// Each side signs its OWN X25519 ephemeral pubkey (localPub). The verifier
// reconstructs the signed message using the peer's X25519 pubkey (remotePub,
// which was received during the ECDH exchange). This binds the ephemeral ECDH
// key to the long-term Ed25519 identity: a MITM cannot substitute their own
// X25519 key because they cannot produce a valid Ed25519 signature for it.
func performAuth(sc *SecureConn, cfg *HandshakeConfig, localX25519Pub, remoteX25519Pub []byte, isServer bool) error {
	// Build our auth frame
	now := time.Now()
	ts := uint64(now.Unix())

	var authNonce [16]byte
	if _, err := rand.Read(authNonce[:]); err != nil {
		return fmt.Errorf("generate auth nonce: %w", err)
	}

	// Sign over our own X25519 pubkey to bind our identity to this ECDH session
	sigMsg := buildAuthSignMessage(cfg.NodeID, localX25519Pub, ts, authNonce)
	signature := ed25519.Sign(cfg.Signer, sigMsg)

	// Build the wire frame: nodeID(4) + timestamp(8) + nonce(16) + signature(64)
	frame := make([]byte, authFrameLen)
	binary.BigEndian.PutUint32(frame[0:4], cfg.NodeID)
	binary.BigEndian.PutUint64(frame[4:12], ts)
	copy(frame[12:28], authNonce[:])
	copy(frame[28:92], signature)

	// Exchange auth frames. Server sends first, then reads.
	// Client reads first, then sends. This prevents deadlock on net.Pipe.
	if isServer {
		if _, err := sc.Write(frame); err != nil {
			return fmt.Errorf("send auth frame: %w", err)
		}
		peerFrame, err := readAuthFrame(sc)
		if err != nil {
			return fmt.Errorf("read peer auth frame: %w", err)
		}
		peerNodeID, err := verifyAuthFrame(peerFrame, cfg.PeerPubKey, remoteX25519Pub, now)
		if err != nil {
			return err
		}
		sc.PeerNodeID = peerNodeID
	} else {
		peerFrame, err := readAuthFrame(sc)
		if err != nil {
			return fmt.Errorf("read peer auth frame: %w", err)
		}
		peerNodeID, err := verifyAuthFrame(peerFrame, cfg.PeerPubKey, remoteX25519Pub, now)
		if err != nil {
			return err
		}
		sc.PeerNodeID = peerNodeID
		if _, err := sc.Write(frame); err != nil {
			return fmt.Errorf("send auth frame: %w", err)
		}
	}

	return nil
}

// readAuthFrame reads exactly authFrameLen bytes from the SecureConn.
// The data is already decrypted by SecureConn.Read.
func readAuthFrame(sc *SecureConn) ([]byte, error) {
	frame := make([]byte, authFrameLen)
	n := 0
	for n < authFrameLen {
		nn, err := sc.Read(frame[n:])
		if err != nil {
			return nil, err
		}
		n += nn
	}
	return frame, nil
}

// verifyAuthFrame validates a peer's auth frame. The peer signed over their own
// X25519 ephemeral pubkey (peerX25519Pub), which we received during the ECDH
// exchange. We reconstruct the signed message and verify against the peer's
// Ed25519 public key from the registry.
func verifyAuthFrame(frame []byte, peerEdPubKey ed25519.PublicKey, peerX25519Pub []byte, now time.Time) (uint32, error) {
	if len(frame) != authFrameLen {
		return 0, fmt.Errorf("auth frame wrong size: %d", len(frame))
	}

	peerNodeID := binary.BigEndian.Uint32(frame[0:4])
	peerTS := binary.BigEndian.Uint64(frame[4:12])
	var peerNonce [16]byte
	copy(peerNonce[:], frame[12:28])
	peerSig := frame[28:92]

	// Check timestamp within skew window
	peerTime := time.Unix(int64(peerTS), 0)
	diff := now.Sub(peerTime)
	if diff < 0 {
		diff = -diff
	}
	if diff > authTimestampSkew {
		return 0, fmt.Errorf("auth timestamp expired: skew %v exceeds %v", diff, authTimestampSkew)
	}

	// Check nonce replay
	if err := checkAndRecordNonce(peerNonce); err != nil {
		return 0, err
	}

	// Reconstruct the message the peer signed: domain + nodeID + peerX25519Pub + timestamp + nonce
	sigMsg := buildAuthSignMessage(peerNodeID, peerX25519Pub, peerTS, peerNonce)

	// Verify Ed25519 signature
	if !ed25519.Verify(peerEdPubKey, sigMsg, peerSig) {
		return 0, fmt.Errorf("auth signature verification failed")
	}

	return peerNodeID, nil
}

// buildAuthSignMessage constructs the message that is signed in the auth frame.
// Format: "pilot-secure-auth:" + nodeID(4) + X25519_ephemeral_pubkey(32) + timestamp(8) + nonce(16)
func buildAuthSignMessage(nodeID uint32, x25519Pub []byte, timestamp uint64, nonce [16]byte) []byte {
	domain := []byte("pilot-secure-auth:")
	msg := make([]byte, len(domain)+4+32+8+16)
	copy(msg, domain)
	off := len(domain)
	binary.BigEndian.PutUint32(msg[off:off+4], nodeID)
	off += 4
	copy(msg[off:off+32], x25519Pub)
	off += 32
	binary.BigEndian.PutUint64(msg[off:off+8], timestamp)
	off += 8
	copy(msg[off:off+16], nonce[:])
	return msg
}

// Read decrypts and reads data from the connection.
// Leftover plaintext from a previous decryption is returned first (H14 fix).
func (sc *SecureConn) Read(b []byte) (int, error) {
	sc.rmu.Lock()
	defer sc.rmu.Unlock()

	// Return buffered leftover data first (H14 fix — prevents silent truncation)
	if len(sc.readBuf) > 0 {
		n := copy(b, sc.readBuf)
		sc.readBuf = sc.readBuf[n:]
		return n, nil
	}

	// Read 4-byte length prefix
	lenBuf, err := readExact(sc.raw, 4)
	if err != nil {
		return 0, err
	}
	msgLen := binary.BigEndian.Uint32(lenBuf)
	if msgLen < uint32(sc.aead.NonceSize()) {
		return 0, fmt.Errorf("encrypted message too short")
	}
	// Reject unreasonably large messages to prevent OOM (M13 fix)
	if msgLen > uint32(MaxEncryptedMessageLen) {
		return 0, fmt.Errorf("encrypted message too large: %d bytes", msgLen)
	}

	// Read nonce + ciphertext
	ciphertext, err := readExact(sc.raw, int(msgLen))
	if err != nil {
		return 0, err
	}

	nonce := ciphertext[:sc.aead.NonceSize()]
	encrypted := ciphertext[sc.aead.NonceSize():]

	// Decrypt with sender's nonce prefix as AAD (H3 fix)
	peerAAD := nonce[:4]
	plaintext, err := sc.aead.Open(nil, nonce, encrypted, peerAAD)
	if err != nil {
		return 0, fmt.Errorf("decrypt: %w", err)
	}

	n := copy(b, plaintext)
	// Buffer any remaining plaintext for subsequent Read calls (H14 fix)
	if n < len(plaintext) {
		sc.readBuf = make([]byte, len(plaintext)-n)
		copy(sc.readBuf, plaintext[n:])
	}
	return n, nil
}

// Write encrypts and writes data to the connection.
func (sc *SecureConn) Write(b []byte) (int, error) {
	sc.wmu.Lock()
	defer sc.wmu.Unlock()

	// Generate nonce from prefix + counter
	nonce := make([]byte, sc.aead.NonceSize())
	copy(nonce[0:4], sc.noncePrefix[:])
	sc.nonce++
	binary.BigEndian.PutUint64(nonce[sc.aead.NonceSize()-8:], sc.nonce)

	// Encrypt with nonce prefix as AAD (H3 fix)
	ciphertext := sc.aead.Seal(nil, nonce, b, sc.noncePrefix[:])

	// Write: [4-byte length][nonce][ciphertext]
	total := len(nonce) + len(ciphertext)
	msg := make([]byte, 4+total)
	binary.BigEndian.PutUint32(msg[0:4], uint32(total))
	copy(msg[4:], nonce)
	copy(msg[4+len(nonce):], ciphertext)

	if _, err := sc.raw.Write(msg); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (sc *SecureConn) Close() error                       { return sc.raw.Close() }
func (sc *SecureConn) LocalAddr() net.Addr                { return sc.raw.LocalAddr() }
func (sc *SecureConn) RemoteAddr() net.Addr               { return sc.raw.RemoteAddr() }
func (sc *SecureConn) SetDeadline(t time.Time) error      { return sc.raw.SetDeadline(t) }
func (sc *SecureConn) SetReadDeadline(t time.Time) error  { return sc.raw.SetReadDeadline(t) }
func (sc *SecureConn) SetWriteDeadline(t time.Time) error { return sc.raw.SetWriteDeadline(t) }

func readExact(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

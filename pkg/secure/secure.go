package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
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

// SecureConn wraps a net.Conn with AES-256-GCM encryption.
// After a successful ECDH handshake, all reads and writes are encrypted.
type SecureConn struct {
	raw         net.Conn
	aead        cipher.AEAD
	rmu         sync.Mutex
	wmu         sync.Mutex
	nonce       uint64   // monotonic counter for nonces
	noncePrefix [4]byte  // role-based prefix for nonce domain separation
	readBuf     []byte   // leftover plaintext from a previous Read
}

// Handshake performs an ECDH key exchange over the connection.
// isServer determines which side reads first.
// A deadline is set to prevent indefinite blocking (M14 fix).
func Handshake(conn net.Conn, isServer bool) (*SecureConn, error) {
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

	// Derive AES-256 key from shared secret with domain separator
	h := sha256.New()
	h.Write([]byte("pilot-secure-v1:"))
	h.Write(shared)
	key := h.Sum(nil)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
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

	return sc, nil
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

	// Decrypt
	plaintext, err := sc.aead.Open(nil, nonce, encrypted, nil)
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

	// Encrypt
	ciphertext := sc.aead.Seal(nil, nonce, b, nil)

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

func (sc *SecureConn) Close() error               { return sc.raw.Close() }
func (sc *SecureConn) LocalAddr() net.Addr         { return sc.raw.LocalAddr() }
func (sc *SecureConn) RemoteAddr() net.Addr        { return sc.raw.RemoteAddr() }
func (sc *SecureConn) SetDeadline(t time.Time) error      { return sc.raw.SetDeadline(t) }
func (sc *SecureConn) SetReadDeadline(t time.Time) error   { return sc.raw.SetReadDeadline(t) }
func (sc *SecureConn) SetWriteDeadline(t time.Time) error  { return sc.raw.SetWriteDeadline(t) }

func readExact(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

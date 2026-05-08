// SPDX-License-Identifier: AGPL-3.0-or-later

// Package accept contains the TCP accept layer for the registry server:
// connection handling, TLS configuration, rate limiting, log sampling, and
// panic recovery. It is intentionally free of domain logic — all message
// dispatch is delegated to the Dispatcher interface provided at construction.
package accept

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

// ── Panic recovery ────────────────────────────────────────────────────────────

var recoveredPanicCount atomic.Uint64

// RecoveredPanicCount returns the total number of panics swallowed since start.
func RecoveredPanicCount() uint64 {
	return recoveredPanicCount.Load()
}

// recoverHandler is the standard panic-recovery shim placed at the top of
// every connection-handling goroutine in this package. Usage:
//
//	defer recoverHandler("handleConn", nil)
func recoverHandler(label string, onPanic func(panicCount uint64)) {
	r := recover()
	if r == nil {
		return
	}
	count := recoveredPanicCount.Add(1)
	slog.Error("panic recovered",
		"where", label,
		"panic", r,
		"recovered_total", count,
		"stack", string(debug.Stack()),
	)
	if onPanic != nil {
		func() {
			defer func() { _ = recover() }()
			onPanic(count)
		}()
	}
}

// ── Log sampler ───────────────────────────────────────────────────────────────

// logSampler caps per-key log frequency; map size is bounded at maxSamplerKeys
// to prevent attacker-controlled keys from exhausting memory.
type logSampler struct {
	mu             sync.Mutex
	counts         map[string]int64
	interval       int64
	maxSamplerKeys int
}

func newLogSampler(interval int64) *logSampler {
	return &logSampler{
		counts:         make(map[string]int64),
		interval:       interval,
		maxSamplerKeys: 10000,
	}
}

// shouldLog returns true if this occurrence should be logged, plus the count
// of suppressed occurrences since the last log.
func (ls *logSampler) shouldLog(key string) (bool, int64) {
	ls.mu.Lock()
	if len(ls.counts) >= ls.maxSamplerKeys {
		ls.mu.Unlock()
		return true, 0
	}
	ls.counts[key]++
	count := ls.counts[key]
	if count == 1 {
		ls.mu.Unlock()
		return true, 1
	}
	if count >= ls.interval {
		ls.counts[key] = 0
		ls.mu.Unlock()
		return true, count
	}
	ls.mu.Unlock()
	return false, 0
}

// Cleanup removes all tracked keys (call periodically from a maintenance loop).
func (ls *logSampler) Cleanup() {
	ls.mu.Lock()
	clear(ls.counts)
	ls.mu.Unlock()
}

// ── Rate limiter ──────────────────────────────────────────────────────────────

// RateLimiter tracks per-IP registration attempts using a token bucket.
type RateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*bucket
	rate       int
	window     time.Duration
	maxBuckets int
	now        func() time.Time
}

type bucket struct {
	tokens   float64
	lastFill time.Time
}

// NewRateLimiter creates a rate limiter allowing rate requests per window per IP.
// maxBuckets caps the number of tracked IPs to prevent memory exhaustion.
// Pass 0 for unlimited (not recommended in production).
func NewRateLimiter(rate int, window time.Duration, maxBuckets int) *RateLimiter {
	return &RateLimiter{
		buckets:    make(map[string]*bucket),
		rate:       rate,
		window:     window,
		maxBuckets: maxBuckets,
		now:        time.Now,
	}
}

// SetClock overrides the time source (for testing).
func (rl *RateLimiter) SetClock(fn func() time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.now = fn
}

// Allow checks if a request from the given IP is allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	if os.Getenv("PILOT_REGISTRY_NORATELIMIT") == "1" {
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	b, ok := rl.buckets[ip]
	if !ok {
		if rl.maxBuckets > 0 && len(rl.buckets) >= rl.maxBuckets {
			threshold := now.Add(-2 * rl.window)
			for ip2, b2 := range rl.buckets {
				if b2.lastFill.Before(threshold) {
					delete(rl.buckets, ip2)
				}
			}
			if len(rl.buckets) >= rl.maxBuckets {
				return false
			}
		}
		rl.buckets[ip] = &bucket{tokens: float64(rl.rate) - 1, lastFill: now}
		return true
	}

	elapsed := now.Sub(b.lastFill)
	refill := float64(rl.rate) * (float64(elapsed) / float64(rl.window))
	b.tokens += refill
	if b.tokens > float64(rl.rate) {
		b.tokens = float64(rl.rate)
	}
	b.lastFill = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Cleanup removes stale buckets. Call periodically.
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	threshold := rl.now().Add(-2 * rl.window)
	for ip, b := range rl.buckets {
		if b.lastFill.Before(threshold) {
			delete(rl.buckets, ip)
		}
	}
}

// BucketCount returns the number of tracked IPs (for testing).
func (rl *RateLimiter) BucketCount() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.buckets)
}

// HasBucket returns whether a given IP has an active bucket (for testing).
func (rl *RateLimiter) HasBucket(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	_, ok := rl.buckets[ip]
	return ok
}

// ── TLS helpers ───────────────────────────────────────────────────────────────

// GenerateSelfSignedCert creates an in-memory self-signed TLS certificate.
func GenerateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"Pilot Protocol"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// SanitizeListenAddr uses the TCP source IP from remoteAddr but accepts the
// port from the client-provided address. Prevents clients from registering
// arbitrary IPs while allowing them to specify their actual listening port.
func SanitizeListenAddr(remoteAddr, clientAddr string) string {
	remoteHost, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	if clientAddr == "" {
		return remoteAddr
	}
	_, clientPort, err := net.SplitHostPort(clientAddr)
	if err != nil {
		return remoteAddr
	}
	return net.JoinHostPort(remoteHost, clientPort)
}

// ── Wire framing helpers ──────────────────────────────────────────────────────

// rawResponseKey is a sentinel used by writeMessage: when the response map
// contains this key with a []byte value, writeMessage writes the bytes verbatim
// (skipping json.Marshal). Mirrors the same constant in the server package.
const rawResponseKey = "_pilot_raw_body"

// writeMessageDeadline bounds how long a single response write can block.
const writeMessageDeadline = 5 * time.Second

func readMessage(r io.Reader) (map[string]interface{}, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > wire.MaxMessageSize {
		return nil, fmt.Errorf("message too large: %d bytes (max %d)", length, wire.MaxMessageSize)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}

	var msg map[string]interface{}
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	return msg, nil
}

func writeMessage(w io.Writer, msg map[string]interface{}) error {
	if raw, ok := msg[rawResponseKey].([]byte); ok && raw != nil {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(raw)))
		if c, ok := w.(net.Conn); ok {
			_ = c.SetWriteDeadline(time.Now().Add(writeMessageDeadline))
			defer c.SetWriteDeadline(time.Time{})
		}
		if _, err := w.Write(lenBuf[:]); err != nil {
			return err
		}
		if _, err := w.Write(raw); err != nil {
			return err
		}
		return nil
	}

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("json encode: %w", err)
	}

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))

	if c, ok := w.(net.Conn); ok {
		_ = c.SetWriteDeadline(time.Now().Add(writeMessageDeadline))
		defer c.SetWriteDeadline(time.Time{})
	}

	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	return nil
}

// ── Dispatcher interface ──────────────────────────────────────────────────────

// Dispatcher is the callback interface that the Acceptor uses to hand off
// decoded messages and native binary frames to the domain layer (Server).
// Implementing this interface on *Server keeps the accept layer free of any
// import cycle with the server package.
type Dispatcher interface {
	// HandleMessage dispatches a decoded JSON message and returns the response map.
	HandleMessage(msg map[string]interface{}, remoteAddr string) (map[string]interface{}, error)

	// HandleSubscribeReplication takes over the conn for replication streaming.
	HandleSubscribeReplication(conn net.Conn)

	// HandleBinaryHeartbeat processes a native binary heartbeat frame.
	HandleBinaryHeartbeat(conn net.Conn, payload []byte)

	// HandleBinaryLookup processes a native binary lookup frame.
	HandleBinaryLookup(conn net.Conn, payload []byte, host string)

	// HandleBinaryResolve processes a native binary resolve frame.
	HandleBinaryResolve(conn net.Conn, payload []byte, host string)

	// ReplicationToken returns the current replication auth token.
	// An empty string means replication is disabled.
	ReplicationToken() string

	// AddRequest increments the server-level request counter.
	AddRequest()
}

// ── Acceptor ─────────────────────────────────────────────────────────────────

// Acceptor manages the TCP accept loop with TLS, rate limiting, log sampling,
// and per-connection panic recovery. All domain logic is delegated to the
// Dispatcher supplied at construction.
type Acceptor struct {
	tlsConfig      *tls.Config
	connCount      atomic.Int64
	maxConnections int64
	rateLimiter    *RateLimiter
	logSampler     *logSampler
	listener       net.Listener
	dispatcher     Dispatcher
}

// NewAcceptor creates an Acceptor with the given connection limit and dispatcher.
// A rate limiter (100 req/s per IP, 50 000-bucket cap) and log sampler
// (every 1000th suppressed log) are created automatically.
func NewAcceptor(maxConns int64, d Dispatcher) *Acceptor {
	return &Acceptor{
		maxConnections: maxConns,
		rateLimiter:    NewRateLimiter(100, time.Second, 50_000),
		logSampler:     newLogSampler(1000),
		dispatcher:     d,
	}
}

// SetTLS configures TLS. If certFile is empty a self-signed certificate is
// generated automatically.
func (a *Acceptor) SetTLS(certFile, keyFile string) error {
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("load TLS keypair: %w", err)
		}
		a.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		slog.Info("registry TLS configured", "cert", certFile)
		return nil
	}

	cert, err := GenerateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("generate self-signed cert: %w", err)
	}
	a.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	slog.Info("registry TLS configured with auto-generated self-signed certificate")
	return nil
}

// TLSConfig returns the active TLS config (nil = plaintext).
func (a *Acceptor) TLSConfig() *tls.Config {
	return a.tlsConfig
}

// Listen binds the listener on addr (with TLS if configured).
func (a *Acceptor) Listen(addr string) error {
	var ln net.Listener
	var err error

	if a.tlsConfig != nil {
		ln, err = tls.Listen("tcp", addr, a.tlsConfig)
	} else {
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	a.listener = ln
	return nil
}

// Listener returns the underlying net.Listener (nil before Listen).
func (a *Acceptor) Listener() net.Listener {
	return a.listener
}

// ConnCount returns the number of active connections.
func (a *Acceptor) ConnCount() int64 {
	return a.connCount.Load()
}

// SetMaxConnections overrides the active connection limit (for testing).
func (a *Acceptor) SetMaxConnections(max int64) {
	a.maxConnections = max
}

// LogSamplerCleanup resets the log sampler counters. Call from a maintenance loop.
func (a *Acceptor) LogSamplerCleanup() {
	a.logSampler.Cleanup()
}

// ShouldLog delegates to the internal log sampler. Returns true if this
// occurrence of key should be logged, plus the suppressed count since the
// last logged occurrence. Used by sibling files (e.g. wal_replay.go) that
// need access to log sampling without importing the sampler directly.
func (a *Acceptor) ShouldLog(key string) (bool, int64) {
	return a.logSampler.shouldLog(key)
}

// Accept runs the accept loop. For each accepted connection it checks the
// connection limit and spawns handleConn in a goroutine. The loop returns nil
// when done is closed.
//
// The caller is responsible for closing the listener (e.g. via Close()) when
// done is closed, which unblocks the Accept() call on the listener.
func (a *Acceptor) Accept(done <-chan struct{}) error {
	ln := a.listener

	// Warmup throttle: limit new connections for the first 60s to prevent
	// thundering herd after a restart.
	const throttleDuration = 60 * time.Second
	const throttleRate = 1000
	startedAt := time.Now()
	acceptCount := 0
	acceptWindow := time.Now()

	consecutiveErrors := 0
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-done:
				return nil
			default:
			}
			consecutiveErrors++
			slog.Error("registry accept error", "err", err, "consecutive", consecutiveErrors)
			if consecutiveErrors >= 10 {
				return fmt.Errorf("accept: %d consecutive errors, last: %w", consecutiveErrors, err)
			}
			backoff := time.Duration(consecutiveErrors) * 100 * time.Millisecond
			if backoff > 2*time.Second {
				backoff = 2 * time.Second
			}
			time.Sleep(backoff)
			continue
		}
		consecutiveErrors = 0

		// Warmup throttle
		if time.Since(startedAt) < throttleDuration {
			now := time.Now()
			if now.Sub(acceptWindow) >= time.Second {
				acceptCount = 0
				acceptWindow = now
			}
			acceptCount++
			if acceptCount > throttleRate {
				time.Sleep(time.Until(acceptWindow.Add(time.Second)))
			}
		}

		// Connection limit
		if a.connCount.Load() >= a.maxConnections {
			slog.Warn("connection limit reached, rejecting",
				"remote", conn.RemoteAddr(),
				"limit", a.maxConnections)
			conn.Close()
			continue
		}
		a.connCount.Add(1)
		go a.handleConn(conn)
	}
}

// ── Connection handlers ───────────────────────────────────────────────────────

func (a *Acceptor) handleConn(conn net.Conn) {
	defer recoverHandler("handleConn", nil)
	defer func() {
		conn.Close()
		a.connCount.Add(-1)
	}()

	// Shrink socket buffers — heartbeat/lookup messages are tiny (~100-200 B).
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetReadBuffer(4096)
		tc.SetWriteBuffer(4096)
	}

	// Protocol detection: read first 4 bytes to distinguish binary vs JSON.
	// Binary clients send magic 0x50494C54 ("PILT"). JSON clients send a
	// 4-byte big-endian length prefix which is always < 64 KB, while the magic
	// value (~1.3 billion) is orders of magnitude larger.
	conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
	var peek [4]byte
	if _, err := io.ReadFull(conn, peek[:]); err != nil {
		if err != io.EOF {
			slog.Debug("registry read error", "remote", conn.RemoteAddr(), "err", err)
		}
		return
	}

	if peek == wire.Magic {
		// Binary wire protocol — read version byte
		var ver [1]byte
		if _, err := io.ReadFull(conn, ver[:]); err != nil {
			slog.Debug("binary version read error", "remote", conn.RemoteAddr(), "err", err)
			return
		}
		if ver[0] != wire.Version {
			wire.WriteFrame(conn, wire.MsgError, wire.EncodeError(
				fmt.Sprintf("unsupported wire version %d", ver[0])))
			return
		}
		a.handleBinaryConn(conn)
		return
	}

	// JSON protocol: prepend the 4 peeked bytes so readMessage sees the
	// complete length prefix.
	reader := io.MultiReader(bytes.NewReader(peek[:]), conn)
	a.handleJSONConn(conn, reader)
}

// handleJSONConn handles a JSON-protocol connection. reader must include the
// first 4-byte length prefix (prepended via io.MultiReader if consumed during
// protocol detection).
func (a *Acceptor) handleJSONConn(conn net.Conn, reader io.Reader) {
	var connReqCount int64
	connStart := time.Now()

	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		msg, err := readMessage(reader)
		if err != nil {
			if err != io.EOF {
				slog.Debug("registry read error", "remote", conn.RemoteAddr(), "err", err)
			}
			return
		}

		// Replication subscription takes over the connection (checked before
		// backpressure so standbys aren't throttled during initial handshake).
		if msgType, _ := msg["type"].(string); msgType == "subscribe_replication" {
			token := a.dispatcher.ReplicationToken()
			if token == "" {
				writeMessage(conn, map[string]interface{}{
					"type":  "error",
					"error": "replication not configured",
				})
				return
			}
			providedToken, _ := msg["token"].(string)
			if subtle.ConstantTimeCompare([]byte(providedToken), []byte(token)) != 1 {
				writeMessage(conn, map[string]interface{}{
					"type":  "error",
					"error": "invalid replication token",
				})
				return
			}
			a.dispatcher.HandleSubscribeReplication(conn)
			return
		}

		// Per-connection rate check with 5 s grace period.
		connReqCount++
		if elapsed := time.Since(connStart).Seconds(); elapsed >= 5 {
			rate := float64(connReqCount) / elapsed
			if rate > 500 {
				slog.Warn("closing abusive connection", "remote", conn.RemoteAddr(), "rate", rate)
				return
			}
			if rate > 100 {
				time.Sleep(10 * time.Millisecond)
			}
		}

		remoteAddr := conn.RemoteAddr().String()
		host, _, _ := net.SplitHostPort(remoteAddr)
		msgType, _ := msg["type"].(string)

		resp, err := a.dispatcher.HandleMessage(msg, remoteAddr)
		if err != nil {
			errMsg := "request failed"
			if strings.Contains(err.Error(), "rate limited") ||
				strings.Contains(err.Error(), "enterprise feature") ||
				strings.Contains(err.Error(), "expired") ||
				strings.Contains(err.Error(), "already") ||
				strings.Contains(err.Error(), "not a member") ||
				strings.Contains(err.Error(), "cannot") ||
				strings.Contains(err.Error(), "too many") ||
				strings.Contains(err.Error(), "too long") ||
				strings.Contains(err.Error(), "not found") ||
				strings.Contains(err.Error(), "invalid") ||
				strings.Contains(err.Error(), "require") ||
				strings.Contains(err.Error(), "signature") {
				errMsg = err.Error()
			}
			if shouldLog, suppressed := a.logSampler.shouldLog(host + ":" + msgType); shouldLog {
				slog.Warn("registry handle error",
					"remote", host,
					"type", msgType,
					"err", err,
					"suppressed", suppressed)
			}
			resp = map[string]interface{}{
				"type":  "error",
				"error": errMsg,
			}
		}

		if err := writeMessage(conn, resp); err != nil {
			samplerKey := "write-error:" + conn.RemoteAddr().String()
			if shouldLog, suppressed := a.logSampler.shouldLog(samplerKey); shouldLog {
				if suppressed > 1 {
					slog.Error("registry write error",
						"remote", conn.RemoteAddr(),
						"err", err,
						"suppressed", suppressed-1)
				} else {
					slog.Error("registry write error", "remote", conn.RemoteAddr(), "err", err)
				}
			}
			return
		}
	}
}

// handleBinaryConn handles a binary-protocol connection after the magic and
// version bytes have been consumed.
func (a *Acceptor) handleBinaryConn(conn net.Conn) {
	var connReqCount int64
	connStart := time.Now()
	remoteAddr := conn.RemoteAddr().String()
	host, _, _ := net.SplitHostPort(remoteAddr)

	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		msgType, payload, err := wire.ReadFrame(conn)
		if err != nil {
			if err != io.EOF {
				slog.Debug("binary read error", "remote", conn.RemoteAddr(), "err", err)
			}
			return
		}

		connReqCount++
		if elapsed := time.Since(connStart).Seconds(); elapsed >= 5 {
			rate := float64(connReqCount) / elapsed
			if rate > 500 {
				slog.Warn("closing abusive binary connection", "remote", conn.RemoteAddr(), "rate", rate)
				return
			}
			if rate > 100 {
				time.Sleep(10 * time.Millisecond)
			}
		}

		a.dispatcher.AddRequest()

		switch msgType {
		case wire.MsgHeartbeat:
			a.dispatcher.HandleBinaryHeartbeat(conn, payload)
		case wire.MsgLookup:
			a.dispatcher.HandleBinaryLookup(conn, payload, host)
		case wire.MsgResolve:
			a.dispatcher.HandleBinaryResolve(conn, payload, host)
		case wire.MsgJSON:
			a.handleBinaryJSONFallback(conn, payload, remoteAddr, host)
		default:
			wire.WriteFrame(conn, wire.MsgError,
				wire.EncodeError(fmt.Sprintf("unknown message type 0x%02x", msgType)))
		}
	}
}

// handleBinaryJSONFallback handles a JSON message sent inside a binary frame.
func (a *Acceptor) handleBinaryJSONFallback(conn net.Conn, payload []byte, remoteAddr, host string) {
	var msg map[string]interface{}
	if err := json.Unmarshal(payload, &msg); err != nil {
		wire.WriteFrame(conn, wire.MsgError, wire.EncodeError(fmt.Sprintf("json decode: %s", err)))
		return
	}

	if mt, _ := msg["type"].(string); mt == "subscribe_replication" {
		wire.WriteFrame(conn, wire.MsgError,
			wire.EncodeError("replication not supported over binary protocol"))
		return
	}

	msgType, _ := msg["type"].(string)
	resp, err := a.dispatcher.HandleMessage(msg, remoteAddr)
	if err != nil {
		errMsg := "request failed"
		if strings.Contains(err.Error(), "rate limited") ||
			strings.Contains(err.Error(), "enterprise feature") ||
			strings.Contains(err.Error(), "expired") ||
			strings.Contains(err.Error(), "already") ||
			strings.Contains(err.Error(), "not a member") ||
			strings.Contains(err.Error(), "cannot") ||
			strings.Contains(err.Error(), "too many") ||
			strings.Contains(err.Error(), "too long") ||
			strings.Contains(err.Error(), "not found") ||
			strings.Contains(err.Error(), "invalid") ||
			strings.Contains(err.Error(), "require") ||
			strings.Contains(err.Error(), "signature") {
			errMsg = err.Error()
		}
		if shouldLog, suppressed := a.logSampler.shouldLog(host + ":" + msgType); shouldLog {
			slog.Warn("registry handle error",
				"remote", host,
				"type", msgType,
				"err", err,
				"suppressed", suppressed)
		}
		resp = map[string]interface{}{
			"type":  "error",
			"error": errMsg,
		}
	}

	// Honor raw-response sentinel — mirrors the fast path in writeMessage.
	if raw, ok := resp[rawResponseKey].([]byte); ok && raw != nil {
		wire.WriteFrame(conn, wire.MsgJSON, raw)
		return
	}

	body, marshalErr := json.Marshal(resp)
	if marshalErr != nil {
		wire.WriteFrame(conn, wire.MsgError, wire.EncodeError("response encode failed"))
		return
	}
	wire.WriteFrame(conn, wire.MsgJSON, body)
}

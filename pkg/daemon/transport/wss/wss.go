// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wss implements pkg/daemon/transport.Transport over a WebSocket
// Secure connection to a Pilot beacon. Used in "compat mode" by daemons
// running in environments where UDP is impractical (Docker on
// Render/Railway/Vercel/Lambda, restrictive corp networks).
//
// Wire model:
//
//   - The daemon opens ONE long-lived wss:// connection to the beacon.
//   - TLS is verified against the embedded Pilot root CA (or the OS
//     trust store if -tls-trust=system).
//   - After upgrade, the daemon completes an Ed25519 challenge so the
//     beacon can authenticate it against the registry's stored pubkey.
//   - Every Pilot UDP packet the daemon would send becomes one binary
//     WS frame; every inbound binary WS frame becomes one Pilot UDP
//     packet returned by Recv. The beacon transparently relays between
//     UDP peers and WSS peers — see docs/SPEC-compat-mode.md §"Transport
//     matrix".
//
// What this transport intentionally does NOT do:
//
//   - No NAT traversal. Compat-mode peers are unreachable for direct UDP
//     by definition; they register with relay_only=true.
//   - No per-peer flow control. The wssTransport is a pipe to the beacon;
//     Pilot's own L3 reliability layer handles retransmits/ordering on
//     top, identical to today's UDP path.
//   - No reconnect during graceful shutdown. Close() is final; the
//     read goroutine exits cleanly and the next Recv returns ErrClosed.
package wss

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/transport"
)

// DefaultIdlePingInterval is how often the daemon pings the beacon to
// keep the WS connection alive through proxy idle timeouts. 30s is
// short enough for most corporate proxies (which cull at 60-300s) and
// long enough not to flood the link.
const DefaultIdlePingInterval = 30 * time.Second

// DefaultDialTimeout caps the time we spend on a single dial attempt
// (DNS + TCP + TLS + WS upgrade + auth challenge). Beyond this we
// fail fast and let the reconnect loop try again.
const DefaultDialTimeout = 20 * time.Second

// DefaultRecvBuffer is the buffered channel size for inbound frames.
// Sized at 256 to absorb modest bursts without backpressure into the
// WS read goroutine; the daemon's dispatcher (single Recv consumer)
// drains it.
const DefaultRecvBuffer = 256

// authChallengeMsg / authReplyMsg / authOKMsg are the JSON shapes for
// the post-upgrade authentication handshake. They live on the text-frame
// channel; everything after auth_ok is binary frames carrying raw
// Pilot packets.
type authChallengeMsg struct {
	Type  string `json:"type"`  // "auth_challenge"
	Nonce string `json:"nonce"` // 32 random bytes, hex-encoded
}

type authReplyMsg struct {
	Type      string `json:"type"` // "auth_reply"
	NodeID    uint32 `json:"node_id"`
	PublicKey string `json:"public_key"` // base64 Ed25519 pubkey
	Sig       string `json:"sig"`        // base64 Ed25519 signature over "compat_auth:"+node_id+":"+nonce
}

type authOKMsg struct {
	Type string `json:"type"` // "auth_ok"
}

// Config configures a Transport.
type Config struct {
	// URL is the beacon's WSS endpoint, e.g.
	// "wss://beacon-us.pilotprotocol.network/v1/compat".
	URL string

	// TLSConfig pins the trust store. Production builds use a config
	// with RootCAs set to compat.PinnedRoots(); -tls-trust=system uses
	// a config with RootCAs=nil so Go falls back to the OS trust
	// store. Always non-nil — the caller picks the policy.
	TLSConfig *tls.Config

	// Identity provides the Ed25519 keypair used for the auth challenge.
	Identity *crypto.Identity

	// NodeID is the daemon's registered node ID. The auth challenge
	// binds the signature to this nodeID so the beacon can look up the
	// expected pubkey in the registry.
	NodeID uint32

	// IdlePingInterval overrides DefaultIdlePingInterval.
	IdlePingInterval time.Duration

	// DialTimeout overrides DefaultDialTimeout.
	DialTimeout time.Duration

	// RecvBuffer overrides DefaultRecvBuffer.
	RecvBuffer int
}

// Transport is the daemon-side WSS implementation of
// transport.Transport. One Transport == one long-lived WSS connection
// to one beacon.
//
// The Transport is safe for one concurrent reader (Recv) and one
// concurrent writer (Send), matching the contract today's UDP socket
// provides to pkg/daemon/tunnel.go.
type Transport struct {
	cfg Config

	// localAddr is a synthetic local address returned by LocalAddr().
	// Higher layers (routing) use it only for log strings; nothing
	// in L4+ keys on the local addr's IP/port for a compat peer.
	localAddr *net.UDPAddr

	// beaconAddr is a synthetic address representing "the beacon" for
	// inbound frames. Every Recv returns this as the src so the
	// dispatcher can distinguish compat-mode traffic without
	// understanding the URL.
	beaconAddr *net.UDPAddr

	// conn is the live WS connection. Replaced atomically by reconnect
	// logic; reads are serialized through the read goroutine, writes
	// through writeMu.
	connMu sync.RWMutex
	conn   *websocket.Conn

	// writeMu serializes WS writes across Send + idle-ping. WS framing
	// requires one writer at a time.
	writeMu sync.Mutex

	// recvCh delivers inbound frames + errors to Recv().
	recvCh chan recvItem

	// closeOnce + closed ensure Close is idempotent and the read
	// goroutine exits exactly once.
	closeOnce sync.Once
	closed    atomic.Bool

	// readDoneCh closes when the read goroutine exits.
	readDoneCh chan struct{}
}

// recvItem is the unit shipped from the read goroutine to Recv().
// frame is nil on error.
type recvItem struct {
	frame []byte
	err   error
}

// Dial opens a WSS connection to the beacon, completes the Ed25519
// auth challenge, and returns a live Transport. Returns a wrapped
// error if any step fails. Caller is responsible for Close().
func Dial(ctx context.Context, cfg Config) (*Transport, error) {
	if cfg.URL == "" {
		return nil, errors.New("wss: URL is required")
	}
	if cfg.TLSConfig == nil {
		return nil, errors.New("wss: TLSConfig is required (caller picks pinned vs system trust)")
	}
	if cfg.Identity == nil {
		return nil, errors.New("wss: Identity is required for auth")
	}
	if cfg.IdlePingInterval == 0 {
		cfg.IdlePingInterval = DefaultIdlePingInterval
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = DefaultDialTimeout
	}
	if cfg.RecvBuffer <= 0 {
		cfg.RecvBuffer = DefaultRecvBuffer
	}

	dialCtx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	defer cancel()

	// Synthetic local + beacon addresses. The IPs are reserved
	// documentation ranges (RFC 5737) so they cannot collide with a
	// real UDP peer. Ports are 0 — they're not meaningful for WS.
	t := &Transport{
		cfg:        cfg,
		localAddr:  &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 0},
		beaconAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 0},
		recvCh:     make(chan recvItem, cfg.RecvBuffer),
		readDoneCh: make(chan struct{}),
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: cfg.TLSConfig.Clone(),
		},
	}
	conn, _, err := websocket.Dial(dialCtx, cfg.URL, &websocket.DialOptions{
		HTTPClient:   httpClient,
		Subprotocols: []string{"pilot.v1"},
	})
	if err != nil {
		return nil, fmt.Errorf("wss dial: %w", err)
	}

	if err := t.runAuth(dialCtx, conn); err != nil {
		conn.Close(websocket.StatusPolicyViolation, "auth failed")
		return nil, fmt.Errorf("wss auth: %w", err)
	}

	t.connMu.Lock()
	t.conn = conn
	t.connMu.Unlock()

	go t.readLoop()
	return t, nil
}

// runAuth performs the post-upgrade challenge/response. Reads one
// text frame (auth_challenge), signs the nonce, writes auth_reply,
// reads auth_ok. Bounded by dialCtx.
func (t *Transport) runAuth(ctx context.Context, conn *websocket.Conn) error {
	msgType, body, err := conn.Read(ctx)
	if err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}
	if msgType != websocket.MessageText {
		return fmt.Errorf("expected text frame for challenge, got %v", msgType)
	}
	var ch authChallengeMsg
	if err := json.Unmarshal(body, &ch); err != nil {
		return fmt.Errorf("parse challenge: %w", err)
	}
	if ch.Type != "auth_challenge" || ch.Nonce == "" {
		return fmt.Errorf("malformed challenge: type=%q nonce-len=%d", ch.Type, len(ch.Nonce))
	}

	// Sign "compat_auth:<nodeID>:<nonce>" — same shape the beacon
	// verifies. Binding nodeID + nonce into the signed bytes prevents
	// replay across different daemon identities.
	msg := fmt.Sprintf("compat_auth:%d:%s", t.cfg.NodeID, ch.Nonce)
	sig := t.cfg.Identity.Sign([]byte(msg))

	reply := authReplyMsg{
		Type:      "auth_reply",
		NodeID:    t.cfg.NodeID,
		PublicKey: crypto.EncodePublicKey(t.cfg.Identity.PublicKey),
		Sig:       base64.StdEncoding.EncodeToString(sig),
	}
	replyBytes, _ := json.Marshal(reply)
	if err := conn.Write(ctx, websocket.MessageText, replyBytes); err != nil {
		return fmt.Errorf("write reply: %w", err)
	}

	msgType, body, err = conn.Read(ctx)
	if err != nil {
		return fmt.Errorf("read auth_ok: %w", err)
	}
	if msgType != websocket.MessageText {
		return fmt.Errorf("expected text frame for auth_ok, got %v", msgType)
	}
	var ok authOKMsg
	if err := json.Unmarshal(body, &ok); err != nil {
		return fmt.Errorf("parse auth_ok: %w", err)
	}
	if ok.Type != "auth_ok" {
		return fmt.Errorf("auth rejected: %s", string(body))
	}
	return nil
}

// Send writes frame as one binary WS frame. The dst argument is
// ignored — every send goes to the single beacon at the other end
// of this Transport. Returns (len(frame), nil) on success.
func (t *Transport) Send(frame []byte, _ *net.UDPAddr) (int, error) {
	if t.closed.Load() {
		return 0, transport.ErrClosed
	}
	t.connMu.RLock()
	conn := t.conn
	t.connMu.RUnlock()
	if conn == nil {
		return 0, transport.ErrClosed
	}
	t.writeMu.Lock()
	err := conn.Write(context.Background(), websocket.MessageBinary, frame)
	t.writeMu.Unlock()
	if err != nil {
		if t.closed.Load() {
			return 0, transport.ErrClosed
		}
		return 0, fmt.Errorf("wss send: %w", err)
	}
	return len(frame), nil
}

// Recv returns the next inbound frame. The src argument is always
// t.beaconAddr — every inbound packet "arrived from the beacon" from
// the daemon's local viewpoint. The Pilot packet header carries the
// real source nodeID.
func (t *Transport) Recv() ([]byte, *net.UDPAddr, error) {
	item, ok := <-t.recvCh
	if !ok {
		return nil, nil, transport.ErrClosed
	}
	if item.err != nil {
		return nil, nil, item.err
	}
	return item.frame, t.beaconAddr, nil
}

// LocalAddr returns a synthetic local address. Used only in log
// messages by upper layers. Never nil.
func (t *Transport) LocalAddr() *net.UDPAddr {
	return t.localAddr
}

// Close shuts down the WSS connection. Idempotent. After Close, the
// read goroutine exits and subsequent Recv calls return ErrClosed.
func (t *Transport) Close() error {
	var closeErr error
	t.closeOnce.Do(func() {
		t.closed.Store(true)
		t.connMu.Lock()
		conn := t.conn
		t.conn = nil
		t.connMu.Unlock()
		if conn != nil {
			closeErr = conn.Close(websocket.StatusNormalClosure, "")
		}
		// Wait for the read goroutine to drain so we don't race on
		// recvCh close.
		<-t.readDoneCh
		close(t.recvCh)
	})
	return closeErr
}

// readLoop drains binary frames from the WS connection into recvCh.
// Exits on Close() or on the first read error. Errors are surfaced to
// Recv() callers as the last recvItem before the channel closes.
func (t *Transport) readLoop() {
	defer close(t.readDoneCh)

	for {
		if t.closed.Load() {
			return
		}
		t.connMu.RLock()
		conn := t.conn
		t.connMu.RUnlock()
		if conn == nil {
			return
		}

		msgType, body, err := conn.Read(context.Background())
		if err != nil {
			if !t.closed.Load() {
				// Surface the error to the next Recv() then exit.
				// Don't block on a full channel — drop oldest if
				// the consumer is stuck.
				select {
				case t.recvCh <- recvItem{err: fmt.Errorf("wss read: %w", err)}:
				default:
				}
			}
			return
		}

		if msgType == websocket.MessageText {
			// Reserved for future control messages. Today: log and
			// continue (don't drop the connection over an unknown
			// control frame — forward compat).
			continue
		}
		if msgType != websocket.MessageBinary {
			continue
		}
		// Copy: the WS library reuses its internal buffer for the next
		// read. Upper layers may retain the slice across Recv calls
		// (e.g. queuing into the per-peer pending buffer).
		frameCopy := make([]byte, len(body))
		copy(frameCopy, body)
		select {
		case t.recvCh <- recvItem{frame: frameCopy}:
		case <-t.readDoneCh:
			return
		}
	}
}

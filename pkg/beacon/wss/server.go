// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wss is the beacon-side WSS listener for compat-mode daemons.
// See docs/SPEC-compat-mode.md.
//
// Architecture:
//
//   - Accept incoming WebSocket upgrades on a bind address (typically
//     127.0.0.1:8443, behind a Caddy reverse proxy that terminates TLS
//     on port 443). The binary does not handle TLS itself — Caddy does
//     — but plain WS is also supported for in-process tests via
//     httptest.NewServer.
//   - After upgrade, complete an Ed25519 challenge: send a random
//     nonce, receive the daemon's signed reply, verify against the
//     daemon's known pubkey (looked up via PubKeyLookupFn).
//   - On success, store the conn in the wssPeers map keyed by node ID.
//     The conn is owned by a per-peer goroutine that reads binary
//     frames and dispatches them via OnFrame.
//   - Outbound writes: WriteFrame(destID, frame) finds the conn and
//     writes one binary WS frame. Returns false if destID is not
//     currently connected — caller falls back to UDP.
//
// This package is transport-only. It does not know what's inside a
// frame; it just shuttles bytes both directions. The beacon's
// existing relay router calls WriteFrame first and falls back to UDP
// if the destination is a UDP-only peer.
package wss

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

// MaxFrameSize bounds the size of an inbound binary frame. Matches
// the Pilot wire MTU cap (16 KB on data frames + 34-byte header) with
// margin for future fields. Larger frames are rejected and the peer
// is disconnected.
const MaxFrameSize = 64 * 1024

// DefaultAuthTimeout caps the time a peer has to complete the auth
// challenge after WS upgrade. Bots that don't sign correctly drop
// off after this.
const DefaultAuthTimeout = 10 * time.Second

// DefaultIdleTimeout disconnects peers that don't send or pong within
// this window. Pings from the WS library run automatically; this is
// the outer ceiling.
const DefaultIdleTimeout = 90 * time.Second

// Config configures a Server.
type Config struct {
	// BindAddr is the host:port to listen on. Typically
	// "127.0.0.1:8443" with Caddy fronting TLS on :443, or ":8443"
	// for direct exposure.
	BindAddr string

	// PubKeyLookup returns the Ed25519 pubkey registered for nodeID.
	// In production this is plumbed to the registry-shared pubkey
	// cache. Returns (nil, false) if nodeID is unknown.
	PubKeyLookup PubKeyLookupFn

	// OnFrame is invoked when a connected WSS peer sends a binary
	// frame. senderID is the verified node ID (from the auth phase);
	// the caller must not retain the frame slice past the callback.
	OnFrame OnFrameFn

	// AuthTimeout overrides DefaultAuthTimeout.
	AuthTimeout time.Duration

	// IdleTimeout overrides DefaultIdleTimeout.
	IdleTimeout time.Duration

	// MaxPeers caps the number of concurrent WSS peer connections.
	// New upgrades beyond this are rejected with 503. 0 = unlimited.
	MaxPeers int
}

// PubKeyLookupFn fetches the Ed25519 pubkey for a node ID. Returns
// ok=false if the node ID is not registered.
type PubKeyLookupFn func(nodeID uint32) (pubKey ed25519.PublicKey, ok bool)

// OnFrameFn handles an inbound binary frame from a connected WSS peer.
// senderID is the authenticated node ID. frame is owned by the caller
// of OnFrame — must not be retained past the call.
type OnFrameFn func(senderID uint32, frame []byte)

// Server accepts WSS upgrades and maintains the peer connection map.
// Safe for concurrent use after Start.
type Server struct {
	cfg Config

	mu     sync.RWMutex
	peers  map[uint32]*wssPeer
	closed bool

	httpSrv  *http.Server
	listener net.Listener // captured at Start, so Addr() reports the real bound port even when BindAddr=":0"
	wg       sync.WaitGroup

	// Metrics
	upgradeOK    atomic.Uint64
	upgradeFail  atomic.Uint64
	authOK       atomic.Uint64
	authFail     atomic.Uint64
	framesIn     atomic.Uint64
	framesOut    atomic.Uint64
	idleDisconns atomic.Uint64
}

// wssPeer holds the state for one authenticated WSS connection.
type wssPeer struct {
	nodeID  uint32
	conn    *websocket.Conn
	writeMu sync.Mutex
	closed  atomic.Bool
}

// authChallengeMsg / authReplyMsg / authOKMsg mirror the daemon-side
// shapes in pkg/daemon/transport/wss. Kept in sync via SPEC.
type authChallengeMsg struct {
	Type  string `json:"type"`
	Nonce string `json:"nonce"`
}

type authReplyMsg struct {
	Type      string `json:"type"`
	NodeID    uint32 `json:"node_id"`
	PublicKey string `json:"public_key"`
	Sig       string `json:"sig"`
}

type authOKMsg struct {
	Type string `json:"type"`
}

// New constructs a Server with the given configuration. Returns an
// error for missing required fields.
func New(cfg Config) (*Server, error) {
	if cfg.BindAddr == "" {
		return nil, errors.New("wss: BindAddr is required")
	}
	if cfg.PubKeyLookup == nil {
		return nil, errors.New("wss: PubKeyLookup is required")
	}
	if cfg.OnFrame == nil {
		return nil, errors.New("wss: OnFrame is required")
	}
	if cfg.AuthTimeout == 0 {
		cfg.AuthTimeout = DefaultAuthTimeout
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	return &Server{
		cfg:   cfg,
		peers: make(map[uint32]*wssPeer),
	}, nil
}

// Start binds the listener and starts accepting upgrades. Non-blocking;
// returns after the listener is bound. Use Close() to shut down.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/compat", s.handleUpgrade)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	s.httpSrv = &http.Server{
		Addr:              s.cfg.BindAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", s.cfg.BindAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.BindAddr, err)
	}
	s.listener = ln
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("wss server stopped", "err", err)
		}
	}()
	slog.Info("wss server listening", "addr", ln.Addr())
	return nil
}

// Addr returns the actual listen address after Start (useful for
// tests that bind to :0). Returns the configured BindAddr if Start
// has not yet been called.
func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.cfg.BindAddr
}

// Close stops the server, drops all peer connections, and waits for
// the accept goroutine to exit. Idempotent.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	peers := s.peers
	s.peers = nil
	s.mu.Unlock()

	for _, p := range peers {
		_ = p.conn.Close(websocket.StatusGoingAway, "beacon shutting down")
		p.closed.Store(true)
	}

	if s.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(ctx)
	}
	s.wg.Wait()
	return nil
}

// WriteFrame sends a binary frame to the connected WSS peer with the
// given node ID. Returns false if destID is not currently connected
// — the caller (relay router) should fall back to UDP. Returns false
// + logs on write error (peer is then dropped).
func (s *Server) WriteFrame(destID uint32, frame []byte) bool {
	s.mu.RLock()
	p := s.peers[destID]
	s.mu.RUnlock()
	if p == nil || p.closed.Load() {
		return false
	}
	p.writeMu.Lock()
	err := p.conn.Write(context.Background(), websocket.MessageBinary, frame)
	p.writeMu.Unlock()
	if err != nil {
		s.dropPeer(destID, "write error: "+err.Error())
		return false
	}
	s.framesOut.Add(1)
	return true
}

// IsConnected returns whether nodeID has an active WSS peer
// connection. Used by the relay router's "WSS first, UDP fallback"
// decision. O(1) sharded map read.
func (s *Server) IsConnected(nodeID uint32) bool {
	s.mu.RLock()
	p, ok := s.peers[nodeID]
	s.mu.RUnlock()
	return ok && !p.closed.Load()
}

// PeerCount returns the number of currently connected WSS peers.
// Useful for capacity monitoring + Prometheus gauge.
func (s *Server) PeerCount() int {
	s.mu.RLock()
	n := len(s.peers)
	s.mu.RUnlock()
	return n
}

// Metrics returns a snapshot of the counter set for Prometheus
// scraping or logs.
func (s *Server) Metrics() Metrics {
	return Metrics{
		UpgradeOK:    s.upgradeOK.Load(),
		UpgradeFail:  s.upgradeFail.Load(),
		AuthOK:       s.authOK.Load(),
		AuthFail:     s.authFail.Load(),
		FramesIn:     s.framesIn.Load(),
		FramesOut:    s.framesOut.Load(),
		IdleDisconns: s.idleDisconns.Load(),
		ActivePeers:  uint64(s.PeerCount()),
	}
}

// Metrics is the structured counter snapshot returned by
// Server.Metrics. Field semantics:
//
//   - UpgradeOK / UpgradeFail: HTTP upgrade outcomes (before auth).
//   - AuthOK / AuthFail: post-upgrade Ed25519 challenge outcomes.
//   - FramesIn / FramesOut: binary frame counts. One per Pilot packet.
//   - IdleDisconns: peers dropped for inactivity.
//   - ActivePeers: gauge — live WSS connections.
type Metrics struct {
	UpgradeOK, UpgradeFail uint64
	AuthOK, AuthFail       uint64
	FramesIn, FramesOut    uint64
	IdleDisconns           uint64
	ActivePeers            uint64
}

// handleUpgrade accepts the WS upgrade + auth challenge and starts
// the per-peer read goroutine.
func (s *Server) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	// Capacity check before doing the upgrade work.
	if s.cfg.MaxPeers > 0 && s.PeerCount() >= s.cfg.MaxPeers {
		http.Error(w, "wss: at capacity", http.StatusServiceUnavailable)
		s.upgradeFail.Add(1)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{"pilot.v1"},
	})
	if err != nil {
		s.upgradeFail.Add(1)
		return
	}
	s.upgradeOK.Add(1)

	authCtx, cancel := context.WithTimeout(r.Context(), s.cfg.AuthTimeout)
	defer cancel()

	nodeID, err := s.runAuth(authCtx, conn)
	if err != nil {
		s.authFail.Add(1)
		conn.Close(websocket.StatusPolicyViolation, "auth failed")
		return
	}
	s.authOK.Add(1)

	p := &wssPeer{nodeID: nodeID, conn: conn}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		conn.Close(websocket.StatusGoingAway, "server shutting down")
		return
	}
	// Replace any prior peer for this nodeID (last-writer-wins; the
	// old connection's read goroutine will exit on next read error).
	if old := s.peers[nodeID]; old != nil {
		old.closed.Store(true)
		_ = old.conn.Close(websocket.StatusNormalClosure, "replaced")
	}
	s.peers[nodeID] = p
	s.mu.Unlock()

	slog.Info("wss peer connected", "node_id", nodeID, "remote", r.RemoteAddr)
	s.peerReadLoop(p)
}

// runAuth performs the Ed25519 challenge/response with a peer that
// just completed the WS upgrade. Returns the verified node ID on
// success.
func (s *Server) runAuth(ctx context.Context, conn *websocket.Conn) (uint32, error) {
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return 0, fmt.Errorf("nonce gen: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)

	challenge := authChallengeMsg{Type: "auth_challenge", Nonce: nonce}
	chBytes, _ := json.Marshal(challenge)
	if err := conn.Write(ctx, websocket.MessageText, chBytes); err != nil {
		return 0, fmt.Errorf("write challenge: %w", err)
	}

	msgType, body, err := conn.Read(ctx)
	if err != nil {
		return 0, fmt.Errorf("read reply: %w", err)
	}
	if msgType != websocket.MessageText {
		return 0, errors.New("reply not a text frame")
	}
	var reply authReplyMsg
	if err := json.Unmarshal(body, &reply); err != nil {
		return 0, fmt.Errorf("parse reply: %w", err)
	}
	if reply.Type != "auth_reply" || reply.NodeID == 0 {
		return 0, fmt.Errorf("malformed reply: type=%q node_id=%d", reply.Type, reply.NodeID)
	}

	pubKey, ok := s.cfg.PubKeyLookup(reply.NodeID)
	if !ok {
		return 0, fmt.Errorf("unknown node_id %d", reply.NodeID)
	}
	sig, err := base64.StdEncoding.DecodeString(reply.Sig)
	if err != nil {
		return 0, fmt.Errorf("bad sig encoding: %w", err)
	}
	signed := fmt.Sprintf("compat_auth:%d:%s", reply.NodeID, nonce)
	if !ed25519.Verify(pubKey, []byte(signed), sig) {
		return 0, fmt.Errorf("ed25519 verify failed for node_id %d", reply.NodeID)
	}

	okMsg := authOKMsg{Type: "auth_ok"}
	okBytes, _ := json.Marshal(okMsg)
	if err := conn.Write(ctx, websocket.MessageText, okBytes); err != nil {
		return 0, fmt.Errorf("write auth_ok: %w", err)
	}
	return reply.NodeID, nil
}

// peerReadLoop drains binary frames from a peer's WS connection into
// the OnFrame callback. Exits on Close, read error, or idle timeout.
func (s *Server) peerReadLoop(p *wssPeer) {
	defer s.dropPeer(p.nodeID, "read loop exit")

	for {
		if p.closed.Load() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.IdleTimeout)
		msgType, body, err := p.conn.Read(ctx)
		cancel()
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				s.idleDisconns.Add(1)
				slog.Info("wss peer idle disconnect", "node_id", p.nodeID)
				return
			}
			// Any other read error = peer gone.
			return
		}
		if msgType != websocket.MessageBinary {
			// Ignore text frames after auth (reserved for future
			// control); don't disconnect over unknown control msgs.
			continue
		}
		if len(body) > MaxFrameSize {
			slog.Warn("wss peer sent oversized frame", "node_id", p.nodeID, "len", len(body))
			return
		}
		s.framesIn.Add(1)
		s.cfg.OnFrame(p.nodeID, body)
	}
}

// dropPeer removes a peer from the map and closes the underlying WS
// connection. Idempotent — safe to call from both the read loop exit
// and an explicit Close path.
func (s *Server) dropPeer(nodeID uint32, reason string) {
	s.mu.Lock()
	p := s.peers[nodeID]
	if p != nil {
		delete(s.peers, nodeID)
	}
	s.mu.Unlock()
	if p != nil && !p.closed.Swap(true) {
		_ = p.conn.Close(websocket.StatusNormalClosure, reason)
		slog.Info("wss peer disconnected", "node_id", nodeID, "reason", reason)
	}
}

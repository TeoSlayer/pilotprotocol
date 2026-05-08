// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

// Client talks to a registry server over TCP (optionally TLS).
// It automatically reconnects if the connection drops.
//
// By default a Client owns a single TCP connection (Dial / DialTLS /
// DialTLSPinned). Each Send takes c.mu and serialises the entire
// request/response round-trip on that one conn. Under heavy concurrent
// load (the §4.8 lock-graph stress harness — 250 heartbeat goroutines
// per daemon hammering Health / Info / SetTags / ResolveHostname plus
// the per-resolve prewarm goroutines and persistHostnameCache writers,
// all funnelling through regConn.Send) that single mutex becomes the
// bottleneck: in-flight calls cannot honour shutdown signals because
// they're queued behind the mutex.
//
// DialPool / DialTLSPool create a Client backed by a small pool of
// connections (the primary c.conn plus N-1 secondary conns). Each
// concurrent Send picks a free pooled conn (blocking only if every
// conn is in use), eliminating the head-of-line wait. The primary
// c.conn / c.mu / c.closed fields are retained for backward compatibility
// with tests that touch them directly.
type Client struct {
	// Primary connection. Always present; tests in this package read
	// c.conn / c.mu / c.closed directly so the field set must stay stable.
	conn      net.Conn
	mu        sync.Mutex
	addr      string // registry address for reconnection
	closed    bool
	tlsConfig *tls.Config
	signer    func(challenge string) string // H3 fix: optional message signer

	// Optional pool of secondary connections used to parallelise Send.
	// nil / empty when DialPool was not used.
	pool poolState
}

// poolState holds the secondary-conn pool. The primary slot (c.conn / c.mu)
// is also represented here as the first entry, so acquireConn / releaseConn
// can pick uniformly across all conns.
type poolState struct {
	// entries is the full set of conns including the primary at index 0.
	// Each entry has its own mu — taking entry.mu lets one Send proceed
	// without blocking other Sends on different entries. Closed when the
	// Client is closed.
	entries []*pooledConn
	// free is a buffered channel of pointers to entries currently free.
	// Capacity equals len(entries). Send: <-free; defer free<-entry.
	// nil means "no pool" (legacy single-conn path via c.mu).
	free chan *pooledConn
	// done is closed by Close() to wake goroutines blocked on <-free and to
	// signal the deferred pool-return in sendPool to drop its entry instead
	// of sending on free. Using a separate done channel avoids the race
	// between close(free) and concurrent sends on free.
	done chan struct{}
}

// pooledConn wraps one TCP connection plus its own mutex. The mutex
// guards both the conn pointer and any reconnect that happens through
// it; sendOnEntry takes it for the full write/read round-trip.
type pooledConn struct {
	mu   sync.Mutex
	conn net.Conn
}

// SetSigner sets a signing function for authenticated registry operations (H3 fix).
// The signer receives a challenge string and returns a base64-encoded Ed25519 signature.
//
// Issue #93: when the regConn is pooled (DialPool), multiple Send goroutines
// may call sign() concurrently while a parallel RotateKey path calls
// SetSigner. We guard the field with c.mu to keep that race-free; reads via
// sign() take the same lock so the loaded function pointer is consistent.
func (c *Client) SetSigner(fn func(challenge string) string) {
	c.mu.Lock()
	c.signer = fn
	c.mu.Unlock()
}

// sign returns a signature for the challenge, or empty string if no signer is set.
func (c *Client) sign(challenge string) string {
	c.mu.Lock()
	fn := c.signer
	c.mu.Unlock()
	if fn == nil {
		return ""
	}
	return fn(challenge)
}

func Dial(addr string) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial registry: %w", err)
	}
	return &Client{conn: conn, addr: addr}, nil
}

// DialPool connects to a registry server over plain TCP and pre-warms a
// pool of `size` connections (size >= 1). When size == 1 this is identical
// to Dial. When size > 1, additional secondary conns are dialed; concurrent
// Send calls then run in parallel up to `size` at a time, instead of all
// queueing on a single mutex.
//
// DialPool exists to fix #93 (regConn fairness under sustained load): the
// daemon's IPC handlers spawn goroutines that all call regConn.Send and
// previously serialised on c.mu. With DialPool the daemon can keep the
// same code path while letting up to `size` registry round-trips run
// concurrently.
//
// On any pool conn dial failure DialPool closes the conns it had already
// opened and returns an error.
func DialPool(addr string, size int) (*Client, error) {
	if size <= 0 {
		size = 1
	}
	primary, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial registry: %w", err)
	}
	c := &Client{conn: primary, addr: addr}
	if err := c.initPool(size, nil); err != nil {
		primary.Close()
		return nil, err
	}
	return c, nil
}

// DialTLS connects to a registry server over TLS.
// A non-nil tlsConfig is required. For certificate pinning, use DialTLSPinned.
func DialTLS(addr string, tlsConfig *tls.Config) (*Client, error) {
	if tlsConfig == nil {
		return nil, fmt.Errorf("TLS config required; use DialTLSPinned for certificate pinning")
	}
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("dial registry TLS: %w", err)
	}
	return &Client{conn: conn, addr: addr, tlsConfig: tlsConfig}, nil
}

// DialTLSPool is the TLS variant of DialPool.
func DialTLSPool(addr string, tlsConfig *tls.Config, size int) (*Client, error) {
	if tlsConfig == nil {
		return nil, fmt.Errorf("TLS config required; use DialTLSPinnedPool for certificate pinning")
	}
	if size <= 0 {
		size = 1
	}
	primary, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("dial registry TLS: %w", err)
	}
	c := &Client{conn: primary, addr: addr, tlsConfig: tlsConfig}
	if err := c.initPool(size, tlsConfig); err != nil {
		primary.Close()
		return nil, err
	}
	return c, nil
}

// initPool dials size-1 additional connections and registers them in c.pool.
// It assumes c.conn (primary) is already set. tlsCfg, when non-nil, is used
// for TLS dialing; otherwise plain TCP.
func (c *Client) initPool(size int, tlsCfg *tls.Config) error {
	if size <= 1 {
		// No secondary conns — single-conn legacy path; pool stays empty.
		return nil
	}
	entries := make([]*pooledConn, 0, size)
	entries = append(entries, &pooledConn{conn: c.conn})
	for i := 1; i < size; i++ {
		var conn net.Conn
		var err error
		if tlsCfg != nil {
			conn, err = tls.Dial("tcp", c.addr, tlsCfg)
		} else {
			conn, err = net.Dial("tcp", c.addr)
		}
		if err != nil {
			// Close any conns we already opened (excluding primary —
			// caller closes that on failure).
			for _, e := range entries[1:] {
				e.conn.Close()
			}
			return fmt.Errorf("dial pool conn %d: %w", i, err)
		}
		entries = append(entries, &pooledConn{conn: conn})
	}
	free := make(chan *pooledConn, len(entries))
	for _, e := range entries {
		free <- e
	}
	c.pool.entries = entries
	c.pool.free = free
	c.pool.done = make(chan struct{})
	return nil
}

// DialTLSPinned connects to a registry server over TLS with certificate pinning.
// The fingerprint is a hex-encoded SHA-256 hash of the server's DER-encoded certificate.
func DialTLSPinned(addr, fingerprint string) (*Client, error) {
	tlsConfig := &tls.Config{
		// InsecureSkipVerify disables the default CA chain check so we can
		// use VerifyPeerCertificate for certificate pinning (SHA-256 fingerprint).
		// This is the standard Go pattern — the custom callback below provides
		// strictly stronger verification than CA-based trust.
		InsecureSkipVerify: true, //nolint:gosec // cert pinning via VerifyPeerCertificate
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificate presented")
			}
			hash := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(hash[:])
			if got != fingerprint {
				return fmt.Errorf("certificate fingerprint mismatch: got %s, want %s", got, fingerprint)
			}
			return nil
		},
	}
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("dial registry TLS pinned: %w", err)
	}
	return &Client{conn: conn, addr: addr, tlsConfig: tlsConfig}, nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	conn := c.conn
	pool := c.pool.entries
	c.mu.Unlock()
	// Close the conn after releasing the lock; conn is captured by value
	// so reconnect() can't see it after we set c.closed=true (M7 fix)
	var firstErr error
	if conn != nil {
		if err := conn.Close(); err != nil {
			firstErr = err
		}
	}
	// Close every secondary pooled conn. The primary is already closed
	// above (entries[0] holds the same fd as c.conn). Skip index 0 so
	// we don't double-close.
	for i := 1; i < len(pool); i++ {
		e := pool[i]
		// Take e.mu to coordinate with any in-flight sendOnEntry that
		// holds it; once we release the mutex it'll see a closed conn
		// on its next Read/Write and return an error to the caller.
		e.mu.Lock()
		if e.conn != nil {
			if err := e.conn.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		e.mu.Unlock()
	}
	// Close pool.done to wake any goroutine blocked on <-c.pool.free and to
	// signal the deferred pool-return in sendPool to drop its entry. We never
	// close pool.free itself because that would race with concurrent sends on
	// it from the sendPool defer.
	if c.pool.done != nil {
		close(c.pool.done)
	}
	return firstErr
}

// reconnect re-establishes the TCP connection to the registry.
// Must be called with c.mu held.
func (c *Client) reconnect() error {
	if c.closed {
		return fmt.Errorf("client closed")
	}
	if c.conn != nil {
		c.conn.Close()
	}

	var conn net.Conn
	var err error
	backoff := 500 * time.Millisecond
	maxBackoff := 10 * time.Second

	for attempts := 0; attempts < 5; attempts++ {
		if c.tlsConfig != nil {
			dialer := &tls.Dialer{Config: c.tlsConfig, NetDialer: &net.Dialer{Timeout: 5 * time.Second}}
			conn, err = dialer.DialContext(context.Background(), "tcp", c.addr)
		} else {
			conn, err = net.DialTimeout("tcp", c.addr, 5*time.Second)
		}
		if err == nil {
			c.conn = conn
			slog.Info("registry reconnected", "addr", c.addr)
			return nil
		}
		slog.Warn("registry reconnect failed", "attempt", attempts+1, "err", err)
		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	return fmt.Errorf("reconnect failed after 5 attempts: %w", err)
}

func (c *Client) Send(msg map[string]interface{}) (map[string]interface{}, error) {
	// Pool-enabled path (DialPool / DialTLSPool): pick a free conn and
	// run the round-trip on it without touching c.mu. Multiple Send
	// callers can run concurrently on different pooled conns.
	if c.pool.free != nil {
		return c.sendPool(msg)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	resp, err := c.sendLocked(msg)
	if err != nil && resp == nil && !c.closed {
		// Connection-level failure (no response received) — reconnect and retry once.
		// Server error responses (resp != nil) do NOT trigger reconnection.
		if reconnErr := c.reconnect(); reconnErr != nil {
			return nil, fmt.Errorf("send failed and reconnect failed: %w", err)
		}
		resp, err = c.sendLocked(msg)
	}
	return resp, err
}

// sendPool runs Send on a free pooled connection. It blocks only when
// every pooled conn is busy (capacity exhausted) — one concurrent Send
// per pool entry can be in flight at a time.
func (c *Client) sendPool(msg map[string]interface{}) (map[string]interface{}, error) {
	// Cheap closed check — avoids a wedged caller waiting on a free
	// channel that nobody will ever return to once Close has run.
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, fmt.Errorf("client closed")
	}

	var entry *pooledConn
	select {
	case entry = <-c.pool.free:
	case <-c.pool.done:
		return nil, fmt.Errorf("client closed")
	}
	defer func() {
		select {
		case c.pool.free <- entry:
		case <-c.pool.done:
			// pool is torn down; drop the entry
		}
	}()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	resp, err := c.sendOnEntry(entry, msg)
	if err != nil && resp == nil && !c.isClosed() {
		// Connection-level failure on this entry — reconnect THIS entry
		// only (other pool entries are unaffected) and retry once.
		if reconnErr := c.reconnectEntry(entry); reconnErr != nil {
			return nil, fmt.Errorf("send failed and reconnect failed: %w", err)
		}
		resp, err = c.sendOnEntry(entry, msg)
	}
	return resp, err
}

// sendOnEntry writes the request and reads the response on entry.conn.
// Caller must hold entry.mu.
func (c *Client) sendOnEntry(entry *pooledConn, msg map[string]interface{}) (map[string]interface{}, error) {
	if err := wire.WriteMessage(entry.conn, msg); err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}
	entry.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	resp, err := wire.ReadMessage(entry.conn)
	entry.conn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, fmt.Errorf("recv: %w", err)
	}
	if errMsg, ok := resp["error"].(string); ok {
		return resp, fmt.Errorf("registry: %s", errMsg)
	}
	return resp, nil
}

// reconnectEntry redials a single pool entry. Caller must hold entry.mu.
// This is the per-entry analogue of Client.reconnect.
func (c *Client) reconnectEntry(entry *pooledConn) error {
	if c.isClosed() {
		return fmt.Errorf("client closed")
	}
	if entry.conn != nil {
		entry.conn.Close()
	}

	var conn net.Conn
	var err error
	backoff := 500 * time.Millisecond
	maxBackoff := 10 * time.Second
	for attempts := 0; attempts < 5; attempts++ {
		if c.tlsConfig != nil {
			dialer := &tls.Dialer{Config: c.tlsConfig, NetDialer: &net.Dialer{Timeout: 5 * time.Second}}
			conn, err = dialer.DialContext(context.Background(), "tcp", c.addr)
		} else {
			conn, err = net.DialTimeout("tcp", c.addr, 5*time.Second)
		}
		if err == nil {
			entry.conn = conn
			// Keep c.conn (primary) in sync if this is the primary entry.
			// Tests in this package read c.conn directly, so we must not
			// leave it pointing at a closed fd.
			if entry == c.pool.entries[0] {
				c.mu.Lock()
				c.conn = conn
				c.mu.Unlock()
			}
			slog.Info("registry pool conn reconnected", "addr", c.addr)
			return nil
		}
		slog.Warn("registry pool conn reconnect failed", "attempt", attempts+1, "err", err)
		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	return fmt.Errorf("reconnect failed after 5 attempts: %w", err)
}

// isClosed returns whether Close has been called. Cheap, lock-protected.
func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// sendLocked sends a message and reads the response. Must be called with c.mu held.
func (c *Client) sendLocked(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := wire.WriteMessage(c.conn, msg); err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}
	c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	resp, err := wire.ReadMessage(c.conn)
	c.conn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, fmt.Errorf("recv: %w", err)
	}
	if errMsg, ok := resp["error"].(string); ok {
		return resp, fmt.Errorf("registry: %s", errMsg)
	}
	return resp, nil
}

func (c *Client) Register(listenAddr string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "register",
		"listen_addr": listenAddr,
	})
}

// RegisterWithOwner registers a new node with an owner identifier (email/name)
// for key rotation recovery.
func (c *Client) RegisterWithOwner(listenAddr, owner string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "register",
		"listen_addr": listenAddr,
		"owner":       owner,
	})
}

// RegisterWithKey re-registers using an existing Ed25519 public key.
// The registry returns the same node_id if the key is known.
// lanAddrs are the node's LAN addresses for same-network peer detection.
func (c *Client) RegisterWithKey(listenAddr, publicKeyB64, owner string, lanAddrs []string, opts ...string) (map[string]interface{}, error) {
	return c.RegisterWithKeyOpts(RegisterOpts{
		ListenAddr: listenAddr,
		PublicKey:  publicKeyB64,
		Owner:      owner,
		LANAddrs:   lanAddrs,
		Version:    firstNonEmpty(opts...),
	})
}

// RegisterOpts is the full set of registration options. Lets us add
// fields (like RelayOnly for task 32) without breaking the variadic
// signature of RegisterWithKey.
type RegisterOpts struct {
	ListenAddr string
	PublicKey  string // base64 Ed25519
	Owner      string
	LANAddrs   []string
	Version    string
	RelayOnly  bool // task 32: hide real_addr from peers
}

// RegisterWithKeyOpts is the structured-form register call. Existing
// callers keep using RegisterWithKey; new flags go here.
func (c *Client) RegisterWithKeyOpts(o RegisterOpts) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":        "register",
		"listen_addr": o.ListenAddr,
		"public_key":  o.PublicKey,
	}
	if o.Owner != "" {
		msg["owner"] = o.Owner
	}
	if len(o.LANAddrs) > 0 {
		msg["lan_addrs"] = o.LANAddrs
	}
	if o.Version != "" {
		msg["version"] = o.Version
	}
	if o.RelayOnly {
		msg["relay_only"] = true
	}
	return c.Send(msg)
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// RotateKey requests a key rotation for a node.
// Requires a signature proving ownership of the current key and the new public key.
func (c *Client) RotateKey(nodeID uint32, signatureB64, newPubKeyB64 string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "rotate_key",
		"node_id": nodeID,
	}
	if signatureB64 != "" {
		msg["signature"] = signatureB64
	}
	if newPubKeyB64 != "" {
		msg["new_public_key"] = newPubKeyB64
	}
	return c.Send(msg)
}

func (c *Client) Lookup(nodeID uint32) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":    "lookup",
		"node_id": nodeID,
	})
}

func (c *Client) Resolve(nodeID, requesterID uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":         "resolve",
		"node_id":      nodeID,
		"requester_id": requesterID,
	}
	if sig := c.sign(fmt.Sprintf("resolve:%d:%d", requesterID, nodeID)); sig != "" {
		msg["signature"] = sig
	}
	return c.Send(msg)
}

func (c *Client) ReportTrust(nodeID, peerID uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "report_trust",
		"node_id": nodeID,
		"peer_id": peerID,
	}
	if sig := c.sign(fmt.Sprintf("report_trust:%d:%d", nodeID, peerID)); sig != "" {
		msg["signature"] = sig
	}
	return c.Send(msg)
}

func (c *Client) RevokeTrust(nodeID, peerID uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "revoke_trust",
		"node_id": nodeID,
		"peer_id": peerID,
	}
	if sig := c.sign(fmt.Sprintf("revoke_trust:%d:%d", nodeID, peerID)); sig != "" {
		msg["signature"] = sig
	}
	return c.Send(msg)
}

func (c *Client) SetVisibility(nodeID uint32, public bool) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "set_visibility",
		"node_id": nodeID,
		"public":  public,
	}
	if sig := c.sign(fmt.Sprintf("set_visibility:%d", nodeID)); sig != "" {
		msg["signature"] = sig
	}
	return c.Send(msg)
}

func (c *Client) CreateNetwork(nodeID uint32, name, joinRule, token, adminToken string, enterprise bool, networkAdminToken ...string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":      "create_network",
		"node_id":   nodeID,
		"name":      name,
		"join_rule": joinRule,
		"token":     token,
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	if enterprise {
		msg["enterprise"] = true
	}
	if len(networkAdminToken) > 0 && networkAdminToken[0] != "" {
		msg["network_admin_token"] = networkAdminToken[0]
	}
	return c.Send(msg)
}

// CreateManagedNetwork creates a network with managed rules.
func (c *Client) CreateManagedNetwork(nodeID uint32, name, joinRule, token, adminToken string, enterprise bool, rules string, networkAdminToken ...string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":      "create_network",
		"node_id":   nodeID,
		"name":      name,
		"join_rule": joinRule,
		"token":     token,
		"rules":     rules,
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	if enterprise {
		msg["enterprise"] = true
	}
	if len(networkAdminToken) > 0 && networkAdminToken[0] != "" {
		msg["network_admin_token"] = networkAdminToken[0]
	}
	return c.Send(msg)
}

func (c *Client) JoinNetwork(nodeID uint32, networkID uint16, token string, inviterID uint32, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":       "join_network",
		"node_id":    nodeID,
		"network_id": networkID,
		"token":      token,
		"inviter_id": inviterID,
	}
	if sig := c.sign(fmt.Sprintf("join_network:%d:%d", nodeID, networkID)); sig != "" {
		msg["signature"] = sig
	} else if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return c.Send(msg)
}

func (c *Client) LeaveNetwork(nodeID uint32, networkID uint16, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":       "leave_network",
		"node_id":    nodeID,
		"network_id": networkID,
	}
	if sig := c.sign(fmt.Sprintf("leave_network:%d:%d", nodeID, networkID)); sig != "" {
		msg["signature"] = sig
	} else if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return c.Send(msg)
}

func (c *Client) DeleteNetwork(networkID uint16, adminToken string, nodeID ...uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":       "delete_network",
		"network_id": networkID,
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	if len(nodeID) > 0 && nodeID[0] != 0 {
		msg["node_id"] = nodeID[0]
	}
	return c.Send(msg)
}

func (c *Client) RenameNetwork(networkID uint16, name, adminToken string, nodeID ...uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":       "rename_network",
		"network_id": networkID,
		"name":       name,
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	if len(nodeID) > 0 && nodeID[0] != 0 {
		msg["node_id"] = nodeID[0]
	}
	return c.Send(msg)
}

func (c *Client) SetNetworkEnterprise(networkID uint16, enterprise bool, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_network_enterprise",
		"network_id":  networkID,
		"enterprise":  enterprise,
		"admin_token": adminToken,
	})
}

// ListNetworks returns the registry's network catalog. Member counts
// (the `members` field on each entry) are admin-only — pass a non-empty
// adminToken to receive them; otherwise the field is omitted.
func (c *Client) ListNetworks(adminToken ...string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type": "list_networks",
	}
	if len(adminToken) > 0 && adminToken[0] != "" {
		msg["admin_token"] = adminToken[0]
	}
	return c.Send(msg)
}

func (c *Client) ListNodes(networkID uint16, adminToken ...string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":       "list_nodes",
		"network_id": networkID,
	}
	if len(adminToken) > 0 && adminToken[0] != "" {
		msg["admin_token"] = adminToken[0]
	}
	return c.Send(msg)
}

func (c *Client) Deregister(nodeID uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "deregister",
		"node_id": nodeID,
	}
	if sig := c.sign(fmt.Sprintf("deregister:%d", nodeID)); sig != "" {
		msg["signature"] = sig
	}
	return c.Send(msg)
}

func (c *Client) Heartbeat(nodeID uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "heartbeat",
		"node_id": nodeID,
	}
	if sig := c.sign(fmt.Sprintf("heartbeat:%d", nodeID)); sig != "" {
		msg["signature"] = sig
	}
	return c.Send(msg)
}

func (c *Client) Punch(requesterID, nodeA, nodeB uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":         "punch",
		"requester_id": requesterID,
		"node_a":       nodeA,
		"node_b":       nodeB,
	}
	if sig := c.sign(fmt.Sprintf("punch:%d:%d", nodeA, nodeB)); sig != "" {
		msg["signature"] = sig
	}
	return c.Send(msg)
}

// RequestHandshake relays a handshake request through the registry to a target node.
// This works even for private nodes — no IP exposure needed.
// M12 fix: includes a signature to prove sender identity.
func (c *Client) RequestHandshake(fromNodeID, toNodeID uint32, justification, signatureB64 string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":          "request_handshake",
		"from_node_id":  fromNodeID,
		"to_node_id":    toNodeID,
		"justification": justification,
	}
	if signatureB64 != "" {
		msg["signature"] = signatureB64
	}
	return c.Send(msg)
}

// PollHandshakes retrieves and clears pending handshake requests for a node.
// H3 fix: includes a signature to prove node identity.
func (c *Client) PollHandshakes(nodeID uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "poll_handshakes",
		"node_id": nodeID,
	}
	if sig := c.sign(fmt.Sprintf("poll_handshakes:%d", nodeID)); sig != "" {
		msg["signature"] = sig
	}
	return c.Send(msg)
}

// RespondHandshake approves or rejects a relayed handshake request.
// If accepted, the registry creates a mutual trust pair.
// M12 fix: includes a signature to prove responder identity.
func (c *Client) RespondHandshake(nodeID, peerID uint32, accept bool, signatureB64 string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "respond_handshake",
		"node_id": nodeID,
		"peer_id": peerID,
		"accept":  accept,
	}
	if signatureB64 != "" {
		msg["signature"] = signatureB64
	}
	return c.Send(msg)
}

// SetHostname sets or clears the hostname for a node.
// An empty hostname clears the current hostname.
func (c *Client) SetHostname(nodeID uint32, hostname string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":     "set_hostname",
		"node_id":  nodeID,
		"hostname": hostname,
	}
	if sig := c.sign(fmt.Sprintf("set_hostname:%d", nodeID)); sig != "" {
		msg["signature"] = sig
	}
	return c.Send(msg)
}

// SetTags sets the capability tags for a node.
func (c *Client) SetTags(nodeID uint32, tags []string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "set_tags",
		"node_id": nodeID,
		"tags":    tags,
	}
	if sig := c.sign(fmt.Sprintf("set_tags:%d", nodeID)); sig != "" {
		msg["signature"] = sig
	}
	return c.Send(msg)
}

// ResolveHostname resolves a hostname to node info (node_id, address, public flag).
func (c *Client) ResolveHostname(hostname string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":     "resolve_hostname",
		"hostname": hostname,
	})
}

// ResolveHostnameAs resolves a hostname with a requester_id for privacy checks.
// Private nodes require the requester to have a trust pair or shared network.
func (c *Client) ResolveHostnameAs(requesterID uint32, hostname string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":         "resolve_hostname",
		"hostname":     hostname,
		"requester_id": requesterID,
	})
}

// CheckTrust checks if a trust pair or shared network exists between two nodes.
func (c *Client) CheckTrust(nodeA, nodeB uint32) (bool, error) {
	resp, err := c.Send(map[string]interface{}{
		"type":    "check_trust",
		"node_id": nodeA,
		"peer_id": nodeB,
	})
	if err != nil {
		return false, err
	}
	trusted, _ := resp["trusted"].(bool)
	return trusted, nil
}

// InviteToNetwork stores a pending invite for a target node to join an invite-only network.
func (c *Client) InviteToNetwork(networkID uint16, inviterID, targetNodeID uint32, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":           "invite_to_network",
		"network_id":     networkID,
		"inviter_id":     inviterID,
		"target_node_id": targetNodeID,
	}
	if sig := c.sign(fmt.Sprintf("invite:%d:%d:%d", inviterID, networkID, targetNodeID)); sig != "" {
		msg["signature"] = sig
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return c.Send(msg)
}

// PollInvites returns and clears pending network invites for a node. Signed.
func (c *Client) PollInvites(nodeID uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "poll_invites",
		"node_id": nodeID,
	}
	if sig := c.sign(fmt.Sprintf("poll_invites:%d", nodeID)); sig != "" {
		msg["signature"] = sig
	}
	return c.Send(msg)
}

// RespondInvite accepts or rejects a pending network invite. Signed.
func (c *Client) RespondInvite(nodeID uint32, networkID uint16, accept bool) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":       "respond_invite",
		"node_id":    nodeID,
		"network_id": networkID,
		"accept":     accept,
	}
	if sig := c.sign(fmt.Sprintf("respond_invite:%d:%d", nodeID, networkID)); sig != "" {
		msg["signature"] = sig
	}
	return c.Send(msg)
}

// PromoteMember promotes a network member to admin. Only the owner can promote.
func (c *Client) PromoteMember(networkID uint16, nodeID, targetNodeID uint32, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":           "promote_member",
		"network_id":     networkID,
		"node_id":        nodeID,
		"target_node_id": targetNodeID,
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return c.Send(msg)
}

// DemoteMember demotes an admin to member. Only the owner can demote.
func (c *Client) DemoteMember(networkID uint16, nodeID, targetNodeID uint32, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":           "demote_member",
		"network_id":     networkID,
		"node_id":        nodeID,
		"target_node_id": targetNodeID,
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return c.Send(msg)
}

// KickMember removes a member from a network. Requires owner or admin role.
func (c *Client) KickMember(networkID uint16, nodeID, targetNodeID uint32, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":           "kick_member",
		"network_id":     networkID,
		"node_id":        nodeID,
		"target_node_id": targetNodeID,
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return c.Send(msg)
}

// TransferOwnership transfers network ownership to another member. Only the current owner can transfer.
func (c *Client) TransferOwnership(networkID uint16, ownerNodeID, newOwnerID uint32, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":         "transfer_ownership",
		"network_id":   networkID,
		"node_id":      ownerNodeID,
		"new_owner_id": newOwnerID,
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return c.Send(msg)
}

// GetMemberRole returns the RBAC role of a node in a network.
func (c *Client) GetMemberRole(networkID uint16, targetNodeID uint32) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":           "get_member_role",
		"network_id":     networkID,
		"target_node_id": targetNodeID,
	})
}

// SetNetworkPolicy sets or updates a network's policy. Requires owner/admin role or admin token.
func (c *Client) SetNetworkPolicy(networkID uint16, policy map[string]interface{}, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{}
	for k, v := range policy {
		msg[k] = v
	}
	msg["type"] = "set_network_policy"
	msg["network_id"] = networkID
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return c.Send(msg)
}

// GetNetworkPolicy returns the policy for a given network.
func (c *Client) GetNetworkPolicy(networkID uint16) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":       "get_network_policy",
		"network_id": networkID,
	})
}

// SetExprPolicy sets the programmable policy for a network.
// Requires owner/admin role or admin token.
func (c *Client) SetExprPolicy(networkID uint16, policyJSON json.RawMessage, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":        "set_expr_policy",
		"network_id":  networkID,
		"expr_policy": string(policyJSON),
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return c.Send(msg)
}

// GetExprPolicy returns the programmable policy for a network.
func (c *Client) GetExprPolicy(networkID uint16) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":       "get_expr_policy",
		"network_id": networkID,
	})
}

// SetKeyExpiry sets the key expiry time for a node. Requires signature.
func (c *Client) SetKeyExpiry(nodeID uint32, expiresAt time.Time) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":       "set_key_expiry",
		"node_id":    nodeID,
		"expires_at": expiresAt.Format(time.RFC3339),
	}
	if sig := c.sign(fmt.Sprintf("set_key_expiry:%d", nodeID)); sig != "" {
		msg["signature"] = sig
	}
	return c.Send(msg)
}

// GetKeyInfo returns key lifecycle metadata for a node.
func (c *Client) GetKeyInfo(nodeID uint32) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":    "get_key_info",
		"node_id": nodeID,
	})
}

// --- Admin methods (bypass node signature, use admin_token instead) ---

// SetHostnameAdmin sets a node's hostname using admin token auth.
func (c *Client) SetHostnameAdmin(nodeID uint32, hostname, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_hostname",
		"node_id":     nodeID,
		"hostname":    hostname,
		"admin_token": adminToken,
	})
}

// SetVisibilityAdmin sets a node's visibility using admin token auth.
func (c *Client) SetVisibilityAdmin(nodeID uint32, public bool, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_visibility",
		"node_id":     nodeID,
		"public":      public,
		"admin_token": adminToken,
	})
}

// SetTagsAdmin sets a node's tags using admin token auth.
func (c *Client) SetTagsAdmin(nodeID uint32, tags []string, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_tags",
		"node_id":     nodeID,
		"tags":        tags,
		"admin_token": adminToken,
	})
}

// SetMemberTags sets admin-assigned tags for a member within a network.
func (c *Client) SetMemberTags(netID uint16, targetNodeID uint32, tags []string, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":           "set_member_tags",
		"network_id":     netID,
		"target_node_id": targetNodeID,
		"tags":           tags,
		"admin_token":    adminToken,
	})
}

// GetMemberTags returns admin-assigned member tags for a node (or all members if targetNodeID=0).
func (c *Client) GetMemberTags(netID uint16, targetNodeID uint32) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":           "get_member_tags",
		"network_id":     netID,
		"target_node_id": targetNodeID,
	})
}

// SetKeyExpiryAdmin sets a node's key expiry using admin token auth.
func (c *Client) SetKeyExpiryAdmin(nodeID uint32, expiresAt time.Time, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_key_expiry",
		"node_id":     nodeID,
		"expires_at":  expiresAt.Format(time.RFC3339),
		"admin_token": adminToken,
	})
}

// ClearKeyExpiryAdmin removes the key expiry from a node using admin token auth.
func (c *Client) ClearKeyExpiryAdmin(nodeID uint32, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_key_expiry",
		"node_id":     nodeID,
		"expires_at":  "never",
		"admin_token": adminToken,
	})
}

// DeregisterAdmin removes a node using admin token auth.
func (c *Client) DeregisterAdmin(nodeID uint32, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "deregister",
		"node_id":     nodeID,
		"admin_token": adminToken,
	})
}

// GetAuditLog returns recent audit entries from the registry.
func (c *Client) GetAuditLog(networkID uint16, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":        "get_audit_log",
		"admin_token": adminToken,
	}
	if networkID != 0 {
		msg["network_id"] = networkID
	}
	return c.Send(msg)
}

// SetWebhook configures the registry webhook URL. Pass empty string to disable.
func (c *Client) SetWebhook(url, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_webhook",
		"url":         url,
		"admin_token": adminToken,
	})
}

// GetWebhook returns the current webhook configuration.
func (c *Client) GetWebhook(adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "get_webhook",
		"admin_token": adminToken,
	})
}

// GetWebhookDLQ returns the dead letter queue (failed webhook events).
func (c *Client) GetWebhookDLQ(adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "get_webhook_dlq",
		"admin_token": adminToken,
	})
}

// SetIdentityWebhook configures the identity verification webhook URL.
func (c *Client) SetIdentityWebhook(url, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_identity_webhook",
		"url":         url,
		"admin_token": adminToken,
	})
}

// SetExternalID sets the external identity on a node. Requires admin token.
func (c *Client) SetExternalID(nodeID uint32, externalID, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_external_id",
		"node_id":     nodeID,
		"external_id": externalID,
		"admin_token": adminToken,
	})
}

// GetIdentity returns the external identity of a node. Requires admin token.
func (c *Client) GetIdentity(nodeID uint32, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "get_identity",
		"node_id":     nodeID,
		"admin_token": adminToken,
	})
}

// ProvisionNetwork applies a network blueprint. Requires admin token.
func (c *Client) ProvisionNetwork(blueprint map[string]interface{}, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "provision_network",
		"blueprint":   blueprint,
		"admin_token": adminToken,
	})
}

// SetAuditExport configures the audit export adapter. Requires admin token.
func (c *Client) SetAuditExport(format, endpoint, token, index, source, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_audit_export",
		"format":      format,
		"endpoint":    endpoint,
		"token":       token,
		"index":       index,
		"source":      source,
		"admin_token": adminToken,
	})
}

// GetAuditExport returns the current audit export configuration. Requires admin token.
func (c *Client) GetAuditExport(adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "get_audit_export",
		"admin_token": adminToken,
	})
}

// SetIDPConfig configures the identity provider. Requires admin token.
func (c *Client) SetIDPConfig(idpType, url, issuer, clientID, tenantID, domain, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":        "set_idp_config",
		"idp_type":    idpType,
		"url":         url,
		"admin_token": adminToken,
	}
	if issuer != "" {
		msg["issuer"] = issuer
	}
	if clientID != "" {
		msg["client_id"] = clientID
	}
	if tenantID != "" {
		msg["tenant_id"] = tenantID
	}
	if domain != "" {
		msg["domain"] = domain
	}
	return c.Send(msg)
}

// GetIDPConfig returns the current identity provider configuration. Requires admin token.
func (c *Client) GetIDPConfig(adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "get_idp_config",
		"admin_token": adminToken,
	})
}

// GetProvisionStatus returns per-network provisioning status. Requires admin token.
func (c *Client) GetProvisionStatus(adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "get_provision_status",
		"admin_token": adminToken,
	})
}

// DirectorySync pushes a directory listing to update RBAC roles and membership.
func (c *Client) DirectorySync(networkID uint16, entries []map[string]interface{}, removeUnlisted bool, adminToken string) (map[string]interface{}, error) {
	entryList := make([]interface{}, len(entries))
	for i, e := range entries {
		entryList[i] = e
	}
	return c.Send(map[string]interface{}{
		"type":            "directory_sync",
		"network_id":      networkID,
		"entries":         entryList,
		"remove_unlisted": removeUnlisted,
		"admin_token":     adminToken,
	})
}

// DirectoryStatus returns directory sync status for a network.
func (c *Client) DirectoryStatus(networkID uint16, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "directory_status",
		"network_id":  networkID,
		"admin_token": adminToken,
	})
}

// ValidateToken validates a JWT token against the configured IDP. Requires admin token.
func (c *Client) ValidateToken(token, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "validate_token",
		"token":       token,
		"admin_token": adminToken,
	})
}

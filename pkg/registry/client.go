package registry

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Client talks to a registry server over TCP (optionally TLS).
// It automatically reconnects if the connection drops.
type Client struct {
	conn      net.Conn
	mu        sync.Mutex
	addr      string // registry address for reconnection
	closed    bool
	tlsConfig *tls.Config
	signer    func(challenge string) string // H3 fix: optional message signer
}

// SetSigner sets a signing function for authenticated registry operations (H3 fix).
// The signer receives a challenge string and returns a base64-encoded Ed25519 signature.
func (c *Client) SetSigner(fn func(challenge string) string) {
	c.signer = fn
}

// sign returns a signature for the challenge, or empty string if no signer is set.
func (c *Client) sign(challenge string) string {
	if c.signer == nil {
		return ""
	}
	return c.signer(challenge)
}

func Dial(addr string) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial registry: %w", err)
	}
	return &Client{conn: conn, addr: addr}, nil
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
	c.mu.Unlock()
	// Close the conn after releasing the lock; conn is captured by value
	// so reconnect() can't see it after we set c.closed=true (M7 fix)
	if conn != nil {
		return conn.Close()
	}
	return nil
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

// sendLocked sends a message and reads the response. Must be called with c.mu held.
func (c *Client) sendLocked(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := writeMessage(c.conn, msg); err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}
	resp, err := readMessage(c.conn)
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
func (c *Client) RegisterWithKey(listenAddr, publicKeyB64, owner string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":        "register",
		"listen_addr": listenAddr,
		"public_key":  publicKeyB64,
	}
	if owner != "" {
		msg["owner"] = owner
	}
	return c.Send(msg)
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

func (c *Client) CreateNetwork(nodeID uint32, name, joinRule, token, adminToken string) (map[string]interface{}, error) {
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
	if adminToken != "" {
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
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return c.Send(msg)
}

func (c *Client) ListNetworks() (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type": "list_networks",
	})
}

func (c *Client) ListNodes(networkID uint16) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":       "list_nodes",
		"network_id": networkID,
	})
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

func (c *Client) SetTaskExec(nodeID uint32, enabled bool) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "set_task_exec",
		"node_id": nodeID,
		"enabled": enabled,
	}
	if sig := c.sign(fmt.Sprintf("set_task_exec:%d", nodeID)); sig != "" {
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

// UpdatePoloScore adjusts the polo score of a node by the given delta.
// Delta can be positive (increase polo score) or negative (decrease polo score).
func (c *Client) UpdatePoloScore(nodeID uint32, delta int) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":    "update_polo_score",
		"node_id": nodeID,
		"delta":   float64(delta),
	})
}

// SetPoloScore sets the polo score of a node to a specific value.
func (c *Client) SetPoloScore(nodeID uint32, poloScore int) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":       "set_polo_score",
		"node_id":    nodeID,
		"polo_score": float64(poloScore),
	})
}

// GetPoloScore retrieves the current polo score for a node.
func (c *Client) GetPoloScore(nodeID uint32) (int, error) {
	resp, err := c.Send(map[string]interface{}{
		"type":    "get_polo_score",
		"node_id": nodeID,
	})
	if err != nil {
		return 0, err
	}
	if poloScore, ok := resp["polo_score"].(float64); ok {
		return int(poloScore), nil
	}
	return 0, fmt.Errorf("polo_score not found in response")
}

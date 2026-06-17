// SPDX-License-Identifier: AGPL-3.0-or-later

// Package telemetry provides a consent-gated telemetry client that signs
// event POSTs with the node's Ed25519 identity and sends them to a
// configured telemetry endpoint. When the consent flag is off (empty URL),
// the client is a hard no-op: no dial, no buffering, no goroutines.
package telemetry

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pilot-protocol/common/crypto"
)

// DefaultEndpoint is the production telemetry ingestion URL.
const DefaultEndpoint = "https://telemetry.pilotprotocol.network/v1/events"

// Canonical signing header names, matching the telemetry server's
// internal/sig contract.
const (
	HeaderTimestamp = "X-Pilot-Timestamp"
	HeaderPubKey    = "X-Pilot-Public-Key"
	HeaderSignature = "X-Pilot-Signature"
)

// Event is the wire shape sent to the telemetry endpoint.
type Event struct {
	EventID string          `json:"event_id"`
	Kind    string          `json:"kind"`
	TS      string          `json:"ts"` // RFC3339; empty = server defaults to receive time
	NodeID  int64           `json:"node_id,omitempty"`
	Payload json.RawMessage `json:"payload"`
}

// Client is a consent-gated telemetry sender. Zero value is a no-op.
type Client struct {
	mu       sync.Mutex
	url      string    // empty = no-op
	nodeID   int64     // node ID included in events
	sign     signFunc  // ed25519 signer (set via SetSigner)
	pubKeyB  string    // base64-encoded public key
	once     sync.Once // lazy init guard
	initErr  error     // capture init failures
	disabled bool      // true when url is empty
}

type signFunc func(msg []byte) []byte

// New creates a consent-gated telemetry client.
// When url is empty the client is a permanent no-op.
func New(url string, nodeID int64) *Client {
	return &Client{
		url:      strings.TrimSpace(url),
		nodeID:   nodeID,
		disabled: strings.TrimSpace(url) == "",
	}
}

// SetSigner installs the Ed25519 signing function and the corresponding
// base64-encoded public key. Must be called before the first Send call.
// When signer is nil the client stays disabled.
func (c *Client) SetSigner(sign signFunc, pubKeyB64 string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if sign == nil || pubKeyB64 == "" {
		c.sign = nil
		c.pubKeyB = ""
		return
	}
	c.sign = sign
	c.pubKeyB = pubKeyB64
}

// Send POSTs one or more events to the telemetry endpoint. Returns
// immediately (no-op) when the client is disabled (no consent) or
// no signer is configured.
//
// The request is Ed25519-signed with the node's identity, following
// the telemetry server's signing contract:
//   - X-Pilot-Timestamp:  unix seconds (decimal string)
//   - X-Pilot-Public-Key:  base64(std) of the 32-byte Ed25519 public key
//   - X-Pilot-Signature:   base64(std) of the Ed25519 signature over
//     (timestamp + "\n" + body)
func (c *Client) Send(events ...Event) error {
	c.mu.Lock()
	disabled := c.disabled
	url := c.url
	sign := c.sign
	pubKeyB := c.pubKeyB
	nodeID := c.nodeID
	c.mu.Unlock()

	if disabled || url == "" {
		slog.Debug("telemetry: consent off, dropping events", "count", len(events))
		return nil
	}
	if sign == nil {
		slog.Debug("telemetry: no signer configured, dropping events", "count", len(events))
		return nil
	}

	if len(events) == 0 {
		return nil
	}

	// Inject node ID into events that don't supply their own.
	if nodeID != 0 {
		for i := range events {
			if events[i].NodeID == 0 {
				events[i].NodeID = nodeID
			}
		}
	}

	body, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("telemetry marshal: %w", err)
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	// Build signed message as ts + newline + body.
	// Avoid pre-allocated capacity hint: len() sum could overflow on 32-bit
	// platforms with very large body values (CodeQL SAST).
	message := make([]byte, 0, len(ts)+1)
	message = append(message, ts...)
	message = append(message, '\n')
	message = append(message, body...)
	sigB64 := base64.StdEncoding.EncodeToString(sign(message))

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("telemetry new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderPubKey, pubKeyB)
	req.Header.Set(HeaderSignature, sigB64)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("telemetry post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telemetry server %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}

	// Drain body so the connection can be reused
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// NewClientFromIdentity creates a consent-gated telemetry client from an
// Ed25519 identity file on disk and a telemetry URL. When url is empty
// the client is a permanent no-op. When the identity file does not exist
// (first-run grace), Send calls are no-ops until the identity is created.
func NewClientFromIdentity(url, identityPath string, nodeID int64) *Client {
	c := New(url, nodeID)
	if c.disabled {
		return c
	}

	id, err := crypto.LoadIdentity(identityPath)
	if err != nil {
		slog.Warn("telemetry: can't load identity, staying disabled", "path", identityPath, "err", err)
		return c
	}
	if id == nil {
		slog.Debug("telemetry: no identity file yet, staying disabled", "path", identityPath)
		return c
	}

	slog.Debug("telemetry: identity loaded, enabling client", "path", identityPath,
		"pubkey", crypto.EncodePublicKey(id.PublicKey))
	c.SetSigner(id.Sign, crypto.EncodePublicKey(id.PublicKey))
	return c
}

// SignMessage implements the signing contract directly, without an HTTP
// POST. Useful for tests and for components that want to sign arbitrary
// byte payloads. Returns (timestamp, pubKeyB64, signatureB64, error).
func SignMessage(priv ed25519.PrivateKey, body []byte) (ts, pubB64, sigB64 string, err error) {
	if len(body) == 0 {
		return "", "", "", fmt.Errorf("telemetry: cannot sign empty body")
	}
	pub := priv.Public().(ed25519.PublicKey)
	ts = strconv.FormatInt(time.Now().Unix(), 10)
	message := make([]byte, 0, len(ts)+1)
	message = append(message, ts...)
	message = append(message, '\n')
	message = append(message, body...)
	sig := ed25519.Sign(priv, message)
	return ts, base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(sig), nil
}

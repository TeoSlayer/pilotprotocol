// SPDX-License-Identifier: AGPL-3.0-or-later

// Package identity implements the registry's identity, key-lifecycle, and
// identity-provider handlers. It is extracted from pkg/registry/server as
// part of the R2.3 registry decomposition.
//
// Thread safety: all exported methods are safe for concurrent use.
package identity

import (
	"bytes"
	gocrypto "crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	pilotcrypto "github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry/server/events"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

// BlueprintIdentityProvider is a type alias so callers don't need to import wire.
type BlueprintIdentityProvider = wire.BlueprintIdentityProvider

// KeyRotationCallback is called after a successful key rotation so that the
// caller (Server) can update its pubKeyIdx index.
//
//	nodeID     — node whose key was rotated
//	oldPubKey  — base64-encoded old public key (key to delete from index)
//	newPubKey  — base64-encoded new public key (key to add to index)
type KeyRotationCallback func(nodeID uint32, oldPubKey, newPubKey string)

// KeyInfo mirrors server.KeyInfo; we declare it here to keep the sub-package
// independent of the parent package. The two must stay in sync.
type KeyInfo struct {
	CreatedAt   time.Time `json:"created_at"`
	RotatedAt   time.Time `json:"rotated_at,omitempty"`
	RotateCount int       `json:"rotate_count"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

// WALRecorder is called to write a WAL entry after a key rotation.
type WALRecorder func(nodeID uint32, newPubKeyB64, rotatedAt string)

// ErrKeyRotatedConcurrently is returned by NodeView.UpdateNodeKey when a
// concurrent rotation landed between Phase 1 (snapshot) and Phase 3 (commit).
var ErrKeyRotatedConcurrently = fmt.Errorf("rotate_key: key rotated concurrently, retry")

// sharedHTTPClient is reused across identity webhook and JWKS fetch calls so
// that the underlying TCP connections are pooled by the transport layer.
var sharedHTTPClient = &http.Client{Timeout: 5 * time.Second}

// NodeView is the read/write interface the Store uses to access node data.
// All methods must be safe for concurrent use.
type NodeView interface {
	// LookupNodeKey returns the current public key for a node.
	// ok is false if the node does not exist.
	LookupNodeKey(id uint32) (pubKey []byte, ok bool)

	// LookupNodeFull returns full identity-related fields for a node.
	// ok is false if the node does not exist.
	LookupNodeFull(id uint32) (pubKey []byte, keyMeta KeyInfo, networks []uint16, externalID, owner string, ok bool)

	// UpdateNodeKey atomically swaps the node's public key if it still matches
	// expectedPubKey (stale-check for concurrent-rotation detection).
	// Returns the old public key (base64-encoded) and nil on success.
	// Returns ErrKeyRotatedConcurrently if the key was rotated concurrently.
	// Returns protocol.ErrNodeNotFound if the node was deregistered.
	UpdateNodeKey(id uint32, expectedPubKey, newPubKey []byte, rotatedAt time.Time) (oldPubKeyB64 string, err error)

	// UpdateNodeKeyExpiry sets/clears the key expiry for a node.
	// Returns the old expiry value. ok is false if the node does not exist.
	UpdateNodeKeyExpiry(id uint32, expiresAt time.Time) (oldExpiry time.Time, ok bool)

	// UpdateNodeExternalID sets the external identity string on a node.
	// Returns the old external ID. ok is false if the node does not exist.
	UpdateNodeExternalID(id uint32, externalID string) (oldID string, ok bool)

	// NodeIsEnterprise returns true if the node belongs to at least one
	// enterprise-flagged network.
	NodeIsEnterprise(id uint32) bool

	// AdminToken returns the global admin token.
	AdminToken() string

	// CheckAdminToken returns nil if the message carries a valid admin token.
	CheckAdminToken(msg map[string]interface{}) error

	// VerifyHeartbeatSignature verifies a heartbeat-style Ed25519 signature.
	VerifyHeartbeatSignature(pubKey []byte, adminToken string, msg map[string]interface{}, challenge string) error

	// Now returns the current time (may be overridden in tests).
	Now() time.Time
}

// Callbacks bundles the side-effect functions the Store calls on state changes.
// All functions must be safe for concurrent use.
type Callbacks struct {
	// Save triggers a debounced snapshot write.
	Save func()

	// Audit records an audit-log entry.
	Audit func(action string, attrs ...any)

	// IncKeyRotations increments the key-rotation counter.
	IncKeyRotations func()

	// IncIDPVerifications increments the IDP-verification counter.
	IncIDPVerifications func()

	// RecordWAL writes a key-rotation WAL entry.
	RecordWAL WALRecorder

	// OnKeyRotated is the callback that updates pubKeyIdx in the parent Server.
	OnKeyRotated KeyRotationCallback

	// Bus is the event bus used to publish "key.rotated" events.
	Bus events.Bus
}

// Store holds the mutable identity and key-lifecycle state.
//
// Lock ordering:
//
//	mu (RWMutex) — protects identityWebhookURL, idpConfig.
//	jwksCache has its own internal mutex.
//
// These are independent of the parent Server's mu. Store methods must not
// acquire the parent mutex.
type Store struct {
	nodes NodeView
	cb    Callbacks

	mu                 sync.RWMutex
	identityWebhookURL string
	idpConfig          *BlueprintIdentityProvider

	jwksCache *JWKSCache
}

// NewStore creates an empty, ready-to-use Store.
func NewStore(nodes NodeView, cb Callbacks) *Store {
	return &Store{
		nodes:     nodes,
		cb:        cb,
		jwksCache: NewJWKSCache(),
	}
}

// ---------------------------------------------------------------------------
// Identity webhook
// ---------------------------------------------------------------------------

// SetWebhookURL sets the identity verification webhook URL.
// An empty string disables identity verification.
func (st *Store) SetWebhookURL(url string) {
	st.mu.Lock()
	st.identityWebhookURL = url
	st.mu.Unlock()
	if url != "" {
		slog.Info("identity webhook configured", "url", url)
	}
}

// GetWebhookURL returns the currently configured identity webhook URL.
func (st *Store) GetWebhookURL() string {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.identityWebhookURL
}

// VerifyToken sends the token to the configured identity webhook and returns
// the verified external ID. Returns ("", nil) if no webhook is configured.
func (st *Store) VerifyToken(token string) (string, error) {
	st.mu.RLock()
	url := st.identityWebhookURL
	st.mu.RUnlock()

	if url == "" {
		return "", nil
	}
	if token == "" {
		return "", nil
	}

	body, err := json.Marshal(identityVerifyRequest{Token: token})
	if err != nil {
		return "", fmt.Errorf("marshal identity request: %w", err)
	}

	resp, err := sharedHTTPClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		slog.Warn("identity webhook request failed", "error", err)
		return "", fmt.Errorf("identity verification failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("identity webhook returned status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("read identity response: %w", err)
	}

	var result identityVerifyResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse identity response: %w", err)
	}

	if !result.Verified {
		errMsg := result.Error
		if errMsg == "" {
			errMsg = "token not verified"
		}
		return "", fmt.Errorf("identity verification rejected: %s", errMsg)
	}

	if result.ExternalID == "" {
		return "", fmt.Errorf("identity webhook returned empty external_id")
	}

	if st.cb.IncIDPVerifications != nil {
		st.cb.IncIDPVerifications()
	}
	slog.Info("identity verified", "external_id", result.ExternalID)
	return result.ExternalID, nil
}

// ---------------------------------------------------------------------------
// IDP config
// ---------------------------------------------------------------------------

// SetIDPConfig stores the identity provider configuration.
func (st *Store) SetIDPConfig(cfg *BlueprintIdentityProvider) {
	st.mu.Lock()
	st.idpConfig = cfg
	if cfg != nil {
		st.identityWebhookURL = cfg.URL
	}
	st.mu.Unlock()
}

// GetIDPConfig returns the current identity provider configuration.
func (st *Store) GetIDPConfig() *BlueprintIdentityProvider {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.idpConfig
}

// ClearIDPConfig removes the identity provider configuration and webhook URL.
func (st *Store) ClearIDPConfig() {
	st.mu.Lock()
	st.idpConfig = nil
	st.identityWebhookURL = ""
	st.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Protocol handlers
// ---------------------------------------------------------------------------

// HandleRotateKey implements the "rotate_key" protocol command.
//
// 3-PHASE LOCK PATTERN (delegated through NodeView):
//
//	Phase 1: snapshot current pubkey via LookupNodeKey (under NodeView's RLock).
//	Phase 2: Ed25519 verify outside all locks (~28µs).
//	Phase 3: UpdateNodeKey re-checks pubkey and commits (under NodeView's Lock).
func (st *Store) HandleRotateKey(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	sigB64, _ := msg["signature"].(string)
	newPubKeyB64, _ := msg["new_public_key"].(string)

	if sigB64 == "" {
		return nil, fmt.Errorf("rotate_key requires a valid signature")
	}
	if newPubKeyB64 == "" {
		return nil, fmt.Errorf("rotate_key requires new_public_key")
	}

	newPubKey, err := pilotcrypto.DecodePublicKey(newPubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("invalid new_public_key: %w", err)
	}

	// Phase 1 — snapshot current pubkey (under RLock inside LookupNodeKey).
	currentPubKey, ok := st.nodes.LookupNodeKey(nodeID)
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	// Phase 2 — verify outside the lock (~28µs Ed25519).
	challenge := fmt.Sprintf("rotate:%d:%s", nodeID, newPubKeyB64)
	sig, err := base64Decode(sigB64)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}
	if !pilotcrypto.Verify(currentPubKey, []byte(challenge), sig) {
		return nil, fmt.Errorf("signature verification failed")
	}

	// Phase 3 — commit via NodeView.UpdateNodeKey with stale-key re-check.
	rotatedAt := st.nodes.Now()
	oldPubKeyB64, err := st.nodes.UpdateNodeKey(nodeID, currentPubKey, newPubKey, rotatedAt)
	if err != nil {
		return nil, err // ErrNodeNotFound or ErrKeyRotatedConcurrently
	}

	// Update pubKeyIdx in parent Server via callback.
	if st.cb.OnKeyRotated != nil {
		st.cb.OnKeyRotated(nodeID, oldPubKeyB64, newPubKeyB64)
	}

	// WAL the rotation.
	if st.cb.RecordWAL != nil {
		st.cb.RecordWAL(nodeID, newPubKeyB64, rotatedAt.UTC().Format(time.RFC3339))
	}

	if st.cb.Save != nil {
		st.cb.Save()
	}

	addr := protocol.Addr{Network: 0, Node: nodeID}
	slog.Debug("rotated key", "node_id", nodeID, "addr", addr)
	if st.cb.Audit != nil {
		st.cb.Audit("key.rotated", "node_id", nodeID)
	}
	if st.cb.IncKeyRotations != nil {
		st.cb.IncKeyRotations()
	}
	if st.cb.Bus != nil {
		st.cb.Bus.Publish(events.Event{
			Source:  "identity",
			Type:    "key.rotated",
			Payload: map[string]any{"node_id": nodeID},
		})
	}

	return map[string]interface{}{
		"type":       "rotate_key_ok",
		"node_id":    nodeID,
		"address":    addr.String(),
		"public_key": newPubKeyB64,
	}, nil
}

// HandleSetKeyExpiry implements the "set_key_expiry" protocol command.
func (st *Store) HandleSetKeyExpiry(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")

	expiresAtStr, _ := msg["expires_at"].(string)
	var expiresAt time.Time
	clearExpiry := expiresAtStr == "" || expiresAtStr == "never"
	if !clearExpiry {
		var err error
		expiresAt, err = time.Parse(time.RFC3339, expiresAtStr)
		if err != nil {
			return nil, fmt.Errorf("invalid expires_at: %w", err)
		}
		now := st.nodes.Now()
		if expiresAt.Before(now) {
			return nil, fmt.Errorf("expires_at must be in the future")
		}
		if expiresAt.After(now.Add(10 * 365 * 24 * time.Hour)) {
			return nil, fmt.Errorf("invalid expires_at: cannot exceed 10 years")
		}
	}

	// Phase 1 — snapshot pubkey + adminToken for verification.
	currentPubKey, ok := st.nodes.LookupNodeKey(nodeID)
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}
	adminToken := st.nodes.AdminToken()

	// Phase 2 — verify signature outside the lock.
	sigErr := st.nodes.VerifyHeartbeatSignature(currentPubKey, adminToken, msg, fmt.Sprintf("set_key_expiry:%d", nodeID))
	if sigErr != nil {
		if err := st.nodes.CheckAdminToken(msg); err != nil {
			return nil, sigErr
		}
	}

	// Enterprise gate.
	if !st.nodes.NodeIsEnterprise(nodeID) {
		return nil, fmt.Errorf("enterprise feature: key expiry requires enterprise network membership")
	}

	// Phase 3 — commit.
	oldExpiry, ok := st.nodes.UpdateNodeKeyExpiry(nodeID, expiresAt)
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	if st.cb.Save != nil {
		st.cb.Save()
	}

	if clearExpiry {
		slog.Debug("cleared key expiry", "node_id", nodeID)
		if st.cb.Audit != nil {
			if !oldExpiry.IsZero() {
				st.cb.Audit("key.expiry_cleared", "node_id", nodeID, "old_expires_at", oldExpiry.Format(time.RFC3339))
			} else {
				st.cb.Audit("key.expiry_cleared", "node_id", nodeID)
			}
		}
		return map[string]interface{}{
			"type":    "set_key_expiry_ok",
			"node_id": nodeID,
		}, nil
	}

	slog.Debug("set key expiry", "node_id", nodeID, "expires_at", expiresAt)
	if st.cb.Audit != nil {
		if !oldExpiry.IsZero() {
			st.cb.Audit("key.expiry_set", "node_id", nodeID, "expires_at", expiresAt.Format(time.RFC3339), "old_expires_at", oldExpiry.Format(time.RFC3339))
		} else {
			st.cb.Audit("key.expiry_set", "node_id", nodeID, "expires_at", expiresAt.Format(time.RFC3339))
		}
	}

	return map[string]interface{}{
		"type":       "set_key_expiry_ok",
		"node_id":    nodeID,
		"expires_at": expiresAt.Format(time.RFC3339),
	}, nil
}

// HandleGetKeyInfo implements the "get_key_info" protocol command.
func (st *Store) HandleGetKeyInfo(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")

	_, keyMeta, _, _, _, ok := st.nodes.LookupNodeFull(nodeID)
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	resp := map[string]interface{}{
		"type":         "get_key_info_ok",
		"node_id":      nodeID,
		"created_at":   keyMeta.CreatedAt.Format(time.RFC3339),
		"rotate_count": keyMeta.RotateCount,
	}
	if !keyMeta.RotatedAt.IsZero() {
		resp["rotated_at"] = keyMeta.RotatedAt.Format(time.RFC3339)
	}
	if !keyMeta.ExpiresAt.IsZero() {
		resp["expires_at"] = keyMeta.ExpiresAt.Format(time.RFC3339)
	}

	keyStart := keyMeta.CreatedAt
	if !keyMeta.RotatedAt.IsZero() {
		keyStart = keyMeta.RotatedAt
	}
	if !keyStart.IsZero() {
		resp["key_age_days"] = int(time.Since(keyStart).Hours() / 24)
	}

	return resp, nil
}

// HandleGetIdentity implements the "get_identity" protocol command.
func (st *Store) HandleGetIdentity(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := st.nodes.CheckAdminToken(msg); err != nil {
		return nil, err
	}
	nodeID := jsonUint32(msg, "node_id")

	_, _, _, externalID, owner, ok := st.nodes.LookupNodeFull(nodeID)
	if !ok {
		return nil, fmt.Errorf("node not found")
	}

	return map[string]interface{}{
		"type":        "get_identity_ok",
		"node_id":     nodeID,
		"external_id": externalID,
		"owner":       owner,
	}, nil
}

// HandleSetIdentityWebhook implements the "set_identity_webhook" protocol command.
// URL validation (SSRF prevention) must be performed by the caller before
// invoking this method.
func (st *Store) HandleSetIdentityWebhook(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := st.nodes.CheckAdminToken(msg); err != nil {
		return nil, err
	}
	url, _ := msg["url"].(string)
	st.SetWebhookURL(url)
	status := "disabled"
	if url != "" {
		status = "enabled"
	}
	return map[string]interface{}{
		"type":   "set_identity_webhook_ok",
		"status": status,
	}, nil
}

// HandleSetExternalID implements the "set_external_id" protocol command.
func (st *Store) HandleSetExternalID(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := st.nodes.CheckAdminToken(msg); err != nil {
		return nil, err
	}
	nodeID := jsonUint32(msg, "node_id")
	externalID, _ := msg["external_id"].(string)

	oldID, ok := st.nodes.UpdateNodeExternalID(nodeID, externalID)
	if !ok {
		return nil, fmt.Errorf("node not found")
	}

	if st.cb.Save != nil {
		st.cb.Save()
	}
	if st.cb.Audit != nil {
		st.cb.Audit("identity.external_id_set", "node_id", nodeID, "old_external_id", oldID, "new_external_id", externalID)
	}

	return map[string]interface{}{
		"type":        "set_external_id_ok",
		"node_id":     nodeID,
		"external_id": externalID,
	}, nil
}

// HandleSetIDPConfig implements the "set_idp_config" protocol command.
// URL validation (SSRF prevention) must be performed by the caller before
// invoking this method.
func (st *Store) HandleSetIDPConfig(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := st.nodes.CheckAdminToken(msg); err != nil {
		return nil, err
	}

	idpType, _ := msg["idp_type"].(string)
	url, _ := msg["url"].(string)

	if idpType == "" || url == "" {
		st.ClearIDPConfig()
		return map[string]interface{}{
			"type":   "set_idp_config_ok",
			"status": "disabled",
		}, nil
	}

	cfg := &BlueprintIdentityProvider{
		Type: idpType,
		URL:  url,
	}
	if v, ok := msg["issuer"].(string); ok {
		cfg.Issuer = v
	}
	if v, ok := msg["client_id"].(string); ok {
		cfg.ClientID = v
	}
	if v, ok := msg["tenant_id"].(string); ok {
		cfg.TenantID = v
	}
	if v, ok := msg["domain"].(string); ok {
		cfg.Domain = v
	}

	st.SetIDPConfig(cfg)

	if st.cb.Audit != nil {
		st.cb.Audit("idp.configured", "type", idpType, "url", url)
	}
	return map[string]interface{}{
		"type":     "set_idp_config_ok",
		"status":   "enabled",
		"idp_type": idpType,
	}, nil
}

// HandleGetIDPConfig implements the "get_idp_config" protocol command.
func (st *Store) HandleGetIDPConfig(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := st.nodes.CheckAdminToken(msg); err != nil {
		return nil, err
	}
	cfg := st.GetIDPConfig()
	resp := map[string]interface{}{
		"type":       "get_idp_config_ok",
		"configured": cfg != nil,
	}
	if cfg != nil {
		resp["idp_type"] = cfg.Type
		resp["url"] = cfg.URL
		if cfg.Issuer != "" {
			resp["issuer"] = cfg.Issuer
		}
		if cfg.ClientID != "" {
			resp["client_id"] = cfg.ClientID
		}
		if cfg.TenantID != "" {
			resp["tenant_id"] = cfg.TenantID
		}
		if cfg.Domain != "" {
			resp["domain"] = cfg.Domain
		}
	}
	return resp, nil
}

// HandleGetProvisionStatus implements the "get_provision_status" protocol command.
// The networkSummary callback produces the per-network list so the Store
// does not need to access s.networks directly.
func (st *Store) HandleGetProvisionStatus(
	msg map[string]interface{},
	networkSummary func() []map[string]interface{},
	webhookEnabled bool,
	auditExportFormat string,
) (map[string]interface{}, error) {
	if err := st.nodes.CheckAdminToken(msg); err != nil {
		return nil, err
	}

	networks := networkSummary()
	if networks == nil {
		networks = []map[string]interface{}{}
	}

	resp := map[string]interface{}{
		"type":     "get_provision_status_ok",
		"networks": networks,
	}

	cfg := st.GetIDPConfig()
	if cfg != nil {
		resp["idp_type"] = cfg.Type
	}
	if auditExportFormat != "" {
		resp["audit_export"] = auditExportFormat
	}
	if webhookEnabled {
		resp["webhook_enabled"] = true
	}
	return resp, nil
}

// HandleValidateToken implements the "validate_token" protocol command.
func (st *Store) HandleValidateToken(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := st.nodes.CheckAdminToken(msg); err != nil {
		return nil, err
	}

	token, _ := msg["token"].(string)
	if token == "" {
		return nil, fmt.Errorf("token is required")
	}

	idp := st.GetIDPConfig()
	if idp == nil {
		return nil, fmt.Errorf("no identity provider configured")
	}

	header, claims, signingInput, err := DecodeJWT(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if err := ValidateJWTClaims(claims, idp.Issuer, idp.ClientID); err != nil {
		return map[string]interface{}{
			"type":     "validate_token_ok",
			"verified": false,
			"error":    err.Error(),
		}, nil
	}

	parts := strings.SplitN(token, ".", 3)

	switch header.Alg {
	case "HS256":
		key, err := st.jwksCache.GetKey(idp.URL, header.Kid)
		if err != nil {
			return nil, fmt.Errorf("JWKS: %w", err)
		}
		if key.Alg != "" && key.Alg != "HS256" {
			return nil, fmt.Errorf("algorithm mismatch: JWT header says HS256, JWKS key says %s", key.Alg)
		}
		if key.Kty != "" && key.Kty != "oct" {
			return nil, fmt.Errorf("key type mismatch: HS256 requires oct key, got %s", key.Kty)
		}
		secret, err := base64.RawURLEncoding.DecodeString(key.K)
		if err != nil {
			return nil, fmt.Errorf("decode HMAC key: %w", err)
		}
		if err := VerifyJWTSignatureHS256(signingInput, parts[2], secret); err != nil {
			return map[string]interface{}{
				"type":     "validate_token_ok",
				"verified": false,
				"error":    err.Error(),
			}, nil
		}

	case "RS256":
		key, err := st.jwksCache.GetKey(idp.URL, header.Kid)
		if err != nil {
			return nil, fmt.Errorf("JWKS: %w", err)
		}
		if key.Alg != "" && key.Alg != "RS256" {
			return nil, fmt.Errorf("algorithm mismatch: JWT header says RS256, JWKS key says %s", key.Alg)
		}
		if key.Kty != "" && key.Kty != "RSA" {
			return nil, fmt.Errorf("key type mismatch: RS256 requires RSA key, got %s", key.Kty)
		}
		if err := verifyJWTSignatureRS256(signingInput, parts[2], key); err != nil {
			return map[string]interface{}{
				"type":     "validate_token_ok",
				"verified": false,
				"error":    err.Error(),
			}, nil
		}

	default:
		return nil, fmt.Errorf("unsupported JWT algorithm: %s", header.Alg)
	}

	if st.cb.IncIDPVerifications != nil {
		st.cb.IncIDPVerifications()
	}
	return map[string]interface{}{
		"type":     "validate_token_ok",
		"verified": true,
		"subject":  claims.Subject,
		"issuer":   claims.Issuer,
	}, nil
}

// ---------------------------------------------------------------------------
// JWT / JWKS internals (moved from identity.go)
// ---------------------------------------------------------------------------

type identityVerifyRequest struct {
	Token string `json:"token"`
}

type identityVerifyResponse struct {
	Verified   bool   `json:"verified"`
	ExternalID string `json:"external_id"`
	Error      string `json:"error,omitempty"`
}

type JwtClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  JwtAud `json:"aud"`
	Expiry    int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
}

type JwtAud []string

func (a *JwtAud) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*a = []string{s}
		return nil
	}
	var ss []string
	if err := json.Unmarshal(data, &ss); err == nil {
		*a = ss
		return nil
	}
	return fmt.Errorf("aud must be string or []string")
}

type JwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

func DecodeJWT(token string) (*JwtHeader, *JwtClaims, string, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, nil, "", fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, "", fmt.Errorf("decode JWT header: %w", err)
	}
	var header JwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, "", fmt.Errorf("parse JWT header: %w", err)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, "", fmt.Errorf("decode JWT claims: %w", err)
	}
	var claims JwtClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, nil, "", fmt.Errorf("parse JWT claims: %w", err)
	}

	return &header, &claims, parts[0] + "." + parts[1], nil
}

const jwtClockSkew = 60

func ValidateJWTClaims(claims *JwtClaims, expectedIssuer, expectedAudience string) error {
	if expectedIssuer != "" && claims.Issuer != expectedIssuer {
		return fmt.Errorf("issuer mismatch: got %q, want %q", claims.Issuer, expectedIssuer)
	}

	if expectedAudience != "" {
		found := false
		for _, aud := range claims.Audience {
			if aud == expectedAudience {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("audience mismatch: got %v, want %q", []string(claims.Audience), expectedAudience)
		}
	}

	now := time.Now().Unix()
	if claims.Expiry > 0 && claims.Expiry < now-jwtClockSkew {
		return fmt.Errorf("token expired at %d (now %d)", claims.Expiry, now)
	}
	if claims.NotBefore > 0 && claims.NotBefore > now+jwtClockSkew {
		return fmt.Errorf("token not yet valid (nbf %d, now %d)", claims.NotBefore, now)
	}

	return nil
}

// ---------------------------------------------------------------------------
// JWKS cache
// ---------------------------------------------------------------------------

type JwksKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	K   string `json:"k,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// JWKSCache holds a cached set of JWKS keys for a single issuer URL.
// Fields are exported so that white-box tests in package server can
// construct a cache with pre-populated state.
type JWKSCache struct {
	mu        sync.RWMutex
	Keys      []JwksKey
	URL       string
	FetchedAt time.Time
	TTL       time.Duration
}

// jwksCache is an alias kept for internal use within this package.
type jwksCache = JWKSCache

// JwksCacheTTL is the default TTL for cached JWKS keys.
const JwksCacheTTL = 5 * time.Minute

// jwksCacheTTL is the internal constant (same value, kept for existing code).
const jwksCacheTTL = JwksCacheTTL

// NewJWKSCache returns a new JWKSCache with the default TTL.
func NewJWKSCache() *JWKSCache {
	return &JWKSCache{TTL: JwksCacheTTL}
}

func newJWKSCache() *JWKSCache {
	return NewJWKSCache()
}

// GetKey returns the JWKS key for the given URL and kid, fetching if stale.
func (c *JWKSCache) GetKey(jwksURL, kid string) (*JwksKey, error) {
	c.mu.RLock()
	if c.URL == jwksURL && time.Since(c.FetchedAt) < c.TTL && len(c.Keys) > 0 {
		if kid == "" {
			if len(c.Keys) == 1 {
				key := c.Keys[0]
				c.mu.RUnlock()
				return &key, nil
			}
			c.mu.RUnlock()
			return nil, fmt.Errorf("JWT missing required 'kid' header; JWKS has %d keys", len(c.Keys))
		}
		for i := range c.Keys {
			if c.Keys[i].Kid == kid {
				key := c.Keys[i]
				c.mu.RUnlock()
				return &key, nil
			}
		}
		c.mu.RUnlock()
		return nil, fmt.Errorf("JWKS key %q not found (cached)", kid)
	}
	c.mu.RUnlock()

	keys, err := FetchJWKSKeys(jwksURL)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.Keys = keys
	c.URL = jwksURL
	c.FetchedAt = time.Now()
	c.mu.Unlock()

	if kid == "" {
		if len(keys) == 1 {
			return &keys[0], nil
		}
		return nil, fmt.Errorf("JWT missing required 'kid' header; JWKS has %d keys", len(keys))
	}
	for i := range keys {
		if keys[i].Kid == kid {
			return &keys[i], nil
		}
	}
	return nil, fmt.Errorf("JWKS key %q not found", kid)
}

// getKey is the unexported accessor kept for backward compatibility within the package.
func (c *JWKSCache) getKey(jwksURL, kid string) (*JwksKey, error) {
	return c.GetKey(jwksURL, kid)
}

// FetchJWKSKeys fetches the list of JWKS keys from the given URL.
func FetchJWKSKeys(jwksURL string) ([]JwksKey, error) {
	return fetchJWKSKeys(jwksURL)
}

func fetchJWKSKeys(jwksURL string) ([]JwksKey, error) {
	resp, err := sharedHTTPClient.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read JWKS: %w", err)
	}

	var jwks struct {
		Keys []JwksKey `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	return jwks.Keys, nil
}

func VerifyJWTSignatureHS256(signingInput string, signatureB64 string, secret []byte) error {
	expectedSig, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	computed := mac.Sum(nil)
	if !hmac.Equal(computed, expectedSig) {
		return fmt.Errorf("invalid HMAC signature")
	}
	return nil
}

// VerifyJWTSignatureRS256 verifies an RS256 JWT signature using the given JwksKey.
func VerifyJWTSignatureRS256(signingInput, signatureB64 string, key *JwksKey) error {
	return verifyJWTSignatureRS256(signingInput, signatureB64, key)
}

func verifyJWTSignatureRS256(signingInput, signatureB64 string, key *JwksKey) error {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return fmt.Errorf("decode RSA n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return fmt.Errorf("decode RSA e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	pubKey := &rsa.PublicKey{N: n, E: e}

	sig, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	hash := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pubKey, gocrypto.SHA256, hash[:], sig); err != nil {
		return fmt.Errorf("invalid RSA signature: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func jsonUint32(msg map[string]interface{}, key string) uint32 {
	v, ok := msg[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return uint32(n)
	case uint32:
		return n
	case int:
		return uint32(n)
	}
	return 0
}

func base64Decode(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// HashOwner returns a truncated SHA-256 hash of the owner for safe logging.
func HashOwner(owner string) string {
	if owner == "" {
		return ""
	}
	h := sha256.Sum256([]byte(owner))
	return fmt.Sprintf("sha256:%x", h[:4])
}

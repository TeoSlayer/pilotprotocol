package registry

import (
	"bytes"
	"crypto"
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
)

// identityVerifyRequest is sent to the identity webhook for verification.
type identityVerifyRequest struct {
	Token string `json:"token"`
}

// identityVerifyResponse is the expected response from the identity webhook.
type identityVerifyResponse struct {
	Verified   bool   `json:"verified"`
	ExternalID string `json:"external_id"` // e.g., OIDC sub, email, or any unique identity
	Error      string `json:"error,omitempty"`
}

// verifyIdentityToken sends the token to the configured identity webhook
// and returns the verified external ID. Returns empty string if no webhook
// is configured. Returns error if webhook rejects the token.
func (s *Server) verifyIdentityToken(token string) (string, error) {
	s.mu.RLock()
	url := s.identityWebhookURL
	s.mu.RUnlock()

	if url == "" {
		return "", nil // no webhook configured, skip verification
	}
	if token == "" {
		return "", nil // no token provided, skip
	}

	body, err := json.Marshal(identityVerifyRequest{Token: token})
	if err != nil {
		return "", fmt.Errorf("marshal identity request: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
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

	s.metrics.idpVerifications.Inc()
	slog.Info("identity verified", "external_id", result.ExternalID)
	return result.ExternalID, nil
}

// --- Built-in OIDC JWT Validation ---

// jwtClaims holds the standard OIDC JWT claims we validate.
type jwtClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  jwtAud `json:"aud"`
	Expiry    int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
}

// jwtAud handles both string and []string audience claims.
type jwtAud []string

func (a *jwtAud) UnmarshalJSON(data []byte) error {
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

// jwtHeader holds the JWT header fields.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// decodeJWT splits and decodes a JWT token into header, claims, and signature.
func decodeJWT(token string) (*jwtHeader, *jwtClaims, string, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, nil, "", fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, "", fmt.Errorf("decode JWT header: %w", err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, "", fmt.Errorf("parse JWT header: %w", err)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, "", fmt.Errorf("decode JWT claims: %w", err)
	}
	var claims jwtClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, nil, "", fmt.Errorf("parse JWT claims: %w", err)
	}

	return &header, &claims, parts[0] + "." + parts[1], nil
}

// verifyJWTSignatureHS256 verifies an HS256 JWT signature.
func verifyJWTSignatureHS256(signingInput string, signatureB64 string, secret []byte) error {
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

// jwtClockSkew is the allowed clock drift between IDP and registry (60 seconds).
const jwtClockSkew = 60

// validateJWTClaims checks issuer, audience, expiry, and not-before.
func validateJWTClaims(claims *jwtClaims, expectedIssuer, expectedAudience string) error {
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

// --- JWKS Cache ---

// jwksKey represents a key from a JWKS endpoint.
type jwksKey struct {
	Kty string `json:"kty"` // "RSA" or "oct"
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	// Symmetric (oct)
	K string `json:"k,omitempty"`
	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
}

// jwksCache caches JWKS responses to avoid fetching on every validation.
type jwksCache struct {
	mu        sync.RWMutex
	keys      []jwksKey
	url       string
	fetchedAt time.Time
	ttl       time.Duration
}

const jwksCacheTTL = 5 * time.Minute

func newJWKSCache() *jwksCache {
	return &jwksCache{ttl: jwksCacheTTL}
}

// getKey returns a key by kid, fetching from the JWKS endpoint if needed.
func (c *jwksCache) getKey(jwksURL, kid string) (*jwksKey, error) {
	c.mu.RLock()
	if c.url == jwksURL && time.Since(c.fetchedAt) < c.ttl && len(c.keys) > 0 {
		for i := range c.keys {
			if kid == "" || c.keys[i].Kid == kid {
				key := c.keys[i]
				c.mu.RUnlock()
				return &key, nil
			}
		}
		c.mu.RUnlock()
		return nil, fmt.Errorf("JWKS key %q not found (cached)", kid)
	}
	c.mu.RUnlock()

	// Fetch fresh JWKS
	keys, err := fetchJWKSKeys(jwksURL)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.keys = keys
	c.url = jwksURL
	c.fetchedAt = time.Now()
	c.mu.Unlock()

	for i := range keys {
		if kid == "" || keys[i].Kid == kid {
			return &keys[i], nil
		}
	}
	return nil, fmt.Errorf("JWKS key %q not found", kid)
}

// fetchJWKSKeys fetches keys from a JWKS endpoint.
func fetchJWKSKeys(jwksURL string) ([]jwksKey, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(jwksURL)
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
		Keys []jwksKey `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	return jwks.Keys, nil
}

// verifyJWTSignatureRS256 verifies an RS256 JWT signature with an RSA public key.
func verifyJWTSignatureRS256(signingInput, signatureB64 string, key *jwksKey) error {
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
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sig); err != nil {
		return fmt.Errorf("invalid RSA signature: %w", err)
	}
	return nil
}

// handleValidateToken handles the "validate_token" protocol command.
func (s *Server) handleValidateToken(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := s.requireAdminToken(msg); err != nil {
		return nil, err
	}

	token, _ := msg["token"].(string)
	if token == "" {
		return nil, fmt.Errorf("token is required")
	}

	s.mu.RLock()
	idp := s.idpConfig
	s.mu.RUnlock()

	if idp == nil {
		return nil, fmt.Errorf("no identity provider configured")
	}

	header, claims, signingInput, err := decodeJWT(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Validate claims
	if err := validateJWTClaims(claims, idp.Issuer, idp.ClientID); err != nil {
		return map[string]interface{}{
			"type":     "validate_token_ok",
			"verified": false,
			"error":    err.Error(),
		}, nil
	}

	parts := strings.SplitN(token, ".", 3)

	// Signature verification based on algorithm
	switch header.Alg {
	case "HS256":
		key, err := s.jwksCache.getKey(idp.URL, header.Kid)
		if err != nil {
			return nil, fmt.Errorf("JWKS: %w", err)
		}
		// Enforce algorithm match to prevent algorithm confusion attacks
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
		if err := verifyJWTSignatureHS256(signingInput, parts[2], secret); err != nil {
			return map[string]interface{}{
				"type":     "validate_token_ok",
				"verified": false,
				"error":    err.Error(),
			}, nil
		}

	case "RS256":
		key, err := s.jwksCache.getKey(idp.URL, header.Kid)
		if err != nil {
			return nil, fmt.Errorf("JWKS: %w", err)
		}
		// Enforce algorithm match to prevent algorithm confusion attacks
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

	s.metrics.idpVerifications.Inc()
	return map[string]interface{}{
		"type":     "validate_token_ok",
		"verified": true,
		"subject":  claims.Subject,
		"issuer":   claims.Issuer,
	}, nil
}

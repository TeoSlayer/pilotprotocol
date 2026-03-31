package registry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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

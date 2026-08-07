// SPDX-License-Identifier: AGPL-3.0-or-later

package authorityhttp

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	agentRequestDomain          = "pilot-agent-request-v1"
	agentRequestAgentIDHeader   = "X-Pilot-Agent-Id"
	agentRequestKeyIDHeader     = "X-Pilot-Agent-Key-Id"
	agentRequestTimestampHeader = "X-Pilot-Agent-Timestamp"
	agentRequestNonceHeader     = "X-Pilot-Agent-Nonce"
	agentRequestSignatureHeader = "X-Pilot-Agent-Signature"
)

var emptyAgentRequestBodyHash = sha256.Sum256(nil)

// AgentRequestSigner proves which enrolled node is fetching account-specific
// policy or control-plane state. It is intentionally limited to bodyless GETs:
// node reports already carry their own signed, validated artifacts.
type AgentRequestSigner struct {
	agentID    string
	keyID      string
	privateKey ed25519.PrivateKey
	now        func() time.Time
	random     io.Reader
}

// NewAgentRequestSigner binds one active agent intent key to node-plane reads.
func NewAgentRequestSigner(agentID, keyID string, privateKey ed25519.PrivateKey) (*AgentRequestSigner, error) {
	if !clientIdentifier(agentID) || !clientIdentifier(keyID) || len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("authorityhttp: invalid agent request signing credentials")
	}
	return &AgentRequestSigner{
		agentID: agentID, keyID: keyID,
		privateKey: append(ed25519.PrivateKey(nil), privateKey...),
		now:        time.Now,
		random:     rand.Reader,
	}, nil
}

// ConfigureAgentRequestSigning enables authenticated policy, mandate, and
// fleet reads. Configure the client before concurrent use.
func (client *Client) ConfigureAgentRequestSigning(agentID, keyID string, privateKey ed25519.PrivateKey) error {
	if client == nil {
		return fmt.Errorf("authorityhttp: client is not initialized")
	}
	signer, err := NewAgentRequestSigner(agentID, keyID, privateKey)
	if err != nil {
		return err
	}
	client.agentRequestSigner = signer
	return nil
}

// SignAgentRequest signs a bodyless GET for integrations that do not use
// Client. tenantID and agentID must exactly match the request query.
func SignAgentRequest(request *http.Request, tenantID, agentID, keyID string, privateKey ed25519.PrivateKey) error {
	signer, err := NewAgentRequestSigner(agentID, keyID, privateKey)
	if err != nil {
		return err
	}
	return signer.Sign(request, tenantID, agentID)
}

func (client *Client) signAgentRequest(request *http.Request, tenantID, agentID string) error {
	// Optional signing preserves compatibility with older/self-hosted
	// authorities. Hosted node-plane endpoints require the signature.
	if client == nil || client.agentRequestSigner == nil {
		return nil
	}
	return client.agentRequestSigner.Sign(request, tenantID, agentID)
}

// Sign binds the method, normalized path and query, tenant, node identity,
// delegated key, short-lived timestamp, nonce, and empty-body digest.
func (signer *AgentRequestSigner) Sign(request *http.Request, tenantID, agentID string) error {
	if signer == nil || request == nil || request.URL == nil || signer.now == nil || signer.random == nil || len(signer.privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("authorityhttp: agent request signer is not initialized")
	}
	if request.Method != http.MethodGet || (request.Body != nil && request.Body != http.NoBody) {
		return fmt.Errorf("authorityhttp: agent request signing requires a bodyless GET")
	}
	if !clientIdentifier(tenantID) || agentID != signer.agentID || !clientIdentifier(agentID) {
		return fmt.Errorf("authorityhttp: agent request identity mismatch")
	}
	query, err := strictAgentRequestQuery(request.URL, tenantID, agentID)
	if err != nil {
		return err
	}
	nonceBytes := make([]byte, 16)
	if _, err := io.ReadFull(signer.random, nonceBytes); err != nil {
		return fmt.Errorf("authorityhttp: generate agent request nonce: %w", err)
	}
	timestamp := strconv.FormatInt(signer.now().UTC().Unix(), 10)
	nonce := hex.EncodeToString(nonceBytes)
	canonical, err := canonicalAgentRequest(request.Method, request.URL, query, tenantID, agentID, signer.keyID, timestamp, nonce)
	if err != nil {
		return err
	}
	signature := ed25519.Sign(signer.privateKey, canonical)
	request.Header.Set(agentRequestAgentIDHeader, agentID)
	request.Header.Set(agentRequestKeyIDHeader, signer.keyID)
	request.Header.Set(agentRequestTimestampHeader, timestamp)
	request.Header.Set(agentRequestNonceHeader, nonce)
	request.Header.Set(agentRequestSignatureHeader, base64.RawURLEncoding.EncodeToString(signature))
	return nil
}

func strictAgentRequestQuery(target *url.URL, tenantID, agentID string) (string, error) {
	if target == nil {
		return "", fmt.Errorf("authorityhttp: agent request URL is required")
	}
	values, err := url.ParseQuery(target.RawQuery)
	if err != nil || len(values["tenant_id"]) != 1 || len(values["agent_id"]) != 1 || values.Get("tenant_id") != tenantID || values.Get("agent_id") != agentID {
		return "", fmt.Errorf("authorityhttp: agent request query identity mismatch")
	}
	return values.Encode(), nil
}

func canonicalAgentRequest(method string, target *url.URL, query, tenantID, agentID, keyID, timestamp, nonce string) ([]byte, error) {
	path := ""
	if target != nil {
		path = target.EscapedPath()
	}
	if method != http.MethodGet || path == "" || !strings.HasPrefix(path, "/") || !clientIdentifier(tenantID) || !clientIdentifier(agentID) || !clientIdentifier(keyID) || timestamp == "" || len(nonce) != 32 {
		return nil, fmt.Errorf("authorityhttp: invalid canonical agent request")
	}
	fields := []string{
		agentRequestDomain,
		method,
		path,
		query,
		hex.EncodeToString(emptyAgentRequestBodyHash[:]),
		tenantID,
		agentID,
		keyID,
		timestamp,
		nonce,
	}
	return []byte(strings.Join(fields, "\n")), nil
}

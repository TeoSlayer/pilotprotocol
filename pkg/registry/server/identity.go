// SPDX-License-Identifier: AGPL-3.0-or-later

// This file previously contained the JWT/JWKS validation types and methods,
// and the identity verification webhook client. All of that logic has been
// extracted to pkg/registry/server/identity/ (R2.3).
//
// The re-exported forwarding types and functions below keep existing white-box
// tests (package server) working without modification. New tests should be
// written against the identity sub-package directly.

package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	identpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/identity"
)

// --- type aliases for tests in package server --------------------------------
// These are unexported aliases that forward to the identity sub-package types.
// They exist solely to satisfy zz_identity_jwt_test.go without modification.

type jwtAud = identpkg.JwtAud
type jwtClaims = identpkg.JwtClaims
type jwksKey = identpkg.JwksKey

// jwksCache is a server-local mirror of the identity sub-package's cache.
// It exists only to keep the white-box tests (package server) working
// without modification — those tests set unexported fields directly.
// New tests should use the identity sub-package's JWKSCache.
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

func (c *jwksCache) getKey(jwksURL, kid string) (*jwksKey, error) {
	c.mu.RLock()
	if c.url == jwksURL && time.Since(c.fetchedAt) < c.ttl && len(c.keys) > 0 {
		if kid == "" {
			if len(c.keys) == 1 {
				key := c.keys[0]
				c.mu.RUnlock()
				return &key, nil
			}
			c.mu.RUnlock()
			return nil, fmt.Errorf("JWT missing required 'kid' header; JWKS has %d keys", len(c.keys))
		}
		for i := range c.keys {
			if c.keys[i].Kid == kid {
				key := c.keys[i]
				c.mu.RUnlock()
				return &key, nil
			}
		}
		c.mu.RUnlock()
		return nil, fmt.Errorf("JWKS key %q not found (cached)", kid)
	}
	c.mu.RUnlock()

	keys, err := fetchJWKSKeys(jwksURL)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.keys = keys
	c.url = jwksURL
	c.fetchedAt = time.Now()
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

// fetchJWKSKeys fetches the JWKS key list from the given URL.
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

	var result struct {
		Keys []jwksKey `json:"keys"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	return result.Keys, nil
}

// These unexported functions forward JWT operations to the identity sub-package
// so white-box tests in package server can call them without importing identpkg.
func decodeJWT(token string) (*identpkg.JwtHeader, *identpkg.JwtClaims, string, error) {
	return identpkg.DecodeJWT(token)
}

func verifyJWTSignatureHS256(signingInput string, signatureB64 string, secret []byte) error {
	return identpkg.VerifyJWTSignatureHS256(signingInput, signatureB64, secret)
}

func verifyJWTSignatureRS256(signingInput, signatureB64 string, key *jwksKey) error {
	return identpkg.VerifyJWTSignatureRS256(signingInput, signatureB64, key)
}

func validateJWTClaims(claims *jwtClaims, expectedIssuer, expectedAudience string) error {
	return identpkg.ValidateJWTClaims(claims, expectedIssuer, expectedAudience)
}

func (s *Server) verifyIdentityToken(token string) (string, error) {
	return s.identity.VerifyToken(token)
}

// SetIdentityWebhookURL sets the webhook URL used to verify identity tokens.
func (s *Server) SetIdentityWebhookURL(url string) {
	s.identity.SetWebhookURL(url)
}

func (s *Server) GetIdentityWebhookURL() string {
	return s.identity.GetWebhookURL()
}

func (s *Server) provisionCallbacks() identpkg.ProvisionCallbacks {
	return identpkg.ProvisionCallbacks{
		FindOrCreateNetwork: s.findOrCreateNetwork,
		EnableEnterprise:    s.enableEnterpriseLocked,
		ApplyNetworkPolicy:  s.applyBlueprintPolicy,
		ApplyExprPolicy:     s.applyBlueprintExprPolicy,
		SetAuditWebhookURL:  s.SetWebhookURL,
		StoreRBACPreAssignments: s.storeRBACPreAssignments,
		ConfigureAuditExport:    s.configureAuditExport,
		IncProvisionsTotal:      s.metrics.ProvisionsTotal.Inc,
	}
}

func (s *Server) ApplyBlueprint(bp *identpkg.NetworkBlueprint, adminToken string) (*identpkg.ProvisionResult, error) {
	return s.identity.ApplyBlueprint(bp, adminToken, s.provisionCallbacks())
}

func (s *Server) handleProvisionNetwork(msg map[string]interface{}) (map[string]interface{}, error) {
	return s.identity.HandleProvisionNetwork(msg, s.authz.AdminToken(), s.provisionCallbacks())
}

func (s *Server) GetIdentityProviderConfig() *identpkg.BlueprintIdentityProvider {
	return s.identity.GetIDPConfig()
}

func (s *Server) GetAuditExportConfig() *identpkg.BlueprintAuditExport {
	return s.auditStore.ExporterConfig()
}

// storeIdentityProviderConfig is unexported so white-box tests can call it directly.
func (s *Server) storeIdentityProviderConfig(idp *identpkg.BlueprintIdentityProvider) {
	s.identity.SetIDPConfig(idp)
}

func (s *Server) storeRBACPreAssignments(netID uint16, roles []BlueprintRole) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rbacPreAssign == nil {
		s.rbacPreAssign = make(map[uint16][]BlueprintRole)
	}
	s.rbacPreAssign[netID] = roles
}

// applyRBACPreAssignmentLocked applies any pre-assigned role to nodeID if its
// external_id matches a stored pre-assignment for netID. Caller must hold s.mu.
func (s *Server) applyRBACPreAssignmentLocked(netID uint16, nodeID uint32) {
	callbacks := identpkg.RBACPreAssignCallbacks{
		GetRoles: func(nid uint16, uid uint32) ([]BlueprintRole, string, bool) {
			roles, ok := s.rbacPreAssign[nid]
			if !ok {
				return nil, "", false
			}
			node, ok := s.nodes[uid]
			if !ok {
				return nil, "", false
			}
			return roles, node.ExternalID, true
		},
		CommitRole: func(nid uint16, uid uint32, role string) {
			net, ok := s.networks[nid]
			if !ok {
				return
			}
			var r Role
			switch role {
			case "owner":
				r = RoleOwner
			case "admin":
				r = RoleAdmin
			default:
				r = RoleMember
			}
			net.MemberRoles[uid] = r
			s.save()
		},
		IncCounter: s.metrics.RbacPreAssignments.Inc,
	}
	s.identity.ApplyRBACPreAssignment(netID, nodeID, callbacks)
}

func (s *Server) findOrCreateNetwork(name string, enterprise bool, joinRule, joinToken, networkAdminToken, adminToken string) (uint16, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, net := range s.networks {
		if net.Name == name {
			return net.ID, false, nil
		}
	}

	if s.authz.AdminToken() == "" {
		return 0, false, fmt.Errorf("network creation disabled (no admin token)")
	}
	if err := s.checkAdminToken(map[string]interface{}{"admin_token": adminToken}, s.authz.AdminToken()); err != nil {
		return 0, false, err
	}
	if err := validateNetworkName(name); err != nil {
		return 0, false, err
	}

	netID := s.nextNet
	s.nextNet++

	if joinRule == "" {
		joinRule = "open"
	}

	net := &NetworkInfo{
		ID:          netID,
		Name:        name,
		Enterprise:  enterprise,
		Members:     nil,
		MemberRoles: make(map[uint32]Role),
		JoinRule:    joinRule,
		Created:     s.now(),
	}
	if joinToken != "" {
		net.Token = joinToken
	}
	if networkAdminToken != "" {
		net.AdminToken = networkAdminToken
	}
	s.networks[netID] = net
	s.save()

	return netID, true, nil
}

func (s *Server) enableEnterpriseLocked(netID uint16) {
	s.mu.Lock()
	net, ok := s.networks[netID]
	if ok && !net.Enterprise {
		net.Enterprise = true
		s.save()
	}
	s.mu.Unlock()
}

func (s *Server) applyBlueprintPolicy(netID uint16, pol *identpkg.BlueprintPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	net, ok := s.networks[netID]
	if !ok {
		return fmt.Errorf("network %d not found", netID)
	}
	if pol.MaxMembers > 0 {
		net.Policy.MaxMembers = pol.MaxMembers
	}
	if len(pol.AllowedPorts) > 0 {
		net.Policy.AllowedPorts = pol.AllowedPorts
	}
	if pol.Description != "" {
		net.Policy.Description = pol.Description
	}
	s.save()
	return nil
}

func (s *Server) applyBlueprintExprPolicy(netID uint16, policyData json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	net, ok := s.networks[netID]
	if !ok {
		return fmt.Errorf("network %d not found", netID)
	}
	net.ExprPolicy = policyData
	s.save()
	return nil
}

func (s *Server) configureAuditExport(cfg *identpkg.BlueprintAuditExport) {
	s.auditStore.SetExporter(cfg)
	slog.Info("audit export configured", "format", cfg.Format, "endpoint", cfg.Endpoint)
}

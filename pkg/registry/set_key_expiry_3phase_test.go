// SPDX-License-Identifier: AGPL-3.0-or-later

package registry

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// seedEnterpriseNetwork seeds a network marked Enterprise=true and adds the
// given node as a member. The node must already exist.
func seedEnterpriseNetwork(t *testing.T, s *Server, netID uint16, nodeID uint32) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.networks[netID] == nil {
		s.networks[netID] = &NetworkInfo{
			ID:         netID,
			Name:       fmt.Sprintf("ent-%d", netID),
			JoinRule:   "open",
			Enterprise: true,
			Members:    []uint32{nodeID},
			Created:    time.Now(),
		}
	}
	if n, ok := s.nodes[nodeID]; ok {
		found := false
		for _, x := range n.Networks {
			if x == netID {
				found = true
				break
			}
		}
		if !found {
			n.Networks = append(n.Networks, netID)
		}
	}
	if s.nextNet <= netID {
		s.nextNet = netID + 1
	}
}

// TestHandleSetKeyExpirySuccess locks down the happy path.
func TestHandleSetKeyExpirySuccess(t *testing.T) {
	s := newTestServer(t, "")
	id, _ := seedNodeWithIdentity(t, s, 1100, "alice")
	seedEnterpriseNetwork(t, s, 50, 1100)

	expires := time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Second)
	expiresStr := expires.Format(time.RFC3339)
	challenge := fmt.Sprintf("set_key_expiry:%d", uint32(1100))
	sig := id.Sign([]byte(challenge))

	resp, err := s.handleSetKeyExpiry(map[string]interface{}{
		"node_id":    float64(1100),
		"expires_at": expiresStr,
		"signature":  base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatalf("set_key_expiry: %v", err)
	}
	if got, _ := resp["expires_at"].(string); got != expiresStr {
		t.Fatalf("response expires_at = %q, want %q", got, expiresStr)
	}

	// State updated.
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.nodes[1100].KeyMeta.ExpiresAt.Equal(expires) {
		t.Fatalf("KeyMeta.ExpiresAt = %v, want %v", s.nodes[1100].KeyMeta.ExpiresAt, expires)
	}
}

// TestHandleSetKeyExpiryRejectsBadSignature ensures forged signatures don't mutate.
func TestHandleSetKeyExpiryRejectsBadSignature(t *testing.T) {
	s := newTestServer(t, "")
	seedNodeWithIdentity(t, s, 1200, "bob")
	seedEnterpriseNetwork(t, s, 51, 1200)

	attacker, _ := crypto.GenerateIdentity()
	expiresStr := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	sig := attacker.Sign([]byte(fmt.Sprintf("set_key_expiry:%d", uint32(1200))))

	_, err := s.handleSetKeyExpiry(map[string]interface{}{
		"node_id":    float64(1200),
		"expires_at": expiresStr,
		"signature":  base64.StdEncoding.EncodeToString(sig),
	})
	if err == nil {
		t.Fatalf("set_key_expiry with bogus signature should fail")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.nodes[1200].KeyMeta.ExpiresAt.IsZero() {
		t.Fatalf("expiry was mutated despite signature failure")
	}
}

// TestHandleSetKeyExpiryNonEnterpriseDenied asserts the gate (currently
// inside the Lock-phase) still rejects non-enterprise nodes after the
// 3-phase refactor.
func TestHandleSetKeyExpiryNonEnterpriseDenied(t *testing.T) {
	s := newTestServer(t, "")
	id, _ := seedNodeWithIdentity(t, s, 1300, "carol")
	// No enterprise network membership.

	expiresStr := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	sig := id.Sign([]byte(fmt.Sprintf("set_key_expiry:%d", uint32(1300))))

	_, err := s.handleSetKeyExpiry(map[string]interface{}{
		"node_id":    float64(1300),
		"expires_at": expiresStr,
		"signature":  base64.StdEncoding.EncodeToString(sig),
	})
	if err == nil {
		t.Fatalf("non-enterprise node should be rejected")
	}
}

// TestHandleSetKeyExpiryClearAcceptsEmptyAndNever validates both reset paths.
func TestHandleSetKeyExpiryClearAcceptsEmptyAndNever(t *testing.T) {
	s := newTestServer(t, "")
	id, _ := seedNodeWithIdentity(t, s, 1400, "dave")
	seedEnterpriseNetwork(t, s, 52, 1400)

	// Pre-populate an expiry so we can confirm the clear path mutates.
	s.mu.Lock()
	s.nodes[1400].KeyMeta.ExpiresAt = time.Now().Add(time.Hour)
	s.mu.Unlock()

	for _, val := range []string{"", "never"} {
		challenge := fmt.Sprintf("set_key_expiry:%d", uint32(1400))
		sig := base64.StdEncoding.EncodeToString(id.Sign([]byte(challenge)))
		_, err := s.handleSetKeyExpiry(map[string]interface{}{
			"node_id":    float64(1400),
			"expires_at": val,
			"signature":  sig,
		})
		if err != nil {
			t.Fatalf("clear with %q: %v", val, err)
		}
		s.mu.RLock()
		if !s.nodes[1400].KeyMeta.ExpiresAt.IsZero() {
			s.mu.RUnlock()
			t.Fatalf("clear with %q: expiry not cleared", val)
		}
		s.mu.RUnlock()

		// Re-set an expiry between iterations so the second call has work to do.
		s.mu.Lock()
		s.nodes[1400].KeyMeta.ExpiresAt = time.Now().Add(time.Hour)
		s.mu.Unlock()
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package registry

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// seedNodeWithIdentity inserts a node with a real Ed25519 keypair into the
// server. Returns the node ID, the identity (so the caller can sign), and
// the base64 public key (in pubKeyIdx).
func seedNodeWithIdentity(t *testing.T, s *Server, nodeID uint32, owner string) (*crypto.Identity, string) {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	pkB64 := crypto.EncodePublicKey(id.PublicKey)

	s.mu.Lock()
	n := &NodeInfo{
		ID:        nodeID,
		Owner:     owner,
		PublicKey: id.PublicKey,
	}
	n.setLastSeen(time.Now())
	s.nodes[nodeID] = n
	s.pubKeyIdx[pkB64] = nodeID
	if s.nextNode <= nodeID {
		s.nextNode = nodeID + 1
	}
	s.mu.Unlock()
	return id, pkB64
}

// TestHandleRotateKeySuccess locks down the happy path: signature with the
// CURRENT key produces a valid rotation; pubKeyIdx is updated.
func TestHandleRotateKeySuccess(t *testing.T) {
	s := newTestServer(t, "")
	id, oldPkB64 := seedNodeWithIdentity(t, s, 100, "alice")

	newID, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("gen new: %v", err)
	}
	newPkB64 := crypto.EncodePublicKey(newID.PublicKey)

	challenge := fmt.Sprintf("rotate:%d:%s", uint32(100), newPkB64)
	sig := id.Sign([]byte(challenge))

	resp, err := s.handleRotateKey(map[string]interface{}{
		"node_id":        float64(100),
		"new_public_key": newPkB64,
		"signature":      base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if resp["public_key"].(string) != newPkB64 {
		t.Fatalf("response public_key = %q, want %q", resp["public_key"], newPkB64)
	}

	// pubKeyIdx must reflect the swap.
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, exists := s.pubKeyIdx[oldPkB64]; exists {
		t.Fatalf("old public key still in pubKeyIdx after rotate")
	}
	if got := s.pubKeyIdx[newPkB64]; got != 100 {
		t.Fatalf("new pubKeyIdx[%s] = %d, want 100", newPkB64, got)
	}
}

// TestHandleRotateKeyBadSignature ensures forged signatures don't mutate.
func TestHandleRotateKeyBadSignature(t *testing.T) {
	s := newTestServer(t, "")
	_, oldPkB64 := seedNodeWithIdentity(t, s, 200, "bob")

	// Sign with a DIFFERENT identity → verification must fail.
	attackerID, _ := crypto.GenerateIdentity()
	newID, _ := crypto.GenerateIdentity()
	newPkB64 := crypto.EncodePublicKey(newID.PublicKey)
	challenge := fmt.Sprintf("rotate:%d:%s", uint32(200), newPkB64)
	sig := attackerID.Sign([]byte(challenge))

	_, err := s.handleRotateKey(map[string]interface{}{
		"node_id":        float64(200),
		"new_public_key": newPkB64,
		"signature":      base64.StdEncoding.EncodeToString(sig),
	})
	if err == nil {
		t.Fatalf("rotate with bogus signature should fail")
	}

	// State must be unchanged.
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, exists := s.pubKeyIdx[oldPkB64]; !exists {
		t.Fatalf("rotation aborted but old key was dropped from pubKeyIdx")
	}
	if _, exists := s.pubKeyIdx[newPkB64]; exists {
		t.Fatalf("new key was inserted despite signature failure")
	}
}

// TestHandleRotateKeyChallengeBindsNewPubKey defends against a MITM
// signature substitution: a signature valid for one (nodeID, newPK) pair
// must NOT validate when re-used with a different newPK.
func TestHandleRotateKeyChallengeBindsNewPubKey(t *testing.T) {
	s := newTestServer(t, "")
	id, _ := seedNodeWithIdentity(t, s, 300, "carol")

	intendedKey, _ := crypto.GenerateIdentity()
	intendedB64 := crypto.EncodePublicKey(intendedKey.PublicKey)
	mitmKey, _ := crypto.GenerateIdentity()
	mitmB64 := crypto.EncodePublicKey(mitmKey.PublicKey)

	// Sign for the intended key.
	challenge := fmt.Sprintf("rotate:%d:%s", uint32(300), intendedB64)
	sig := id.Sign([]byte(challenge))

	// Replay the signature with mitmB64 as new_public_key.
	_, err := s.handleRotateKey(map[string]interface{}{
		"node_id":        float64(300),
		"new_public_key": mitmB64,
		"signature":      base64.StdEncoding.EncodeToString(sig),
	})
	if err == nil {
		t.Fatalf("MITM substitution should fail")
	}
}

// TestHandleRotateKeyConcurrentRaceLosesOne stresses the two-rotation race
// where two callers prepare valid rotations simultaneously. With the
// 3-phase implementation (Phase 1 RLock → Phase 2 verify → Phase 3 Lock+
// re-check), one wins and the other returns "concurrent rotation" error.
// The pre-3-phase implementation also serialized via s.mu.Lock so this
// test passes either way; the value is catching regressions and asserting
// the single-rotation-wins invariant.
func TestHandleRotateKeyConcurrentRaceLosesOne(t *testing.T) {
	s := newTestServer(t, "")
	id, _ := seedNodeWithIdentity(t, s, 400, "dave")

	keyA, _ := crypto.GenerateIdentity()
	keyB, _ := crypto.GenerateIdentity()
	keyABase := crypto.EncodePublicKey(keyA.PublicKey)
	keyBBase := crypto.EncodePublicKey(keyB.PublicKey)

	chalA := fmt.Sprintf("rotate:%d:%s", uint32(400), keyABase)
	chalB := fmt.Sprintf("rotate:%d:%s", uint32(400), keyBBase)
	sigA := base64.StdEncoding.EncodeToString(id.Sign([]byte(chalA)))
	sigB := base64.StdEncoding.EncodeToString(id.Sign([]byte(chalB)))

	const N = 64
	results := make([]error, N)

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			var (
				newKey string
				sig    string
			)
			if i%2 == 0 {
				newKey, sig = keyABase, sigA
			} else {
				newKey, sig = keyBBase, sigB
			}
			_, err := s.handleRotateKey(map[string]interface{}{
				"node_id":        float64(400),
				"new_public_key": newKey,
				"signature":      sig,
			})
			results[i] = err
		}()
	}
	wg.Wait()

	// At least one rotation should have succeeded.
	successCount := 0
	for _, e := range results {
		if e == nil {
			successCount++
		}
	}
	if successCount == 0 {
		t.Fatalf("expected at least one success across %d concurrent rotations; got %d (all errored)", N, successCount)
	}

	// Final key must be one of keyA / keyB and pubKeyIdx must be consistent.
	s.mu.RLock()
	defer s.mu.RUnlock()
	finalPK := crypto.EncodePublicKey(s.nodes[400].PublicKey)
	if finalPK != keyABase && finalPK != keyBBase {
		t.Fatalf("final pubkey neither A nor B: %q", finalPK)
	}
	if got := s.pubKeyIdx[finalPK]; got != 400 {
		t.Fatalf("pubKeyIdx[final] = %d, want 400", got)
	}
	// The other key must NOT appear in pubKeyIdx.
	other := keyABase
	if finalPK == keyABase {
		other = keyBBase
	}
	if _, exists := s.pubKeyIdx[other]; exists {
		t.Fatalf("losing key %q still indexed in pubKeyIdx", other)
	}
}

// Avoid the import-only ed25519 reference being unused if tests narrow.
var _ = ed25519.PublicKeySize

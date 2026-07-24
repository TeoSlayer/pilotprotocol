// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync/atomic"
	"testing"
)

// TestGetPeerPubKeyNegativeCacheCoalescesFailures is the PPA-011 regression:
// repeated key-exchange frames for a node ID the registry cannot resolve must
// not re-hit the registry (and re-run the Ed25519 path) on every frame.
func TestGetPeerPubKeyNegativeCacheCoalescesFailures(t *testing.T) {
	t.Parallel()
	m := New(nil)

	var calls int32
	m.SetPeerVerifyFunc(func(uint32) (ed25519.PublicKey, error) {
		atomic.AddInt32(&calls, 1)
		return nil, errors.New("not registered")
	})

	const node = uint32(9999)
	for i := 0; i < 8; i++ {
		if _, err := m.GetPeerPubKey(node); err == nil {
			t.Fatalf("call %d: expected error for unresolved node", i)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("verifyFunc called %d times; negative cache should coalesce to 1", got)
	}

	// RemovePeer clears the negative entry so an honest late-registering peer
	// is retried.
	m.RemovePeer(node)
	if _, err := m.GetPeerPubKey(node); err == nil {
		t.Fatalf("expected error after RemovePeer")
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("verifyFunc called %d times after RemovePeer; want 2", got)
	}
}

// TestGetPeerPubKeySuccessBypassesNegativeCache confirms a resolvable peer is
// never blocked: a successful lookup is positively cached and served without
// re-invoking verifyFunc, and never trips the negative path.
func TestGetPeerPubKeySuccessBypassesNegativeCache(t *testing.T) {
	t.Parallel()
	m := New(nil)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	var calls int32
	m.SetPeerVerifyFunc(func(uint32) (ed25519.PublicKey, error) {
		atomic.AddInt32(&calls, 1)
		return pub, nil
	})

	const node = uint32(4321)
	for i := 0; i < 4; i++ {
		pk, err := m.GetPeerPubKey(node)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if !pk.Equal(pub) {
			t.Fatalf("call %d: pubkey mismatch", i)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("verifyFunc called %d times for a resolvable peer; want 1", got)
	}

	m.pubKeysMu.RLock()
	_, negged := m.negPubKeys[node]
	m.pubKeysMu.RUnlock()
	if negged {
		t.Fatalf("a resolvable peer was negatively cached")
	}
}

// TestNegativePubKeyCacheBounded pins the map cap so an attacker spraying
// rotating unresolved node IDs cannot grow it without bound.
func TestNegativePubKeyCacheBounded(t *testing.T) {
	t.Parallel()
	m := New(nil)
	m.SetPeerVerifyFunc(func(uint32) (ed25519.PublicKey, error) {
		return nil, errors.New("not registered")
	})

	for i := 0; i < MaxNegPubKeyEntries+512; i++ {
		m.GetPeerPubKey(uint32(i))
	}
	m.pubKeysMu.RLock()
	size := len(m.negPubKeys)
	m.pubKeysMu.RUnlock()
	if size > MaxNegPubKeyEntries {
		t.Fatalf("negPubKeys grew to %d entries, want <= %d", size, MaxNegPubKeyEntries)
	}
}

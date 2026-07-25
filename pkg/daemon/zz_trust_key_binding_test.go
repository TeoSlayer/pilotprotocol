// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

// keyBoundFakeHandshakeService implements HandshakeService plus the
// optional IsTrustedWithKey half, recording what the daemon passed in.
type keyBoundFakeHandshakeService struct {
	trusted     map[uint32]string // node ID → bound key ("" = unbound)
	gotKeyFor   map[uint32]string
	withKeyHits int
}

func newKeyBoundFake() *keyBoundFakeHandshakeService {
	return &keyBoundFakeHandshakeService{
		trusted:   map[uint32]string{},
		gotKeyFor: map[uint32]string{},
	}
}

func (f *keyBoundFakeHandshakeService) IsTrusted(nodeID uint32) bool {
	_, ok := f.trusted[nodeID]
	return ok
}

func (f *keyBoundFakeHandshakeService) IsTrustedWithKey(nodeID uint32, pubKeyB64 string) bool {
	f.withKeyHits++
	f.gotKeyFor[nodeID] = pubKeyB64
	bound, ok := f.trusted[nodeID]
	if !ok {
		return false
	}
	if bound == "" || pubKeyB64 == "" {
		return true
	}
	return bound == pubKeyB64
}

func (f *keyBoundFakeHandshakeService) TrustedPeers() []HandshakeTrustRecord      { return nil }
func (f *keyBoundFakeHandshakeService) PendingRequests() []HandshakePendingRecord { return nil }
func (f *keyBoundFakeHandshakeService) PendingCount() int                         { return 0 }
func (f *keyBoundFakeHandshakeService) SendRequest(uint32, string) error          { return nil }
func (f *keyBoundFakeHandshakeService) ApproveHandshake(uint32) error             { return nil }
func (f *keyBoundFakeHandshakeService) RejectHandshake(uint32, string) error      { return nil }
func (f *keyBoundFakeHandshakeService) RevokeTrust(uint32) error                  { return nil }
func (f *keyBoundFakeHandshakeService) WaitForTrust(uint32, time.Duration) bool   { return false }
func (f *keyBoundFakeHandshakeService) ProcessRelayedRequest(uint32, string)      {}
func (f *keyBoundFakeHandshakeService) ProcessRelayedApproval(uint32)             {}
func (f *keyBoundFakeHandshakeService) ProcessRelayedRejection(uint32)            {}
func (f *keyBoundFakeHandshakeService) Stop()                                     {}

// nodeIDOnlyFakeHandshakeService embeds the interface, so its method
// set is exactly HandshakeService — no IsTrustedWithKey. That is what
// an older plugin build looks like to the daemon's type assertion.
type nodeIDOnlyFakeHandshakeService struct{ HandshakeService }

func testPubKey(t *testing.T, seed byte) (ed25519.PublicKey, string) {
	t.Helper()
	raw := make([]byte, ed25519.SeedSize)
	for i := range raw {
		raw[i] = seed
	}
	pk := ed25519.NewKeyFromSeed(raw).Public().(ed25519.PublicKey)
	return pk, base64.StdEncoding.EncodeToString(pk)
}

// The daemon hands the cached tunnel key to the trust store, so a node
// ID whose key changed does not keep the previous holder's trust.
func TestHandshakeTrustsPassesCachedPeerKey(t *testing.T) {
	d := New(Config{})
	pkA, pkAB64 := testPubKey(t, 1)
	pkB, _ := testPubKey(t, 2)

	svc := newKeyBoundFake()
	svc.trusted[42] = pkAB64
	d.RegisterHandshakeService(svc)

	d.tunnels.kx.SetPeerPubKey(42, pkA)
	if !d.handshakeTrusts(42) {
		t.Fatal("peer whose cached key matches the binding should be trusted")
	}
	if got := svc.gotKeyFor[42]; got != pkAB64 {
		t.Fatalf("daemon passed %q, want the cached key %q", got, pkAB64)
	}

	// Same node ID, different key behind it.
	d.tunnels.kx.SetPeerPubKey(42, pkB)
	if d.handshakeTrusts(42) {
		t.Fatal("peer presenting a different key must not be trusted")
	}
}

// With no key cached for the peer the daemon passes "", and the store
// falls back to its node-ID-only answer.
func TestHandshakeTrustsNoCachedKeyPassesEmpty(t *testing.T) {
	d := New(Config{})

	svc := newKeyBoundFake()
	svc.trusted[42] = "some-bound-key"
	d.RegisterHandshakeService(svc)

	if !d.handshakeTrusts(42) {
		t.Fatal("trust must not be denied just because no key is cached")
	}
	if got, ok := svc.gotKeyFor[42]; !ok || got != "" {
		t.Fatalf("daemon passed %q, want empty string when no key is cached", got)
	}
}

// A handshake service without the key-bound check keeps working through
// the node-ID-only path.
func TestHandshakeTrustsFallsBackForServiceWithoutKeyCheck(t *testing.T) {
	d := New(Config{})

	inner := newKeyBoundFake()
	inner.trusted[42] = ""
	d.RegisterHandshakeService(&nodeIDOnlyFakeHandshakeService{HandshakeService: inner})

	pk, _ := testPubKey(t, 3)
	d.tunnels.kx.SetPeerPubKey(42, pk)

	if !d.handshakeTrusts(42) {
		t.Fatal("node-ID-only service should still report trust")
	}
	if inner.withKeyHits != 0 {
		t.Fatal("key-bound check should not have been reached")
	}
	if d.handshakeTrusts(43) {
		t.Fatal("unknown node should not be trusted")
	}
}

// A nil handshake service is not trusted and must not panic.
func TestHandshakeTrustsNilServiceIsFalse(t *testing.T) {
	d := New(Config{})
	if d.handshakeTrusts(42) {
		t.Fatal("no handshake service means no trust")
	}
}

// cachedPeerKeyB64 never triggers a registry lookup, so it stays safe on
// the packet path.
func TestCachedPeerKeyB64IsCacheOnly(t *testing.T) {
	d := New(Config{})

	if got := d.cachedPeerKeyB64(42); got != "" {
		t.Fatalf("uncached peer should yield empty string, got %q", got)
	}

	pk, b64 := testPubKey(t, 4)
	d.tunnels.kx.SetPeerPubKey(42, pk)
	if got := d.cachedPeerKeyB64(42); got != b64 {
		t.Fatalf("cachedPeerKeyB64 = %q, want %q", got, b64)
	}
}

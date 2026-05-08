// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestGetPeerPubKeyReturnsCachedWithoutCallingVerifyFunc(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tm.kx.SetPeerPubKey(42, pub)

	calls := 0
	tm.SetPeerVerifyFunc(func(uint32) (ed25519.PublicKey, error) {
		calls++
		return nil, errors.New("must not be called")
	})

	got, err := tm.getPeerPubKey(42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatalf("got %x want %x", got, pub)
	}
	if calls != 0 {
		t.Fatalf("verifyFunc calls = %d, want 0", calls)
	}
}

func TestGetPeerPubKeyNilVerifyFuncReturnsError(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()

	got, err := tm.getPeerPubKey(99)
	if err == nil {
		t.Fatalf("expected error, got nil (key=%x)", got)
	}
	if got != nil {
		t.Fatalf("expected nil key, got %x", got)
	}
	if err.Error() != "no verify function" {
		t.Fatalf("error = %q, want \"no verify function\"", err.Error())
	}
}

func TestGetPeerPubKeyVerifyFuncErrorPropagatesAndDoesNotCache(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	wantErr := errors.New("registry down")
	tm.SetPeerVerifyFunc(func(uint32) (ed25519.PublicKey, error) {
		return nil, wantErr
	})

	_, err := tm.getPeerPubKey(7)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}

	if tm.kx.HasPeerPubKey(7) {
		t.Fatalf("key for node 7 should not be cached after verifyFunc error")
	}
}

func TestGetPeerPubKeySuccessCachesKeyForNextCall(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	calls := 0
	tm.SetPeerVerifyFunc(func(nodeID uint32) (ed25519.PublicKey, error) {
		calls++
		if nodeID != 123 {
			t.Fatalf("verifyFunc called with nodeID %d, want 123", nodeID)
		}
		return pub, nil
	})

	got1, err := tm.getPeerPubKey(123)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if !got1.Equal(pub) {
		t.Fatalf("first call returned wrong key")
	}
	if calls != 1 {
		t.Fatalf("after first call, verifyFunc calls = %d, want 1", calls)
	}

	got2, err := tm.getPeerPubKey(123)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !got2.Equal(pub) {
		t.Fatalf("second call returned wrong key")
	}
	if calls != 1 {
		t.Fatalf("after second call, verifyFunc calls = %d, want 1 (cache miss)", calls)
	}

	cached, err := tm.kx.GetPeerPubKey(123)
	if err != nil || !cached.Equal(pub) {
		t.Fatalf("cache not populated: err=%v cached=%x want=%x", err, cached, pub)
	}
}

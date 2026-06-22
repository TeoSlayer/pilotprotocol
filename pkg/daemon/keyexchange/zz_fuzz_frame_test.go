// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange_test

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"

	icrypto "github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

// fuzzManager builds a Manager wired the same way newPeer does, but against a
// testing.TB so it can be constructed once at the *testing.F scope (key
// generation per fuzz iteration would dominate runtime). A peer-verify func is
// installed so HandleAuthFrame can reach the identity-resolution path; it
// returns a fixed pubkey for node 1 and nil otherwise, so fuzzed frames
// exercise both the resolved and unresolved branches.
func fuzzManager(tb testing.TB) *keyexchange.Manager {
	tb.Helper()
	idn, err := icrypto.GenerateIdentity()
	if err != nil {
		tb.Fatalf("identity: %v", err)
	}
	xpriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("x25519: %v", err)
	}
	m := keyexchange.New(nil)
	m.SetIdentity(idn)
	m.SetX25519Keys(xpriv, xpriv.PublicKey().Bytes())
	m.SetLocalNodeIDFn(func() uint32 { return 7 })
	m.SetPeerVerifyFunc(func(nodeID uint32) (ed25519.PublicKey, error) {
		if nodeID == 1 {
			return idn.PublicKey, nil
		}
		return nil, nil
	})
	return m
}

// FuzzHandleAuthFrame throws arbitrary bytes at the PILA (authenticated key
// exchange) wire parser. The contract: never panic, and never install crypto
// from an unauthenticated / malformed frame (HandleAuthFrame returns true only
// after a registry-verified Ed25519 signature check, which fuzzed random bytes
// cannot satisfy). We assert no panic and fail-closed: a random frame that
// somehow returns true would be a forged-auth acceptance — a hard failure.
func FuzzHandleAuthFrame(f *testing.F) {
	m := fuzzManager(f)
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}

	// Deterministic seeds: empty, exactly-min-length zeros, a structurally
	// well-formed-but-unsigned frame, and a boundary-length frame.
	f.Add([]byte{})
	f.Add(make([]byte, 4+32+32+64))
	wellFormed := make([]byte, 4+32+32+64)
	binary.BigEndian.PutUint32(wellFormed[0:4], 1) // claims to be node 1
	f.Add(wellFormed)
	f.Add(make([]byte, 4+32+32+63)) // one byte short of minimum

	f.Fuzz(func(t *testing.T, data []byte) {
		if m.HandleAuthFrame(data, from, false) {
			t.Fatalf("HandleAuthFrame accepted an unauthenticated frame (len=%d)", len(data))
		}
		// fromRelay path must be equally fail-closed.
		if m.HandleAuthFrame(data, from, true) {
			t.Fatalf("HandleAuthFrame(relay) accepted an unauthenticated frame (len=%d)", len(data))
		}
	})
}

// FuzzHandleUnauthFrame throws arbitrary bytes at the PILK (unauthenticated
// key exchange) wire parser. Contract: never panic on malformed input. Unlike
// the auth frame, an unauth frame can legitimately install crypto when the
// node operates without identity-based auth, so we only assert no-panic — the
// fuzzer's job here is to find a decode that crashes, not an acceptance bug.
func FuzzHandleUnauthFrame(f *testing.F) {
	m := fuzzManager(f)
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}

	f.Add([]byte{})
	f.Add([]byte{0x00, 0x01})
	f.Add(make([]byte, 4+32))
	f.Add(make([]byte, 128))

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = m.HandleUnauthFrame(data, from, false)
		_ = m.HandleUnauthFrame(data, from, true)
	})
}

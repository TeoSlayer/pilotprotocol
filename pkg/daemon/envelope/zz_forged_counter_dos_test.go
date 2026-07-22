// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/envelope"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

// forgeFrame builds a structurally-valid PILS frame that claims to come
// from senderID at the given nonce counter but whose ciphertext is random
// junk — so AEAD.Open MUST fail. Returned bytes start at the senderID
// (i.e. the `data` shape DecryptFrame consumes, PILS magic stripped).
func forgeFrame(senderID uint32, counter uint64) []byte {
	// [senderID(4)][nonce(12) = prefix(4)+counter(8)][ciphertext+tag(>=16)]
	buf := make([]byte, 4+12+16)
	binary.BigEndian.PutUint32(buf[0:4], senderID)
	// nonce prefix (bytes 4..8) left zero; counter in the last 8 nonce bytes.
	binary.BigEndian.PutUint64(buf[4+4:4+12], counter)
	// ciphertext+tag stays all-zero — guaranteed to fail GCM authentication
	// against any real key.
	return buf
}

// TestForgedHighCounterDoesNotWedgeWindow is the regression test for the
// HIGH-severity remote-DoS: a forged PILS frame carrying a maximal nonce
// counter that FAILS AEAD must NOT advance MaxRecvNonce. Before the
// authenticate-before-commit fix, DecryptFrame recorded the nonce (pinning
// MaxRecvNonce at ~2^63) BEFORE AEAD.Open ran; the failing Open rolled back
// only the replay bit, leaving the high-water-mark stuck. Every subsequent
// genuine frame then fell outside the replay window and was dropped.
//
// This test FAILS on the pre-fix code (the genuine follow-up frame comes
// back ErrOutsideWindow) and PASSES after (it decrypts cleanly).
func TestForgedHighCounterDoesNotWedgeWindow(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	// A couple of genuine frames flow first, establishing a normal, low
	// MaxRecvNonce (counters 1, 2) on the peer side.
	for i := 0; i < 2; i++ {
		f, err := envelope.EncryptFrame(s.localStore, s.peerID, []byte("legit-early"))
		if err != nil {
			t.Fatalf("encrypt legit #%d: %v", i, err)
		}
		if r := envelope.DecryptFrame(s.peerStore, f[4:]); r.Err != nil {
			t.Fatalf("decrypt legit #%d: %v", i, r.Err)
		}
	}

	maxBefore := recvMax(s.peerStore, s.localID)
	if maxBefore == 0 {
		t.Fatalf("precondition: expected MaxRecvNonce advanced, got 0")
	}

	// ATTACK: inject one forged frame with a maximal counter. It claims to
	// be from localID (a public node ID) but its ciphertext is junk, so
	// AEAD.Open fails.
	const forgedCounter = uint64(1) << 63
	res := envelope.DecryptFrame(s.peerStore, forgeFrame(s.localID, forgedCounter))
	if !errors.Is(res.Err, envelope.ErrAEAD) {
		t.Fatalf("forged frame: err = %v, want ErrAEAD", res.Err)
	}

	// CORE ASSERTION: the forged frame must NOT have advanced the window.
	maxAfter := recvMax(s.peerStore, s.localID)
	if maxAfter != maxBefore {
		t.Fatalf("forged AEAD-fail advanced MaxRecvNonce: before=%d after=%d "+
			"(window wedged — the DoS bug)", maxBefore, maxAfter)
	}

	// END-TO-END: the next genuine frame (real counter) must still decrypt.
	// On the buggy code MaxRecvNonce is pinned at 2^63 so this frame is
	// ReplayWindowSize behind the max and comes back ErrOutsideWindow.
	legit, err := envelope.EncryptFrame(s.localStore, s.peerID, []byte("post-attack"))
	if err != nil {
		t.Fatalf("encrypt post-attack: %v", err)
	}
	got := envelope.DecryptFrame(s.peerStore, legit[4:])
	if got.Err != nil {
		t.Fatalf("genuine frame after forged injection: err = %v, want success "+
			"(window wedged by forged high counter)", got.Err)
	}
	if !bytes.Equal(got.Plaintext, []byte("post-attack")) {
		t.Fatalf("plaintext mismatch: got %q", got.Plaintext)
	}
}

// TestForgedInjectionPreservesReplayAndReordering asserts the fix does not
// weaken the legitimate replay-window guarantees: genuine replays are still
// rejected, and in-window out-of-order delivery is still accepted.
func TestForgedInjectionPreservesReplayAndReordering(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	// Encrypt three frames up front (counters 1, 2, 3) but deliver them out
	// of order and with a forged frame interleaved.
	f1, _ := envelope.EncryptFrame(s.localStore, s.peerID, []byte("c1"))
	f2, _ := envelope.EncryptFrame(s.localStore, s.peerID, []byte("c2"))
	f3, _ := envelope.EncryptFrame(s.localStore, s.peerID, []byte("c3"))

	// Deliver counter=2 first (advances max to 2).
	if r := envelope.DecryptFrame(s.peerStore, f2[4:]); r.Err != nil {
		t.Fatalf("deliver c2: %v", r.Err)
	}

	// Forged high-counter injection between legit frames — must be ErrAEAD
	// and must NOT wedge the window.
	if r := envelope.DecryptFrame(s.peerStore, forgeFrame(s.localID, uint64(1)<<62)); !errors.Is(r.Err, envelope.ErrAEAD) {
		t.Fatalf("forged interleave: err = %v, want ErrAEAD", r.Err)
	}

	// In-window REORDERING: counter=1 arrives after 2 — still accepted.
	if r := envelope.DecryptFrame(s.peerStore, f1[4:]); r.Err != nil {
		t.Fatalf("in-window reorder (c1 after c2): err = %v, want success", r.Err)
	}

	// In-order continuation: counter=3 accepted.
	if r := envelope.DecryptFrame(s.peerStore, f3[4:]); r.Err != nil {
		t.Fatalf("deliver c3: %v", r.Err)
	}

	// GENUINE REPLAY: re-deliver counter=2 — must be rejected as a replay.
	if r := envelope.DecryptFrame(s.peerStore, f2[4:]); !errors.Is(r.Err, envelope.ErrReplay) {
		t.Fatalf("genuine replay of c2: err = %v, want ErrReplay", r.Err)
	}
	// And counter=1 replay too.
	if r := envelope.DecryptFrame(s.peerStore, f1[4:]); !errors.Is(r.Err, envelope.ErrReplay) {
		t.Fatalf("genuine replay of c1: err = %v, want ErrReplay", r.Err)
	}
}

// recvMax reads the peer-side MaxRecvNonce for the Crypto keyed under
// senderID, under the same lock DecryptFrame uses.
func recvMax(store *keyexchange.Store, senderID uint32) uint64 {
	c := store.Get(senderID)
	if c == nil {
		return 0
	}
	c.ReplayMu.Lock()
	defer c.ReplayMu.Unlock()
	return c.MaxRecvNonce
}

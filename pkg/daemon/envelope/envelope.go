// SPDX-License-Identifier: AGPL-3.0-or-later

// Package envelope is L6 — the per-peer AEAD framing layer. It runs the
// AEAD wrap/unwrap and replay-window check on every tunnel frame.
//
// envelope is a downward consumer of L5 (keyexchange): it reads per-peer
// Crypto state from keyexchange.Store, but does NOT own that state.
// Ownership of Crypto, the salvage ring, the replay-bitmap, and the
// MaxCryptoPeers cap lives at L5.
//
// Per docs/architecture/01-LAYERS.md L6:
//
//	Role: AEAD encrypt and decrypt every frame; per-peer replay
//	  detection.
//	Owns: NOTHING persistent — framing functions are stateless and
//	  operate on Crypto values supplied by L5.
//	Consumes: L1, L2, L3 (primitives), L5 (key state).
//	Exposes: EncryptFrame(store, dst, plaintext) → frame,
//	  DecryptFrame(store, frame) → DecryptResult.
//
// Per docs/architecture/03-INVARIANTS.md §3 (lock graph): the only
// locks taken here are keyexchange.Crypto.ReplayMu (LEAF). They are
// never nested with any TunnelManager-side mutex.
//
// Per docs/architecture/03-INVARIANTS.md §9 (horizontal-incest): L6 →
// L5 is a downward import (allowed). envelope/ MUST NOT be imported
// by keyexchange/ — that would be upward.
package envelope

import (
	"encoding/binary"
	"errors"
	"sync/atomic"

	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

// DecryptResult is the outcome of DecryptFrame.
type DecryptResult struct {
	// Plaintext is the AEAD-Open output (nil on failure / replay).
	Plaintext []byte
	// PeerNodeID is the sender ID parsed from the frame header.
	PeerNodeID uint32
	// Counter is the nonce counter pulled from the frame.
	Counter uint64

	// Err categorises the outcome:
	//   nil — success.
	//   keyexchange.ErrNoKey — no Crypto installed for this peer (caller
	//     should trigger a rekey request).
	//   ErrReplay — replay-window check rejected the nonce.
	//   ErrOutsideWindow — counter older than the window (likely peer
	//     replaced their crypto and counter restarted from low).
	//   ErrAEAD — AEAD-Open failed (key divergence or corruption).
	//   ErrTooShort — frame structurally invalid.
	Err error

	// MaxRecvNonce is the recv-nonce high-water-mark observed under
	// ReplayMu, captured for caller logging without re-locking.
	MaxRecvNonce uint64
}

// Framing-level errors. Pure verdicts on the wire-format / AEAD path —
// they do not depend on L5 key-state policy. Key-state errors
// (ErrNoKey, ErrNotReady) live with the Store at L5 (keyexchange).
var (
	ErrReplay        = errors.New("envelope: nonce replay detected")
	ErrOutsideWindow = errors.New("envelope: counter outside replay window")
	ErrAEAD          = errors.New("envelope: AEAD authentication failed")
	ErrTooShort      = errors.New("envelope: frame too short")
)

// EncryptFrame encrypts plaintext using the Crypto installed for dst in
// store and returns the on-wire frame:
//
//	[PILS magic(4)][localNodeID(4)][nonce(12)][ciphertext+GCM tag]
//
// The local node ID is written into both the frame header and the AEAD
// AAD (H3 fix — binds sender identity into authentication).
func EncryptFrame(store *keyexchange.Store, dst uint32, plaintext []byte) ([]byte, error) {
	c := store.Get(dst)
	if c == nil {
		return nil, keyexchange.ErrNoKey
	}
	if !c.Ready {
		return nil, keyexchange.ErrNotReady
	}
	return EncryptWith(store, c, plaintext), nil
}

// EncryptWith is the variant used by callers that already hold the
// Crypto pointer (e.g. flushPending, keepaliveSweep, replaySalvage).
// Bypasses the map lookup. Caller must ensure c is non-nil and Ready.
func EncryptWith(store *keyexchange.Store, c *keyexchange.Crypto, plaintext []byte) []byte {
	nonce := make([]byte, c.AEAD.NonceSize())
	copy(nonce[0:4], c.NoncePrefix[:])
	counter := atomic.AddUint64(&c.Nonce, 1)
	binary.BigEndian.PutUint64(nonce[c.AEAD.NonceSize()-8:], counter)

	// H3 fix: bind sender's nodeID as AAD
	local := store.LocalNodeID()
	aad := make([]byte, 4)
	binary.BigEndian.PutUint32(aad, local)
	ciphertext := c.AEAD.Seal(nil, nonce, plaintext, aad)
	store.EncryptOK.Add(1)

	frame := make([]byte, 4+4+len(nonce)+len(ciphertext))
	copy(frame[0:4], protocol.TunnelMagicSecure[:])
	binary.BigEndian.PutUint32(frame[4:8], local)
	copy(frame[8:8+len(nonce)], nonce)
	copy(frame[8+len(nonce):], ciphertext)

	return frame
}

// DecryptFrame parses an inbound encrypted frame, runs replay check, and
// AEAD-Open. The frame argument is the bytes AFTER the PILS magic
// (i.e. starting at the 4-byte sender nodeID — matches the readLoop's
// `data` parameter to handleEncrypted).
//
// Returns a DecryptResult describing the outcome. The caller (L5/L7)
// consults Result.Err to decide rekey requests, drop policy, etc.
//
// Ordering (authenticate-before-commit — the remote-DoS fix):
//  1. A read-only pre-check (WouldAcceptNonce) rejects obvious replays /
//     out-of-window frames WITHOUT mutating any replay state, so the
//     expensive AEAD work is skipped for junk.
//  2. AEAD.Open runs on frames the pre-check would accept.
//  3. ONLY on a successful Open is the nonce committed to the replay
//     window (CheckAndRecordNonce advances MaxRecvNonce / sets the bit).
//
// This is deliberately the WireGuard-style ordering: the replay counter is
// only ever advanced by an authenticated frame. The previous
// check-record-then-open ordering let an attacker who knew a victim's node
// ID + a peer it had a session with (both public) inject one PILS frame
// with a maximal counter: CheckAndRecordNonce pinned MaxRecvNonce at that
// value, AEAD.Open then failed, and every subsequent genuine frame from
// the real peer fell >= ReplayWindowSize behind the pinned max — dropped as
// ErrOutsideWindow, tripping the aged-session fast-drop into a permanent
// packet-loss + rekey storm. Reachable through the beacon relay
// (handleRelayDeliver → handleEncrypted), so NAT'd victims were hit with no
// spoofing. Advancing the window only after authentication closes it.
//
// On AEAD-Open failure DecryptFrame increments c.DecryptFailCount under
// c.ReplayMu (kept on the Crypto rather than under Store.mu — c.ReplayMu is
// leaf-level so this preserves the lock graph invariant). No replay-window
// mutation happens on the failure path (nothing was speculatively
// recorded), so MaxRecvNonce is untouched by a forged frame.
//
// The grace-gated drop decision (ShouldDropOnDecryptFail) lives on
// keyexchange.Store; this function only signals via DecryptResult.Err.
func DecryptFrame(store *keyexchange.Store, data []byte) DecryptResult {
	if len(data) < 4+12+16 { // nodeID + 12-byte nonce + min GCM tag
		return DecryptResult{Err: ErrTooShort}
	}
	peerNodeID := binary.BigEndian.Uint32(data[0:4])
	nonce := data[4:16]
	ciphertext := data[16:]

	c := store.Get(peerNodeID)
	if c == nil || !c.Ready {
		return DecryptResult{PeerNodeID: peerNodeID, Err: keyexchange.ErrNoKey}
	}

	recvCounter := binary.BigEndian.Uint64(nonce[len(nonce)-8:])

	// Step 1: read-only pre-check. Reject obvious replays / out-of-window
	// frames before spending AEAD, but WITHOUT mutating replay state. A
	// forged high-counter frame passes this pre-check (a new maximum is not
	// a replay) — it is only committed in step 3, after authentication.
	c.ReplayMu.Lock()
	accept := c.WouldAcceptNonce(recvCounter)
	maxN := c.MaxRecvNonce
	c.ReplayMu.Unlock()

	if !accept {
		return rejectResult(c, peerNodeID, recvCounter, maxN)
	}

	// Step 2: authenticate. H3 fix — verify sender's nodeID as AAD.
	aad := make([]byte, 4)
	binary.BigEndian.PutUint32(aad, peerNodeID)
	plaintext, err := c.AEAD.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		store.EncryptFail.Add(1)
		// AEAD failed: the frame is unauthenticated. The pre-check above
		// recorded NOTHING in the replay window, so there is no speculative
		// bit to roll back and — critically — MaxRecvNonce is untouched. A
		// forged frame therefore cannot wedge the window.
		c.ReplayMu.Lock()
		c.DecryptFailCount++
		c.ReplayMu.Unlock()
		return DecryptResult{
			PeerNodeID:   peerNodeID,
			Counter:      recvCounter,
			MaxRecvNonce: maxN,
			Err:          ErrAEAD,
		}
	}

	// Step 3: authenticated — commit the nonce to the replay window. Use
	// CheckAndRecordNonce (a full re-check, not a blind record) because a
	// concurrent authenticated frame may have advanced the window between
	// the read-only pre-check and here. If this frame lost that benign
	// reorder/duplicate race it is rejected as replay/outside-window,
	// exactly as the old check-then-open ordering would have rejected it.
	c.ReplayMu.Lock()
	committed := c.CheckAndRecordNonce(recvCounter)
	maxN = c.MaxRecvNonce
	c.ReplayMu.Unlock()

	if !committed {
		return rejectResult(c, peerNodeID, recvCounter, maxN)
	}

	// Successful decrypt — reset all three fault counters under one lock.
	c.ReplayMu.Lock()
	if c.DecryptFailCount != 0 {
		c.DecryptFailCount = 0
	}
	if c.OutsideWindowCount != 0 {
		c.OutsideWindowCount = 0
	}
	if c.ReplayCount != 0 {
		c.ReplayCount = 0
	}
	c.ReplayMu.Unlock()

	return DecryptResult{
		Plaintext:    plaintext,
		PeerNodeID:   peerNodeID,
		Counter:      recvCounter,
		MaxRecvNonce: maxN,
	}
}

// rejectResult builds the DecryptResult for a nonce the replay window
// rejects, and bumps the matching consecutive-fault counter. Shared by the
// read-only pre-check (step 1) and the post-AEAD commit re-check (step 3).
// maxN is the MaxRecvNonce observed under ReplayMu at the point of
// rejection, used both for the caller's logging and to classify the
// rejection as in-window replay vs. outside-window divergence.
func rejectResult(c *keyexchange.Crypto, peerNodeID uint32, recvCounter, maxN uint64) DecryptResult {
	err := ErrReplay
	if recvCounter < maxN && maxN-recvCounter >= keyexchange.ReplayWindowSize {
		err = ErrOutsideWindow
		// Track consecutive outside-window rejections. A sustained burst
		// means the peer's send counter has diverged from our window's
		// high-water-mark too far for in-band recovery — only a fresh key
		// exchange resets both sides. The caller (L7) consults
		// ShouldDropOnOutsideWindow to enforce the threshold + grace gate.
		// Mirrors DecryptFailCount.
		c.ReplayMu.Lock()
		c.OutsideWindowCount++
		c.ReplayMu.Unlock()
	} else {
		// In-window replay collision. Symmetric counterpart to
		// OutsideWindowCount on the *other* side of the window: peer's
		// counter is INSIDE [max-window, max] but at a position we've
		// already marked. Sustained collisions mean the peer's send counter
		// reset (peer restarted with a persistent X25519 identity, so no
		// PILA was negotiated) and every frame they now produce lands on a
		// bit we already set. Recovery is structurally identical to
		// outside-window: gate via ShouldDropOnReplay (threshold + grace),
		// then drop the Crypto and trigger a fresh exchange.
		c.ReplayMu.Lock()
		c.ReplayCount++
		c.ReplayMu.Unlock()
	}
	return DecryptResult{
		PeerNodeID:   peerNodeID,
		Counter:      recvCounter,
		MaxRecvNonce: maxN,
		Err:          err,
	}
}

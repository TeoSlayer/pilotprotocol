// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange

import (
	"crypto/cipher"
	"sync"
	"time"
)

// ReplayWindowSize is the number of nonces tracked in the sliding window
// bitmap for replay detection (H8 fix). Nonces within
// [maxNonce-ReplayWindowSize, maxNonce] are tracked; nonces below the
// window are rejected.
//
// Per-peer state — owned with the key, hence on L5 (keyexchange) rather
// than L6 (envelope).
const ReplayWindowSize = 256

// SalvageMaxEntries bounds memory + replay-storm size on rekey. Originally
// 32, but a 32-frame burst replayed on rekey caused receiver-side nonce
// confusion (concurrent dataexchange retransmits filling salvage +
// out-of-order delivery on the wire). 4 covers the typical "send-message +
// a couple of retries" without overwhelming the receiver.
// Memory at max: 4 × ~1500 B = 6 KiB / peer, ~6 MiB across maxCryptoPeers
// (1024).
const SalvageMaxEntries = 4

// SalvageMaxAge is how far back we replay sends after a rekey. The rekey
// round-trip itself is ~1 RTT plus the rate-limit window (3 s); 5 s gives
// margin for slow handshakes under loss.
const SalvageMaxAge = 5 * time.Second

// DecryptFailDropThreshold is how many consecutive AEAD-authentication
// failures from a single peer trigger a full Crypto drop + re-handshake.
// Sized to swallow a small burst of legitimate packet corruption (kernel
// buffer overruns, mid-flight key rotation crossing the wire) while still
// recovering from peer-side AEAD-key divergence within a few seconds — a
// daemon restart on either side cycles the peer through a fresh
// handshake; this is the "equivalent recovery without restarting" path.
//
// Lives on L5 with the per-peer state it gates rather than on L6 framing,
// because the drop decision uses Crypto.CreatedAt (key-install time, an
// L5 concept) and Crypto.DecryptFailCount (per-peer state).
const DecryptFailDropThreshold = 5

// OutsideWindowDropThreshold is how many consecutive outside-replay-window
// rejections cause us to drop the peer's Crypto and trigger a fresh key
// exchange. Tuned conservatively: ReplayWindowSize=256 means an in-spec
// burst of late relay-buffered frames can produce a few outside-window
// rejections normally. 30 consecutive without any successful decrypt is
// strong evidence the peer's send counter is far behind our window
// max-water-mark and no in-band recovery exists. Reset to 0 on success.
const OutsideWindowDropThreshold = 30

// OutsideWindowDropGrace mirrors DecryptFailDropGrace but for the
// outside-window path. Reuses the same 3-second value: a freshly
// installed Crypto can legitimately see a small flurry of stale
// in-flight frames at low counters; only after the new state has had
// time to drain those should we treat the persistence as divergence.
const OutsideWindowDropGrace = 3 * time.Second

// ReplayDropThreshold is how many consecutive in-window replay
// rejections trigger a Crypto drop + fresh key exchange. Symmetric
// counterpart to OutsideWindowDropThreshold for the *other* side of
// the window: the peer's send counter is INSIDE our ReplayWindowSize
// range but at positions we've already seen.
//
// Reproduces the rc5 list-agents wedge (2026-05-11): peer daemon
// restarts but keeps its persisted X25519 identity, so no PILA is
// negotiated; the peer's send counter resets to 1 while our
// MaxRecvNonce sits at ~50. Every subsequent frame from the peer
// authenticates with the same key, lands at counter=1..50, and is
// dropped as a replay before AEAD-Open ever runs — neither
// DecryptFailCount nor OutsideWindowCount increment, so the existing
// recovery paths never engage. Sustained replays are the only signal
// that the peer's counter and our window are mis-aligned.
//
// 30 matches OutsideWindowDropThreshold for the same reason: a
// legitimate duplicate-delivery burst (direct + relay both delivering
// the same frame) typically tops out at 1–3 collisions per frame
// pair; 30 consecutive same-peer replays without any successful
// decrypt cleanly distinguishes the wedge from legitimate
// duplication. Reset to 0 on successful decrypt.
const ReplayDropThreshold = 30

// ReplayDropGrace mirrors OutsideWindowDropGrace. A freshly installed
// Crypto can legitimately see a few replays as both direct and relay
// paths catch up to the new key; only after the new state has had
// time to drain those should we treat the persistence as divergence.
const ReplayDropGrace = 3 * time.Second

// DecryptFailDropGrace is the minimum age a Crypto must reach before
// repeated decrypt failures can drop it. Set above the typical relay RTT
// (≤200 ms) plus a comfortable margin: stale ciphertext from before the
// peer's last rekey takes ~1 RTT to drain, but if salvage replay is in
// play it can stretch slightly. 3 s covers worst-case drain without
// holding a genuinely diverged session for long.
const DecryptFailDropGrace = 3 * time.Second

// SalvageEntry is a single plaintext frame retained for post-rekey replay.
type SalvageEntry struct {
	Plaintext []byte
	When      time.Time
}

// Crypto holds per-peer encryption state. Created by L5 (DeriveSecret)
// after key derivation; mutated by L6 on every encrypt/decrypt; cleared
// on rekey or peer drop.
//
// Per docs/architecture/03-INVARIANTS.md §3 (lock graph): Crypto's
// ReplayMu and SalvageMu are LEAF locks. They are never nested with
// any TunnelManager-side mutex (tm.mu, tm.rkPendingMu, etc.). Methods
// on Crypto must not acquire any external lock while holding them.
//
// Ownership lives on L5 (keyexchange) per docs/architecture/01-LAYERS.md:
// L6 'Consumes: ... L5 (key state)' — the envelope is a downward
// consumer of L5's per-peer state, not its owner.
type Crypto struct {
	AEAD        cipher.AEAD
	Nonce       uint64  // monotonic send counter (atomic)
	NoncePrefix [4]byte // random prefix for nonce domain separation

	// Replay detection (H8 fix): sliding window bitmap instead of simple
	// high-water mark.
	ReplayMu     sync.Mutex
	MaxRecvNonce uint64                        // highest nonce received
	ReplayBitmap [ReplayWindowSize / 64]uint64 // bitmap for nonces in [max-windowSize, max]

	Ready         bool     // true once key exchange is complete
	Authenticated bool     // true if peer proved Ed25519 identity
	PeerX25519Key [32]byte // peer's X25519 public key (for detecting rekeying)

	// DecryptFailCount tracks consecutive AEAD authentication failures
	// since the last successful decrypt. Older-version peer daemons drift
	// into a state where their derived AEAD key no longer matches ours
	// (likely a session-id or info-string mismatch in HKDF), at which
	// point every encrypted packet from the peer fails with "cipher:
	// message authentication failed". Once this counter exceeds
	// DecryptFailDropThreshold the daemon drops this Crypto entirely
	// and triggers a fresh key exchange — equivalent to a daemon-restart
	// recovery without actually restarting. Reset to 0 on any successful
	// decrypt.
	DecryptFailCount int

	// OutsideWindowCount tracks consecutive frames rejected because their
	// counter was more than ReplayWindowSize behind MaxRecvNonce. A few
	// of these are normal (late relay-buffered frames). A sustained burst
	// means the peer's send counter and our receive window have diverged
	// far enough that no in-band recovery is possible — the only signal
	// the peer has to know there's a problem is silence, and the only
	// fix is a fresh key exchange. Once this counter exceeds
	// OutsideWindowDropThreshold AND the Crypto is older than
	// OutsideWindowDropGrace, the daemon drops this Crypto and requests
	// a rekey. Reset to 0 on any successful decrypt.
	OutsideWindowCount int

	// ReplayCount tracks consecutive in-window replay rejections (counter
	// within ReplayWindowSize of MaxRecvNonce but already marked in the
	// bitmap). Distinct from OutsideWindowCount, which handles the
	// counter-far-behind case. A few replays are normal (duplicate
	// delivery across direct + relay paths); a sustained burst means
	// peer's send counter reset (peer restart with persistent identity)
	// and our window's high-water-mark sits ahead of every frame the
	// peer can now produce — the wedge resolves only when peer's counter
	// climbs past our max, but with no traffic in flight it never will.
	// Once this counter exceeds ReplayDropThreshold AND the Crypto is
	// older than ReplayDropGrace, drop the Crypto and request rekey.
	// Reset to 0 on any successful decrypt.
	ReplayCount int

	// CreatedAt is when this Crypto was installed. Used by L5's
	// handleAuthKeyExchange to decide between preserving existing state
	// (fresh handshake retransmit/reply within seconds) and resetting it
	// (long-lived peer's own state desynced — e.g. older-version daemon
	// rotated its send counter without rotating X25519 keys, which
	// otherwise leaves us with a high MaxRecvNonce that rejects the
	// peer's resumed packets as replays). Also gates the rc5 grace
	// period (see DecryptFailDropGrace).
	CreatedAt time.Time

	// P1-010 desync salvage: ring buffer of recent plaintext sent with
	// this key. On a peer-initiated rekey, these are re-encrypted with
	// the new key and re-sent — recovering the data that was vaporized
	// when the peer dropped our stale-keyed frames.
	SalvageMu sync.Mutex
	Salvage   []SalvageEntry
}

// CheckAndRecordNonce returns true if the nonce is valid (not replayed,
// not too old). Must be called with c.ReplayMu held.
//
// Note on nonce wraparound: the counter is uint64, so it wraps after
// 2^64 packets. At 1 billion packets/sec this takes ~585 years — purely
// theoretical. If a connection ever approaches this limit, rekeying
// (new secure handshake) resets the counter naturally.
func (c *Crypto) CheckAndRecordNonce(counter uint64) bool {
	if c.MaxRecvNonce == 0 {
		// First packet ever
		c.MaxRecvNonce = counter
		c.SetReplayBit(counter)
		return true
	}

	if counter > c.MaxRecvNonce {
		// New maximum — shift window forward
		shift := counter - c.MaxRecvNonce
		if shift >= ReplayWindowSize {
			// Clear entire bitmap
			c.ReplayBitmap = [ReplayWindowSize / 64]uint64{}
		} else {
			// Clear the new positions that the shifted window will occupy
			for s := uint64(0); s < shift; s++ {
				newBit := (counter - s) % ReplayWindowSize
				c.ReplayBitmap[newBit/64] &^= 1 << (newBit % 64)
			}
		}
		c.MaxRecvNonce = counter
		c.SetReplayBit(counter)
		return true
	}

	// counter <= MaxRecvNonce
	diff := c.MaxRecvNonce - counter
	if diff >= ReplayWindowSize {
		return false // too old
	}

	// Check if already seen
	bit := counter % ReplayWindowSize
	if c.ReplayBitmap[bit/64]&(1<<(bit%64)) != 0 {
		return false // replay
	}
	c.SetReplayBit(counter)
	return true
}

// SetReplayBit sets the replay-window bit corresponding to counter.
// Must be called with c.ReplayMu held.
func (c *Crypto) SetReplayBit(counter uint64) {
	bit := counter % ReplayWindowSize
	c.ReplayBitmap[bit/64] |= 1 << (bit % 64)
}

// UndoReplayBit clears the bit set by a prior SetReplayBit. Used by L6
// when AEAD-Open fails to roll back the speculative bookkeeping —
// without this, a flood of failed-decrypt frames would wedge legitimate
// later packets out of the replay window. Must be called with
// c.ReplayMu held.
func (c *Crypto) UndoReplayBit(counter uint64) {
	bit := counter % ReplayWindowSize
	c.ReplayBitmap[bit/64] &^= 1 << (bit % 64)
}

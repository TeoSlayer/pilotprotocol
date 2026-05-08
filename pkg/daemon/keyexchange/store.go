// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// MaxCryptoPeers caps the crypto map for unauth key-exchange insertions.
// HandleAuthFrame is implicitly bounded by the registry-verified pubkey
// lookup, but HandleUnauthFrame accepts any peerNodeID and performs an
// X25519 scalar multiplication per packet. Without a cap, a peer
// spraying unauth key-exchange frames with random node IDs can grow the
// map to 2^32 entries while also burning CPU on derivation. Set high
// enough that real deployments never hit it.
//
// Lives on L5 with the per-peer Store rather than as a free constant
// in L6 framing — the cap is a property of key-state ownership.
const MaxCryptoPeers = 16384

// ErrNoKey is returned when no Crypto is installed for a peer
// (encrypt-side: no key to wrap with; decrypt-side: nothing to unwrap
// with). Caller's responsibility to trigger a rekey request.
var ErrNoKey = errors.New("keyexchange: no key installed for peer")

// ErrNotReady is returned when a Crypto exists but is not yet marked
// Ready (key exchange in progress).
var ErrNotReady = errors.New("keyexchange: crypto installed but not ready")

// Store is the per-tunnel key-state registry. It owns the map of node ID
// → Crypto. Counter, replay-window, and salvage state live on the
// per-peer Crypto values; Store's mutex only protects the map itself.
//
// The mutex is intentionally a simple sync.RWMutex used as a leaf lock —
// it must NEVER be held while invoking a TunnelManager-side mutex
// (tm.mu, tm.rkPendingMu, tm.pendMu). All callers obey this by reading
// from Store first, then mutating tm state in a separate critical
// section.
//
// Store is L5-owned. L6 (envelope) imports Store to pull per-peer
// Crypto pointers when wrapping/unwrapping AEAD frames; the import
// direction is L6 → L5, matching docs/architecture/01-LAYERS.md.
type Store struct {
	mu     sync.RWMutex
	crypto map[uint32]*Crypto

	// localNodeID is our own node ID, written into the AEAD AAD (H3)
	// and the secure-frame header. Stored as atomic uint32 so SetLocalNodeID
	// can be called from any goroutine without locking the map.
	localNodeID atomic.Uint32

	// EncryptOK / EncryptFail track AEAD operation success/failure
	// counts. Exposed as atomic counters so L7 / metrics readers don't
	// need to take Store.mu. Bumped by the L6 framing functions in
	// pkg/daemon/envelope.
	EncryptOK   atomic.Uint64
	EncryptFail atomic.Uint64
}

// NewStore returns an empty Store.
func NewStore() *Store {
	return &Store{crypto: make(map[uint32]*Crypto)}
}

// SetLocalNodeID stores our own node ID (used in encrypt-side AAD and
// secure-frame headers). Safe to call concurrently with other Store
// operations.
func (s *Store) SetLocalNodeID(id uint32) {
	s.localNodeID.Store(id)
}

// LocalNodeID returns our own node ID.
func (s *Store) LocalNodeID() uint32 {
	return s.localNodeID.Load()
}

// Install adds (or replaces) the Crypto for the given peer. Caller is
// responsible for any "preserve on duplicate same-pubkey" logic — Store
// just unconditionally writes.
func (s *Store) Install(peerNodeID uint32, c *Crypto) {
	s.mu.Lock()
	s.crypto[peerNodeID] = c
	s.mu.Unlock()
}

// Get returns the Crypto installed for peerNodeID, or nil if none.
func (s *Store) Get(peerNodeID uint32) *Crypto {
	s.mu.RLock()
	c := s.crypto[peerNodeID]
	s.mu.RUnlock()
	return c
}

// Has returns true if a Crypto is installed for peerNodeID.
func (s *Store) Has(peerNodeID uint32) bool {
	s.mu.RLock()
	_, ok := s.crypto[peerNodeID]
	s.mu.RUnlock()
	return ok
}

// IsReady returns true if a Crypto is installed AND its handshake is
// complete (Ready=true).
func (s *Store) IsReady(peerNodeID uint32) bool {
	s.mu.RLock()
	c := s.crypto[peerNodeID]
	s.mu.RUnlock()
	return c != nil && c.Ready
}

// Drop removes the Crypto for peerNodeID. Safe even if no entry exists.
func (s *Store) Drop(peerNodeID uint32) {
	s.mu.Lock()
	delete(s.crypto, peerNodeID)
	s.mu.Unlock()
}

// CompareAndDrop deletes the entry only if the currently-installed
// pointer equals expected. Returns true if a delete occurred. Used by
// the decrypt-fail drop path to avoid deleting a Crypto that a
// concurrent rekey already replaced.
func (s *Store) CompareAndDrop(peerNodeID uint32, expected *Crypto) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.crypto[peerNodeID] != expected {
		return false
	}
	delete(s.crypto, peerNodeID)
	return true
}

// Len returns the number of installed Cryptos. Used by the
// MaxCryptoPeers cap pre-check.
func (s *Store) Len() int {
	s.mu.RLock()
	n := len(s.crypto)
	s.mu.RUnlock()
	return n
}

// PeerIDs returns a snapshot of all peer IDs with installed Cryptos.
func (s *Store) PeerIDs() []uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]uint32, 0, len(s.crypto))
	for id := range s.crypto {
		ids = append(ids, id)
	}
	return ids
}

// ShouldDropOnDecryptFail implements the rc5 grace gate: returns true
// if the failing Crypto's DecryptFailCount has reached
// DecryptFailDropThreshold AND the Crypto is older than
// DecryptFailDropGrace AND it is still the currently-installed entry
// for peerNodeID.
//
// The caller (L6 framing path) is responsible for the side-effect: drop
// via CompareAndDrop and trigger a fresh key exchange. This split keeps
// the rekey-trigger / event-publish responsibility OUT of Store.
func (s *Store) ShouldDropOnDecryptFail(peerNodeID uint32, c *Crypto) bool {
	if c == nil {
		return false
	}
	c.ReplayMu.Lock()
	failures := c.DecryptFailCount
	c.ReplayMu.Unlock()
	if failures < DecryptFailDropThreshold {
		return false
	}
	if time.Since(c.CreatedAt) < DecryptFailDropGrace {
		return false
	}
	// Only drop if c is still the currently-installed entry.
	current := s.Get(peerNodeID)
	return current == c
}

// RecordSalvage stashes a plaintext send into the per-peer ring buffer.
// On a subsequent peer-initiated rekey, DrainSalvage will hand back the
// entries; the caller re-encrypts with the new key and re-sends —
// recovering data that the peer dropped because our frame was keyed
// under their now-stale crypto context.
//
// Bounded by SalvageMaxEntries and SalvageMaxAge. The plaintext is
// copied, not referenced — caller can reuse its buffer.
//
// nil c is a no-op (safe for callers that don't gate on Ready).
func (s *Store) RecordSalvage(c *Crypto, plaintext []byte) {
	if c == nil {
		return
	}
	now := time.Now()
	cutoff := now.Add(-SalvageMaxAge)
	c.SalvageMu.Lock()
	// Trim aged entries from the head.
	for len(c.Salvage) > 0 && c.Salvage[0].When.Before(cutoff) {
		c.Salvage = c.Salvage[1:]
	}
	// Bound size — drop oldest.
	if len(c.Salvage) >= SalvageMaxEntries {
		c.Salvage = c.Salvage[1:]
	}
	cp := make([]byte, len(plaintext))
	copy(cp, plaintext)
	c.Salvage = append(c.Salvage, SalvageEntry{Plaintext: cp, When: now})
	c.SalvageMu.Unlock()
}

// DrainSalvage atomically removes and returns all non-aged salvage
// entries from c. Returns nil if c is nil or empty. Each returned
// Plaintext is the same byte slice that was stored — RecordSalvage
// already copied at insert time.
func (s *Store) DrainSalvage(c *Crypto) []SalvageEntry {
	if c == nil {
		return nil
	}
	c.SalvageMu.Lock()
	entries := c.Salvage
	c.Salvage = nil
	c.SalvageMu.Unlock()
	if len(entries) == 0 {
		return nil
	}
	cutoff := time.Now().Add(-SalvageMaxAge)
	out := entries[:0]
	for _, e := range entries {
		if e.When.Before(cutoff) {
			continue
		}
		out = append(out, e)
	}
	return out
}

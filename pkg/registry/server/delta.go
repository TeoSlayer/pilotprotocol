// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/json"
	"sync"

	walpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/wal"
)

// DeltaType identifies what kind of mutation a delta represents.
// This is an alias for the canonical definition in the wal sub-package (R6.1).
type DeltaType = walpkg.DeltaType

// DeltaEntry records a single state mutation for incremental replication.
// This is an alias for the canonical definition in the wal sub-package (R6.1).
type DeltaEntry = walpkg.DeltaEntry

// Re-export the delta-type constants so existing server code compiles without
// qualification changes.
const (
	DeltaRegister      = walpkg.DeltaRegister
	DeltaDeregister    = walpkg.DeltaDeregister
	DeltaHeartbeat     = walpkg.DeltaHeartbeat
	DeltaTrustAdd      = walpkg.DeltaTrustAdd
	DeltaTrustRevoke   = walpkg.DeltaTrustRevoke
	DeltaVisibility    = walpkg.DeltaVisibility
	DeltaHostname      = walpkg.DeltaHostname
	DeltaTags          = walpkg.DeltaTags
	DeltaNetworkCreate = walpkg.DeltaNetworkCreate
	DeltaNetworkJoin   = walpkg.DeltaNetworkJoin
	DeltaNetworkLeave  = walpkg.DeltaNetworkLeave
	DeltaKeyRotation   = walpkg.DeltaKeyRotation
	DeltaTaskExec      = walpkg.DeltaTaskExec
	DeltaNetworkDelete = walpkg.DeltaNetworkDelete
)

// maxDeltaLogSize bounds the delta log to prevent unbounded memory growth.
// At ~500 bytes per entry, 10K entries ≈ 5MB.
const maxDeltaLogSize = 10000

// deltaLog is a bounded, append-only log of recent mutations.
// When the log exceeds maxDeltaLogSize, oldest entries are discarded.
// Standbys that fall behind the log window receive a full snapshot instead.
type deltaLog struct {
	mu      sync.Mutex
	entries []DeltaEntry
	nextSeq uint64
}

func newDeltaLog() *deltaLog {
	return &deltaLog{
		entries: make([]DeltaEntry, 0, 1024),
		nextSeq: 1,
	}
}

// Append adds a new delta entry to the log and returns its sequence number.
func (dl *deltaLog) Append(typ DeltaType, nodeID uint32, data json.RawMessage) uint64 {
	dl.mu.Lock()
	defer dl.mu.Unlock()

	seq := dl.nextSeq
	dl.nextSeq++

	dl.entries = append(dl.entries, DeltaEntry{
		SeqNo:  seq,
		Type:   typ,
		NodeID: nodeID,
		Data:   data,
	})

	// Trim oldest entries if log exceeds max size
	if len(dl.entries) > maxDeltaLogSize {
		// Keep last maxDeltaLogSize entries
		excess := len(dl.entries) - maxDeltaLogSize
		copy(dl.entries, dl.entries[excess:])
		dl.entries = dl.entries[:maxDeltaLogSize]
	}

	return seq
}

// Since returns all entries with SeqNo > sinceSeq.
// Returns nil if sinceSeq is too old (before the oldest entry in the log).
// The caller should fall back to a full snapshot in that case.
func (dl *deltaLog) Since(sinceSeq uint64) []DeltaEntry {
	dl.mu.Lock()
	defer dl.mu.Unlock()

	if len(dl.entries) == 0 {
		return nil
	}

	// If requested seq is before our oldest entry, caller needs full snapshot
	if sinceSeq < dl.entries[0].SeqNo {
		return nil
	}

	// Binary search for the start position
	start := 0
	for start < len(dl.entries) && dl.entries[start].SeqNo <= sinceSeq {
		start++
	}

	if start >= len(dl.entries) {
		return []DeltaEntry{} // up to date, no new entries
	}

	// Return a copy to avoid data races
	result := make([]DeltaEntry, len(dl.entries)-start)
	copy(result, dl.entries[start:])
	return result
}

// CurrentSeq returns the most recent sequence number.
func (dl *deltaLog) CurrentSeq() uint64 {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	if dl.nextSeq == 0 {
		return 0
	}
	return dl.nextSeq - 1
}

// Len returns the number of entries currently in the log.
func (dl *deltaLog) Len() int {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	return len(dl.entries)
}

package registry

import (
	"encoding/json"
	"sync"
)

// DeltaType identifies what kind of mutation a delta represents.
type DeltaType uint8

const (
	DeltaRegister      DeltaType = 1
	DeltaDeregister    DeltaType = 2
	DeltaHeartbeat     DeltaType = 3
	DeltaTrustAdd      DeltaType = 4
	DeltaTrustRevoke   DeltaType = 5
	DeltaVisibility    DeltaType = 6
	DeltaHostname      DeltaType = 7
	DeltaTags          DeltaType = 8
	DeltaNetworkCreate DeltaType = 9
	DeltaNetworkJoin   DeltaType = 10
	DeltaNetworkLeave  DeltaType = 11
	DeltaKeyRotation   DeltaType = 12
	DeltaTaskExec      DeltaType = 13
)

// DeltaEntry records a single state mutation for incremental replication.
type DeltaEntry struct {
	SeqNo  uint64          `json:"seq_no"`
	Type   DeltaType       `json:"type"`
	NodeID uint32          `json:"node_id,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

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

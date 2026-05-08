// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wal implements the write-ahead log (WAL) and persistence lifecycle
// for the registry server. It is extracted from pkg/registry/server as part
// of the registry monolith decomposition (R6.1).
//
// The WAL closes the data-loss window between snapshot saves. flushSave runs
// on saveLoopInterval (5s); a crash between saves would otherwise drop every
// mutation in that window. Each low-frequency mutation records a delta to the
// WAL synchronously. On startup the snapshot is loaded, then any post-snapshot
// WAL entries are replayed on top.
package wal

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"
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
	// DeltaNetworkDelete added for WAL wiring. On older binaries that
	// don't recognize this type, replay logs and skips — safe forward-compat.
	DeltaNetworkDelete DeltaType = 14
)

// DeltaEntry records a single state mutation for WAL durability.
type DeltaEntry struct {
	SeqNo  uint64          `json:"seq_no"`
	Type   DeltaType       `json:"type"`
	NodeID uint32          `json:"node_id,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

// maxWALSize bounds the WAL to prevent disk exhaustion if flushSave keeps
// failing (snapshot cannot be written → WAL never gets truncated → it
// grows unboundedly). 256 MiB is generous enough for many minutes of
// mutations at peak rates while leaving headroom on a typical 10-100GB
// system disk.
const maxWALSize = 256 << 20

// ErrWALFull is returned by Append when the WAL would exceed maxWALSize.
// Callers should log + drop the entry (best-effort durability); the
// in-memory mutation still completed, and the next successful flushSave
// will persist via the snapshot path and truncate the WAL.
var ErrWALFull = errors.New("WAL: at size cap, refusing append")

// WAL implements an append-only write-ahead log for registry mutations.
// Instead of serializing the entire state on every mutation (O(N) per save),
// the WAL appends only the delta entry (O(1) per mutation). Full snapshots
// are written periodically (compaction) and the WAL is truncated.
//
// On-disk format: sequential records of [4-byte little-endian length][delta entry JSON].
// The WAL file path is derived from the snapshot path: "{storePath}.wal".
type WAL struct {
	mu   sync.Mutex
	f    *os.File
	path string
	size int64 // current file size for monitoring
}

// NewWAL opens or creates a WAL file at the given path.
// Returns nil if path is empty (no persistence configured).
func NewWAL(path string) (*WAL, error) {
	if path == "" {
		return nil, nil
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open WAL: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat WAL: %w", err)
	}

	return &WAL{
		f:    f,
		path: path,
		size: info.Size(),
	}, nil
}

// Append writes a delta entry to the WAL. The entry is fsync'd to ensure
// durability. Returns an error if the write fails.
func (w *WAL) Append(entry DeltaEntry) error {
	if w == nil {
		return nil
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal WAL entry: %w", err)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Refuse the append if it would push past the cap. Operators see this
	// in metrics + logs; the next successful flushSave will Truncate and
	// reset the cap. Critically: the in-memory mutation already happened,
	// so the only consequence is "loss window grows from 5s of WAL gap
	// to 5s + (time since cap hit)" — much better than crashing on disk
	// full.
	if int64(4+len(data))+w.size > maxWALSize {
		return ErrWALFull
	}

	// Write [4-byte length][data]
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(data)))

	if _, err := w.f.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write WAL length: %w", err)
	}
	if _, err := w.f.Write(data); err != nil {
		return fmt.Errorf("write WAL data: %w", err)
	}
	if err := w.f.Sync(); err != nil {
		return fmt.Errorf("sync WAL: %w", err)
	}

	w.size += int64(4 + len(data))
	return nil
}

// Replay reads all entries from the WAL and calls fn for each.
// Used during startup to replay mutations that occurred after the last snapshot.
func (w *WAL) Replay(fn func(DeltaEntry) error) (int, error) {
	if w == nil {
		return 0, nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Seek to beginning for replay
	if _, err := w.f.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("seek WAL: %w", err)
	}

	count := 0
	var lenBuf [4]byte
	for {
		if _, err := io.ReadFull(w.f, lenBuf[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break // end of WAL
			}
			return count, fmt.Errorf("read WAL length at entry %d: %w", count, err)
		}

		length := binary.LittleEndian.Uint32(lenBuf[:])
		if length > 1<<20 { // sanity: max 1MB per entry
			return count, fmt.Errorf("WAL entry %d too large: %d bytes", count, length)
		}

		data := make([]byte, length)
		if _, err := io.ReadFull(w.f, data); err != nil {
			return count, fmt.Errorf("read WAL data at entry %d: %w", count, err)
		}

		var entry DeltaEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			slog.Warn("WAL: skipping corrupt entry", "entry", count, "err", err)
			continue
		}

		if err := fn(entry); err != nil {
			return count, fmt.Errorf("apply WAL entry %d: %w", count, err)
		}
		count++
	}

	// Seek back to end for future appends
	if _, err := w.f.Seek(0, io.SeekEnd); err != nil {
		return count, fmt.Errorf("seek WAL end: %w", err)
	}

	return count, nil
}

// Truncate clears the WAL file (called after a successful full snapshot).
// This is the "compaction" step — the snapshot supersedes all WAL entries.
func (w *WAL) Truncate() error {
	if w == nil {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.f.Truncate(0); err != nil {
		return fmt.Errorf("truncate WAL: %w", err)
	}
	if _, err := w.f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek WAL after truncate: %w", err)
	}
	if err := w.f.Sync(); err != nil {
		return fmt.Errorf("sync WAL after truncate: %w", err)
	}

	w.size = 0
	return nil
}

// Size returns the current WAL file size in bytes.
func (w *WAL) Size() int64 {
	if w == nil {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.size
}

// Path returns the underlying file path. Exposed for tests.
func (w *WAL) Path() string {
	if w == nil {
		return ""
	}
	return w.path
}

// SetSize forces the in-memory size counter to v. Exposed for tests
// that need to simulate the size cap being reached without writing
// hundreds of MiB to disk.
func (w *WAL) SetSize(v int64) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.size = v
}

// MaxWALSize is the upper bound enforced by Append. Exposed for tests.
const MaxWALSize = maxWALSize

// Close closes the WAL file.
func (w *WAL) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}

// saveLoopInterval is how often Store.saveLoop flushes dirty state to disk.
const saveLoopInterval = 5 * time.Second

// replicaPushInterval is how often Store.replicaPushLoop builds + pushes
// the replication snapshot to standbys.
const replicaPushInterval = 1 * time.Second

// StoreCallbacks bundles the server-side callbacks that Store needs without
// creating a circular import between the wal and server packages.
type StoreCallbacks struct {
	// FlushSave persists the current server state to disk. Called by saveLoop.
	FlushSave func() error
	// SnapshotJSON builds the current state as JSON bytes for replication.
	// Returns nil on error (push is skipped).
	SnapshotJSON func() []byte
	// Push sends snapshot bytes to all replication subscribers.
	Push func([]byte)
	// IncSaveFailures increments the save-failure metric counter.
	IncSaveFailures func()
}

// Store manages the WAL file, save channels, standby flag, and replication
// token on behalf of the registry Server. It runs saveLoop and replicaPushLoop
// as background goroutines started by Start.
type Store struct {
	wal  *WAL
	cbs  StoreCallbacks
	done <-chan struct{}

	mu        sync.RWMutex
	standby   bool
	replToken string

	saveCh          chan struct{}
	saveDone        chan struct{}
	replicaPushCh   chan struct{}
	replicaPushDone chan struct{}
}

// NewStore creates a Store. The WAL is opened at walPath (empty = no WAL).
// done is the server shutdown channel; callbacks wire the server-specific
// persistence and replication operations.
func NewStore(walPath string, done <-chan struct{}, cbs StoreCallbacks) (*Store, error) {
	w, err := NewWAL(walPath)
	if err != nil {
		return nil, err
	}
	return &Store{
		wal:             w,
		cbs:             cbs,
		done:            done,
		saveCh:          make(chan struct{}, 1),
		saveDone:        make(chan struct{}),
		replicaPushCh:   make(chan struct{}, 1),
		replicaPushDone: make(chan struct{}),
	}, nil
}

// WAL returns the underlying WAL file. Nil if no persistence is configured.
func (st *Store) WAL() *WAL { return st.wal }

// SaveCh returns the save signal channel (write to trigger a debounced save).
func (st *Store) SaveCh() chan struct{} { return st.saveCh }

// SaveDone returns the channel closed when saveLoop exits.
func (st *Store) SaveDone() <-chan struct{} { return st.saveDone }

// ReplicaPushCh returns the replica-push signal channel.
func (st *Store) ReplicaPushCh() chan struct{} { return st.replicaPushCh }

// ReplicaPushDone returns the channel closed when replicaPushLoop exits.
func (st *Store) ReplicaPushDone() <-chan struct{} { return st.replicaPushDone }

// TriggerSave signals both the save loop and replica-push loop.
func (st *Store) TriggerSave() {
	select {
	case st.saveCh <- struct{}{}:
	default:
	}
	select {
	case st.replicaPushCh <- struct{}{}:
	default:
	}
}

// TriggerSnapshot immediately runs a full snapshot flush. Returns nil if
// no storePath is configured (i.e. WAL is nil).
func (st *Store) TriggerSnapshot() error {
	if st.wal == nil {
		return nil // no persistence configured
	}
	return st.cbs.FlushSave()
}

// SetStandby configures standby mode. In standby mode the server rejects
// writes and instead receives snapshots from a primary.
func (st *Store) SetStandby(v bool) {
	st.mu.Lock()
	st.standby = v
	st.mu.Unlock()
}

// IsStandby returns true if standby mode is active.
func (st *Store) IsStandby() bool {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.standby
}

// SetReplicationToken sets the token required for subscribe_replication.
func (st *Store) SetReplicationToken(token string) {
	st.mu.Lock()
	st.replToken = token
	st.mu.Unlock()
}

// ReplicationToken returns the current replication token.
func (st *Store) ReplicationToken() string {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.replToken
}

// Start launches saveLoop and replicaPushLoop as goroutines. It must be
// called exactly once after NewStore.
func (st *Store) Start() {
	go st.saveLoop()
	go st.replicaPushLoop()
}

// Close closes the underlying WAL file. The caller must wait for saveLoop and
// replicaPushLoop to exit (via SaveDone / ReplicaPushDone) before calling Close.
func (st *Store) Close() error {
	return st.wal.Close()
}

// saveLoop runs in the background and coalesces save signals. It flushes
// state to disk at most once per saveLoopInterval, preventing serialization
// storms when many mutations happen in quick succession.
func (st *Store) saveLoop() {
	defer close(st.saveDone)
	ticker := time.NewTicker(saveLoopInterval)
	defer ticker.Stop()
	dirty := false
	for {
		select {
		case <-st.saveCh:
			dirty = true
		case <-ticker.C:
			if dirty {
				if err := st.cbs.FlushSave(); err != nil {
					if st.cbs.IncSaveFailures != nil {
						st.cbs.IncSaveFailures()
					}
					slog.Error("periodic save failed (will retry next tick)", "err", err)
				} else {
					dirty = false
				}
			}
		case <-st.done:
			// Drain pending save signal
			select {
			case <-st.saveCh:
				dirty = true
			default:
			}
			if dirty {
				if err := st.cbs.FlushSave(); err != nil {
					if st.cbs.IncSaveFailures != nil {
						st.cbs.IncSaveFailures()
					}
					slog.Error("final save failed", "err", err)
				}
			}
			return
		}
	}
}

// replicaPushLoop runs in the background and coalesces replica push
// signals. It rebuilds + pushes the replication snapshot at most once per
// replicaPushInterval. Decoupled from disk save so replicas stay current
// regardless of how aggressive operators set saveLoopInterval.
func (st *Store) replicaPushLoop() {
	defer close(st.replicaPushDone)
	ticker := time.NewTicker(replicaPushInterval)
	defer ticker.Stop()
	dirty := false
	for {
		select {
		case <-st.replicaPushCh:
			dirty = true
		case <-ticker.C:
			if dirty {
				if data := st.cbs.SnapshotJSON(); data != nil {
					st.cbs.Push(data)
				}
				dirty = false
			}
		case <-st.done:
			// Drain on shutdown so the last mutation reaches replicas.
			select {
			case <-st.replicaPushCh:
				dirty = true
			default:
			}
			if dirty {
				if data := st.cbs.SnapshotJSON(); data != nil {
					st.cbs.Push(data)
				}
			}
			return
		}
	}
}

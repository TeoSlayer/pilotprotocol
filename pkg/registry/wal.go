package registry

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
)

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

// Close closes the WAL file.
func (w *WAL) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}

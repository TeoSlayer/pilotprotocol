// SPDX-License-Identifier: AGPL-3.0-or-later

// Package replication provides the push-based replication manager for the
// registry server and directory-sync support types. The Manager maintains a
// set of standby subscriber connections and broadcasts snapshots/deltas to
// all of them. Directory-sync types and helpers used by the server-side
// handler are also defined here.
package replication

import (
	"encoding/json"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	walpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/wal"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

// connWriter wraps a net.Conn with a write mutex to prevent interleaved
// writes from concurrent Push() and heartbeat goroutines.
type connWriter struct {
	conn net.Conn
	wmu  sync.Mutex
}

// Manager handles push-based replication from primary to standbys.
// Standbys connect to the primary and subscribe; the primary pushes
// snapshots after every state mutation.
type Manager struct {
	mu   sync.Mutex
	subs map[net.Conn]*connWriter
}

// NewManager creates a Manager ready to accept subscribers.
func NewManager() *Manager {
	return &Manager{
		subs: make(map[net.Conn]*connWriter),
	}
}

func (m *Manager) AddSub(conn net.Conn) {
	m.mu.Lock()
	m.subs[conn] = &connWriter{conn: conn}
	total := len(m.subs)
	m.mu.Unlock()
	slog.Info("replication subscriber added", "remote", conn.RemoteAddr(), "total", total)
}

func (m *Manager) RemoveSub(conn net.Conn) {
	m.mu.Lock()
	delete(m.subs, conn)
	total := len(m.subs)
	m.mu.Unlock()
	slog.Info("replication subscriber removed", "remote", conn.RemoteAddr(), "total", total)
}

// Push sends a full snapshot to all subscribers. Failed subscribers are
// removed. Each write is serialized per-connection via connWriter.wmu.
func (m *Manager) Push(snapJSON []byte) {
	m.mu.Lock()
	if len(m.subs) == 0 {
		m.mu.Unlock()
		return
	}
	writers := make([]*connWriter, 0, len(m.subs))
	for _, cw := range m.subs {
		writers = append(writers, cw)
	}
	m.mu.Unlock()

	msg := map[string]interface{}{
		"type":     "replication_snapshot",
		"snapshot": json.RawMessage(snapJSON),
	}

	var failed []net.Conn
	for _, cw := range writers {
		cw.wmu.Lock()
		cw.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
		err := wire.WriteMessage(cw.conn, msg)
		cw.wmu.Unlock()
		if err != nil {
			slog.Warn("replication push failed", "remote", cw.conn.RemoteAddr(), "err", err)
			failed = append(failed, cw.conn)
		}
	}

	if len(failed) > 0 {
		m.mu.Lock()
		for _, c := range failed {
			delete(m.subs, c)
			c.Close() //nolint:errcheck
		}
		m.mu.Unlock()
	}
}

// PushDelta sends delta entries to all subscribers. This is much smaller
// than a full snapshot. Standbys that fall behind the delta window will be
// sent a full snapshot on the next Push().
func (m *Manager) PushDelta(entries []walpkg.DeltaEntry, seqNo uint64) {
	m.mu.Lock()
	if len(m.subs) == 0 {
		m.mu.Unlock()
		return
	}
	writers := make([]*connWriter, 0, len(m.subs))
	for _, cw := range m.subs {
		writers = append(writers, cw)
	}
	m.mu.Unlock()

	msg := map[string]interface{}{
		"type":    "replication_delta",
		"entries": entries,
		"seq_no":  seqNo,
	}

	var failed []net.Conn
	for _, cw := range writers {
		cw.wmu.Lock()
		cw.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
		err := wire.WriteMessage(cw.conn, msg)
		cw.wmu.Unlock()
		if err != nil {
			slog.Warn("replication delta push failed", "remote", cw.conn.RemoteAddr(), "err", err)
			failed = append(failed, cw.conn)
		}
	}

	if len(failed) > 0 {
		m.mu.Lock()
		for _, c := range failed {
			delete(m.subs, c)
			c.Close() //nolint:errcheck
		}
		m.mu.Unlock()
	}
}

// StartHeartbeat sends periodic heartbeat messages to all replication
// subscribers so standbys can detect primary failure within ~30s.
// It blocks until done is closed.
func (m *Manager) StartHeartbeat(done <-chan struct{}) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			m.mu.Lock()
			if len(m.subs) == 0 {
				m.mu.Unlock()
				continue
			}
			writers := make([]*connWriter, 0, len(m.subs))
			for _, cw := range m.subs {
				writers = append(writers, cw)
			}
			m.mu.Unlock()

			msg := map[string]interface{}{"type": "heartbeat"}
			var failed []net.Conn
			for _, cw := range writers {
				cw.wmu.Lock()
				cw.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
				err := wire.WriteMessage(cw.conn, msg)
				cw.wmu.Unlock()
				if err != nil {
					failed = append(failed, cw.conn)
				}
			}
			if len(failed) > 0 {
				m.mu.Lock()
				for _, c := range failed {
					delete(m.subs, c)
					c.Close() //nolint:errcheck
				}
				m.mu.Unlock()
			}
		}
	}
}

func (m *Manager) SubCount() int {
	m.mu.Lock()
	n := len(m.subs)
	m.mu.Unlock()
	return n
}

// ---------------------------------------------------------------------------
// Directory-sync types and utilities
// ---------------------------------------------------------------------------

// DirectoryEntry represents a user from an enterprise directory
// (AD, Entra ID, LDAP).
type DirectoryEntry struct {
	ExternalID  string   `json:"external_id"` // unique ID from directory (OIDC sub, email, GUID)
	DisplayName string   `json:"display_name,omitempty"`
	Email       string   `json:"email,omitempty"`
	Groups      []string `json:"groups,omitempty"`   // directory groups
	Role        string   `json:"role,omitempty"`     // desired pilot role: "owner", "admin", "member"
	Disabled    bool     `json:"disabled,omitempty"` // deprovisioned users
}

// DirectorySyncRequest is the protocol payload for directory sync.
type DirectorySyncRequest struct {
	NetworkID uint16           `json:"network_id"`
	Entries   []DirectoryEntry `json:"entries"`
	// If true, nodes whose external_id is not in the entries list will be kicked.
	RemoveUnlisted bool `json:"remove_unlisted,omitempty"`
}

// DirectorySyncResult describes what the sync operation did.
type DirectorySyncResult struct {
	Updated  int      `json:"updated"`  // roles updated
	Disabled int      `json:"disabled"` // nodes disabled (kicked)
	Mapped   int      `json:"mapped"`   // entries mapped to existing nodes
	Unmapped int      `json:"unmapped"` // entries with no matching node
	Actions  []string `json:"actions"`
}

// ParseDirectoryEntries parses the raw interface{} slice produced by
// json.Unmarshal into map[string]interface{} — entries missing external_id are dropped.
func ParseDirectoryEntries(raw []interface{}) []DirectoryEntry {
	entries := make([]DirectoryEntry, 0, len(raw))
	for _, e := range raw {
		m, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		de := DirectoryEntry{
			ExternalID:  StrField(m, "external_id"),
			DisplayName: StrField(m, "display_name"),
			Email:       StrField(m, "email"),
			Role:        StrField(m, "role"),
			Disabled:    BoolField(m, "disabled"),
		}
		if groupsRaw, ok := m["groups"].([]interface{}); ok {
			for _, g := range groupsRaw {
				if gs, ok := g.(string); ok {
					de.Groups = append(de.Groups, gs)
				}
			}
		}
		if de.ExternalID == "" {
			continue
		}
		entries = append(entries, de)
	}
	return entries
}

func StrField(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}

func BoolField(m map[string]interface{}, key string) bool {
	v, _ := m[key].(bool)
	return v
}

// NormalizeExternalID normalizes to lowercase so lookups are case-insensitive.
func NormalizeExternalID(id string) string {
	return strings.ToLower(id)
}

// ---------------------------------------------------------------------------
// Slice clone helpers (used by snapshotJSON / applySnapshot in server.go)
// ---------------------------------------------------------------------------

// CloneSliceUint16 returns a defensive copy. nil-in → nil-out.
func CloneSliceUint16(s []uint16) []uint16 {
	if s == nil {
		return nil
	}
	cp := make([]uint16, len(s))
	copy(cp, s)
	return cp
}

// CloneSliceUint32 returns a defensive copy. nil-in → nil-out.
func CloneSliceUint32(s []uint32) []uint32 {
	if s == nil {
		return nil
	}
	cp := make([]uint32, len(s))
	copy(cp, s)
	return cp
}

// CloneSliceString returns a defensive copy. nil-in → nil-out.
func CloneSliceString(s []string) []string {
	if s == nil {
		return nil
	}
	cp := make([]string, len(s))
	copy(cp, s)
	return cp
}

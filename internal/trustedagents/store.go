// SPDX-License-Identifier: AGPL-3.0-or-later

// Package trustedagents distributes a list of well-known agent pubkeys
// whose handshake requests the daemon auto-accepts. The list is a JSON
// file in the main repo at internal/trustedagents/trusted-agents.json,
// embedded into the daemon binary at build time and refreshed from
// raw.githubusercontent.com on a timer.
//
// Authenticity comes from HTTPS to GitHub plus repo write access — only
// people with commit rights to this repo can change the list. There is
// no separate signing layer.
//
// Adding a new trusted agent: edit trusted-agents.json, bump version,
// commit. Daemons in the field pick it up within the fetch interval
// (~1h) without needing an upgrade. Brand-new daemons get the list
// embedded at build time so the feature works on first boot, even
// airgapped.
package trustedagents

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/fsutil"
)

// Agent is one entry in the trusted-agents list.
type Agent struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"` // base64 Ed25519 pubkey
	AddedAt   string `json:"added_at"`   // RFC3339 timestamp
}

// List is the on-disk + on-wire format. Version is monotonic — the
// store only adopts a candidate whose version is strictly greater than
// the current one, so a stale or rolled-back fetch can't downgrade
// the active list.
type List struct {
	Version  int     `json:"version"`
	IssuedAt string  `json:"issued_at"`
	Agents   []Agent `json:"agents"`
}

// Store holds the highest-version List seen so far and the lookup set
// of trusted agent pubkeys. All accessors are safe for concurrent use.
type Store struct {
	mu        sync.RWMutex
	list      List
	pubkeySet map[string]string // base64 pubkey -> agent name
	cachePath string
}

// NewStore loads the embedded list, then upgrades to a higher-version
// cached list at cachePath if one exists. The embedded list is the
// floor — a corrupt or missing cache never reduces the set of trusted
// agents below the embedded baseline.
//
// cachePath may be "" to disable on-disk caching.
func NewStore(cachePath string) (*Store, error) {
	embedded, err := decode(embeddedList)
	if err != nil {
		return nil, fmt.Errorf("trustedagents: embedded list malformed: %w", err)
	}

	s := &Store{cachePath: cachePath}
	s.adopt(embedded)

	if cachePath != "" {
		if cached, ok := loadCache(cachePath); ok && cached.Version > s.list.Version {
			s.adopt(cached)
		}
	}

	return s, nil
}

// IsTrusted reports whether the given base64 Ed25519 pubkey belongs to
// a trusted agent in the current list.
func (s *Store) IsTrusted(pubkeyB64 string) (string, bool) {
	if pubkeyB64 == "" {
		return "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	name, ok := s.pubkeySet[pubkeyB64]
	return name, ok
}

// Snapshot returns a copy of the current list.
func (s *Store) Snapshot() List {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return List{
		Version:  s.list.Version,
		IssuedAt: s.list.IssuedAt,
		Agents:   append([]Agent(nil), s.list.Agents...),
	}
}

// Version returns the version of the currently-active list.
func (s *Store) Version() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.list.Version
}

// TryUpdate adopts a candidate list if its version is strictly greater
// than the current. Returns true if the store was updated. The
// candidate is persisted to cachePath on success.
func (s *Store) TryUpdate(rawJSON []byte) (bool, error) {
	cand, err := decode(rawJSON)
	if err != nil {
		return false, err
	}

	s.mu.Lock()
	if cand.Version <= s.list.Version {
		s.mu.Unlock()
		return false, nil
	}
	s.adoptLocked(cand)
	cachePath := s.cachePath
	s.mu.Unlock()

	if cachePath != "" {
		writeCache(cachePath, rawJSON)
	}
	return true, nil
}

func (s *Store) adopt(l List) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.adoptLocked(l)
}

func (s *Store) adoptLocked(l List) {
	s.list = l
	set := make(map[string]string, len(l.Agents))
	for _, a := range l.Agents {
		if a.PublicKey == "" {
			continue
		}
		set[a.PublicKey] = a.Name
	}
	s.pubkeySet = set
}

// decode parses raw JSON into a List with light schema validation.
func decode(raw []byte) (List, error) {
	var l List
	if err := json.Unmarshal(raw, &l); err != nil {
		return List{}, fmt.Errorf("decode list: %w", err)
	}
	if l.Version < 1 {
		return List{}, fmt.Errorf("version must be >= 1, got %d", l.Version)
	}
	if _, err := time.Parse(time.RFC3339, l.IssuedAt); err != nil {
		return List{}, fmt.Errorf("issued_at not RFC3339: %w", err)
	}
	return l, nil
}

func loadCache(cachePath string) (List, bool) {
	raw, err := os.ReadFile(cachePath)
	if err != nil {
		return List{}, false
	}
	l, err := decode(raw)
	if err != nil {
		return List{}, false
	}
	return l, true
}

func writeCache(cachePath string, raw []byte) {
	dir := filepath.Dir(cachePath)
	_ = os.MkdirAll(dir, 0700)
	_ = fsutil.AtomicWrite(cachePath, raw)
}

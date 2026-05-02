// SPDX-License-Identifier: AGPL-3.0-or-later

package trustedagents

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// List is the on-disk + on-wire format of the signed trusted-agents file.
// Version is monotonic — daemons reject any candidate whose version is
// less than or equal to the highest already-verified one (rollback
// protection).
type List struct {
	Version  int     `json:"version"`
	IssuedAt string  `json:"issued_at"`
	Agents   []Agent `json:"agents"`
}

// Store holds the highest-version verified List and the lookup set of
// trusted agent pubkeys. All accessors are safe for concurrent use.
type Store struct {
	mu        sync.RWMutex
	list      List
	pubkeySet map[string]string // base64 pubkey -> agent name
	cachePath string
}

// NewStore loads the embedded list (verified against SignerPublicKey),
// then upgrades to a higher-version cached list at cachePath if one
// exists and verifies. The embedded list is the floor — a corrupt or
// missing cache never reduces the set of trusted agents below the
// embedded baseline.
//
// cachePath may be "" to disable on-disk caching (useful in tests).
func NewStore(cachePath string) (*Store, error) {
	signerPub, err := base64.StdEncoding.DecodeString(SignerPublicKey)
	if err != nil || len(signerPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trustedagents: bad SignerPublicKey constant")
	}

	embedded, err := parseAndVerify(embeddedList, embeddedSig, signerPub)
	if err != nil {
		return nil, fmt.Errorf("trustedagents: embedded blob failed verification: %w", err)
	}

	s := &Store{cachePath: cachePath}
	s.adopt(embedded)

	if cachePath != "" {
		if cached, ok := loadCache(cachePath, signerPub); ok && cached.Version > s.list.Version {
			s.adopt(cached)
		}
	}

	return s, nil
}

// IsTrusted reports whether the given base64-encoded Ed25519 pubkey
// belongs to a trusted agent in the current list.
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
	out := List{
		Version:  s.list.Version,
		IssuedAt: s.list.IssuedAt,
		Agents:   append([]Agent(nil), s.list.Agents...),
	}
	return out
}

// Version returns the version of the currently-active list.
func (s *Store) Version() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.list.Version
}

// TryUpdate verifies a candidate (raw JSON + base64 sig) and adopts it if
// its version is strictly greater than the current. Returns true if the
// store was updated. Used by the fetcher when GitHub returns a fresher
// list. The candidate is persisted to cachePath atomically on success.
func (s *Store) TryUpdate(rawJSON, sigB64 []byte) (bool, error) {
	signerPub, err := base64.StdEncoding.DecodeString(SignerPublicKey)
	if err != nil {
		return false, err
	}
	cand, err := parseAndVerify(rawJSON, sigB64, signerPub)
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
		writeCache(cachePath, rawJSON, sigB64)
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

// parseAndVerify validates the signature with signerPub and unmarshals
// the JSON payload. Returns the parsed List on success.
func parseAndVerify(raw, sigB64 []byte, signerPub ed25519.PublicKey) (List, error) {
	sigStr := strings.TrimSpace(string(sigB64))
	sig, err := base64.StdEncoding.DecodeString(sigStr)
	if err != nil {
		return List{}, fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(signerPub, raw, sig) {
		return List{}, fmt.Errorf("signature verification failed")
	}
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

// loadCache reads {cachePath} and {cachePath}.sig and returns the parsed
// List if both exist and verify; otherwise returns ok=false silently.
func loadCache(cachePath string, signerPub ed25519.PublicKey) (List, bool) {
	raw, err := os.ReadFile(cachePath)
	if err != nil {
		return List{}, false
	}
	sig, err := os.ReadFile(cachePath + ".sig")
	if err != nil {
		return List{}, false
	}
	l, err := parseAndVerify(raw, sig, signerPub)
	if err != nil {
		return List{}, false
	}
	return l, true
}

func writeCache(cachePath string, raw, sig []byte) {
	dir := filepath.Dir(cachePath)
	_ = os.MkdirAll(dir, 0700)
	_ = fsutil.AtomicWrite(cachePath, raw)
	_ = fsutil.AtomicWrite(cachePath+".sig", sig)
}

// SPDX-License-Identifier: AGPL-3.0-or-later

// Package trustedagents holds a list of node IDs whose handshake
// requests the daemon auto-accepts (e.g. list-agents and other service
// agents that need to talk to every node without per-node manual
// approval).
//
// The list is plain JSON in this directory, embedded into the binary at
// build time and refreshed hourly from raw.githubusercontent.com.
// Authenticity comes from HTTPS to GitHub plus repo write access — the
// daemon does no separate signature check.
//
// Adding an agent: edit trusted-agents.json, commit. Daemons in the
// field pick it up within ~1h. Brand-new daemons get the embedded copy
// from the binary, so the feature works on first boot even airgapped.
package trustedagents

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const (
	defaultURL    = "https://raw.githubusercontent.com/TeoSlayer/pilotprotocol/main/internal/trustedagents/trusted-agents.json"
	fetchInterval = 1 * time.Hour
)

// Agent is one entry in the trusted-agents list. Match is by NodeID.
// Name is metadata for logs and `pilotctl trusted list`.
type Agent struct {
	Name   string `json:"name"`
	NodeID uint32 `json:"node_id"`
}

//go:embed trusted-agents.json
var embeddedJSON []byte

var (
	mu     sync.RWMutex
	byNode map[uint32]string // node_id -> name
	all    []Agent
)

func init() {
	if err := load(embeddedJSON); err != nil {
		// CI guards this via TestEmbeddedListLoads; if it ever fires in
		// production, an empty list (zero auto-accepts) is the safe default.
		slog.Error("trustedagents: embedded list malformed", "err", err)
		mu.Lock()
		byNode = map[uint32]string{}
		mu.Unlock()
	}
}

// IsTrusted reports whether nodeID is in the trusted-agents list. The
// caller MUST verify the (node_id, public_key) binding at the registry
// before acting on a true result — this package only checks the list.
func IsTrusted(nodeID uint32) (string, bool) {
	mu.RLock()
	defer mu.RUnlock()
	name, ok := byNode[nodeID]
	return name, ok
}

// SetForTest replaces the active list with agents and returns a restore
// function that reloads the embedded list. Test-only — never call from
// production code.
func SetForTest(agents []Agent) (restore func()) {
	idx := make(map[uint32]string, len(agents))
	for _, a := range agents {
		if a.NodeID == 0 {
			continue
		}
		idx[a.NodeID] = a.Name
	}
	mu.Lock()
	prevByNode, prevAll := byNode, all
	byNode = idx
	all = append([]Agent(nil), agents...)
	mu.Unlock()
	return func() {
		mu.Lock()
		byNode = prevByNode
		all = prevAll
		mu.Unlock()
	}
}

// All returns a copy of the current list. Used by `pilotctl trusted list`.
func All() []Agent {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Agent, len(all))
	copy(out, all)
	return out
}

// Run polls the canonical URL on a timer, replacing the active list
// whenever a new one is fetched. Blocks until ctx is cancelled. The
// first fetch is delayed 0–30s so a fleet rebooting at the same time
// doesn't thunder the URL.
func Run(ctx context.Context) {
	client := &http.Client{Timeout: 30 * time.Second}
	timer := time.NewTimer(jitter(30 * time.Second))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := fetchOnce(ctx, client); err != nil {
			slog.Warn("trustedagents fetch failed", "err", err)
		}
		timer.Reset(fetchInterval + jitter(fetchInterval/10))
	}
}

func fetchOnce(ctx context.Context, client *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, "GET", defaultURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "pilot-daemon/trustedagents")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return err
	}
	if err := load(body); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	mu.RLock()
	n := len(all)
	mu.RUnlock()
	slog.Info("trustedagents list fetched", "agents", n)
	return nil
}

// load parses raw JSON and atomically replaces the active list. Safe to
// call from any goroutine.
func load(raw []byte) error {
	var doc struct {
		Agents []Agent `json:"agents"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	idx := make(map[uint32]string, len(doc.Agents))
	for _, a := range doc.Agents {
		if a.NodeID == 0 {
			continue // 0 is reserved / would silently match unset fields
		}
		idx[a.NodeID] = a.Name
	}
	mu.Lock()
	byNode = idx
	all = doc.Agents
	mu.Unlock()
	return nil
}

func jitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return max / 2
	}
	return time.Duration(n.Int64())
}

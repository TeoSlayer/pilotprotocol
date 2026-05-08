// SPDX-License-Identifier: AGPL-3.0-or-later

// Package trustedagents holds the daemon-side service that periodically
// refreshes the trusted-agents allowlist from GitHub. The data layer
// (embedded JSON, Agent type, IsTrusted, All) lives in
// internal/trustedagents so the CLI can read the list without pulling
// in an L11 plugin import.
package trustedagents

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"time"

	internaltrusted "github.com/TeoSlayer/pilotprotocol/internal/trustedagents"
)

const (
	defaultURL    = "https://raw.githubusercontent.com/TeoSlayer/pilotprotocol/main/internal/trustedagents/trusted-agents.json"
	fetchInterval = 1 * time.Hour
)

// Agent is re-exported for source compatibility. New code should import
// internal/trustedagents.Agent directly.
type Agent = internaltrusted.Agent

// IsTrusted is re-exported for source compatibility. New code should
// import internal/trustedagents.IsTrusted directly.
func IsTrusted(nodeID uint32) (string, bool) { return internaltrusted.IsTrusted(nodeID) }

// All is re-exported for source compatibility.
func All() []Agent { return internaltrusted.All() }

// SetForTest is re-exported for source compatibility.
func SetForTest(agents []Agent) (restore func()) { return internaltrusted.SetForTest(agents) }

// fetchMu serialises HTTP refreshers when multiple plugin services
// happen to share a process (e.g. tests).
var fetchMu sync.Mutex

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
	fetchMu.Lock()
	defer fetchMu.Unlock()
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
	if err := internaltrusted.Load(body); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	slog.Info("trustedagents list fetched", "agents", len(internaltrusted.All()))
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

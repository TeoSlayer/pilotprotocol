// SPDX-License-Identifier: AGPL-3.0-or-later

package trustedagents

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"time"
)

// DefaultURL is the canonical HTTPS source for the list.
const DefaultURL = "https://raw.githubusercontent.com/TeoSlayer/pilotprotocol/main/internal/trustedagents/trusted-agents.json"

// DefaultFetchInterval is how often the daemon polls the URL for a fresher list.
const DefaultFetchInterval = 1 * time.Hour

// FetcherConfig configures the background poll loop.
type FetcherConfig struct {
	URL      string        // override default URL
	Interval time.Duration // poll interval (0 = DefaultFetchInterval)
	Client   *http.Client  // override default client
}

// Run blocks polling cfg.URL on cfg.Interval until ctx is cancelled,
// updating store with any newer-version list. The first fetch happens
// after a short randomized delay (0–30s) so a fleet rebooting at the
// same time doesn't thunder the URL.
func Run(ctx context.Context, store *Store, cfg FetcherConfig) {
	if cfg.URL == "" {
		cfg.URL = DefaultURL
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultFetchInterval
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 30 * time.Second}
	}

	timer := time.NewTimer(randDuration(30 * time.Second))
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := fetchOnce(ctx, store, cfg); err != nil {
			slog.Warn("trusted-agents fetch failed", "url", cfg.URL, "err", err)
		}
		timer.Reset(cfg.Interval + randDuration(cfg.Interval/10))
	}
}

func fetchOnce(ctx context.Context, store *Store, cfg FetcherConfig) error {
	req, err := http.NewRequestWithContext(ctx, "GET", cfg.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "pilot-daemon/trusted-agents")
	resp, err := cfg.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	const maxBody = 1 << 20 // 1 MiB cap on a config blob
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}

	updated, err := store.TryUpdate(body)
	if err != nil {
		return fmt.Errorf("update store: %w", err)
	}
	if updated {
		snap := store.Snapshot()
		slog.Info("trusted-agents list updated", "version", snap.Version, "agents", len(snap.Agents))
	}
	return nil
}

func randDuration(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return max / 2
	}
	return time.Duration(n.Int64())
}

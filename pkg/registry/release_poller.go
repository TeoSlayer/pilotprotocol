package registry

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

// ReleaseBanner is the public-safe snapshot of the latest GitHub release.
// Surfaced on the dashboard so users see why peers may be briefly unreachable
// while the fleet upgrades.
type ReleaseBanner struct {
	Version     string `json:"version"`
	PublishedAt int64  `json:"published_at"`
}

// releasePoller periodically queries the GitHub releases API and caches the
// most recent non-draft, non-prerelease tag.
type releasePoller struct {
	repo     string
	window   time.Duration
	interval time.Duration
	client   *http.Client
	latest   atomic.Pointer[ReleaseBanner]
}

func newReleasePoller(repo string) *releasePoller {
	return &releasePoller{
		repo:     repo,
		window:   36 * time.Hour,
		interval: 30 * time.Minute,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *releasePoller) run(done <-chan struct{}) {
	p.fetch()
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			p.fetch()
		}
	}
}

func (p *releasePoller) fetch() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	url := "https://api.github.com/repos/" + p.repo + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := p.client.Do(req)
	if err != nil {
		slog.Debug("release poll failed", "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		slog.Debug("release poll bad status", "status", resp.StatusCode)
		return
	}
	var body struct {
		TagName     string    `json:"tag_name"`
		PublishedAt time.Time `json:"published_at"`
		Draft       bool      `json:"draft"`
		Prerelease  bool      `json:"prerelease"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return
	}
	if body.Draft || body.Prerelease || body.TagName == "" {
		return
	}
	p.latest.Store(&ReleaseBanner{
		Version:     body.TagName,
		PublishedAt: body.PublishedAt.Unix(),
	})
}

// current returns the banner if the last release is still within the window.
func (p *releasePoller) current() *ReleaseBanner {
	b := p.latest.Load()
	if b == nil {
		return nil
	}
	if time.Since(time.Unix(b.PublishedAt, 0)) > p.window {
		return nil
	}
	return b
}

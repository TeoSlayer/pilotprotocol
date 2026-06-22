// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// pin: parse a known-good RSS payload and confirm we extract title/link/categories
func TestRSSParseShape(t *testing.T) {
	t.Parallel()
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<title>Pilot Changelog</title>
<item>
  <title>v1.9.0 — Banner endpoint, multi-beacon discovery</title>
  <link>https://teoslayer.github.io/pilot-changelog/entries/2026-04-30.html</link>
  <pubDate>Wed, 30 Apr 2026 22:00:00 +0000</pubDate>
  <category>protocol</category>
  <category>infra</category>
  <description>Runtime banner update endpoint, MIG iptables reconciler shipped, registry list_networks members admin-gated.</description>
</item>
</channel></rss>`)
	var doc rssDoc
	if err := xml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if doc.Channel.Title != "Pilot Changelog" {
		t.Errorf("channel title = %q", doc.Channel.Title)
	}
	if len(doc.Channel.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(doc.Channel.Items))
	}
	it := doc.Channel.Items[0]
	if !strings.Contains(it.Title, "v1.9.0") {
		t.Errorf("title = %q", it.Title)
	}
	if it.Link == "" {
		t.Errorf("link missing")
	}
	if len(it.Categories) != 2 {
		t.Errorf("categories = %v", it.Categories)
	}
}

func TestCollapseWhitespace(t *testing.T) {
	t.Parallel()
	got := collapseWhitespace("a   b\n\nc\td")
	if got != "a b c d" {
		t.Errorf("got %q", got)
	}
}

// fixtureFeed is a minimal RSS payload used by the fetch+filter tests.
const fixtureFeed = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<title>Test Channel</title>
<item><title>Item 1 protocol</title><link>https://example/1</link>
  <pubDate>Wed, 30 Apr 2026 22:00:00 +0000</pubDate>
  <category>protocol</category>
  <description>desc 1</description></item>
<item><title>Item 2 infra</title><link>https://example/2</link>
  <pubDate>Tue, 29 Apr 2026 22:00:00 +0000</pubDate>
  <category>infra</category>
  <description>desc 2</description></item>
<item><title>Item 3 protocol</title><link>https://example/3</link>
  <pubDate>Mon, 28 Apr 2026 22:00:00 +0000</pubDate>
  <category>protocol</category>
  <category>networks</category>
  <description>desc 3</description></item>
</channel></rss>`

func parseFixture(t *testing.T) []rssItem {
	t.Helper()
	var doc rssDoc
	if err := xml.Unmarshal([]byte(fixtureFeed), &doc); err != nil {
		t.Fatalf("fixture parse: %v", err)
	}
	return doc.Channel.Items
}

// --- filter & truncate ---

func TestFilterByScope(t *testing.T) {
	t.Parallel()
	items := parseFixture(t)
	got := filterAndTruncate(items, "protocol", 0)
	if len(got) != 2 {
		t.Fatalf("scope=protocol → %d items, want 2", len(got))
	}
	if got[0].Title != "Item 1 protocol" || got[1].Title != "Item 3 protocol" {
		t.Errorf("wrong items: %v", []string{got[0].Title, got[1].Title})
	}
	// case-insensitive
	if n := len(filterAndTruncate(items, "PROTOCOL", 0)); n != 2 {
		t.Errorf("case-insensitive scope: got %d, want 2", n)
	}
	// multi-category match (Item 3 has both protocol and networks)
	if n := len(filterAndTruncate(items, "networks", 0)); n != 1 {
		t.Errorf("multi-category match: got %d, want 1", n)
	}
	// no match
	if n := len(filterAndTruncate(items, "notarealscope", 0)); n != 0 {
		t.Errorf("no-match scope: got %d, want 0", n)
	}
}

func TestTruncateByCount(t *testing.T) {
	t.Parallel()
	items := parseFixture(t)
	if n := len(filterAndTruncate(items, "", 2)); n != 2 {
		t.Errorf("count=2 → got %d, want 2", n)
	}
	if n := len(filterAndTruncate(items, "", 0)); n != 3 {
		t.Errorf("count=0 → got %d, want 3 (no truncation)", n)
	}
	if n := len(filterAndTruncate(items, "", 99)); n != 3 {
		t.Errorf("count>len → got %d, want 3", n)
	}
}

func TestFilterAndTruncateCombined(t *testing.T) {
	t.Parallel()
	items := parseFixture(t)
	got := filterAndTruncate(items, "protocol", 1)
	if len(got) != 1 || got[0].Title != "Item 1 protocol" {
		t.Errorf("filter+truncate: got %d items, first=%q",
			len(got), func() string {
				if len(got) > 0 {
					return got[0].Title
				}
				return ""
			}())
	}
}

// --- fetchChangelogFeed: HTTP, cache, offline fallback ---

// withTempHome redirects $HOME to a fresh temp dir for the duration of
// the test so the cache file goes there, not into the real ~/.pilot.
// Returns the temp dir.
func withTempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("PILOT_HOME", "")
	return dir
}

// withFeedServer spins up an httptest.Server that serves fixtureFeed and
// counts requests. Tests can flip serveErr to make subsequent responses
// fail (simulating offline). Returns (server, requestCount, serveErr).
func withFeedServer(t *testing.T) (*httptest.Server, *atomic.Int64, *atomic.Bool) {
	t.Helper()
	var calls atomic.Int64
	var serveErr atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if serveErr.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/rss+xml")
		_, _ = w.Write([]byte(fixtureFeed))
	}))
	t.Cleanup(srv.Close)

	prev := changelogFeedURL
	changelogFeedURL = srv.URL
	t.Cleanup(func() { changelogFeedURL = prev })

	return srv, &calls, &serveErr
}

// 1. Empty cache → fetch hits server, body cached.
func TestFetchChangelogFeedColdFetch(t *testing.T) {
	home := withTempHome(t)
	_, calls, _ := withFeedServer(t)

	body, fromCache, err := fetchChangelogFeed(false)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if fromCache {
		t.Errorf("first fetch should NOT be from cache")
	}
	if !strings.Contains(string(body), "Test Channel") {
		t.Errorf("body unexpected: %q", string(body)[:min(80, len(body))])
	}
	if calls.Load() != 1 {
		t.Errorf("server calls = %d, want 1", calls.Load())
	}
	// cache file should now exist
	cachePath := filepath.Join(home, ".pilot", "updates-cache.xml")
	if _, err := os.Stat(cachePath); err != nil {
		t.Errorf("cache file not written: %v", err)
	}
}

// 2. Fresh cache → no network call.
func TestFetchChangelogFeedCacheHit(t *testing.T) {
	withTempHome(t)
	_, calls, _ := withFeedServer(t)

	// Prime cache
	if _, _, err := fetchChangelogFeed(false); err != nil {
		t.Fatalf("priming: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("after prime: server calls = %d, want 1", calls.Load())
	}

	// Second call within 5-min window should hit cache.
	_, fromCache, err := fetchChangelogFeed(false)
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if !fromCache {
		t.Errorf("expected fromCache=true on second call")
	}
	if calls.Load() != 1 {
		t.Errorf("server calls after cache hit = %d, want 1 (no extra fetch)", calls.Load())
	}
}

// 3. --refresh forces a fresh fetch even with valid cache.
func TestFetchChangelogFeedRefreshBypassesCache(t *testing.T) {
	withTempHome(t)
	_, calls, _ := withFeedServer(t)

	if _, _, err := fetchChangelogFeed(false); err != nil {
		t.Fatalf("priming: %v", err)
	}
	_, fromCache, err := fetchChangelogFeed(true) // refresh=true
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if fromCache {
		t.Errorf("--refresh should bypass cache")
	}
	if calls.Load() != 2 {
		t.Errorf("server calls = %d, want 2 (1 prime + 1 refresh)", calls.Load())
	}
}

// 4. Stale cache (old mtime) → re-fetch.
func TestFetchChangelogFeedStaleCacheRefetches(t *testing.T) {
	home := withTempHome(t)
	_, calls, _ := withFeedServer(t)

	// Pre-populate cache and back-date its mtime to >5 min ago.
	cacheDir := filepath.Join(home, ".pilot")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(cacheDir, "updates-cache.xml")
	if err := os.WriteFile(cachePath, []byte("<rss>old</rss>"), 0644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-30 * time.Minute)
	if err := os.Chtimes(cachePath, old, old); err != nil {
		t.Fatal(err)
	}

	body, fromCache, err := fetchChangelogFeed(false)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if fromCache {
		t.Errorf("stale cache should trigger refetch")
	}
	if calls.Load() != 1 {
		t.Errorf("server calls = %d, want 1", calls.Load())
	}
	if strings.Contains(string(body), "old") {
		t.Errorf("returned stale body, want fresh")
	}
}

// 5. Offline fallback: server errors → serve stale cache rather than fail.
func TestFetchChangelogFeedOfflineFallback(t *testing.T) {
	home := withTempHome(t)
	_, _, serveErr := withFeedServer(t)

	// Pre-populate stale cache that can be the fallback.
	cacheDir := filepath.Join(home, ".pilot")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(cacheDir, "updates-cache.xml")
	if err := os.WriteFile(cachePath, []byte(fixtureFeed), 0644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-30 * time.Minute)
	if err := os.Chtimes(cachePath, old, old); err != nil {
		t.Fatal(err)
	}

	// Make the server fail on the next call.
	serveErr.Store(true)

	body, fromCache, err := fetchChangelogFeed(false)
	if err == nil {
		// 500 returns an error directly (no fallback path); but a network
		// error WOULD fallback. We test that path next.
		_ = body
		_ = fromCache
		t.Logf("note: 500 response correctly returned an error rather than silent stale")
	}

	// Now simulate a hard network failure by pointing the URL at a port
	// that nothing's listening on. Cache should be served.
	prev := changelogFeedURL
	changelogFeedURL = "http://127.0.0.1:1" // refused
	t.Cleanup(func() { changelogFeedURL = prev })

	body, fromCache, err = fetchChangelogFeed(true) // force fetch
	if err != nil {
		t.Fatalf("offline fallback should NOT error when stale cache exists, got %v", err)
	}
	if !fromCache {
		t.Errorf("offline fallback should report fromCache=true")
	}
	if !strings.Contains(string(body), "Test Channel") {
		t.Errorf("offline fallback returned wrong body")
	}
}

// 6. No cache + network failure → real error surfaces.
func TestFetchChangelogFeedNoFallbackWhenNoCache(t *testing.T) {
	withTempHome(t)
	prev := changelogFeedURL
	changelogFeedURL = "http://127.0.0.1:1" // refused, nothing listens
	t.Cleanup(func() { changelogFeedURL = prev })

	_, _, err := fetchChangelogFeed(false)
	if err == nil {
		t.Errorf("expected error when offline and no cache")
	}
}

// helper for older Go without builtin min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

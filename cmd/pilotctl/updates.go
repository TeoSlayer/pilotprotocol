// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// changelogFeedURL is the canonical RSS 2.0 feed for the public Pilot
// Protocol changelog. Hosted on GitHub Pages from the pilot-changelog
// repo (per `pilot-changelog/README.md`). RSS chosen over feed.json so
// we can stay on the standard library only — no JSON-feed dep needed.
//
// Declared as a var (not const) so tests can point at httptest.Server.
var changelogFeedURL = "https://teoslayer.github.io/pilot-changelog/feed.xml"

// rssDoc is the minimal RSS 2.0 shape we care about. Only fields needed
// for the human-readable + JSON output are decoded; unknown elements are
// ignored by encoding/xml.
type rssDoc struct {
	XMLName xml.Name `xml:"rss"`
	Channel rssChan  `xml:"channel"`
}

type rssChan struct {
	Title string    `xml:"title"`
	Items []rssItem `xml:"item"`
}

type rssItem struct {
	Title       string   `xml:"title"`
	Link        string   `xml:"link"`
	GUID        string   `xml:"guid"`
	PubDate     string   `xml:"pubDate"`
	Description string   `xml:"description"`
	Categories  []string `xml:"category"`
}

// cmdUpdates fetches the changelog feed, parses it, and prints recent
// entries. Cached at ~/.pilot/updates-cache.xml for 5 minutes so a tight
// loop of `pilotctl updates` doesn't hammer the GH-Pages origin.
//
// Flags:
//
//	--count N        : how many entries to show (default 10)
//	--scope <name>   : filter by RSS <category> (e.g. protocol, networks, ops)
//	--refresh        : force a fresh fetch, bypass cache
//	(global) --json  : emit machine-readable JSON instead of human text
func cmdUpdates(args []string) {
	flags, _ := parseFlags(args)
	count := flagInt(flags, "count", 10)
	scope := strings.ToLower(flagString(flags, "scope", ""))
	refresh := flagBool(flags, "refresh")

	body, fromCache, err := fetchChangelogFeed(refresh)
	if err != nil {
		fatalCode("connection_failed", "fetch %s: %v", changelogFeedURL, err)
	}

	var doc rssDoc
	if err := xml.Unmarshal(body, &doc); err != nil {
		fatalCode("internal", "parse RSS: %v", err)
	}

	items := filterAndTruncate(doc.Channel.Items, scope, count)

	if jsonOutput {
		out := make([]map[string]interface{}, 0, len(items))
		for _, it := range items {
			out = append(out, map[string]interface{}{
				"title":       strings.TrimSpace(it.Title),
				"link":        strings.TrimSpace(it.Link),
				"guid":        strings.TrimSpace(it.GUID),
				"pub_date":    strings.TrimSpace(it.PubDate),
				"description": strings.TrimSpace(it.Description),
				"categories":  it.Categories,
			})
		}
		output(map[string]interface{}{
			"source":     changelogFeedURL,
			"from_cache": fromCache,
			"channel":    doc.Channel.Title,
			"count":      len(out),
			"updates":    out,
		})
		return
	}

	if len(items) == 0 {
		if scope != "" {
			fmt.Printf("no updates matching scope %q (try omitting --scope)\n", scope)
		} else {
			fmt.Println("no updates available")
		}
		return
	}
	if fromCache {
		fmt.Fprintf(os.Stderr, "(cached; --refresh to force re-fetch)\n")
	}
	fmt.Printf("%s — %s\n\n", doc.Channel.Title, changelogFeedURL)
	for _, it := range items {
		date := strings.TrimSpace(it.PubDate)
		// Trim RSS pubDate to YYYY-MM-DD for compactness when we can.
		if t, err := time.Parse(time.RFC1123Z, date); err == nil {
			date = t.Format("2006-01-02")
		} else if t, err := time.Parse(time.RFC1123, date); err == nil {
			date = t.Format("2006-01-02")
		}
		title := strings.TrimSpace(it.Title)
		fmt.Printf("• %s  %s\n", sAccent(date), title)
		if len(it.Categories) > 0 {
			fmt.Printf("    %s\n", sDim("["+strings.Join(it.Categories, ", ")+"]"))
		}
		if d := strings.TrimSpace(it.Description); d != "" {
			fmt.Printf("    %s\n", wrapText(collapseWhitespace(d), 100, 4))
		}
		if l := strings.TrimSpace(it.Link); l != "" {
			fmt.Printf("    %s\n", sDim(l))
		}
		fmt.Println()
	}
}

// wrapText word-wraps s at word boundaries so no line exceeds width
// columns (counting the indent), with a hanging indent: continuation
// lines are prefixed with `indent` spaces to line up under a first line
// the caller has already indented by the same amount. Words longer than
// a full line are emitted unbroken — never split mid-word.
func wrapText(s string, width, indent int) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	pad := strings.Repeat(" ", indent)
	var b strings.Builder
	lineLen := indent // caller prints the first line's indent
	for i, w := range words {
		wl := len([]rune(w))
		switch {
		case i == 0:
			b.WriteString(w)
			lineLen += wl
		case lineLen+1+wl > width:
			b.WriteString("\n")
			b.WriteString(pad)
			b.WriteString(w)
			lineLen = indent + wl
		default:
			b.WriteString(" ")
			b.WriteString(w)
			lineLen += 1 + wl
		}
	}
	return b.String()
}

// filterAndTruncate applies the --scope category filter (case-insensitive,
// match-any-category) and the --count cap to a list of feed items. Both
// arguments are inert when zero/empty, so callers can pass scope="" or
// count=0 to skip either step.
func filterAndTruncate(items []rssItem, scope string, count int) []rssItem {
	if scope != "" {
		filtered := make([]rssItem, 0, len(items))
		for _, it := range items {
			for _, c := range it.Categories {
				if strings.EqualFold(c, scope) {
					filtered = append(filtered, it)
					break
				}
			}
		}
		items = filtered
	}
	if count > 0 && len(items) > count {
		items = items[:count]
	}
	return items
}

func collapseWhitespace(s string) string {
	// Cheap inline whitespace collapse — RSS descriptions often carry HTML
	// linebreaks that print badly in a terminal. We keep one space between
	// runs of any whitespace.
	var b strings.Builder
	prevSpace := false
	for _, r := range s {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		b.WriteRune(r)
		prevSpace = false
	}
	return strings.TrimSpace(b.String())
}

// fetchChangelogFeed returns the cached feed body if it's fresh (< 5 min)
// and `refresh` is false; otherwise hits the network. Returns
// (body, fromCache, err). Cache lives at ~/.pilot/updates-cache.xml so
// repeat invocations within the cache window are zero-network.
func fetchChangelogFeed(refresh bool) ([]byte, bool, error) {
	cachePath := updatesCachePath()
	if !refresh && cachePath != "" {
		if info, err := os.Stat(cachePath); err == nil {
			if time.Since(info.ModTime()) < 5*time.Minute {
				if data, err := os.ReadFile(cachePath); err == nil && len(data) > 0 {
					return data, true, nil
				}
			}
		}
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, changelogFeedURL, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", "pilotctl/"+version)
	req.Header.Set("Accept", "application/rss+xml, application/xml, text/xml")
	resp, err := client.Do(req)
	if err != nil {
		// Fall back to stale cache rather than hard-failing the user — an
		// offline laptop should still be able to see what we knew last.
		if cachePath != "" {
			if data, ferr := os.ReadFile(cachePath); ferr == nil && len(data) > 0 {
				return data, true, nil
			}
		}
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, false, err
	}
	if cachePath != "" {
		// Best-effort cache write; swallow errors so a read-only home
		// doesn't break the command.
		tmp := cachePath + ".tmp"
		if werr := os.WriteFile(tmp, body, 0644); werr == nil {
			_ = os.Rename(tmp, cachePath)
		}
	}
	return body, false, nil
}

func updatesCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	dir := filepath.Join(home, ".pilot")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return ""
	}
	return filepath.Join(dir, "updates-cache.xml")
}

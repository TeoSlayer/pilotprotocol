// SPDX-License-Identifier: AGPL-3.0-or-later

// Package motd implements the "message of the day" mechanism: a small
// always-on banner that the daemon polls from a static JSON feed and
// mirrors to a local file, and that pilotctl prepends to every command's
// output.
//
// The split of responsibilities is deliberate:
//
//   - The daemon is the ONLY component that touches the network. A
//     background loop fetches the feed on an interval, picks the entry
//     active for the current UTC day, and writes it to the local mirror.
//   - pilotctl only ever reads the mirror — one local file read, no HTTP,
//     no IPC — so every command stays fast and works even if the daemon is
//     momentarily unreachable.
//
// Clearing is a first-class operation: an empty feed, a feed with no entry
// for today, or a feed the operator emptied on purpose all resolve to a
// cleared mirror, so the banner disappears on its own within one poll
// interval.
package motd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultFeedURL is the canonical message-of-the-day source: the raw
	// contents of feed-motd.json on the pilot-changelog repo's default
	// branch. That feed is the `scope: motd` per-scope output of the
	// changelog render pipeline — each entry's `date` is the UTC day the
	// banner is active and its `title` is the banner text. Publishing or
	// clearing a motd entry there propagates to every daemon on its next
	// poll (subject to GitHub's raw CDN cache, typically a few minutes).
	DefaultFeedURL = "https://raw.githubusercontent.com/pilot-protocol/pilot-changelog/main/feed-motd.json"

	// DefaultInterval is how often the daemon re-fetches the feed when no
	// interval is configured.
	DefaultInterval = 15 * time.Minute

	// SchemaVersion is the feed schema this build understands. A feed may
	// omit the field (treated as compatible); a feed that declares a
	// different non-zero version is rejected.
	SchemaVersion = 1

	// maxFeedBytes caps how much of the feed body we read. The feed is a
	// handful of short strings; anything larger is malformed or hostile.
	maxFeedBytes = 64 * 1024
)

// Message is a single dated message-of-the-day entry. It maps a
// pilot-changelog feed entry: the entry `date` is the UTC day the banner is
// active, and the entry `title` is the banner text.
type Message struct {
	Date string `json:"date"` // UTC calendar day, "YYYY-MM-DD"
	Text string `json:"title"`
	ID   string `json:"id,omitempty"`
}

// Feed is the on-the-wire shape served at the feed URL — the pilot-changelog
// per-scope feed (feed-motd.json). Only the fields the daemon needs are
// decoded; everything else (scope, visibility, body, excerpt, …) is ignored.
type Feed struct {
	SchemaVersion int       `json:"schema_version"`
	Entries       []Message `json:"entries"`
}

// Mirror is the local materialized "variable" the CLI reads. It holds at
// most the single message active for Date. An empty Text — or a Date that
// no longer matches today — means "no banner".
type Mirror struct {
	Date      string    `json:"date"`
	Text      string    `json:"text"`
	UpdatedAt time.Time `json:"updated_at"`
}

// DayKey returns the UTC calendar-day key ("YYYY-MM-DD") for t.
func DayKey(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}

// Fetch retrieves and parses the feed at url. The caller supplies the
// http.Client so the daemon owns the timeout policy. A non-2xx status or an
// unknown schema version is an error; an empty body is treated as an empty
// feed so operators can clear the board by committing an empty file.
func Fetch(ctx context.Context, client *http.Client, url string) (Feed, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Feed{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return Feed{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return Feed{}, fmt.Errorf("motd: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
	if err != nil {
		return Feed{}, err
	}
	return Parse(body)
}

// Parse decodes feed JSON. Empty or whitespace-only input is treated as an
// empty feed (no messages) rather than an error.
func Parse(body []byte) (Feed, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return Feed{SchemaVersion: SchemaVersion}, nil
	}
	var f Feed
	if err := json.Unmarshal(trimmed, &f); err != nil {
		return Feed{}, fmt.Errorf("motd: parse feed: %w", err)
	}
	if f.SchemaVersion != 0 && f.SchemaVersion != SchemaVersion {
		return Feed{}, fmt.Errorf("motd: unsupported schema_version %d (want %d)", f.SchemaVersion, SchemaVersion)
	}
	return f, nil
}

// SelectForToday returns the message whose Date equals the UTC day of now.
// The second result is false when no message is active (no entry for today,
// or its text is blank). When several entries share today's date the first
// non-blank one wins — operators are expected to keep one per day.
func SelectForToday(f Feed, now time.Time) (Message, bool) {
	today := DayKey(now)
	for _, m := range f.Entries {
		if strings.TrimSpace(m.Date) == today && strings.TrimSpace(m.Text) != "" {
			return m, true
		}
	}
	return Message{}, false
}

// WriteMirror atomically writes the active message to path. Passing a
// message with blank Text writes a cleared mirror (so a reader can tell
// "checked, nothing today" from "never written"). now stamps UpdatedAt.
// The parent directory is created if missing.
func WriteMirror(path string, m Message, now time.Time) error {
	mir := Mirror{Date: m.Date, Text: m.Text, UpdatedAt: now.UTC()}
	if strings.TrimSpace(m.Text) == "" {
		mir.Date = ""
		mir.Text = ""
	}
	data, err := json.MarshalIndent(mir, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if dir := filepath.Dir(path); dir != "" {
		_ = os.MkdirAll(dir, 0o700)
	}
	return atomicWrite(path, data)
}

// ReadActiveMirror reads the local mirror and returns the banner text active
// for the UTC day of now. It returns ("", false) when the file is absent,
// empty, malformed, blank, or dated for a day other than today — so a stale
// mirror (e.g. the daemon was offline across a UTC midnight) never shows
// yesterday's message. This is the only function pilotctl calls on the hot
// path: a single local file read, no network.
func ReadActiveMirror(path string, now time.Time) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	var mir Mirror
	if err := json.Unmarshal(data, &mir); err != nil {
		return "", false
	}
	text := strings.TrimSpace(mir.Text)
	if text == "" {
		return "", false
	}
	if strings.TrimSpace(mir.Date) != DayKey(now) {
		return "", false
	}
	return text, true
}

// atomicWrite writes data to path via a temp file + rename, so the target is
// never observed in a truncated state. Kept inline (rather than importing a
// helper) so this package stays a pure-stdlib leaf importable from any layer.
func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

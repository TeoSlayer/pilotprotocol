// SPDX-License-Identifier: AGPL-3.0-or-later

package motd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse time %q: %v", s, err)
	}
	return tm
}

func TestDayKeyIsUTC(t *testing.T) {
	// 2026-06-15T23:30 in UTC+2 is still 2026-06-15 in UTC, but a naive
	// local-time format would roll to the 16th. DayKey must use UTC.
	loc := time.FixedZone("UTC+2", 2*3600)
	local := time.Date(2026, 6, 15, 23, 30, 0, 0, loc) // 21:30 UTC
	if got := DayKey(local); got != "2026-06-15" {
		t.Fatalf("DayKey = %q, want 2026-06-15", got)
	}
	past := time.Date(2026, 6, 16, 1, 0, 0, 0, loc) // 23:00 UTC on the 15th
	if got := DayKey(past); got != "2026-06-15" {
		t.Fatalf("DayKey = %q, want 2026-06-15 (UTC of 16th 01:00 +2)", got)
	}
}

func TestParse(t *testing.T) {
	t.Run("empty body is an empty feed", func(t *testing.T) {
		f, err := Parse([]byte("   \n"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(f.Messages) != 0 {
			t.Fatalf("want 0 messages, got %d", len(f.Messages))
		}
	})
	t.Run("good feed", func(t *testing.T) {
		f, err := Parse([]byte(`{"schema_version":1,"messages":[{"date":"2026-06-15","text":"hi"}]}`))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(f.Messages) != 1 || f.Messages[0].Text != "hi" {
			t.Fatalf("unexpected feed: %+v", f)
		}
	})
	t.Run("unknown schema version rejected", func(t *testing.T) {
		if _, err := Parse([]byte(`{"schema_version":99,"messages":[]}`)); err == nil {
			t.Fatal("want error for schema_version 99")
		}
	})
	t.Run("missing schema version tolerated", func(t *testing.T) {
		if _, err := Parse([]byte(`{"messages":[]}`)); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("malformed json", func(t *testing.T) {
		if _, err := Parse([]byte(`{not json`)); err == nil {
			t.Fatal("want parse error")
		}
	})
}

func TestSelectForToday(t *testing.T) {
	now := mustTime(t, "2026-06-15T12:00:00Z")
	feed := Feed{SchemaVersion: 1, Messages: []Message{
		{Date: "2026-06-14", Text: "yesterday"},
		{Date: "2026-06-15", Text: "today wins"},
		{Date: "2026-06-15", Text: "second today, ignored"},
		{Date: "2026-06-16", Text: "tomorrow"},
	}}
	m, ok := SelectForToday(feed, now)
	if !ok || m.Text != "today wins" {
		t.Fatalf("SelectForToday = %q,%v; want today wins,true", m.Text, ok)
	}

	t.Run("no entry today", func(t *testing.T) {
		_, ok := SelectForToday(Feed{Messages: []Message{{Date: "2026-06-14", Text: "x"}}}, now)
		if ok {
			t.Fatal("want no active message")
		}
	})
	t.Run("blank text skipped", func(t *testing.T) {
		_, ok := SelectForToday(Feed{Messages: []Message{{Date: "2026-06-15", Text: "  "}}}, now)
		if ok {
			t.Fatal("blank text should not be active")
		}
	})
	t.Run("empty feed", func(t *testing.T) {
		if _, ok := SelectForToday(Feed{}, now); ok {
			t.Fatal("empty feed has no active message")
		}
	})
}

func TestMirrorRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "motd.json")
	now := mustTime(t, "2026-06-15T08:00:00Z")

	// Write an active message; reading on the same UTC day returns it.
	if err := WriteMirror(path, Message{Date: "2026-06-15", Text: "maintenance 22:00 UTC"}, now); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, ok := ReadActiveMirror(path, now)
	if !ok || got != "maintenance 22:00 UTC" {
		t.Fatalf("read = %q,%v; want the message,true", got, ok)
	}

	// The next UTC day must not show yesterday's message even if the mirror
	// is untouched (daemon offline across midnight).
	nextDay := mustTime(t, "2026-06-16T08:00:00Z")
	if _, ok := ReadActiveMirror(path, nextDay); ok {
		t.Fatal("stale mirror must not be active on a later UTC day")
	}
}

func TestMirrorCreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "deeper", "motd.json")
	now := mustTime(t, "2026-06-15T08:00:00Z")
	if err := WriteMirror(path, Message{Date: "2026-06-15", Text: "x"}, now); err != nil {
		t.Fatalf("write into missing dir: %v", err)
	}
	if _, ok := ReadActiveMirror(path, now); !ok {
		t.Fatal("expected active message after writing into nested dir")
	}
}

func TestClearedMirror(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "motd.json")
	now := mustTime(t, "2026-06-15T08:00:00Z")

	// First post a message, then clear it (blank text) — the banner must
	// disappear. This is the "committing an empty motd updates the value"
	// path: SelectForToday returns a zero Message, which WriteMirror stores
	// as a cleared mirror.
	if err := WriteMirror(path, Message{Date: "2026-06-15", Text: "hello"}, now); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, ok := ReadActiveMirror(path, now); !ok {
		t.Fatal("precondition: message should be active")
	}
	if err := WriteMirror(path, Message{}, now); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, ok := ReadActiveMirror(path, now); ok {
		t.Fatal("cleared mirror must not be active")
	}
}

func TestReadActiveMirrorMissingFile(t *testing.T) {
	if _, ok := ReadActiveMirror(filepath.Join(t.TempDir(), "nope.json"), time.Now()); ok {
		t.Fatal("missing file must yield no banner")
	}
}

func TestFetch(t *testing.T) {
	now := mustTime(t, "2026-06-15T12:00:00Z")

	t.Run("serves and selects today", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"schema_version":1,"messages":[{"date":"2026-06-15","text":"served"}]}`))
		}))
		defer srv.Close()
		feed, err := Fetch(context.Background(), srv.Client(), srv.URL)
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		m, ok := SelectForToday(feed, now)
		if !ok || m.Text != "served" {
			t.Fatalf("select = %q,%v", m.Text, ok)
		}
	})

	t.Run("non-2xx is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		defer srv.Close()
		if _, err := Fetch(context.Background(), srv.Client(), srv.URL); err == nil {
			t.Fatal("want error on HTTP 500")
		}
	})

	t.Run("empty body clears", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer srv.Close()
		feed, err := Fetch(context.Background(), srv.Client(), srv.URL)
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		if _, ok := SelectForToday(feed, now); ok {
			t.Fatal("empty feed must have no active message")
		}
	})
}

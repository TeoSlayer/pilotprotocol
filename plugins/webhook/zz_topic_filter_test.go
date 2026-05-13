// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_webhook
// +build !no_webhook

package webhook

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// TestTopicSet_NormalizesEmptyAndDupes confirms topicSet drops empty
// strings and de-duplicates, so the hot-path lookup is correct regardless
// of how operators format the input list.
func TestTopicSet_NormalizesEmptyAndDupes(t *testing.T) {
	t.Parallel()
	got := topicSet([]string{"a", "", "b", "a", ""})
	want := map[string]struct{}{"a": {}, "b": {}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("topicSet got %#v want %#v", got, want)
	}
	if topicSet(nil) != nil {
		t.Fatal("nil input must produce nil map (forward-all)")
	}
	if topicSet([]string{""}) != nil {
		t.Fatal("all-empty input must produce nil map (forward-all)")
	}
}

// TestPersistTopics_RoundTrip writes via SavePersistedTopics, reads via
// LoadPersistedTopics, and asserts the on-disk format (one topic per
// line) round-trips cleanly through both directions.
func TestPersistTopics_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	if err := SavePersistedTopics([]string{"message.received", "file.received"}); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPersistedTopics()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	want := []string{"file.received", "message.received"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip got %v want %v", got, want)
	}

	// Empty save deletes the file → next load returns nil (forward-all).
	if err := SavePersistedTopics(nil); err != nil {
		t.Fatal(err)
	}
	got2, err := LoadPersistedTopics()
	if err != nil {
		t.Fatal(err)
	}
	if got2 != nil {
		t.Fatalf("after clearing, expected nil, got %v", got2)
	}
	// And the file should be gone (not just empty).
	if _, err := os.Stat(filepath.Join(dir, ".pilot", "webhook_topics")); !os.IsNotExist(err) {
		t.Fatalf("topics file should be removed after SavePersistedTopics(nil), stat err: %v", err)
	}
}

// TestPersistTopics_IgnoresCommentsAndBlankLines proves the on-disk
// format tolerates operator edits — comments and blank lines stay out
// of the in-memory set.
func TestPersistTopics_IgnoresCommentsAndBlankLines(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	path := filepath.Join(dir, ".pilot", "webhook_topics")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	body := "# top-of-file comment\nmessage.received\n\n# another comment\nfile.received\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPersistedTopics()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	want := []string{"file.received", "message.received"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

// TestService_SetTopics_PersistsAndExposes covers the operator path:
// after SetTopics, both Topics() and the on-disk file reflect the new
// allow-list; clearing returns the Service to forward-all state.
func TestService_SetTopics_PersistsAndExposes(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	s := NewService("")
	s.SetTopics([]string{"message.received", "handshake.received"})

	got := s.Topics()
	sort.Strings(got)
	want := []string{"handshake.received", "message.received"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Topics() got %v want %v", got, want)
	}
	disk, _ := LoadPersistedTopics()
	sort.Strings(disk)
	if !reflect.DeepEqual(disk, want) {
		t.Fatalf("disk got %v want %v", disk, want)
	}

	s.SetTopics(nil)
	if s.Topics() != nil {
		t.Fatal("after SetTopics(nil), Topics() should be nil (forward-all)")
	}
}

package main

import "testing"

// A rename tombstone (renamed_to set) resolves to the canonical entry, and a
// plain id resolves to itself. This is the shared resolver behind the
// install/view/call redirect.
func TestResolveRenamed(t *testing.T) {
	c := &catalogue{Apps: []catalogueEntry{
		{ID: "io.pilot.smolmachines", RenamedTo: "io.pilot.smol", Hidden: true, Publisher: "ed25519:old"},
		{ID: "io.pilot.smol", Version: "1.2.0", Publisher: "ed25519:new"},
		{ID: "io.pilot.other", Version: "1.0.0"},
	}}

	// Tombstone → canonical entry.
	canonical, entry, renamed := resolveRenamed(c, "io.pilot.smolmachines")
	if !renamed {
		t.Fatalf("expected renamed=true for the tombstone id")
	}
	if canonical != "io.pilot.smol" {
		t.Fatalf("canonical = %q, want io.pilot.smol", canonical)
	}
	if entry == nil || entry.ID != "io.pilot.smol" {
		t.Fatalf("entry = %+v, want the io.pilot.smol entry", entry)
	}

	// Plain id → itself, not flagged renamed.
	id, e2, r2 := resolveRenamed(c, "io.pilot.smol")
	if r2 || id != "io.pilot.smol" || e2 == nil || e2.ID != "io.pilot.smol" {
		t.Fatalf("plain resolve got (%q, %+v, %v), want (io.pilot.smol, io.pilot.smol-entry, false)", id, e2, r2)
	}

	// Unknown id → itself, nil entry, not renamed.
	id3, e3, r3 := resolveRenamed(c, "io.pilot.missing")
	if r3 || e3 != nil || id3 != "io.pilot.missing" {
		t.Fatalf("unknown resolve got (%q, %+v, %v), want (io.pilot.missing, nil, false)", id3, e3, r3)
	}
}

// A tombstone that points at a missing canonical id still reports the rename,
// with a nil entry — callers surface a clear error rather than chasing it.
func TestResolveRenamed_CanonicalMissing(t *testing.T) {
	c := &catalogue{Apps: []catalogueEntry{
		{ID: "io.pilot.old", RenamedTo: "io.pilot.gone"},
	}}
	canonical, entry, renamed := resolveRenamed(c, "io.pilot.old")
	if !renamed || canonical != "io.pilot.gone" || entry != nil {
		t.Fatalf("got (%q, %+v, %v), want (io.pilot.gone, nil, true)", canonical, entry, renamed)
	}
}

// Only one hop is followed: a tombstone pointing at another tombstone is a
// catalogue bug and must not loop. resolveRenamed returns the (still-tombstone)
// second entry without recursing.
func TestResolveRenamed_OneHopOnly(t *testing.T) {
	c := &catalogue{Apps: []catalogueEntry{
		{ID: "a", RenamedTo: "b"},
		{ID: "b", RenamedTo: "c"},
		{ID: "c", Version: "1.0.0"},
	}}
	canonical, entry, renamed := resolveRenamed(c, "a")
	if !renamed || canonical != "b" {
		t.Fatalf("canonical = %q (renamed=%v), want b/true — one hop only", canonical, renamed)
	}
	if entry == nil || entry.ID != "b" {
		t.Fatalf("entry = %+v, want the (tombstone) b entry, not a chased c", entry)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// --- unit tests: cmdReview (call directly, no os.Exit paths) ---

// TestReviewValidSubjectNoFlags: bare subject, no optional flags → exit 0 + confirmation.
func TestReviewValidSubjectNoFlags(t *testing.T) {
	t.Parallel()
	stdout, _, code := runCLI(t, []string{"review", "io.pilot.cosift"}, nil)
	if code != 0 {
		t.Errorf("exit=%d, want 0", code)
	}
	if !strings.Contains(stdout, "io.pilot.cosift") {
		t.Errorf("confirmation missing subject: %q", stdout)
	}
	if !strings.Contains(strings.ToLower(stdout), "thank") {
		t.Errorf("confirmation missing thank-you: %q", stdout)
	}
}

// TestReviewSubjectPilot: reserved subject "pilot" is valid.
func TestReviewSubjectPilot(t *testing.T) {
	t.Parallel()
	stdout, _, code := runCLI(t, []string{"review", "pilot"}, nil)
	if code != 0 {
		t.Errorf("exit=%d, want 0", code)
	}
	if !strings.Contains(stdout, "pilot") {
		t.Errorf("confirmation missing 'pilot': %q", stdout)
	}
}

// TestReviewWithRating: valid rating (1–5) is accepted.
func TestReviewWithRating(t *testing.T) {
	t.Parallel()
	for _, rating := range []string{"1", "3", "5"} {
		rating := rating
		t.Run("rating="+rating, func(t *testing.T) {
			t.Parallel()
			stdout, _, code := runCLI(t, []string{"review", "pilot", "--rating", rating}, nil)
			if code != 0 {
				t.Errorf("rating=%s: exit=%d, want 0", rating, code)
			}
			if !strings.Contains(stdout, "pilot") {
				t.Errorf("rating=%s: missing subject in output: %q", rating, stdout)
			}
		})
	}
}

// TestReviewWithRatingAndText: both optional flags together.
func TestReviewWithRatingAndText(t *testing.T) {
	t.Parallel()
	stdout, _, code := runCLI(t, []string{
		"review", "io.pilot.cosift",
		"--rating", "4",
		"--text", "Very useful",
	}, nil)
	if code != 0 {
		t.Errorf("exit=%d, want 0", code)
	}
	if !strings.Contains(stdout, "io.pilot.cosift") {
		t.Errorf("missing subject: %q", stdout)
	}
}

// TestReviewJSONOutput: --json wraps the result in the standard envelope.
func TestReviewJSONOutput(t *testing.T) {
	t.Parallel()
	stdout, _, code := runCLI(t, []string{
		"--json", "review", "pilot", "--rating", "5", "--text", "great",
	}, nil)
	if code != 0 {
		t.Errorf("exit=%d, want 0", code)
	}
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("json parse: %v (output: %q)", err, stdout)
	}
	if env["status"] != "ok" {
		t.Errorf("status=%v, want ok", env["status"])
	}
	data, ok := env["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("data field missing or wrong type: %v", env["data"])
	}
	if data["subject"] != "pilot" {
		t.Errorf("subject=%v, want pilot", data["subject"])
	}
	if data["submitted"] != true {
		t.Errorf("submitted=%v, want true", data["submitted"])
	}
	if rating, ok := data["rating"].(float64); !ok || rating != 5 {
		t.Errorf("rating=%v, want 5", data["rating"])
	}
	if data["text"] != "great" {
		t.Errorf("text=%v, want 'great'", data["text"])
	}
}

// --- invalid input tests (use runCLI so os.Exit is safe) ---

// TestReviewMissingSubject: no positional arg → exit non-zero with usage hint.
func TestReviewMissingSubject(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"review"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit when subject is missing")
	}
	if !strings.Contains(stderr, "subject") && !strings.Contains(stderr, "required") &&
		!strings.Contains(stderr, "usage") && !strings.Contains(stderr, "pilot") {
		t.Errorf("expected usage hint in stderr, got: %q", stderr)
	}
}

// TestReviewRatingZero: --rating 0 is out of range.
func TestReviewRatingZero(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"review", "pilot", "--rating", "0"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit for --rating 0")
	}
	if !strings.Contains(stderr, "1") || !strings.Contains(stderr, "5") {
		t.Errorf("expected range hint (1–5) in stderr, got: %q", stderr)
	}
}

// TestReviewRatingSix: --rating 6 is out of range.
func TestReviewRatingSix(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"review", "pilot", "--rating", "6"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit for --rating 6")
	}
	if !strings.Contains(stderr, "1") || !strings.Contains(stderr, "5") {
		t.Errorf("expected range hint (1–5) in stderr, got: %q", stderr)
	}
}

// TestReviewRatingNonInteger: --rating xyz is not a number.
func TestReviewRatingNonInteger(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"review", "pilot", "--rating", "xyz"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit for non-integer --rating")
	}
	if !strings.Contains(stderr, "integer") && !strings.Contains(stderr, "rating") {
		t.Errorf("expected error mentioning rating, got: %q", stderr)
	}
}

// TestReviewHelpFlag: --help exits 0 and prints usage.
func TestReviewHelpFlag(t *testing.T) {
	t.Parallel()
	stdout, stderr, code := runCLI(t, []string{"review", "--help"}, nil)
	if code != 0 {
		t.Errorf("--help should exit 0, got %d", code)
	}
	full := stdout + stderr
	if !strings.Contains(full, "review") {
		t.Errorf("help text missing 'review': %s", full)
	}
	if !strings.Contains(full, "--rating") {
		t.Errorf("help text missing --rating: %s", full)
	}
}

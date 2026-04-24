// SPDX-License-Identifier: AGPL-3.0-or-later

package registry

import (
	"testing"
)

// TestDecidePoloGate verifies the pure gate math behind the
// registry-side authorize_task_submit endpoint. Replaces the gate-math
// portion of test_task_polo_gate.sh — docker tier still covers the
// end-to-end "rejection cites polo" wire behavior, but a Go unit test
// covers every decision branch in milliseconds.
func TestDecidePoloGate(t *testing.T) {
	intp := func(n int) *int { return &n }
	cases := []struct {
		name        string
		subPolo     int
		recPolo     int
		minPolo     *int
		wantAllowed bool
	}{
		{"equal_zero_allows", 0, 0, nil, true},
		{"submitter_higher_allows", 5, 0, nil, true},
		{"submitter_lower_denies", -1, 0, nil, false},
		{"equal_nonzero_allows", 7, 7, nil, true},

		{"min_met_allows", 10, 0, intp(5), true},
		{"min_equal_allows", 5, 0, intp(5), true},
		{"min_unmet_denies", 4, 0, intp(5), false},
		{"min_zero_allows", 0, 0, intp(0), true},

		// Guarantee floor takes precedence over the receiver's own polo.
		{"min_beats_receiver_rule_allow", 20, 100, intp(10), true},
		{"min_beats_receiver_rule_deny", 5, 0, intp(10), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allowed, reason := decidePoloGate(tc.subPolo, tc.recPolo, tc.minPolo)
			if allowed != tc.wantAllowed {
				t.Fatalf("allowed=%v want=%v (sub=%d rec=%d min=%v) reason=%q",
					allowed, tc.wantAllowed, tc.subPolo, tc.recPolo, tc.minPolo, reason)
			}
			if !allowed {
				if reason == "" {
					t.Fatal("deny must return a non-empty reason")
				}
				// Privacy: reason must NOT leak numeric polo values.
				if containsDigit(reason) && tc.minPolo == nil {
					t.Fatalf("reason leaks polo numbers: %q", reason)
				}
			}
		})
	}
}

func containsDigit(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

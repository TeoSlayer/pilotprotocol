// SPDX-License-Identifier: AGPL-3.0-or-later

package validate_test

import (
	"testing"

	"github.com/pilot-protocol/pilotprotocol/internal/validate"
)

func TestEmailValid(t *testing.T) {
	t.Parallel()
	valid := []string{
		"user@example.com",
		"admin@pilot.local",
		"test+tag@sub.domain.org",
		"a@b.co",
	}
	for _, email := range valid {
		if err := validate.Email(email); err != nil {
			t.Errorf("Email(%q) = %v, want nil", email, err)
		}
	}
}

func TestEmailInvalid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input string
		want  string
	}{
		{"", "required"},
		{"noatsign", "must contain @"},
		{"@domain.com", "must contain @"},
		{"user@", "must have a domain"},
		{"user@nodot", "must contain a dot"},
		{"user @example.com", "must not contain spaces"},
		{"user@ example.com", "must not contain spaces"},
		{"user@.example.com", "must not start or end with a dot"},
		{"user@example.", "must not start or end with a dot"},
		{"a@b@c.com", "exactly one @"},
	}
	for _, tc := range cases {
		err := validate.Email(tc.input)
		if err == nil {
			t.Errorf("Email(%q) = nil, want error containing %q", tc.input, tc.want)
			continue
		}
		if got := err.Error(); !contains(got, tc.want) {
			t.Errorf("Email(%q) = %q, want error containing %q", tc.input, got, tc.want)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsAt(s, substr)
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "testing"

func TestEnvBool(t *testing.T) {
	const key = "PILOT_UPDATER_TEST_ENVBOOL"
	cases := []struct {
		val  string
		want bool
	}{
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{"Yes", true},
		{" on ", true},
		{"0", false},
		{"false", false},
		{"", false},
		{"nope", false},
	}
	for _, c := range cases {
		t.Setenv(key, c.val)
		if got := envBool(key); got != c.want {
			t.Errorf("envBool(%q) = %v, want %v", c.val, got, c.want)
		}
	}

	// Unset variable is false.
	if got := envBool("PILOT_UPDATER_DEFINITELY_UNSET_XYZ"); got {
		t.Error("envBool on unset var should be false")
	}
}

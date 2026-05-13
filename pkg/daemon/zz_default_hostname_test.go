// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"regexp"
	"testing"
)

// registryHostnameRegex mirrors pkg/registry/server/server_util.go's
// validateHostname regex. Duplicated here so the test fails loudly if
// the registry tightens the rule and our auto-generated default ever
// stops being acceptable.
var registryHostnameRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// TestDefaultHostnameForNode_FormatAndStability pins the auto-default
// shape — `pilot-<8 lowercase hex>` — and the determinism guarantee
// (same nodeID → same hostname across calls/restarts).
func TestDefaultHostnameForNode_FormatAndStability(t *testing.T) {
	t.Parallel()
	cases := []struct {
		id   uint32
		want string
	}{
		{0x00000000, "pilot-00000000"},
		{0x0000000a, "pilot-0000000a"},
		{0x3a4b5c6d, "pilot-3a4b5c6d"},
		{0xffffffff, "pilot-ffffffff"},
	}
	for _, c := range cases {
		got := defaultHostnameForNode(c.id)
		if got != c.want {
			t.Errorf("defaultHostnameForNode(%#08x) = %q; want %q", c.id, got, c.want)
		}
		// Stability: a second call with the same id returns the same
		// string. Important because daemon Start and the re-registration
		// path both compute this independently and must agree.
		again := defaultHostnameForNode(c.id)
		if again != got {
			t.Errorf("defaultHostnameForNode(%#08x) not stable: %q vs %q", c.id, got, again)
		}
	}
}

// TestDefaultHostnameForNode_MatchesRegistryRegex confirms that every
// possible auto-default would be accepted by the registry's hostname
// validator. The regex is duplicated above; if it tightens and the
// default no longer matches, this test catches it before a daemon
// hits the live "hostname rejected" code path.
func TestDefaultHostnameForNode_MatchesRegistryRegex(t *testing.T) {
	t.Parallel()
	// Sweep the boundaries + a handful of arbitrary values.
	for _, id := range []uint32{0, 1, 0xffffffff, 0xdeadbeef, 0xcafebabe, 0x12345678} {
		got := defaultHostnameForNode(id)
		if !registryHostnameRegex.MatchString(got) {
			t.Errorf("registry would reject auto-default %q for nodeID %#08x", got, id)
		}
		if len(got) > 63 {
			t.Errorf("auto-default %q exceeds 63-char registry limit", got)
		}
	}
}

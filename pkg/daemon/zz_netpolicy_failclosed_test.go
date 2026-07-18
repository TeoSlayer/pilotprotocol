// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"errors"
	"testing"
)

// TestMergeNetworkPolicies_FailClosed pins the security-critical
// invariant behind loadNetworkPolicies: a failed GetNetworkPolicy must
// NOT drop an existing restriction (which isPortAllowed would read as
// allow-all), while a successful fetch — including an empty list — is
// authoritative and does relax the policy.
func TestMergeNetworkPolicies_FailClosed(t *testing.T) {
	boom := errors.New("registry unreachable")

	t.Run("error retains prior restriction (no fail-open)", func(t *testing.T) {
		prior := map[uint16][]uint16{7: {80, 443}}
		got := mergeNetworkPolicies(prior, []netPolicyResult{{netID: 7, err: boom}})
		if p, ok := got[7]; !ok || len(p) != 2 || p[0] != 80 || p[1] != 443 {
			t.Fatalf("restricted net 7 must retain [80 443] on load error, got %v (present=%v)", p, ok)
		}
	})

	t.Run("successful empty relaxes restriction", func(t *testing.T) {
		prior := map[uint16][]uint16{7: {80}}
		got := mergeNetworkPolicies(prior, []netPolicyResult{{netID: 7, ports: nil}})
		if p := got[7]; len(p) != 0 {
			t.Fatalf("net 7 should be relaxed to no-restriction on successful empty, got %v", p)
		}
	})

	t.Run("successful update replaces prior", func(t *testing.T) {
		prior := map[uint16][]uint16{7: {80}}
		got := mergeNetworkPolicies(prior, []netPolicyResult{{netID: 7, ports: []uint16{22}}})
		if p := got[7]; len(p) != 1 || p[0] != 22 {
			t.Fatalf("net 7 should become [22], got %v", p)
		}
	})

	t.Run("error with no prior stays absent (allow-all, unchanged behavior)", func(t *testing.T) {
		got := mergeNetworkPolicies(map[uint16][]uint16{}, []netPolicyResult{{netID: 9, err: boom}})
		if _, ok := got[9]; ok {
			t.Fatalf("net 9 with no prior + load error must stay absent, got present")
		}
	})

	t.Run("mixed: one fails (retained), one succeeds (updated)", func(t *testing.T) {
		prior := map[uint16][]uint16{7: {80, 443}, 8: {22}}
		got := mergeNetworkPolicies(prior, []netPolicyResult{
			{netID: 7, err: boom},
			{netID: 8, ports: []uint16{2222}},
		})
		if p := got[7]; len(p) != 2 {
			t.Fatalf("net 7 (errored) must retain prior [80 443], got %v", p)
		}
		if p := got[8]; len(p) != 1 || p[0] != 2222 {
			t.Fatalf("net 8 (ok) must update to [2222], got %v", p)
		}
	})
}

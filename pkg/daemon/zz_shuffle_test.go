// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"fmt"
	"testing"
)

func shuffleOnce(n int) []int {
	s := make([]int, n)
	for i := range s {
		s[i] = i
	}
	cryptoShuffle(n, func(i, j int) { s[i], s[j] = s[j], s[i] })
	return s
}

func TestCryptoShuffleIsPermutation(t *testing.T) {
	const n = 32
	for iter := 0; iter < 200; iter++ {
		s := shuffleOnce(n)
		seen := make(map[int]bool, n)
		for _, v := range s {
			if v < 0 || v >= n {
				t.Fatalf("value %d out of range", v)
			}
			if seen[v] {
				t.Fatalf("duplicate value %d — not a permutation", v)
			}
			seen[v] = true
		}
		if len(seen) != n {
			t.Fatalf("expected %d distinct values, got %d", n, len(seen))
		}
	}
}

func TestCryptoShuffleIsNonDeterministic(t *testing.T) {
	const (
		n     = 16
		iters = 300
	)
	perms := make(map[string]int)
	for i := 0; i < iters; i++ {
		perms[fmt.Sprint(shuffleOnce(n))]++
	}
	if len(perms) < 2 {
		t.Fatalf("shuffle appears deterministic: %d distinct permutation(s) over %d runs", len(perms), iters)
	}
	// A working shuffle of 16 elements almost never repeats; require the
	// vast majority of runs to be unique so a near-constant output fails.
	if len(perms) < iters/2 {
		t.Fatalf("shuffle far too repetitive: only %d distinct of %d runs", len(perms), iters)
	}
}

func TestCryptoShuffleSpreadsEachElement(t *testing.T) {
	const (
		n     = 8
		iters = 4000
	)
	// counts[element][position] = how often element landed at position.
	counts := make([][]int, n)
	for i := range counts {
		counts[i] = make([]int, n)
	}
	for it := 0; it < iters; it++ {
		s := shuffleOnce(n)
		for pos, elem := range s {
			counts[elem][pos]++
		}
	}
	expected := float64(iters) / float64(n)
	for elem := 0; elem < n; elem++ {
		reached := 0
		for pos := 0; pos < n; pos++ {
			if counts[elem][pos] > 0 {
				reached++
			}
			dev := float64(counts[elem][pos]) - expected
			if dev < 0 {
				dev = -dev
			}
			if dev > expected*0.5 {
				t.Fatalf("element %d at position %d: count %d deviates too far from expected %.0f",
					elem, pos, counts[elem][pos], expected)
			}
		}
		if reached != n {
			t.Fatalf("element %d only reached %d of %d positions", elem, reached, n)
		}
	}
}

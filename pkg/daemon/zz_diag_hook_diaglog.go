// SPDX-License-Identifier: AGPL-3.0-or-later
//go:build diaglog

package daemon

import (
	"crypto/rand"
	"math/big"
	"sync/atomic"
)

var diagDropRate atomic.Uint64 // per-mille; 0..1000

// SetDiagDropRate configures the per-mille (0-1000) probabilistic drop
// rate applied at writeFrame entry. Test-only — only compiled with
// -tags diaglog. 0 disables.
func SetDiagDropRate(perMille uint64) {
	if perMille > 1000 {
		perMille = 1000
	}
	diagDropRate.Store(perMille)
}

func diagShouldDropFrame() bool {
	r := diagDropRate.Load()
	if r == 0 {
		return false
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err != nil {
		return false
	}
	return uint64(n.Int64()) < r
}

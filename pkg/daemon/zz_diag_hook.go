// SPDX-License-Identifier: AGPL-3.0-or-later
//go:build !diaglog

package daemon

// diagShouldDropFrame is the no-op stub for production builds. The
// build-tagged variant in zz_diag_hook_diaglog.go injects probabilistic
// drop for restart-recovery testing.
func diagShouldDropFrame() bool { return false }

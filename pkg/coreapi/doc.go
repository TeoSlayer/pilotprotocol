// SPDX-License-Identifier: AGPL-3.0-or-later

// Package coreapi defines the L10 plugin runtime contract.
//
// The interfaces in this package are the only surface a plugin
// (L11) ever sees of the daemon. Plugins import coreapi; the daemon
// implements coreapi; the bridge happens at lifecycle bootstrap
// (cmd/daemon/main.go registers concrete plugins against the
// daemon's coreapi implementations).
//
// See docs/architecture/01-LAYERS.md §10 for the layer's role,
// docs/architecture/03-INVARIANTS.md for the principles this
// package enforces, and docs/architecture/06-CHANGES.md §2 for
// the rationale of each interface signature.
//
// Stability contract: every exported identifier in this package is
// part of the daemon-plugin ABI. Removing or renaming any of them
// breaks every plugin. Additions are forward-compatible.
package coreapi

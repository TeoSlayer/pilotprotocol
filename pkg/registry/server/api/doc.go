// SPDX-License-Identifier: AGPL-3.0-or-later

// Package api defines the read-only view contracts that observability
// (R7 — dashboard, metrics, audit, webhook) and auth gates (R4) consume
// from the registry's R5 state stores (directory, membership, trust,
// policy, identity).
//
// This package is the contract layer for the registry-server split (the
// R10-equivalent of pkg/coreapi for the daemon). No implementations
// live here. Concrete R5 stores in their own sub-packages will satisfy
// these interfaces; consumers in R7 and R4 will hold only the interface
// types, never the writeable *Store pointers.
//
// See architecture-notes/07-REGISTRY-LAYERS.md (Critical invariants
// rule #2) and architecture-notes/08-REGISTRY-EXTRACTION.md (Tier R0.4)
// for the rationale and the full extraction roadmap.
//
// Stability contract: every exported identifier is part of the
// registry-internal layer-boundary ABI. Adding fields to the snapshot
// view structs is backward-compatible; renaming or removing them
// breaks every R7/R4 consumer in lockstep with the R5 store that
// produces the snapshot.
//
// Allowed imports: stdlib only (plus crypto/ed25519 and time when a
// view structurally needs them). No store-package imports — the
// import direction is consumer → api ← store.
package api

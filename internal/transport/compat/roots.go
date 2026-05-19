// SPDX-License-Identifier: AGPL-3.0-or-later

// Package compat is the daemon-side foundation for compat mode (WSS
// tunnel to the beacon). This file exposes the pinned root CA(s) the
// daemon uses to verify the beacon's TLS certificate.
//
// Trust model:
//
//   - The daemon binary ships with one or more Pilot Protocol root CAs
//     baked in via //go:embed. These are the only roots trusted when
//     `-tls-trust=pinned` (the default).
//   - The beacon presents a leaf cert signed by one of these roots
//     during the WSS upgrade. Standard TLS verifies the chain.
//   - With `-tls-trust=system`, callers can opt into the OS trust
//     store as a fallback (for users behind TLS-intercepting corp
//     proxies). See SPEC-compat-mode.md §"Escape hatch".
//
// During root rotation we keep both old and new roots in the embed
// set for one overlap release. Operators run `pilot-ca init-root` to
// mint a new root and commit the resulting `roots/prod-*.pem`. See
// docs/RUNBOOK-pilot-ca.md.
package compat

import (
	"crypto/x509"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strings"
)

//go:embed roots/*.pem
var rootsFS embed.FS

// PinnedRoots returns a CertPool containing every root cert embedded
// in the daemon binary. Used when -tls-trust=pinned (the default).
//
// Errors if no roots are embedded. We refuse to silently fall back to
// the system trust store — that decision must be explicit at the
// daemon CLI layer.
func PinnedRoots() (*x509.CertPool, error) {
	entries, err := fs.ReadDir(rootsFS, "roots")
	if err != nil {
		return nil, fmt.Errorf("read embedded roots: %w", err)
	}
	pool := x509.NewCertPool()
	loaded := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		body, err := rootsFS.ReadFile("roots/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("read embedded root %s: %w", e.Name(), err)
		}
		if !pool.AppendCertsFromPEM(body) {
			return nil, fmt.Errorf("parse embedded root %s: invalid PEM", e.Name())
		}
		loaded++
	}
	if loaded == 0 {
		return nil, errors.New("no embedded Pilot Protocol roots found — build is broken")
	}
	return pool, nil
}

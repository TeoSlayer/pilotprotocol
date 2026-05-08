// SPDX-License-Identifier: AGPL-3.0-or-later

// Package runtime owns the plugin-lifecycle composition root for the
// daemon binary. Holds the coreapi.ServiceRegistry, constructs the
// daemon-side adapters that satisfy plugin Deps (Streams, EventBus,
// Identity, Polo), and registers/starts/stops L11 services.
//
// Lives outside pkg/daemon (L7) so daemon stays free of pkg/coreapi
// (L10) imports — that's T7.1 in docs/architecture/04-EXTRACTION.md.
// Imports both pkg/daemon and pkg/coreapi (downward edges, allowed).
package runtime

import (
	"context"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
)

// Runtime owns the plugin-side glue for a single daemon. cmd/daemon
// constructs one, registers L11 services, then calls StartPlugins
// after Daemon.Start (so regConn etc. are wired) and StopPlugins
// before Daemon.Stop.
type Runtime struct {
	d        *daemon.Daemon
	registry *coreapi.ServiceRegistry
}

// New returns a Runtime bound to the given daemon. Safe to call
// before d.Start.
func New(d *daemon.Daemon) *Runtime {
	return &Runtime{d: d, registry: &coreapi.ServiceRegistry{}}
}

// Daemon returns the underlying daemon (test access).
func (r *Runtime) Daemon() *daemon.Daemon { return r.d }

// Register adds a service to the registry. Mirrors the old
// daemon.RegisterPlugin. Must be called before StartPlugins.
func (r *Runtime) Register(s coreapi.Service) error {
	return r.registry.Register(s)
}

// StartPlugins starts every registered service in Order order. Plugins
// receive a Deps bundle covering Streams, Identity, Events, Trust.
func (r *Runtime) StartPlugins(ctx context.Context) error {
	deps := coreapi.Deps{
		Streams:  daemonStreams{d: r.d},
		Identity: daemonIdentity{d: r.d},
		Events:   daemonEventBus{d: r.d},
		Logger:   nil,
		Trust:    asCoreapiTrust(r.d.GetTrustChecker()),
	}
	return r.registry.StartAll(ctx, deps)
}

// StopPlugins stops every started service in reverse-registration
// order. Each service has its own Stop ctx (caller-supplied here).
func (r *Runtime) StopPlugins(ctx context.Context) error {
	return r.registry.StopAll(ctx)
}

// asCoreapiTrust adapts a daemon.TrustChecker (primitives) to the
// coreapi.TrustChecker plugins expect. Structurally identical
// signatures, but Go's interface-typing requires an explicit bridge
// when the named types differ. nil → nil (no plugin → no auto-accept).
func asCoreapiTrust(t daemon.TrustChecker) coreapi.TrustChecker {
	if t == nil {
		return nil
	}
	return trustAdapter{inner: t}
}

type trustAdapter struct{ inner daemon.TrustChecker }

func (a trustAdapter) IsTrusted(nodeID uint32) (string, bool) {
	return a.inner.IsTrusted(nodeID)
}

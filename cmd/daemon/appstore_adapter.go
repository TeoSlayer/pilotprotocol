// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Inline adapter from *appstore.Service to coreapi.Service.
//
// The app-store module (separate go.mod) ships an
// integration.Adapter in its own integration/ package, but we don't
// want web4 to pull in that whole separate module — the adapter is
// 4 method shims. Duplicating them here keeps web4 self-buildable.
//
// Lockstep contract: if app-store/integration/adapter.go ever needs
// a field added to its Start translation (new coreapi.Deps field
// propagating into appstore.Deps), this file must follow.

package main

import (
	"context"

	"github.com/pilot-protocol/app-store/plugin/appstore"
	"github.com/pilot-protocol/common/coreapi"
)

type appstoreAdapter struct {
	svc *appstore.Service
}

func (a *appstoreAdapter) Name() string { return a.svc.Name() }
func (a *appstoreAdapter) Order() int   { return a.svc.Order() }
func (a *appstoreAdapter) Start(ctx context.Context, deps coreapi.Deps) error {
	return a.svc.Start(ctx, appstore.Deps{
		Streams:  deps.Streams,
		Identity: deps.Identity,
		Resolver: deps.Resolver,
		Events:   deps.Events,
		Logger:   deps.Logger,
		Trust:    deps.Trust,
	})
}
func (a *appstoreAdapter) Stop(ctx context.Context) error { return a.svc.Stop(ctx) }

// Compile-time check — the build breaks loudly if coreapi.Service ever
// drifts away from this shape.
var _ coreapi.Service = (*appstoreAdapter)(nil)

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
	"encoding/json"
	"time"

	"github.com/pilot-protocol/app-store/plugin/appstore"
	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/pilotprotocol/pkg/telemetry"
)

type appstoreAdapter struct {
	svc          *appstore.Service
	telemetryURL string
	identityPath string
	getNodeID    func() int64 // called at emit time, after daemon has registered
}

// telemetryEmitter wraps the consent-gated telemetry client to satisfy
// the appstore.TelemetryEmitter interface. Events are sent as
// "app_usage" kind with the supervisor-provided fields as payload.
// Best-effort: send errors are logged but never block the caller.
type telemetryEmitter struct {
	client    *telemetry.Client
	getNodeID func() int64 // called lazily; valid after daemon has registered
}

func (e *telemetryEmitter) Emit(ev appstore.TelemetryEvent) {
	if e == nil || e.client == nil {
		return
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return
	}
	var nodeID int64
	if e.getNodeID != nil {
		nodeID = e.getNodeID()
	}
	_ = e.client.Send(telemetry.Event{
		Kind:    "app_usage",
		TS:      time.Now().UTC().Format(time.RFC3339),
		NodeID:  nodeID,
		Payload: payload,
	})
}

func (a *appstoreAdapter) Name() string { return a.svc.Name() }
func (a *appstoreAdapter) Order() int   { return a.svc.Order() }
func (a *appstoreAdapter) Start(ctx context.Context, deps coreapi.Deps) error {
	// Build a consent-gated telemetry client for app-usage events.
	// When the URL is empty or identity is absent the client is a
	// permanent no-op — the emitter never sends anything.
	client := telemetry.NewClientFromIdentity(a.telemetryURL, a.identityPath, 0)
	emitter := &telemetryEmitter{client: client, getNodeID: a.getNodeID}

	return a.svc.Start(ctx, appstore.Deps{
		Streams:   deps.Streams,
		Identity:  deps.Identity,
		Resolver:  deps.Resolver,
		Events:    deps.Events,
		Logger:    deps.Logger,
		Trust:     deps.Trust,
		Telemetry: emitter,
	})
}
func (a *appstoreAdapter) Stop(ctx context.Context) error { return a.svc.Stop(ctx) }

// Compile-time check — the build breaks loudly if coreapi.Service ever
// drifts away from this shape.
var _ coreapi.Service = (*appstoreAdapter)(nil)

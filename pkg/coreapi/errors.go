// SPDX-License-Identifier: AGPL-3.0-or-later

package coreapi

import "errors"

// Sentinel errors returned by the L10 surface.
var (
	// ErrRegistryStarted is returned by ServiceRegistry.Register and
	// ServiceRegistry.StartAll when StartAll has already been called.
	// Plugins must register before bootstrap.
	ErrRegistryStarted = errors.New("coreapi: service registry already started")

	// ErrServiceNotReady indicates a Service.Start call was made on a
	// dependency that itself hasn't completed Start. Surface only —
	// Service implementations shouldn't return this; the registry will.
	ErrServiceNotReady = errors.New("coreapi: dependency service not ready")

	// ErrPeerNotFound is the canonical "directory has no record" error
	// from PeerResolver. Plugins should match on errors.Is.
	ErrPeerNotFound = errors.New("coreapi: peer not found")
)

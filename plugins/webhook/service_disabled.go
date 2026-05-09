// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build no_webhook
// +build no_webhook

// Stub — provides a no-op Service when this plugin is disabled at
// build time via -tags=no_webhook. The daemon registers the no-op so
// plugin start/stop are clean; no bus subscription is created and
// no HTTP delivery happens.

package webhook

import (
	"context"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

// Stats mirrors the real Stats so cmd/daemon's webhookManagerAdapter
// (which reads .Dropped and .CircuitSkips) compiles unchanged when
// the plugin is disabled.
type Stats struct {
	Dropped      uint64
	CircuitSkips uint64
}

// Service is a no-op replacement for the real plugin Service.
type Service struct{}

// NewService returns a disabled webhook stub. Same signature as the
// real NewService (variadic Option, defined in webhook.go which stays
// unconditional, so the type is always available).
func NewService(_ string, _ ...Option) *Service { return &Service{} }

func (s *Service) Name() string                                  { return "webhook-disabled" }
func (s *Service) Order() int                                    { return 90 }
func (s *Service) Start(_ context.Context, _ coreapi.Deps) error { return nil }
func (s *Service) Stop(_ context.Context) error                  { return nil }

// SetURL is a silent no-op when the plugin is disabled. Persisting
// the URL would be misleading because nothing is going to deliver to
// it; callers learn the result via Stats() returning zero counters.
func (s *Service) SetURL(_ string) {}

// Stats always returns the zero value when the plugin is disabled.
func (s *Service) Stats() Stats { return Stats{} }

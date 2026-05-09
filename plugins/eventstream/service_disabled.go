// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build no_eventstream
// +build no_eventstream

// Stub — provides a no-op Service when this plugin is disabled at
// build time via -tags=no_eventstream. The daemon registers the
// no-op so plugin start/stop are clean; port 1002 is never bound and
// no pub/sub broker runs in-process.

package eventstream

import (
	"context"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

// Service is a no-op replacement for the real plugin Service.
type Service struct{}

// NewService returns a disabled eventstream stub. Same signature as
// the real NewService.
func NewService() *Service { return &Service{} }

func (s *Service) Name() string                                  { return "eventstream-disabled" }
func (s *Service) Order() int                                    { return 120 }
func (s *Service) Start(_ context.Context, _ coreapi.Deps) error { return nil }
func (s *Service) Stop(_ context.Context) error                  { return nil }

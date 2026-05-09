// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build no_skillinject
// +build no_skillinject

// Stub — provides a no-op Service when this plugin is disabled at
// build time via -tags=no_skillinject. The daemon registers the no-op
// so plugin start/stop are clean; no skill reconciliation runs.

package skillinject

import (
	"context"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

// Service is a no-op replacement for the real plugin Service. Same
// exported surface so cmd/daemon compiles unchanged.
type Service struct{}

// NewService returns a disabled skillinject stub. Same signature as the
// real NewService.
func NewService(_ Config) *Service { return &Service{} }

func (s *Service) Name() string                                  { return "skillinject-disabled" }
func (s *Service) Order() int                                    { return 200 }
func (s *Service) Start(_ context.Context, _ coreapi.Deps) error { return nil }
func (s *Service) Stop(_ context.Context) error                  { return nil }

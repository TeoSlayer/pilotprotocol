// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build no_dataexchange
// +build no_dataexchange

// Stub — provides a no-op Service when this plugin is disabled at
// build time via -tags=no_dataexchange. The daemon registers the
// no-op so plugin start/stop are clean; port 1001 is never bound and
// no inbox/received files are written.

package dataexchange

import (
	"context"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

// ServiceConfig mirrors the real ServiceConfig so cmd/daemon's
// dataexchange.NewService(dataexchange.ServiceConfig{...}) call site
// compiles unchanged when the plugin is disabled.
type ServiceConfig struct {
	ReceivedDir   string
	InboxDir      string
	IncludeBase64 bool
}

// Service is a no-op replacement for the real plugin Service.
type Service struct{}

// NewService returns a disabled dataexchange stub. Same signature as
// the real NewService.
func NewService(_ ServiceConfig) *Service { return &Service{} }

func (s *Service) Name() string                                  { return "dataexchange-disabled" }
func (s *Service) Order() int                                    { return 110 }
func (s *Service) Start(_ context.Context, _ coreapi.Deps) error { return nil }
func (s *Service) Stop(_ context.Context) error                  { return nil }

// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build no_gateway
// +build no_gateway

// Stub — provides a no-op Service when this plugin is disabled at
// build time via -tags=no_gateway. cmd/gateway (the standalone
// binary) keeps using gateway.New / *Gateway.Start regardless of
// build tag — those live in gateway.go which is not tagged.

package gateway

import (
	"context"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

// Service is a no-op replacement for the (today-unused) plugin
// Service adapter. Same exported surface so any future cmd/daemon
// registration compiles unchanged under no_gateway.
type Service struct{}

// NewService returns a disabled gateway plugin stub. Same signature
// as the real NewService in service.go.
func NewService() *Service { return &Service{} }

func (s *Service) Name() string                                  { return "gateway-disabled" }
func (s *Service) Order() int                                    { return 220 }
func (s *Service) Start(_ context.Context, _ coreapi.Deps) error { return nil }
func (s *Service) Stop(_ context.Context) error                  { return nil }

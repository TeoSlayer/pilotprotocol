// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build no_nameserver
// +build no_nameserver

// Stub — provides a no-op Service when this plugin is disabled at
// build time via -tags=no_nameserver. cmd/nameserver (the standalone
// binary) keeps using nameserver.New / *Server.ListenAndServe
// regardless of build tag — those live in server.go which is not
// tagged.

package nameserver

import (
	"context"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

// Service is a no-op replacement for the (today-unused) plugin
// Service adapter. Same exported surface so any future cmd/daemon
// registration compiles unchanged under no_nameserver.
type Service struct{}

// NewService returns a disabled nameserver plugin stub. Same signature
// as the real NewService in service.go.
func NewService() *Service { return &Service{} }

func (s *Service) Name() string                                  { return "nameserver-disabled" }
func (s *Service) Order() int                                    { return 150 }
func (s *Service) Start(_ context.Context, _ coreapi.Deps) error { return nil }
func (s *Service) Stop(_ context.Context) error                  { return nil }

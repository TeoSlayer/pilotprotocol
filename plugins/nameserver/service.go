// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_nameserver
// +build !no_nameserver

package nameserver

import (
	"context"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

// Service is the L11 plugin lifecycle adapter for the nameserver. The
// daemon does not register this today — cmd/nameserver is a
// standalone binary that uses nameserver.New / *Server.ListenAndServe
// directly. The adapter exists so the plugin package conforms to the
// L10 Service contract and so the no_nameserver build tag has a
// meaningful counterpart (see service_disabled.go).
//
// When this plugin is eventually wired into cmd/daemon's plugin
// runtime, this Service will own the *Server lifecycle. Today its
// Start/Stop are no-ops; it is registered nowhere.
type Service struct{}

// NewService returns a Service ready for daemon.RegisterPlugin (when
// cmd/daemon eventually starts registering it). Distinct from
// nameserver.New, which constructs the standalone *Server used by
// cmd/nameserver.
func NewService() *Service { return &Service{} }

func (s *Service) Name() string                                  { return "nameserver" }
func (s *Service) Order() int                                    { return 150 }
func (s *Service) Start(_ context.Context, _ coreapi.Deps) error { return nil }
func (s *Service) Stop(_ context.Context) error                  { return nil }

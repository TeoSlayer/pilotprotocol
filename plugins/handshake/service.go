// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"context"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

// Service is the L11 plugin adapter for the manual trust-handshake
// runtime (port 444). Wraps a Manager and bridges between the
// coreapi.Service lifecycle (Start/Stop with deps) and the
// Runtime-interface accept loop.
type Service struct {
	mgr *Manager
}

// NewService constructs a handshake plugin Service over the given
// Runtime. The composition root (plugins/runtime or test harness) builds
// the Runtime and registers the resulting Service.
func NewService(rt Runtime) *Service {
	return &Service{mgr: NewManager(rt)}
}

// --- coreapi.Service ---

func (s *Service) Name() string  { return "handshake" }
func (s *Service) Order() int    { return 60 }
func (s *Service) Start(_ context.Context, _ coreapi.Deps) error {
	return s.mgr.Start()
}

func (s *Service) Stop(_ context.Context) error {
	if s.mgr.ln != nil {
		s.mgr.ln.Close()
	}
	s.mgr.Stop()
	return nil
}

// Manager returns the underlying Manager (test access + composition glue).
func (s *Service) Manager() *Manager { return s.mgr }

// Compile-time guard.
var _ coreapi.Service = (*Service)(nil)

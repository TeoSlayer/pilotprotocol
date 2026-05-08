// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_skillinject
// +build !no_skillinject

// Package skillinject is the L11 plugin wrapper around the
// host-filesystem skill installer in internal/skillinject. The
// installer itself has no daemon coupling — it scans known agent-tool
// directories and writes SKILL.md/heartbeat references — so the data
// layer lives utility-tier where both the daemon plugin and
// cmd/pilotctl can call it.
package skillinject

import (
	"context"

	internalskillinject "github.com/TeoSlayer/pilotprotocol/internal/skillinject"
	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

// Re-exports for source compatibility. New code should import
// internal/skillinject directly.
type (
	Config  = internalskillinject.Config
	Report  = internalskillinject.Report
	Outcome = internalskillinject.Outcome
)

// Service is the L11 plugin adapter. The daemon (L7) holds plugins
// only as coreapi.Service interfaces — no skillinject import in core.
// Concrete construction happens in cmd/daemon/main.go (L12).
type Service struct {
	cfg    Config
	cancel context.CancelFunc
	done   chan struct{}
}

// NewService returns a Service ready for daemon.RegisterPlugin.
func NewService(cfg Config) *Service {
	return &Service{cfg: cfg}
}

func (s *Service) Name() string { return "skillinject" }

// Order: 200 — runs after core lifecycle services (registry connect,
// IPC, port services). See coreapi.Service docs for the convention.
func (s *Service) Order() int { return 200 }

func (s *Service) Start(ctx context.Context, deps coreapi.Deps) error {
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	events := deps.Events
	go func() {
		defer close(s.done)
		// L11 panic boundary: skillinject runs background fs/network
		// scans; a panic must not kill the daemon.
		// TODO(03-INVARIANTS.md §8): per-plugin supervisor.
		defer coreapi.RecoverPlugin("skillinject", "Run", events, nil)
		internalskillinject.Run(runCtx, s.cfg)
	}()
	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.done == nil {
		return nil
	}
	select {
	case <-s.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

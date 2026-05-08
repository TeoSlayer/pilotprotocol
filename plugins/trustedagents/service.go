// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_trustedagents
// +build !no_trustedagents

package trustedagents

import (
	"context"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

// Service is the L11 plugin adapter. Implements both coreapi.Service
// (lifecycle) and coreapi.TrustChecker (trust gate). Daemon stores it
// twice — once in the plugin registry, once as the trust checker —
// but it's the same struct.
type Service struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// NewService returns a Service ready for daemon.RegisterPlugin and
// daemon.RegisterTrustChecker.
func NewService() *Service {
	return &Service{}
}

func (s *Service) Name() string { return "trustedagents" }

// Order: 50 — must start BEFORE handshake (~order 70) so the
// allowlist is populated when the first trust handshake arrives.
func (s *Service) Order() int { return 50 }

func (s *Service) Start(ctx context.Context, deps coreapi.Deps) error {
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	events := deps.Events
	go func() {
		defer close(s.done)
		// L11 panic boundary.
		// TODO(03-INVARIANTS.md §8): per-plugin supervisor.
		defer coreapi.RecoverPlugin("trustedagents", "Run", events, nil)
		Run(runCtx)
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

// IsTrusted is the coreapi.TrustChecker side of the plugin. Delegates
// to the package-global allowlist that Run() maintains.
func (s *Service) IsTrusted(nodeID uint32) (string, bool) {
	return IsTrusted(nodeID)
}

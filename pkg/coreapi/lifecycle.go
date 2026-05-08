// SPDX-License-Identifier: AGPL-3.0-or-later

package coreapi

import (
	"context"
	"log/slog"
	"sort"
	"sync"
)

// Service is the lifecycle contract every L11 plugin implements.
//
// Order determines the start sequence. Lower numbers start first;
// higher numbers stop first. Suggested ranges:
//
//	  10-49   Foundation (none today)
//	  50-79   Trust / identity-adjacent (trustedagents)
//	  80-99   Observability (webhook)
//	 100-199  Application services (dataexchange, eventstream, tasks)
//	 200-249  Sidecars (skillinject)
//	 250+     Tooling-bound (updater)
//
// Start receives Deps (the L10 surface). Implementations must NOT
// retain references to anything outside Deps — that's the whole
// extraction contract.
//
// Stop should drain in-flight work, close listeners, and signal
// background goroutines to exit. It must return within 5 seconds
// or the daemon shutdown gate will fail.
type Service interface {
	Name() string
	Order() int
	Start(ctx context.Context, deps Deps) error
	Stop(ctx context.Context) error
}

// Deps is the bag of capabilities a plugin can use. Optional fields
// may be nil if the corresponding plugin isn't loaded; plugins that
// hard-depend on them should error in Start().
type Deps struct {
	Streams  Streams
	Identity Identity
	Resolver PeerResolver
	Events   EventBus
	Logger   *slog.Logger

	// Optional — nil if the plugin providing them isn't registered.
	Trust TrustChecker
}

// ServiceRegistry coordinates plugin lifecycle. cmd/daemon/main.go
// constructs one, registers each plugin, and hands it to the daemon.
// The daemon calls StartAll during bootstrap and StopAll during
// shutdown.
type ServiceRegistry struct {
	mu       sync.Mutex
	services []Service
	started  []Service // start order, used to stop in reverse
}

// Register adds a service. Must be called before StartAll. After
// StartAll runs, Register is a no-op error.
func (sr *ServiceRegistry) Register(s Service) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	if len(sr.started) > 0 {
		return ErrRegistryStarted
	}
	sr.services = append(sr.services, s)
	return nil
}

// StartAll sorts by Order and starts every service in sequence.
// The first failing Start aborts and returns its error; previously-
// started services are NOT auto-stopped (the caller's job, via Stop()
// or by passing a context that cancels).
func (sr *ServiceRegistry) StartAll(ctx context.Context, deps Deps) error {
	sr.mu.Lock()
	if len(sr.started) > 0 {
		sr.mu.Unlock()
		return ErrRegistryStarted
	}
	sort.SliceStable(sr.services, func(i, j int) bool {
		return sr.services[i].Order() < sr.services[j].Order()
	})
	queue := append([]Service(nil), sr.services...)
	sr.mu.Unlock()

	for _, s := range queue {
		if err := s.Start(ctx, deps); err != nil {
			return err
		}
		sr.mu.Lock()
		sr.started = append(sr.started, s)
		sr.mu.Unlock()
	}
	return nil
}

// StopAll stops every started service in reverse order. Errors from
// individual Stop calls are collected; the first one is returned but
// every service still gets its Stop call invoked.
func (sr *ServiceRegistry) StopAll(ctx context.Context) error {
	sr.mu.Lock()
	queue := append([]Service(nil), sr.started...)
	sr.started = nil
	sr.mu.Unlock()

	var firstErr error
	for i := len(queue) - 1; i >= 0; i-- {
		if err := queue[i].Stop(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// All returns a snapshot of the registered services in start order.
func (sr *ServiceRegistry) All() []Service {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	out := make([]Service, len(sr.services))
	copy(out, sr.services)
	return out
}

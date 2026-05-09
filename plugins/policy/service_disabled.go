// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build no_policy
// +build no_policy

// Stub — provides a no-op Service when this plugin is disabled at
// build time via -tags=no_policy. The daemon registers the no-op so
// plugin start/stop are clean; no per-network runners are started,
// no network.* events are reacted to, and the PolicyManager exposed
// via Manager() is a no-op (Start returns nil runner+error, All
// returns empty).

package policy

import (
	"context"
	"errors"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

// Service is a no-op replacement for the real plugin Service.
type Service struct{}

// NewService returns a disabled policy stub. Same signature as the
// real NewService (takes a Runtime, ignored under no_policy).
func NewService(_ Runtime) *Service { return &Service{} }

func (s *Service) Name() string                                  { return "policy-disabled" }
func (s *Service) Order() int                                    { return 140 }
func (s *Service) Start(_ context.Context, _ coreapi.Deps) error { return nil }
func (s *Service) Stop(_ context.Context) error                  { return nil }

// Manager returns a no-op coreapi.PolicyManager.
func (s *Service) Manager() coreapi.PolicyManager { return disabledManager{} }

// errPolicyDisabled is returned by Manager().Start to make the disabled
// state observable to callers that explicitly try to start a runner.
var errPolicyDisabled = errors.New("policy: plugin disabled at build time")

type disabledManager struct{}

func (disabledManager) Start(_ uint16, _ []byte) (coreapi.PolicyRunner, error) {
	return nil, errPolicyDisabled
}
func (disabledManager) Stop(_ uint16)                     {}
func (disabledManager) Get(_ uint16) coreapi.PolicyRunner { return nil }
func (disabledManager) All() []coreapi.PolicyRunner       { return nil }
func (disabledManager) StopAll()                          {}
func (disabledManager) LoadPersisted() error              { return nil }

// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build no_trustedagents
// +build no_trustedagents

// Stub — provides a no-op Service when this plugin is disabled at
// build time via -tags=no_trustedagents. The daemon registers the
// no-op so plugin start/stop are clean; the trust-checker surface
// returns "untrusted" for every node so callers degrade gracefully.

package trustedagents

import (
	"context"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

// Service satisfies coreapi.Service and coreapi.TrustChecker with
// no-op implementations. Constructed by NewService when the plugin is
// disabled; behaviour: every IsTrusted query returns ("", false).
type Service struct{}

// NewService returns a disabled trustedagents stub. Same signature as
// the real NewService so cmd/daemon compiles unchanged.
func NewService() *Service { return &Service{} }

func (s *Service) Name() string                                  { return "trustedagents-disabled" }
func (s *Service) Order() int                                    { return 50 }
func (s *Service) Start(_ context.Context, _ coreapi.Deps) error { return nil }
func (s *Service) Stop(_ context.Context) error                  { return nil }

// IsTrusted always reports the node as untrusted when the plugin is
// disabled. Callers should treat this as a fail-closed default.
func (s *Service) IsTrusted(_ uint32) (string, bool) { return "", false }

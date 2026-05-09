// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build no_updater
// +build no_updater

// Stub — provides a no-op Service when this plugin is disabled at
// build time via -tags=no_updater. cmd/updater (the standalone
// binary) keeps using updater.New / *Updater.Start regardless of
// build tag — those live in updater.go which is not tagged.

package updater

import (
	"context"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

// Service is a no-op replacement for the (today-unused) plugin
// Service adapter. Same exported surface so any future cmd/daemon
// registration compiles unchanged under no_updater.
type Service struct{}

// NewService returns a disabled updater plugin stub. Same signature
// as the real NewService in service.go.
func NewService() *Service { return &Service{} }

func (s *Service) Name() string                                  { return "updater-disabled" }
func (s *Service) Order() int                                    { return 250 }
func (s *Service) Start(_ context.Context, _ coreapi.Deps) error { return nil }
func (s *Service) Stop(_ context.Context) error                  { return nil }

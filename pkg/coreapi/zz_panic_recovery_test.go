// SPDX-License-Identifier: AGPL-3.0-or-later

package coreapi_test

// Regression for P1 plugin-crash DoS: StartAll invokes each plugin's
// Start() directly with no recover wrapper. A plugin that panics
// during Start (nil-deref, index OOB, etc.) crashes the entire daemon
// process — operator's recourse is to find the buggy plugin via
// stack trace and disable it, while every other plugin is offline.
//
// Fix: StartAll wraps each plugin Start() in defer recover(), converts
// the panic to an error like any other Start failure. The error path
// (return on first failure, previously-started plugins NOT auto-
// stopped) is preserved — the caller's Stop() handles cleanup.

import (
	"context"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

// panickingService panics during Start with the given message.
type panickingService struct{ msg string }

func (p *panickingService) Name() string                                  { return "panicker" }
func (p *panickingService) Order() int                                    { return 100 }
func (p *panickingService) Start(_ context.Context, _ coreapi.Deps) error { panic(p.msg) }
func (p *panickingService) Stop(_ context.Context) error                  { return nil }

func TestServiceRegistry_StartAllRecoversFromPluginPanic(t *testing.T) {
	t.Parallel()

	sr := &coreapi.ServiceRegistry{}
	if err := sr.Register(&panickingService{msg: "boom from a buggy plugin"}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Without the recover wrapper, this CRASHES the test process.
	err := sr.StartAll(context.Background(), coreapi.Deps{})

	if err == nil {
		t.Fatal("StartAll returned nil for panicking plugin — recover wrapper missing")
	}
	if !strings.Contains(err.Error(), "panic") {
		t.Errorf("expected error to mention 'panic'; got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "boom from a buggy plugin") {
		t.Errorf("expected error to include the panic message; got %q", err.Error())
	}
}
